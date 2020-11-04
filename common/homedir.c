/* homedir.c - Setup the home directory.
 * Copyright (C) 2004, 2006, 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2013, 2016 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_W32_SYSTEM
#include <winsock2.h>   /* Due to the stupid mingw64 requirement to
                           include this header before windows.h which
                           is often implicitly included.  */
#include <shlobj.h>
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CSIDL_COMMON_APPDATA
#define CSIDL_COMMON_APPDATA 0x0023
#endif
#ifndef CSIDL_FLAG_CREATE
#define CSIDL_FLAG_CREATE 0x8000
#endif
#endif /*HAVE_W32_SYSTEM*/

#ifdef HAVE_STAT
#include <sys/stat.h> /* for stat() */
#endif



#include "util.h"
#include "sysutils.h"
#include "i18n.h"
#include "zb32.h"

/* The GnuPG homedir.  This is only accessed by the functions
 * gnupg_homedir and gnupg_set_homedir.  Malloced.  */
static char *the_gnupg_homedir;

/* Flag indicating that home directory is not the default one.  */
static byte non_default_homedir;


#ifdef HAVE_W32_SYSTEM
/* A flag used to indicate that a control file for gpgconf has been
   detected.  Under Windows the presence of this file indicates a
   portable installations and triggers several changes:

   - The GNUGHOME directory is fixed relative to installation
     directory.  All other means to set the home directory are ignore.

   - All registry variables will be ignored.

   This flag is not used on Unix systems.
 */
static byte w32_portable_app;
#endif /*HAVE_W32_SYSTEM*/

#ifdef HAVE_W32_SYSTEM
/* This flag is true if this process' binary has been installed under
   bin and not in the root directory as often used before GnuPG 2.1. */
static byte w32_bin_is_bin;
#endif /*HAVE_W32_SYSTEM*/


#ifdef HAVE_W32_SYSTEM
static const char *w32_rootdir (void);
#endif



#ifdef HAVE_W32_SYSTEM
static void
w32_try_mkdir (const char *dir)
{
#ifdef HAVE_W32CE_SYSTEM
  wchar_t *wdir = utf8_to_wchar (dir);
  if (wdir)
    {
      CreateDirectory (wdir, NULL);
      xfree (wdir);
    }
#else
  CreateDirectory (dir, NULL);
#endif
}
#endif


/* This is a helper function to load and call a Windows function from
 * either of one DLLs.  On success an UTF-8 file name is returned.
 * ERRNO is _not_ set on error.  */
#ifdef HAVE_W32_SYSTEM
static char *
w32_shgetfolderpath (HWND a, int b, HANDLE c, DWORD d)
{
  static int initialized;
  static HRESULT (WINAPI * func)(HWND,int,HANDLE,DWORD,LPWSTR);
  wchar_t wfname[MAX_PATH];

  if (!initialized)
    {
      static char *dllnames[] = { "shell32.dll", "shfolder.dll", NULL };
      void *handle;
      int i;

      initialized = 1;

      for (i=0, handle = NULL; !handle && dllnames[i]; i++)
        {
          handle = dlopen (dllnames[i], RTLD_LAZY);
          if (handle)
            {
              func = dlsym (handle, "SHGetFolderPathW");
              if (!func)
                {
                  dlclose (handle);
                  handle = NULL;
                }
            }
        }
    }

  if (func && func (a,b,c,d,wfname) >= 0)
    return wchar_to_utf8 (wfname);
  else
    return NULL;
}
#endif /*HAVE_W32_SYSTEM*/


/* Check whether DIR is the default homedir.  */
static int
is_gnupg_default_homedir (const char *dir)
{
  int result;
  char *a = make_absfilename (dir, NULL);
  char *b = make_absfilename (GNUPG_DEFAULT_HOMEDIR, NULL);
  result = !compare_filenames (a, b);
  xfree (b);
  xfree (a);
  return result;
}


/* Helper to remove trailing slashes from NEWDIR.  Return a new
 * allocated string if that has been done or NULL if there are no
 * slashes to remove.  Also inserts a missing slash after a Windows
 * drive letter.  */
static char *
copy_dir_with_fixup (const char *newdir)
{
  char *result = NULL;
  char *p;

  if (!*newdir)
    return NULL;

#ifdef HAVE_W32_SYSTEM
  if (newdir[0] && newdir[1] == ':'
      && !(newdir[2] == '/' || newdir[2] == '\\'))
    {
      /* Drive letter with missing leading slash.  */
      p = result = xmalloc (strlen (newdir) + 1 + 1);
      *p++ = newdir[0];
      *p++ = newdir[1];
      *p++ = '\\';
      strcpy (p, newdir+2);

      /* Remove trailing slashes.  */
      p = result + strlen (result) - 1;
      while (p > result+2 && (*p == '/' || *p == '\\'))
        *p-- = 0;
    }
  else if (newdir[strlen (newdir)-1] == '/'
           || newdir[strlen (newdir)-1] == '\\' )
    {
      result = xstrdup (newdir);
      p = result + strlen (result) - 1;
      while (p > result
             && (*p == '/' || *p == '\\')
             && (p-1 > result && p[-1] != ':')) /* We keep "c:/". */
        *p-- = 0;
    }

#else /*!HAVE_W32_SYSTEM*/

  if (newdir[strlen (newdir)-1] == '/')
    {
      result = xstrdup (newdir);
      p = result + strlen (result) - 1;
      while (p > result && *p == '/')
        *p-- = 0;
    }

#endif /*!HAVE_W32_SYSTEM*/

  return result;
}


/* Get the standard home directory.  In general this function should
   not be used as it does not consider a registry value (under W32) or
   the GNUPGHOME environment variable.  It is better to use
   default_homedir(). */
const char *
standard_homedir (void)
{
#ifdef HAVE_W32_SYSTEM
  static const char *dir;

  if (!dir)
    {
      const char *rdir;

      rdir = w32_rootdir ();
      if (w32_portable_app)
        {
          dir = xstrconcat (rdir, DIRSEP_S "home", NULL);
        }
      else
        {
          char *path;

          path = w32_shgetfolderpath (NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE,
                                      NULL, 0);
          if (path)
            {
              dir = xstrconcat (path, "\\gnupg", NULL);
              xfree (path);

              /* Try to create the directory if it does not yet exists.  */
              if (gnupg_access (dir, F_OK))
                w32_try_mkdir (dir);
            }
          else
            dir = GNUPG_DEFAULT_HOMEDIR;
        }
    }
  return dir;
#else/*!HAVE_W32_SYSTEM*/
  return GNUPG_DEFAULT_HOMEDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

/* Set up the default home directory.  The usual --homedir option
   should be parsed later. */
const char *
default_homedir (void)
{
  const char *dir;

#ifdef HAVE_W32_SYSTEM
  /* For a portable application we only use the standard homedir.  */
  w32_rootdir ();
  if (w32_portable_app)
    return standard_homedir ();
#endif /*HAVE_W32_SYSTEM*/

  dir = getenv ("GNUPGHOME");
#ifdef HAVE_W32_SYSTEM
  if (!dir || !*dir)
    {
      static const char *saved_dir;

      if (!saved_dir)
        {
          if (!dir || !*dir)
            {
              char *tmp, *p;

              /* This is deprecated; gpgconf --list-dirs prints a
               * warning if the homedir has been taken from the
               * registry.  */
              tmp = read_w32_registry_string (NULL,
                                              GNUPG_REGISTRY_DIR,
                                              "HomeDir");
              if (tmp && !*tmp)
                {
                  xfree (tmp);
                  tmp = NULL;
                }
              if (tmp)
                {
                  /* Strip trailing backslashes.  */
                  p = tmp + strlen (tmp) - 1;
                  while (p > tmp && *p == '\\')
                    *p-- = 0;
                  saved_dir = tmp;
                }
            }

          if (!saved_dir)
            saved_dir = standard_homedir ();
        }
      dir = saved_dir;
    }
#endif /*HAVE_W32_SYSTEM*/

  if (!dir || !*dir)
    dir = GNUPG_DEFAULT_HOMEDIR;
  else
    {
      char *p;

      p = copy_dir_with_fixup (dir);
      if (p)
        dir = p;

      if (!is_gnupg_default_homedir (dir))
        non_default_homedir = 1;
    }

  return dir;
}


#ifdef HAVE_W32_SYSTEM
/* Check whether gpgconf is installed and if so read the gpgconf.ctl
   file. */
static void
check_portable_app (const char *dir)
{
  char *fname;

  fname = xstrconcat (dir, DIRSEP_S "gpgconf.exe", NULL);
  if (!gnupg_access (fname, F_OK))
    {
      strcpy (fname + strlen (fname) - 3, "ctl");
      if (!gnupg_access (fname, F_OK))
        {
          /* gpgconf.ctl file found.  Record this fact.  */
          w32_portable_app = 1;
          {
            unsigned int flags;
            log_get_prefix (&flags);
            log_set_prefix (NULL, (flags | GPGRT_LOG_NO_REGISTRY));
          }
          /* FIXME: We should read the file to detect special flags
             and print a warning if we don't understand them  */
        }
    }
  xfree (fname);
}


/* Determine the root directory of the gnupg installation on Windows.  */
static const char *
w32_rootdir (void)
{
  static int got_dir;
  static char dir[MAX_PATH+5];

  if (!got_dir)
    {
      char *p;
      int rc;
      wchar_t wdir [MAX_PATH+5];

      rc = GetModuleFileNameW (NULL, wdir, MAX_PATH);
      if (rc && WideCharToMultiByte (CP_UTF8, 0, wdir, -1, dir, MAX_PATH-4,
                                     NULL, NULL) < 0)
        rc = 0;
      if (!rc)
        {
          log_debug ("GetModuleFileName failed: %s\n", w32_strerror (-1));
          *dir = 0;
        }
      got_dir = 1;
      p = strrchr (dir, DIRSEP_C);
      if (p)
        {
          *p = 0;

          check_portable_app (dir);

          /* If we are installed below "bin" we strip that and use
             the top directory instead.  */
          p = strrchr (dir, DIRSEP_C);
          if (p && !strcmp (p+1, "bin"))
            {
              *p = 0;
              w32_bin_is_bin = 1;
            }
        }
      if (!p)
        {
          log_debug ("bad filename '%s' returned for this process\n", dir);
          *dir = 0;
        }
    }

  if (*dir)
    return dir;
  /* Fallback to the hardwired value. */
  return GNUPG_LIBEXECDIR;
}

static const char *
w32_commondir (void)
{
  static char *dir;

  if (!dir)
    {
      const char *rdir;
      char *path;

      /* Make sure that w32_rootdir has been called so that we are
         able to check the portable application flag.  The common dir
         is the identical to the rootdir.  In that case there is also
         no need to strdup its value.  */
      rdir = w32_rootdir ();
      if (w32_portable_app)
        return rdir;

      path = w32_shgetfolderpath (NULL, CSIDL_COMMON_APPDATA, NULL, 0);
      if (path)
        {
          dir = xstrconcat (path, "\\GNU", NULL);
          /* No auto create of the directory.  Either the installer or
           * the admin has to create these directories.  */
        }
      else
        {
          /* Folder not found or defined - probably an old Windows
           * version.  Use the installation directory instead.  */
          dir = xstrdup (rdir);
        }
    }

  return dir;
}
#endif /*HAVE_W32_SYSTEM*/


/* Change the homedir.  Some care must be taken to set this early
 * enough because previous calls to gnupg_homedir may else return a
 * different string.  */
void
gnupg_set_homedir (const char *newdir)
{
  char *tmp = NULL;

  if (!newdir || !*newdir)
    newdir = default_homedir ();
  else
    {
      tmp = copy_dir_with_fixup (newdir);
      if (tmp)
        newdir = tmp;

      if (!is_gnupg_default_homedir (newdir))
        non_default_homedir = 1;
    }
  xfree (the_gnupg_homedir);
  the_gnupg_homedir = make_absfilename (newdir, NULL);;
  xfree (tmp);
}


/* Create the homedir directory only if the supplied directory name is
 * the same as the default one.  This way we avoid to create arbitrary
 * directories when a non-default home directory is used.  To cope
 * with HOME, we do compare only the suffix if we see that the default
 * homedir does start with a tilde.  If the mkdir fails the function
 * terminates the process.  If QUIET is set not diagnostic is printed
 * on homedir creation.  */
void
gnupg_maybe_make_homedir (const char *fname, int quiet)
{
  const char *defhome = standard_homedir ();

  if (
#ifdef HAVE_W32_SYSTEM
      ( !compare_filenames (fname, defhome) )
#else
      ( *defhome == '~'
        && (strlen(fname) >= strlen (defhome+1)
            && !strcmp(fname+strlen(fname)-strlen(defhome+1), defhome+1 ) ))
      || (*defhome != '~'  && !compare_filenames( fname, defhome ) )
#endif
      )
    {
      if (gnupg_mkdir (fname, "-rwx"))
        log_fatal ( _("can't create directory '%s': %s\n"),
                    fname, strerror(errno) );
      else if (!quiet )
        log_info ( _("directory '%s' created\n"), fname );
    }
}


/* Return the homedir.  The returned string is valid until another
 * gnupg-set-homedir call.  This is always an absolute directory name.
 * The function replaces the former global var opt.homedir.  */
const char *
gnupg_homedir (void)
{
  /* If a homedir has not been set, set it to the default.  */
  if (!the_gnupg_homedir)
    the_gnupg_homedir = make_absfilename (default_homedir (), NULL);
  return the_gnupg_homedir;
}


/* Return whether the home dir is the default one.  */
int
gnupg_default_homedir_p (void)
{
  return !non_default_homedir;
}


/* Return the directory name used by daemons for their current working
 * directory.  */
const char *
gnupg_daemon_rootdir (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    {
      char path[MAX_PATH];
      size_t n;

      n = GetSystemDirectoryA (path, sizeof path);
      if (!n || n >= sizeof path)
        name = xstrdup ("/"); /* Error - use the curret top dir instead.  */
      else
        name = xstrdup (path);
    }

  return name;

#else /*!HAVE_W32_SYSTEM*/
  return "/";
#endif /*!HAVE_W32_SYSTEM*/
}


/* Helper for gnupg-socketdir.  This is a global function, so that
 * gpgconf can use it for its --create-socketdir command.  If
 * SKIP_CHECKS is set permission checks etc. are not done.  The
 * function always returns a malloced directory name and stores these
 * bit flags at R_INFO:
 *
 *   1 := Internal error, stat failed, out of core, etc.
 *   2 := No /run/user directory.
 *   4 := Directory not owned by the user, not a directory
 *        or wrong permissions.
 *   8 := Same as 4 but for the subdir.
 *  16 := mkdir failed
 *  32 := Non default homedir; checking subdir.
 *  64 := Subdir does not exist.
 * 128 := Using homedir as fallback.
 */
char *
_gnupg_socketdir_internal (int skip_checks, unsigned *r_info)
{
#if defined(HAVE_W32_SYSTEM) || !defined(HAVE_STAT)

  char *name;

  (void)skip_checks;
  *r_info = 0;
  name = xstrdup (gnupg_homedir ());

#else /* Unix and stat(2) available. */

  static const char * const bases[] = {
#ifdef USE_RUN_GNUPG_USER_SOCKET
    "/run/gnupg",
#endif
    "/run",
#ifdef USE_RUN_GNUPG_USER_SOCKET
    "/var/run/gnupg",
#endif
    "/var/run",
    NULL
  };
  int i;
  struct stat sb;
  char prefix[19 + 1 + 20 + 6 + 1];
  const char *s;
  char *name = NULL;

  *r_info = 0;

  /* First make sure that non_default_homedir can be set.  */
  gnupg_homedir ();

  /* It has been suggested to first check XDG_RUNTIME_DIR envvar.
   * However, the specs state that the lifetime of the directory MUST
   * be bound to the user being logged in.  Now GnuPG may also be run
   * as a background process with no (desktop) user logged in.  Thus
   * we better don't do that.  */

  /* Check whether we have a /run/[gnupg/]user dir.  */
  for (i=0; bases[i]; i++)
    {
      snprintf (prefix, sizeof prefix, "%s/user/%u",
                bases[i], (unsigned int)getuid ());
      if (!stat (prefix, &sb) && S_ISDIR(sb.st_mode))
        break;
    }
  if (!bases[i])
    {
      *r_info |= 2; /* No /run/user directory.  */
      goto leave;
    }

  if (sb.st_uid != getuid ())
    {
      *r_info |= 4; /* Not owned by the user.  */
      if (!skip_checks)
        goto leave;
    }

  if (strlen (prefix) + 7 >= sizeof prefix)
    {
      *r_info |= 1; /* Ooops: Buffer too short to append "/gnupg".  */
      goto leave;
    }
  strcat (prefix, "/gnupg");

  /* Check whether the gnupg sub directory has proper permissions.  */
  if (stat (prefix, &sb))
    {
      if (errno != ENOENT)
        {
          *r_info |= 1; /* stat failed.  */
          goto leave;
        }

      /* Try to create the directory and check again.  */
      if (gnupg_mkdir (prefix, "-rwx"))
        {
          *r_info |= 16; /* mkdir failed.  */
          goto leave;
        }
      if (stat (prefix, &sb))
        {
          *r_info |= 1; /* stat failed.  */
          goto leave;
        }
    }
  /* Check that it is a directory, owned by the user, and only the
   * user has permissions to use it.  */
  if (!S_ISDIR(sb.st_mode)
      || sb.st_uid != getuid ()
      || (sb.st_mode & (S_IRWXG|S_IRWXO)))
    {
      *r_info |= 4; /* Bad permissions or not a directory. */
      if (!skip_checks)
        goto leave;
    }

  /* If a non default homedir is used, we check whether an
   * corresponding sub directory below the socket dir is available
   * and use that.  We hash the non default homedir to keep the new
   * subdir short enough.  */
  if (non_default_homedir)
    {
      char sha1buf[20];
      char *suffix;

      *r_info |= 32; /* Testing subdir.  */
      s = gnupg_homedir ();
      gcry_md_hash_buffer (GCRY_MD_SHA1, sha1buf, s, strlen (s));
      suffix = zb32_encode (sha1buf, 8*15);
      if (!suffix)
        {
          *r_info |= 1; /* Out of core etc. */
          goto leave;
        }
      name = strconcat (prefix, "/d.", suffix, NULL);
      xfree (suffix);
      if (!name)
        {
          *r_info |= 1; /* Out of core etc. */
          goto leave;
        }

      /* Stat that directory and check constraints.
       * The command
       *    gpgconf --remove-socketdir
       * can be used to remove that directory.  */
      if (stat (name, &sb))
        {
          if (errno != ENOENT)
            *r_info |= 1; /* stat failed. */
          else if (!skip_checks)
            {
              /* Try to create the directory and check again.  */
              if (gnupg_mkdir (name, "-rwx"))
                *r_info |= 16; /* mkdir failed.  */
              else if (stat (prefix, &sb))
                {
                  if (errno != ENOENT)
                    *r_info |= 1; /* stat failed. */
                  else
                    *r_info |= 64; /* Subdir does not exist.  */
                }
              else
                goto leave; /* Success!  */
            }
          else
            *r_info |= 64; /* Subdir does not exist.  */
          if (!skip_checks)
            {
              xfree (name);
              name = NULL;
              goto leave;
            }
        }
      else if (!S_ISDIR(sb.st_mode)
               || sb.st_uid != getuid ()
               || (sb.st_mode & (S_IRWXG|S_IRWXO)))
        {
          *r_info |= 8; /* Bad permissions or subdir is not a directory.  */
          if (!skip_checks)
            {
              xfree (name);
              name = NULL;
              goto leave;
            }
        }
    }
  else
    name = xstrdup (prefix);

 leave:
  /* If nothing works fall back to the homedir.  */
  if (!name)
    {
      *r_info |= 128; /* Fallback.  */
      name = xstrdup (gnupg_homedir ());
    }

#endif /* Unix */

  return name;
}


/*
 * Return the name of the socket dir.  That is the directory used for
 * the IPC local sockets.  This is an absolute directory name.
 */
const char *
gnupg_socketdir (void)
{
  static char *name;

  if (!name)
    {
      unsigned int dummy;
      name = _gnupg_socketdir_internal (0, &dummy);
    }

  return name;
}


/* Return the name of the sysconfdir.  This is a static string.  This
   function is required because under Windows we can't simply compile
   it in.  */
const char *
gnupg_sysconfdir (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    {
      const char *s1, *s2;
      s1 = w32_commondir ();
      s2 = DIRSEP_S "etc" DIRSEP_S "gnupg";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return GNUPG_SYSCONFDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


const char *
gnupg_bindir (void)
{
#if defined (HAVE_W32CE_SYSTEM)
  static char *name;

  if (!name)
    name = xstrconcat (w32_rootdir (), DIRSEP_S "bin", NULL);
  return name;
#elif defined(HAVE_W32_SYSTEM)
  const char *rdir;

  rdir = w32_rootdir ();
  if (w32_bin_is_bin)
    {
      static char *name;

      if (!name)
        name = xstrconcat (rdir, DIRSEP_S "bin", NULL);
      return name;
    }
  else
    return rdir;
#else /*!HAVE_W32_SYSTEM*/
  return GNUPG_BINDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Return the name of the libexec directory.  The name is allocated in
   a static area on the first use.  This function won't fail. */
const char *
gnupg_libexecdir (void)
{
#ifdef HAVE_W32_SYSTEM
  return gnupg_bindir ();
#else /*!HAVE_W32_SYSTEM*/
  return GNUPG_LIBEXECDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *
gnupg_libdir (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    name = xstrconcat (w32_rootdir (), DIRSEP_S "lib" DIRSEP_S "gnupg", NULL);
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return GNUPG_LIBDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *
gnupg_datadir (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    name = xstrconcat (w32_rootdir (), DIRSEP_S "share" DIRSEP_S "gnupg", NULL);
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return GNUPG_DATADIR;
#endif /*!HAVE_W32_SYSTEM*/
}


const char *
gnupg_localedir (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    name = xstrconcat (w32_rootdir (), DIRSEP_S "share" DIRSEP_S "locale",
                       NULL);
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return LOCALEDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Return the name of the cache directory.  The name is allocated in a
   static area on the first use.  Windows only: If the directory does
   not exist it is created.  */
const char *
gnupg_cachedir (void)
{
#ifdef HAVE_W32_SYSTEM
  static const char *dir;

  if (!dir)
    {
      const char *rdir;

      rdir = w32_rootdir ();
      if (w32_portable_app)
        {
          dir = xstrconcat (rdir,
                            DIRSEP_S, "var",
                            DIRSEP_S, "cache",
                            DIRSEP_S, "gnupg", NULL);
        }
      else
        {
          char *path;
          const char *s1[] = { "GNU", "cache", "gnupg", NULL };
          int s1_len;
          const char **comp;

          s1_len = 0;
          for (comp = s1; *comp; comp++)
            s1_len += 1 + strlen (*comp);

          path = w32_shgetfolderpath (NULL,
                                      CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE,
                                      NULL, 0);
          if (path)
            {
              char *tmp = xmalloc (strlen (path) + s1_len + 1);
              char *p;

              p = stpcpy (tmp, path);
              for (comp = s1; *comp; comp++)
                {
                  p = stpcpy (p, "\\");
                  p = stpcpy (p, *comp);

                  if (gnupg_access (tmp, F_OK))
                    w32_try_mkdir (tmp);
                }

              dir = tmp;
              xfree (path);
            }
          else
            {
              dir = "c:\\temp\\cache\\gnupg";
#ifdef HAVE_W32CE_SYSTEM
              dir += 2;
              w32_try_mkdir ("\\temp\\cache");
              w32_try_mkdir ("\\temp\\cache\\gnupg");
#endif
            }
        }
    }
  return dir;
#else /*!HAVE_W32_SYSTEM*/
  return GNUPG_LOCALSTATEDIR "/cache/" PACKAGE_NAME;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Return the user socket name used by DirMngr.  */
const char *
dirmngr_socket_name (void)
{
  static char *name;

  if (!name)
    name = make_filename (gnupg_socketdir (), DIRMNGR_SOCK_NAME, NULL);
  return name;
}


/* Return the default pinentry name.  If RESET is true the internal
   cache is first flushed.  */
static const char *
get_default_pinentry_name (int reset)
{
  static struct {
    const char *(*rfnc)(void);
    const char *name;
  } names[] = {
    /* The first entry is what we return in case we found no
       other pinentry.  */
    { gnupg_bindir, DIRSEP_S "pinentry" EXEEXT_S },
#ifdef HAVE_W32_SYSTEM
    /* Try Gpg4win directory (with bin and without.) */
    { w32_rootdir, "\\..\\Gpg4win\\bin\\pinentry.exe" },
    { w32_rootdir, "\\..\\Gpg4win\\pinentry.exe" },
    /* Try a pinentry in a dir above us */
    { w32_rootdir, "\\..\\bin\\pinentry.exe" },
    /* Try old Gpgwin directory.  */
    { w32_rootdir, "\\..\\GNU\\GnuPG\\pinentry.exe" },
    /* Try a Pinentry from the common GNU dir.  */
    { w32_rootdir, "\\..\\GNU\\bin\\pinentry.exe" },
#endif
    /* Last chance is a pinentry-basic (which comes with the
       GnuPG 2.1 Windows installer).  */
    { gnupg_bindir, DIRSEP_S "pinentry-basic" EXEEXT_S }
  };
  static char *name;

  if (reset)
    {
      xfree (name);
      name = NULL;
    }

  if (!name)
    {
      int i;

      for (i=0; i < DIM(names); i++)
        {
          char *name2;

          name2 = xstrconcat (names[i].rfnc (), names[i].name, NULL);
          if (!gnupg_access (name2, F_OK))
            {
              /* Use that pinentry.  */
              xfree (name);
              name = name2;
              break;
            }
          if (!i) /* Store the first as fallback return.  */
            name = name2;
          else
            xfree (name2);
        }
    }

  return name;
}


/* If set, 'gnupg_module_name' returns modules from that build
 * directory.  */
static char *gnupg_build_directory;

/* For sanity checks.  */
static int gnupg_module_name_called;


/* Set NEWDIR as the new build directory.  This will make
 * 'gnupg_module_name' return modules from that build directory.  Must
 * be called before any invocation of 'gnupg_module_name', and must
 * not be called twice.  It can be used by test suites to make sure
 * the components from the build directory are used instead of
 * potentially outdated installed ones.  */
void
gnupg_set_builddir (const char *newdir)
{
  log_assert (! gnupg_module_name_called);
  log_assert (! gnupg_build_directory);
  gnupg_build_directory = xtrystrdup (newdir);
}


/* If no build directory has been configured, try to set it from the
 * environment.  We only do this in development builds to avoid
 * increasing the set of influential environment variables and hence
 * the attack surface of production builds.  */
static void
gnupg_set_builddir_from_env (void)
{
#if defined(IS_DEVELOPMENT_VERSION) || defined(ENABLE_GNUPG_BUILDDIR_ENVVAR)
  if (gnupg_build_directory)
    return;

  gnupg_build_directory = getenv ("GNUPG_BUILDDIR");
#endif
}


/* Return the file name of a helper tool.  WHICH is one of the
   GNUPG_MODULE_NAME_foo constants.  */
const char *
gnupg_module_name (int which)
{
  gnupg_set_builddir_from_env ();
  gnupg_module_name_called = 1;

#define X(a,b,c) do {                                                   \
    static char *name;                                                  \
    if (!name)                                                          \
      name = gnupg_build_directory                                      \
        ? xstrconcat (gnupg_build_directory,                            \
                      DIRSEP_S b DIRSEP_S c EXEEXT_S, NULL)             \
        : xstrconcat (gnupg_ ## a (), DIRSEP_S c EXEEXT_S, NULL);       \
    return name;                                                        \
  } while (0)

  switch (which)
    {
    case GNUPG_MODULE_NAME_AGENT:
#ifdef GNUPG_DEFAULT_AGENT
      return GNUPG_DEFAULT_AGENT;
#else
      X(bindir, "agent", "gpg-agent");
#endif

    case GNUPG_MODULE_NAME_PINENTRY:
#ifdef GNUPG_DEFAULT_PINENTRY
      return GNUPG_DEFAULT_PINENTRY;  /* (Set by a configure option) */
#else
      return get_default_pinentry_name (0);
#endif

    case GNUPG_MODULE_NAME_SCDAEMON:
#ifdef GNUPG_DEFAULT_SCDAEMON
      return GNUPG_DEFAULT_SCDAEMON;
#else
      X(libexecdir, "scd", "scdaemon");
#endif

    case GNUPG_MODULE_NAME_DIRMNGR:
#ifdef GNUPG_DEFAULT_DIRMNGR
      return GNUPG_DEFAULT_DIRMNGR;
#else
      X(bindir, "dirmngr", DIRMNGR_NAME);
#endif

    case GNUPG_MODULE_NAME_PROTECT_TOOL:
#ifdef GNUPG_DEFAULT_PROTECT_TOOL
      return GNUPG_DEFAULT_PROTECT_TOOL;
#else
      X(libexecdir, "agent", "gpg-protect-tool");
#endif

    case GNUPG_MODULE_NAME_DIRMNGR_LDAP:
#ifdef GNUPG_DEFAULT_DIRMNGR_LDAP
      return GNUPG_DEFAULT_DIRMNGR_LDAP;
#else
      X(libexecdir, "dirmngr", "dirmngr_ldap");
#endif

    case GNUPG_MODULE_NAME_CHECK_PATTERN:
      X(libexecdir, "tools", "gpg-check-pattern");

    case GNUPG_MODULE_NAME_GPGSM:
      X(bindir, "sm", "gpgsm");

    case GNUPG_MODULE_NAME_GPG:
#if USE_GPG2_HACK
      if (! gnupg_build_directory)
        X(bindir, "g10", GPG_NAME "2");
      else
#endif
        X(bindir, "g10", GPG_NAME);

    case GNUPG_MODULE_NAME_GPGV:
#if USE_GPG2_HACK
      if (! gnupg_build_directory)
        X(bindir, "g10", GPG_NAME "v2");
      else
#endif
        X(bindir, "g10", GPG_NAME "v");

    case GNUPG_MODULE_NAME_CONNECT_AGENT:
      X(bindir, "tools", "gpg-connect-agent");

    case GNUPG_MODULE_NAME_GPGCONF:
      X(bindir, "tools", "gpgconf");

    default:
      BUG ();
    }
#undef X
}


/* Flush some of the cached module names.  This is for example used by
   gpg-agent to allow configuring a different pinentry.  */
void
gnupg_module_name_flush_some (void)
{
  (void)get_default_pinentry_name (1);
}
