/* homedir.c - Setup the home directory.
 * Copyright (C) 2004, 2006, 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2013 Werner Koch
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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



#include "util.h"
#include "sysutils.h"

#ifdef HAVE_W32_SYSTEM
/* A flag used to indicate that a control file for gpgconf has been
   detected.  Under Windows the presence of this file indicates a
   portable installations and triggers several changes:

   - The GNUGHOME directory is fixed relative to installation
     directory.  All other means to set the home directory are ignore.

   - All registry variables will be ignored.

   This flag is not used on Unix systems.
 */
static int w32_portable_app;
#endif /*HAVE_W32_SYSTEM*/

#ifdef HAVE_W32_SYSTEM
/* This flag is true if this process' binary has been installed under
   bin and not in the root directory as often used before GnuPG 2.1. */
static int w32_bin_is_bin;
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


/* This is a helper function to load a Windows function from either of
   one DLLs. */
#ifdef HAVE_W32_SYSTEM
static HRESULT
w32_shgetfolderpath (HWND a, int b, HANDLE c, DWORD d, LPSTR e)
{
  static int initialized;
  static HRESULT (WINAPI * func)(HWND,int,HANDLE,DWORD,LPSTR);

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
              func = dlsym (handle, "SHGetFolderPathA");
              if (!func)
                {
                  dlclose (handle);
                  handle = NULL;
                }
            }
        }
    }

  if (func)
    return func (a,b,c,d,e);
  else
    return -1;
}
#endif /*HAVE_W32_SYSTEM*/


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
          char path[MAX_PATH];

          /* It might be better to use LOCAL_APPDATA because this is
             defined as "non roaming" and thus more likely to be kept
             locally.  For private keys this is desired.  However,
             given that many users copy private keys anyway forth and
             back, using a system roaming services might be better
             than to let them do it manually.  A security conscious
             user will anyway use the registry entry to have better
             control.  */
          if (w32_shgetfolderpath (NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE,
                                   NULL, 0, path) >= 0)
            {
              char *tmp = xmalloc (strlen (path) + 6 +1);
              strcpy (stpcpy (tmp, path), "\\gnupg");
              dir = tmp;

              /* Try to create the directory if it does not yet exists.  */
              if (access (dir, F_OK))
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
              char *tmp;

              tmp = read_w32_registry_string (NULL,
                                              GNUPG_REGISTRY_DIR,
                                              "HomeDir");
              if (tmp && !*tmp)
                {
                  xfree (tmp);
                  tmp = NULL;
                }
              if (tmp)
                saved_dir = tmp;
            }

          if (!saved_dir)
            saved_dir = standard_homedir ();
        }
      dir = saved_dir;
    }
#endif /*HAVE_W32_SYSTEM*/
  if (!dir || !*dir)
    dir = GNUPG_DEFAULT_HOMEDIR;

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
  if (access (fname, F_OK))
    log_error ("required binary '%s' is not installed\n", fname);
  else
    {
      strcpy (fname + strlen (fname) - 3, "ctl");
      if (!access (fname, F_OK))
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
      char path[MAX_PATH];

      /* Make sure that w32_rootdir has been called so that we are
         able to check the portable application flag.  The common dir
         is the identical to the rootdir.  In that case there is also
         no need to strdup its value.  */
      rdir = w32_rootdir ();
      if (w32_portable_app)
        return rdir;

      if (w32_shgetfolderpath (NULL, CSIDL_COMMON_APPDATA,
                               NULL, 0, path) >= 0)
        {
          char *tmp = xmalloc (strlen (path) + 4 +1);
          strcpy (stpcpy (tmp, path), "\\GNU");
          dir = tmp;
          /* No auto create of the directory.  Either the installer or
             the admin has to create these directories.  */
        }
      else
        {
          /* Ooops: Not defined - probably an old Windows version.
             Use the installation directory instead.  */
          dir = xstrdup (rdir);
        }
    }

  return dir;
}
#endif /*HAVE_W32_SYSTEM*/




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
          char path[MAX_PATH];
          const char *s1[] = { "GNU", "cache", "gnupg", NULL };
          int s1_len;
          const char **comp;

          s1_len = 0;
          for (comp = s1; *comp; comp++)
            s1_len += 1 + strlen (*comp);

          if (w32_shgetfolderpath (NULL, CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE,
                                   NULL, 0, path) >= 0)
            {
              char *tmp = xmalloc (strlen (path) + s1_len + 1);
              char *p;

              p = stpcpy (tmp, path);
              for (comp = s1; *comp; comp++)
                {
                  p = stpcpy (p, "\\");
                  p = stpcpy (p, *comp);

                  if (access (tmp, F_OK))
                    w32_try_mkdir (tmp);
                }

              dir = tmp;
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


/* Return the system socket name used by DirMngr.  */
const char *
dirmngr_sys_socket_name (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    {
      char *p;
# ifdef HAVE_W32CE_SYSTEM
      const char *s1, *s2;

      s1 = default_homedir ();
# else
      char s1buf[MAX_PATH];
      const char *s1, *s2;

      s1 = default_homedir ();
      if (!w32_portable_app)
        {
          /* We need something akin CSIDL_COMMON_PROGRAMS, but local
             (non-roaming).  This is because the file needs to be on
             the local machine and makes only sense on that machine.
             CSIDL_WINDOWS seems to be the only location which
             guarantees that. */
          if (w32_shgetfolderpath (NULL, CSIDL_WINDOWS, NULL, 0, s1buf) < 0)
            strcpy (s1buf, "C:\\WINDOWS");
          s1 = s1buf;
        }
# endif
      s2 = DIRSEP_S DIRMNGR_SOCK_NAME;
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
      for (p=name; *p; p++)
        if (*p == '/')
          *p = '\\';
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return GNUPG_LOCALSTATEDIR "/run/" PACKAGE_NAME "/"DIRMNGR_SOCK_NAME;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Return the user socket name used by DirMngr.  If a user specific
   dirmngr installation is not supported, NULL is returned.  */
const char *
dirmngr_user_socket_name (void)
{
  static char *name;

  if (!name)
    name = make_absfilename (default_homedir (), DIRMNGR_SOCK_NAME, NULL);
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
          if (!access (name2, F_OK))
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


/* Return the file name of a helper tool.  WHICH is one of the
   GNUPG_MODULE_NAME_foo constants.  */
const char *
gnupg_module_name (int which)
{
#define X(a,b) do {                                                     \
    static char *name;                                                  \
    if (!name)                                                          \
      name = xstrconcat (gnupg_ ## a (), DIRSEP_S b EXEEXT_S, NULL);    \
    return name;                                                        \
  } while (0)

  switch (which)
    {
    case GNUPG_MODULE_NAME_AGENT:
#ifdef GNUPG_DEFAULT_AGENT
      return GNUPG_DEFAULT_AGENT;
#else
      X(bindir, "gpg-agent");
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
      X(libexecdir, "scdaemon");
#endif

    case GNUPG_MODULE_NAME_DIRMNGR:
#ifdef GNUPG_DEFAULT_DIRMNGR
      return GNUPG_DEFAULT_DIRMNGR;
#else
      X(bindir, DIRMNGR_NAME);
#endif

    case GNUPG_MODULE_NAME_PROTECT_TOOL:
#ifdef GNUPG_DEFAULT_PROTECT_TOOL
      return GNUPG_DEFAULT_PROTECT_TOOL;
#else
      X(libexecdir, "gpg-protect-tool");
#endif

    case GNUPG_MODULE_NAME_DIRMNGR_LDAP:
#ifdef GNUPG_DEFAULT_DIRMNGR_LDAP
      return GNUPG_DEFAULT_DIRMNGR_LDAP;
#else
      X(libexecdir, "dirmngr_ldap");
#endif

    case GNUPG_MODULE_NAME_CHECK_PATTERN:
      X(libexecdir, "gpg-check-pattern");

    case GNUPG_MODULE_NAME_GPGSM:
      X(bindir, "gpgsm");

    case GNUPG_MODULE_NAME_GPG:
      X(bindir, NAME_OF_INSTALLED_GPG);

    case GNUPG_MODULE_NAME_CONNECT_AGENT:
      X(bindir, "gpg-connect-agent");

    case GNUPG_MODULE_NAME_GPGCONF:
      X(bindir, "gpgconf");

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
