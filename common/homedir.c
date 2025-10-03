/* homedir.c - Setup the home directory.
 * Copyright (C) 2004, 2006, 2007, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2013, 2016 Werner Koch
 * Copyright (C) 2021, 2024 g10 Code GmbH
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
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
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

/* The name of the symbolic link to the file from which the process
 * text was read.  */
#if __linux__
# define MYPROC_SELF_EXE "/proc/self/exe"
#elif defined(__NetBSD__)
# define MYPROC_SELF_EXE "/proc/curproc/exe"
#elif defined(__illumos__) || defined(__sun)
# define MYPROC_SELF_EXE "/proc/self/path/a.out"
#else /* Assume other BSDs */
# define MYPROC_SELF_EXE "/proc/curproc/file"
#endif


/* Mode flags for unix_rootdir.  */
enum wantdir_values {
  WANTDIR_ROOT = 0,
  WANTDIR_SYSCONF,
  WANTDIR_SOCKET
};


/* The GnuPG homedir.  This is only accessed by the functions
 * gnupg_homedir and gnupg_set_homedir.  Malloced.  */
static char *the_gnupg_homedir;

/* Flag indicating that home directory is not the default one.  */
static byte non_default_homedir;


/* An object to store information taken from a gpgconf.ctl file.  This
 * is parsed early at startup time and never changed later.  */
static struct
{
  unsigned int checked:1; /* True if we have checked for a gpgconf.ctl.  */
  unsigned int found:1;   /* True if a gpgconf.ctl was found.            */
  unsigned int empty:1;   /* The file is empty except for comments.      */
  unsigned int valid:1;   /* The entries in gpgconf.ctl are valid.       */
  unsigned int portable:1;/* Windows portable installation.              */
  char *gnupg;            /* The "gnupg" directory part.  */
  char *rootdir;          /* rootdir or NULL        */
  char *sysconfdir;       /* sysconfdir or NULL     */
  char *socketdir;        /* socketdir or NULL      */
} gpgconf_ctl;


#ifdef HAVE_W32_SYSTEM
/* A flag used to indicate that a control file for gpgconf has been
 * detected.  Under Windows the presence of this file indicates a
 * portable installations and triggers several changes:
 *
 * - The GNUGHOME directory is fixed relative to installation
 *   directory.  All other means to set the home directory are ignored.
 *
 * - All registry variables will be ignored.
 *
 * This flag is not used on Unix systems.
 */
static byte w32_portable_app;
#endif /*HAVE_W32_SYSTEM*/

#ifdef HAVE_W32_SYSTEM
/* This flag is true if this process's binary has been installed under
   bin and not in the root directory as often used before GnuPG 2.1. */
static byte w32_bin_is_bin;
#endif /*HAVE_W32_SYSTEM*/


#ifdef HAVE_W32_SYSTEM
static const char *w32_rootdir (void);
#endif

/* Return the name of the gnupg dir.  This is usually "gnupg".  */
static const char *
my_gnupg_dirname (void)
{
  if (gpgconf_ctl.valid && gpgconf_ctl.gnupg)
    return gpgconf_ctl.gnupg;
  return "gnupg";
}

/* Return the hardwired home directory which is not anymore so
 * hardwired because it may now be modified using the gpgconf.ctl
 * "gnupg" keyword.  */
static const char *
my_fixed_default_homedir (void)
{
  if (gpgconf_ctl.valid && gpgconf_ctl.gnupg)
    {
      static char *name;
      char *p;

      if (!name)
        {
          name = xmalloc (strlen (GNUPG_DEFAULT_HOMEDIR)
                          + strlen (gpgconf_ctl.gnupg) + 1);
          strcpy (name, GNUPG_DEFAULT_HOMEDIR);
          p = strrchr (name, '/');
          if (p)
            p++;
          else
            p = name;
          if (*p == '.')
            p++; /* Keep a leading dot.  */
          strcpy (p, gpgconf_ctl.gnupg);
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  return GNUPG_DEFAULT_HOMEDIR;
}



/* Under Windows we need to modify the standard registry key with the
 * "gnupg" keyword from a gpgconf.ctl.  */
#ifdef HAVE_W32_SYSTEM
const char *
gnupg_registry_dir (void)
{
  if (gpgconf_ctl.valid && gpgconf_ctl.gnupg)
    {
      static char *name;
      char *p;

      if (!name)
        {
          name = xmalloc (strlen (GNUPG_REGISTRY_DIR)
                          + strlen (gpgconf_ctl.gnupg) + 1);
          strcpy (name, GNUPG_REGISTRY_DIR);
          p = strrchr (name, '\\');
          if (p)
            p++;
          else
            p = name;
          strcpy (p, gpgconf_ctl.gnupg);
          if (!strncmp (p, "gnupg", 5))
            {
              /* Registry keys are case-insensitive and we use a
               * capitalized version of gnupg by default.  So, if the
               * new value starts with "gnupg" we apply the usual
               * capitalization for this first part.  */
              p[0] = 'G';
              p[3] = 'P';
              p[4] = 'G';
            }
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  return GNUPG_REGISTRY_DIR;
}
#endif /*HAVE_W32_SYSTEM*/


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

/* Given the directory name DNAME try to create a common.conf and
 * enable the keyboxd.  This should only be called for the standard
 * home directory and only if that directory has just been created.  */
static void
create_common_conf (const char *dname)
{
#ifdef BUILD_WITH_KEYBOXD
  estream_t fp;
  char *fcommon;

  fcommon = make_filename (dname, "common.conf", NULL);
  fp = es_fopen (fcommon, "wx,mode=-rw-r");
  if (!fp)
    {
      log_info (_("error creating '%s': %s\n"), fcommon,
                gpg_strerror (gpg_error_from_syserror ()));
    }
  else
    {
      if (es_fputs ("use-keyboxd\n", fp) == EOF)
        {
          log_info (_("error writing to '%s': %s\n"), fcommon,
                    gpg_strerror (es_ferror (fp)
                                  ? gpg_error_from_syserror ()
                                  : gpg_error (GPG_ERR_EOF)));
          es_fclose (fp);
        }
      else if (es_fclose (fp))
        {
          log_info (_("error closing '%s': %s\n"), fcommon,
                    gpg_strerror (gpg_error_from_syserror ()));
        }
    }
#else /* BUILD_WITH_KEYBOXD */
  (void)dname;
#endif /* !BUILD_WITH_KEYBOXD */
}


/* Check whether DIR is the default homedir.  */
static int
is_gnupg_default_homedir (const char *dir)
{
  int result;
  char *a = make_absfilename (dir, NULL);
  char *b = make_absfilename (standard_homedir (), NULL);
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
#ifdef HAVE_W32_SYSTEM
  char *p0;
  const char *s;
#endif

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

  /* Hack to mitigate badly doubled backslashes.  */
  s = result? result : newdir;
  if (s[0] == '\\' && s[1] == '\\' && s[2] != '\\')
    {
      /* UNC (\\Servername\file) or Long UNC (\\?\Servername\file)
       * Does not seem to be double quoted.  */
    }
  else if (strstr (s, "\\\\"))
    {
      /* Double quotes detected.  Fold them into one because that is
       * what what Windows does.  This way we get a unique hash
       * regardless of the number of doubled backslashes. */
      if (!result)
        result = xstrdup (newdir);
      for (p0=p=result; *p; p++)
        {
          *p0++ = *p;
          while (*p == '\\' && p[1] == '\\')
            p++;
        }
      *p0 = 0;
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
   gnupg_homedir(). */
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
          gpgrt_annotate_leaked_object (dir);
        }
      else
        {
          char *path;

          path = w32_shgetfolderpath (NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE,
                                      NULL, 0);
          if (path)
            {
              dir = xstrconcat (path, "\\", my_gnupg_dirname (), NULL);
              xfree (path);
              gpgrt_annotate_leaked_object (dir);

              /* Try to create the directory if it does not yet exists.  */
              if (gnupg_access (dir, F_OK))
                if (!gnupg_mkdir (dir, "-rwx"))
                  create_common_conf (dir);

            }
          else
            dir = my_fixed_default_homedir ();
        }
    }
  return dir;
#else/*!HAVE_W32_SYSTEM*/
  return my_fixed_default_homedir ();
#endif /*!HAVE_W32_SYSTEM*/
}

/* Set up the default home directory.  The usual --homedir option
   should be parsed later. */
static const char *
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
                                              gnupg_registry_dir (),
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
    dir = my_fixed_default_homedir ();
  else
    {
      char *p;

      p = copy_dir_with_fixup (dir);
      if (p)
        {
          /* A new buffer has been allocated with proper semantics.
           * Assign this to DIR.  If DIR is passed again to
           * copy_dir_with_fixup there will be no need for a fix up
           * and the function returns NULL.  Thus we leak only once.
           * Setting the homedir is usually a one-off task but might
           * be called a second time.  We also ignore such extra leaks
           * because we don't know who still references the former
           * string.  */
          gpgrt_annotate_leaked_object (p);
          dir = p;
        }

      if (!is_gnupg_default_homedir (dir))
        non_default_homedir = 1;
    }

  return dir;
}


/* Return true if S can be inteprtated as true.  This is uised for
 * keywords in gpgconf.ctl.  Spaces must have been trimmed.  */
static int
string_is_true (const char *s)
{
  return (atoi (s)
          || !ascii_strcasecmp (s, "yes")
          || !ascii_strcasecmp (s, "true")
          || !ascii_strcasecmp (s, "fact"));
}

/* This function is used to parse the gpgconf.ctl file and set the
 * information ito the gpgconf_ctl structure.  This is called once
 * with the full filename of gpgconf.ctl.  There are two callers: One
 * used on Windows and one on Unix.  No error return but diagnostics
 * are printed.  */
static void
parse_gpgconf_ctl (const char *fname)
{
  gpg_error_t err;
  char *p;
  char *line;
  size_t linelen;
  ssize_t length;
  estream_t fp;
  const char *name;
  int anyitem = 0;
  int ignoreall = 0;
  char *gnupgval = NULL;
  char *rootdir = NULL;
  char *sysconfdir = NULL;
  char *socketdir = NULL;

  if (gpgconf_ctl.checked)
    return;  /* Just in case this is called a second time.  */
  gpgconf_ctl.checked = 1;
  gpgconf_ctl.found = 0;
  gpgconf_ctl.valid = 0;
  gpgconf_ctl.empty = 0;

  if (gnupg_access (fname, F_OK))
    return; /* No gpgconf.ctl file.  */

  /* log_info ("detected '%s'\n", buffer); */
  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_info ("error opening '%s': %s\n", fname, gpg_strerror (err));
      return;
    }
  gpgconf_ctl.found = 1;

  line = NULL;
  linelen = 0;
  while ((length = es_read_line (fp, &line, &linelen, NULL)) > 0)
    {
      static const char *names[] =
        {
          "gnupg",
          "rootdir",
          "sysconfdir",
          "socketdir",
          "portable",
          ".enable"
        };
      int i;
      size_t n;

      /* Strip NL and CR, if present.  */
      while (length > 0
             && (line[length - 1] == '\n' || line[length - 1] == '\r'))
        line[--length] = 0;
      trim_spaces (line);
      if (*line == '#' || !*line)
        continue;
      anyitem = 1;

      /* Find the keyword.  */
      name = NULL;
      p = NULL;
      for (i=0; i < DIM (names); i++)
        {
          n = strlen (names[i]);
          if (!strncmp (line, names[i], n))
            {
              while (line[n] == ' ' || line[n] == '\t')
                n++;
              if (line[n] == '=')
                {
                  name = names[i];
                  p = line + n + 1;
                  break;
                }
            }
        }
      if (!name)
        continue;  /* Keyword not known.  */

      trim_spaces (p);
      p = substitute_envvars (p);
      if (!p)
        {
          err = gpg_error_from_syserror ();
          log_info ("error getting %s from gpgconf.ctl: %s\n",
                    name, gpg_strerror (err));
        }
      else if (!strcmp (name, ".enable"))
        {
          if (string_is_true (p))
            ;              /* Yes, this file shall be used.    */
          else
            ignoreall = 1; /* No, this file shall be ignored.  */
          xfree (p);
        }
      else if (!strcmp (name, "gnupg"))
        {
          xfree (gnupgval);
          gnupgval = p;
        }
      else if (!strcmp (name, "sysconfdir"))
        {
          xfree (sysconfdir);
          sysconfdir = p;
        }
      else if (!strcmp (name, "socketdir"))
        {
          xfree (socketdir);
          socketdir = p;
        }
      else if (!strcmp (name, "rootdir"))
        {
          xfree (rootdir);
          rootdir = p;
        }
      else if (!strcmp (name, "portable"))
        {
          gpgconf_ctl.portable = string_is_true (p);
          xfree (p);
        }
      else /* Unknown keyword.  */
        xfree (p);
    }
  if (es_ferror (fp))
    {
      err = gpg_error_from_syserror ();
      log_info ("error reading '%s': %s\n", fname, gpg_strerror (err));
      ignoreall = 1;  /* Force all entries to invalid.  */
    }
  es_fclose (fp);
  xfree (line);

  if (ignoreall)
    ; /* Forced error.  Note that .found is still set.  */
  else if (gnupgval && (!*gnupgval || strpbrk (gnupgval, "/\\")))
    {
      /* We don't allow a slash or backslash in the value because our
       * code assumes this is a single directory name.  */
      log_info ("invalid %s '%s' specified in gpgconf.ctl\n",
                "gnupg", gnupgval);
    }
  else if (rootdir && (!*rootdir || *rootdir != '/'))
    {
      log_info ("invalid %s '%s' specified in gpgconf.ctl\n",
                "rootdir", rootdir);
    }
  else if (sysconfdir && (!*sysconfdir || *sysconfdir != '/'))
    {
      log_info ("invalid %s '%s' specified in gpgconf.ctl\n",
                "sysconfdir", sysconfdir);
    }
  else if (socketdir && (!*socketdir || *socketdir != '/'))
    {
      log_info ("invalid %s '%s' specified in gpgconf.ctl\n",
                "socketdir", socketdir);
    }
  else
    {
      if (gnupgval)
        {
          gpgconf_ctl.gnupg = gnupgval;
          gpgrt_annotate_leaked_object (gpgconf_ctl.gnupg);
          /* log_info ("want gnupg '%s'\n", dir); */
        }
      if (rootdir)
        {
          while (*rootdir && rootdir[strlen (rootdir)-1] == '/')
            rootdir[strlen (rootdir)-1] = 0;
          gpgconf_ctl.rootdir = rootdir;
          gpgrt_annotate_leaked_object (gpgconf_ctl.rootdir);
          /* log_info ("want rootdir '%s'\n", dir); */
        }
      if (sysconfdir)
        {
          while (*sysconfdir && sysconfdir[strlen (sysconfdir)-1] == '/')
            sysconfdir[strlen (sysconfdir)-1] = 0;
          gpgconf_ctl.sysconfdir = sysconfdir;
          gpgrt_annotate_leaked_object (gpgconf_ctl.sysconfdir);
          /* log_info ("want sysconfdir '%s'\n", sdir); */
        }
      if (socketdir)
        {
          while (*socketdir && socketdir[strlen (socketdir)-1] == '/')
            socketdir[strlen (socketdir)-1] = 0;
          gpgconf_ctl.socketdir = socketdir;
          gpgrt_annotate_leaked_object (gpgconf_ctl.socketdir);
          /* log_info ("want socketdir '%s'\n", s2dir); */
        }
      gpgconf_ctl.valid = 1;
    }

  gpgconf_ctl.empty = !anyitem;
  if (!gpgconf_ctl.valid)
    {
      /* Error reading some entries - clear them all.  */
      xfree (gnupgval);
      xfree (rootdir);
      xfree (sysconfdir);
      xfree (socketdir);
      gpgconf_ctl.gnupg = NULL;
      gpgconf_ctl.rootdir = NULL;
      gpgconf_ctl.sysconfdir = NULL;
      gpgconf_ctl.socketdir = NULL;
    }
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
      parse_gpgconf_ctl (fname);
      if ((gpgconf_ctl.found && gpgconf_ctl.empty)
          || (gpgconf_ctl.valid && gpgconf_ctl.portable))
        {
          unsigned int flags;

          /* Classic gpgconf.ctl file found.  This is a portable
           * application.  Note that if there are any items in that
           * file we don't consider this a portable application unless
           * the (later added) ".portable" keyword has also been
           * seen.  */
          w32_portable_app = 1;
          log_get_prefix (&flags);
          log_set_prefix (NULL, (flags | GPGRT_LOG_NO_REGISTRY));
        }
    }
  xfree (fname);
}
#endif /*HAVE_W32_SYSTEM*/


#ifdef HAVE_W32_SYSTEM
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
#endif /*HAVE_W32_SYSTEM*/


#ifndef HAVE_W32_SYSTEM /* Unix */
/* Determine the root directory of the gnupg installation on Unix.
 * The standard case is that this function returns NULL so that the
 * root directory as configured at build time is used.  However, it
 * may return a static string with a different root directory, similar
 * to what we do on Windows.  That second mode is triggered by the
 * existence of a file gpgconf.ctl installed side-by-side to gpgconf.
 * This file is parsed for keywords describing the actually to be used
 * root directory.  There is no solid standard on Unix to locate the
 * binary used to create the process, thus we support this currently
 * only on Linux and BSD where we can look this info up using the proc
 * file system.  If WANT_SYSCONFDIR is true the optional sysconfdir
 * entry is returned.  */
static const char *
unix_rootdir (enum wantdir_values wantdir)
{
  if (!gpgconf_ctl.checked)
    {
      char *p;
      char *buffer;
      size_t bufsize = 256-1;
      int nread;
      gpg_error_t err;
      const char *name;

      for (;;)
        {
          buffer = xmalloc (bufsize+1);
          nread = readlink (MYPROC_SELF_EXE, buffer, bufsize);
          if (nread < 0)
            {
              err = gpg_error_from_syserror ();
              buffer[0] = 0;
              if ((name = getenv ("GNUPG_BUILD_ROOT")) && *name == '/')
                {
                  /* Try a fallback for systems w/o a supported /proc
                   * file system if we are running a regression test.  */
                  log_info ("error reading symlink '%s': %s\n",
                            MYPROC_SELF_EXE, gpg_strerror (err));
                  xfree  (buffer);
                  buffer = xstrconcat (name, "/bin/gpgconf", NULL);
                  log_info ("trying fallback '%s'\n", buffer);
                }
              break;
            }
          else if (nread < bufsize)
            {
              buffer[nread] = 0;
              break;  /* Got it.  */
            }
          else if (bufsize >= 4095)
            {
              buffer[0] = 0;
              log_info ("error reading symlink '%s': %s\n",
                        MYPROC_SELF_EXE, "value too large");
              break;
            }
          xfree (buffer);
          bufsize += 256;
        }
      if (!*buffer)
        {
          xfree (buffer);
          gpgconf_ctl.checked = 1;
          return NULL;  /* Error - assume no gpgconf.ctl.  */
        }

      p = strrchr (buffer, '/');
      if (!p)
        {
          xfree (buffer);
          gpgconf_ctl.checked = 1;
          return NULL;  /* Erroneous /proc - assume no gpgconf.ctl.  */
        }
      *p = 0;  /* BUFFER has the directory.  */
      if (!(p = strrchr (buffer, '/')))
        {
          /* Installed in the root which is not a good idea.  Assume
           * no gpgconf.ctl.  */
          xfree (buffer);
          gpgconf_ctl.checked = 1;
          return NULL;
        }

      /* Strip one part and expect the file below a bin dir.  */
      *p = 0;
      p = xstrconcat (buffer, "/bin/gpgconf.ctl", NULL);
      xfree (buffer);
      buffer = p;
      parse_gpgconf_ctl (buffer);
      xfree (buffer);
    }

  if (!gpgconf_ctl.valid)
    return NULL; /* No valid entries in gpgconf.ctl  */

  switch (wantdir)
    {
    case WANTDIR_ROOT:    return gpgconf_ctl.rootdir;
    case WANTDIR_SYSCONF: return gpgconf_ctl.sysconfdir;
    case WANTDIR_SOCKET:  return gpgconf_ctl.socketdir;
    }

  return NULL; /* Not reached.  */
}
#endif /* Unix */


#ifdef HAVE_W32_SYSTEM
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
      gpgrt_annotate_leaked_object (dir);
    }

  return dir;
}


/*
 * On Windows, isatty returns TRUE when it's NUL device.
 * We need additional check.
 */
int
gnupg_isatty (int fd)
{
  HANDLE h;
  DWORD mode;

  if (!isatty (fd))
    return 0;

  h = (HANDLE)_get_osfhandle (fd);
  if (h == INVALID_HANDLE_VALUE)
    return 0;

  if (!GetConsoleMode (h, &mode))
    return 0;

  return 1;
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
  /* Fixme: Should we use
   *   gpgrt_annotate_leaked_object(the_gnupg_homedir)
   * despite that we may free and allocate a new one in some
   * cases?  */
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
      else
        {
          if (!quiet )
            log_info ( _("directory '%s' created\n"), fname );
          create_common_conf (fname);
        }
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
        name = xstrdup ("/"); /* Error - use the current top dir instead.  */
      else
        name = xstrdup (path);
      gpgrt_annotate_leaked_object (name);
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
#if defined(HAVE_W32_SYSTEM)
  char *name;
  gpg_err_code_t ec;

  (void)skip_checks;

  *r_info = 0;

  /* First make sure that non_default_homedir and w32_portable_app can
   * be set.  */
  gnupg_homedir ();

  if (w32_portable_app)
    {
      name = xstrconcat (w32_rootdir (), DIRSEP_S, my_gnupg_dirname (), NULL);
    }
  else
    {
      char *path;

      path = w32_shgetfolderpath (NULL,
                                  CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE,
                                  NULL, 0);
      if (path)
        {
          name = xstrconcat (path, "\\", my_gnupg_dirname (), NULL);
          xfree (path);
          if (gnupg_access (name, F_OK))
            gnupg_mkdir (name, "-rwx");
        }
      else
        {
          name = xstrdup (gnupg_homedir ());
        }
    }

  /* If a non default homedir is used, we check whether an
   * corresponding sub directory below the socket dir is available
   * and use that.  We hash the non default homedir to keep the new
   * subdir short enough.  */
  if (non_default_homedir)
    {
      char sha1buf[20];
      struct stat sb;
      char *suffix;
      char *p;

      *r_info |= 32; /* Testing subdir.  */

      /* Canonicalize the name to avoid problems with mixed case
       * names.  Note that we use only 10 bytes of the hash because on
       * Windows the account name is also part of the name.  */
      suffix = ascii_strlwr (xstrdup (gnupg_homedir ()));
      for (p=suffix; *p; p++)
        if ( *p == '\\')
          *p = '/';
      gcry_md_hash_buffer (GCRY_MD_SHA1, sha1buf, suffix, strlen (suffix));
      xfree (suffix);
      suffix = zb32_encode (sha1buf, 8*10);
      if (!suffix)
        {
          *r_info |= 1; /* Out of core etc. */
          goto leave_w32;
        }
      p = xstrconcat (name, "\\d.", suffix, NULL);
      xfree (suffix);
      xfree (name);
      name = p;

      /* Stat that directory and check constraints.
       * The command
       *    gpgconf --remove-socketdir
       * can be used to remove that directory.  */
      if (gnupg_stat (name, &sb))
        {
          if (errno != ENOENT)
            *r_info |= 1; /* stat failed. */
          else if (!skip_checks)
            {
              /* Try to create the directory and check again.  */
              ec = gnupg_mkdir (name, "-rwx");
              if (ec && ec != GPG_ERR_EEXIST)
                *r_info |= 16; /* mkdir failed.  */
              else if (gnupg_stat (name, &sb))
                {
                  if (errno != ENOENT)
                    *r_info |= 1; /* stat failed. */
                  else
                    *r_info |= 64; /* Subdir does not exist.  */
                }
              else
                goto leave_w32; /* Success!  */
            }
          else
            *r_info |= 64; /* Subdir does not exist.  */
          if (!skip_checks)
            {
              xfree (name);
              name = NULL;
              goto leave_w32;
            }
        }
    }

 leave_w32:
  /* If nothing works - fall back to the homedir.  */
  if (!name)
    {
      *r_info |= 128; /* Fallback.  */
      name = xstrdup (gnupg_homedir ());
    }

#elif !defined(HAVE_STAT)
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
  char prefixbuffer[256];
  const char *prefix;
  const char *s;
  char *name = NULL;
  const char *gnupgname = my_gnupg_dirname ();
  gpg_err_code_t ec;

  *r_info = 0;

  /* First make sure that non_default_homedir can be set.  */
  gnupg_homedir ();

  /* It has been suggested to first check XDG_RUNTIME_DIR envvar.
   * However, the specs state that the lifetime of the directory MUST
   * be bound to the user being logged in.  Now GnuPG may also be run
   * as a background process with no (desktop) user logged in.  Thus
   * we better don't do that.  */

  prefix = unix_rootdir (WANTDIR_SOCKET);
  if (!prefix)
    {
      /* gpgconf.ctl does not specify a directory.  Check whether we
       * have the usual /run/[gnupg/]user dir.  */
      for (i=0; bases[i]; i++)
        {
          snprintf (prefixbuffer, sizeof prefixbuffer, "%s/user/%u",
                    bases[i], (unsigned int)getuid ());
          prefix = prefixbuffer;
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

      if (strlen (prefix) + strlen (gnupgname) + 2 >= sizeof prefixbuffer)
        {
          *r_info |= 1; /* Ooops: Buffer too short to append "/gnupg".  */
          goto leave;
        }
      strcat (prefixbuffer, "/");
      strcat (prefixbuffer, gnupgname);
    }

  /* Check whether the gnupg sub directory (or the specified directory)
   * has proper permissions.  */
  if (stat (prefix, &sb))
    {
      if (errno != ENOENT)
        {
          *r_info |= 1; /* stat failed.  */
          goto leave;
        }

      /* Try to create the directory and check again.
       * Here comes a possible race condition:
       *     stat(2) above failed by ENOENT, but another process does
       *     mkdir(2) before we do mkdir(2)
       * So, an error with EEXIST should be handled.
       */
      ec = gnupg_mkdir (prefix, "-rwx");
      if (ec && ec != GPG_ERR_EEXIST)
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
              ec = gnupg_mkdir (name, "-rwx");
              if (ec && ec != GPG_ERR_EEXIST)
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
      gpgrt_annotate_leaked_object (name);
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
      name = xstrconcat (w32_commondir (), DIRSEP_S, "etc", DIRSEP_S,
                         my_gnupg_dirname (), NULL);
      gpgrt_annotate_leaked_object (name);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  const char *dir = unix_rootdir (WANTDIR_SYSCONF);
  if (dir)
    return dir;
  else
    return GNUPG_SYSCONFDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


const char *
gnupg_bindir (void)
{
  static char *name;
  const char *rdir;

#if defined(HAVE_W32_SYSTEM)
  rdir = w32_rootdir ();
  if (w32_bin_is_bin)
    {
      if (!name)
        {
          name = xstrconcat (rdir, DIRSEP_S "bin", NULL);
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  else
    return rdir;
#else /*!HAVE_W32_SYSTEM*/
  rdir = unix_rootdir (WANTDIR_ROOT);
  if (rdir)
    {
      if (!name)
        {
          name = xstrconcat (rdir, DIRSEP_S "bin", NULL);
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  else
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
  static char *name;
  const char *rdir;

  rdir = unix_rootdir (WANTDIR_ROOT);
  if (rdir)
    {
      if (!name)
        {
          name = xstrconcat (rdir, DIRSEP_S "libexec", NULL);
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  else
    return GNUPG_LIBEXECDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *
gnupg_libdir (void)
{
  static char *name;

#ifdef HAVE_W32_SYSTEM
  if (!name)
    {
      name = xstrconcat (w32_rootdir (), DIRSEP_S "lib" DIRSEP_S "gnupg", NULL);
      gpgrt_annotate_leaked_object (name);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  const char *rdir;

  rdir = unix_rootdir (WANTDIR_ROOT);
  if (rdir)
    {
      if (!name)
        {
          name = xstrconcat (rdir, DIRSEP_S "lib", DIRSEP_S, "gnupg", NULL);
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  else
    return GNUPG_LIBDIR;
#endif /*!HAVE_W32_SYSTEM*/
}

const char *
gnupg_datadir (void)
{
  static char *name;

#ifdef HAVE_W32_SYSTEM
  if (!name)
    {
      name = xstrconcat (w32_rootdir (), DIRSEP_S "share" DIRSEP_S "gnupg",
                         NULL);
      gpgrt_annotate_leaked_object (name);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  const char *rdir;

  rdir = unix_rootdir (WANTDIR_ROOT);
  if (rdir)
    {
      if (!name)
        {
          name = xstrconcat (rdir, DIRSEP_S "share" DIRSEP_S "gnupg", NULL);
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  else
    return GNUPG_DATADIR;
#endif /*!HAVE_W32_SYSTEM*/
}


const char *
gnupg_localedir (void)
{
  static char *name;

#ifdef HAVE_W32_SYSTEM
  if (!name)
    {
      name = xstrconcat (w32_rootdir (), DIRSEP_S "share" DIRSEP_S "locale",
                         NULL);
      gpgrt_annotate_leaked_object (name);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  const char *rdir;

  rdir = unix_rootdir (WANTDIR_ROOT);
  if (rdir)
    {
      if (!name)
        {
          name = xstrconcat (rdir, DIRSEP_S "share" DIRSEP_S "locale", NULL);
          gpgrt_annotate_leaked_object (name);
        }
      return name;
    }
  else
    return LOCALEDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Return the standard socket name used by gpg-agent.  */
const char *
gpg_agent_socket_name (void)
{
  static char *name;

  if (!name)
    {
      name = make_filename (gnupg_socketdir (), GPG_AGENT_SOCK_NAME, NULL);
      gpgrt_annotate_leaked_object (name);
    }
  return name;
}

/* Return the user socket name used by DirMngr.  */
const char *
dirmngr_socket_name (void)
{
  static char *name;

  if (!name)
    {
      name = make_filename (gnupg_socketdir (), DIRMNGR_SOCK_NAME, NULL);
      gpgrt_annotate_leaked_object (name);
    }
  return name;
}


/* Return the user socket name used by Keyboxd.  */
const char *
keyboxd_socket_name (void)
{
  static char *name;

  if (!name)
    {
      name = make_filename (gnupg_socketdir (), KEYBOXD_SOCK_NAME, NULL);
      gpgrt_annotate_leaked_object (name);
    }
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
      if (name)
        gpgrt_annotate_leaked_object (name);
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
 * potentially outdated installed ones.
 * Fixme: It might be better to make use of the newer gpgconf.ctl feature
 *        for regression testing.
 */
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
    if (!name) {                                                        \
      name = gnupg_build_directory                                      \
        ? xstrconcat (gnupg_build_directory,                            \
                      DIRSEP_S b DIRSEP_S c EXEEXT_S, NULL)             \
        : xstrconcat (gnupg_ ## a (), DIRSEP_S c EXEEXT_S, NULL);       \
      gpgrt_annotate_leaked_object (name);                              \
    }                                                                   \
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

    case GNUPG_MODULE_NAME_TPM2DAEMON:
#ifdef GNUPG_DEFAULT_TPM2DAEMON
      return GNUPG_DEFAULT_TPM2DAEMON;
#else
      X(libexecdir, "tpm2d", TPM2DAEMON_NAME);
#endif

    case GNUPG_MODULE_NAME_DIRMNGR:
#ifdef GNUPG_DEFAULT_DIRMNGR
      return GNUPG_DEFAULT_DIRMNGR;
#else
      X(bindir, "dirmngr", DIRMNGR_NAME);
#endif

    case GNUPG_MODULE_NAME_KEYBOXD:
#ifdef GNUPG_DEFAULT_KEYBOXD
      return GNUPG_DEFAULT_KEYBOXD;
#else
      X(libexecdir, "kbx", KEYBOXD_NAME);
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
      X(bindir, "g10", GPG_NAME);

    case GNUPG_MODULE_NAME_GPGV:
      X(bindir, "g10", GPG_NAME "v");

    case GNUPG_MODULE_NAME_CONNECT_AGENT:
      X(bindir, "tools", "gpg-connect-agent");

    case GNUPG_MODULE_NAME_GPGCONF:
      X(bindir, "tools", "gpgconf");

    case GNUPG_MODULE_NAME_CARD:
      X(bindir, "tools", "gpg-card");

    case GNUPG_MODULE_NAME_GPGTAR:
      X(bindir, "tools", "gpgtar");

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
