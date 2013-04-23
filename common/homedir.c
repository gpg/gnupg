/* homedir.c - Setup the home directory.
 *	Copyright (C) 2004, 2006, 2007 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
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

#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
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
      char path[MAX_PATH];

      /* It might be better to use LOCAL_APPDATA because this is
         defined as "non roaming" and thus more likely to be kept
         locally.  For private keys this is desired.  However, given
         that many users copy private keys anyway forth and back,
         using a system roaming services might be better than to let
         them do it manually.  A security conscious user will anyway
         use the registry entry to have better control.  */
      if (w32_shgetfolderpath (NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE,
                               NULL, 0, path) >= 0)
        {
          char *tmp = xmalloc (strlen (path) + 6 +1);
          strcpy (stpcpy (tmp, path), "\\gnupg");
          dir = tmp;

          /* Try to create the directory if it does not yet exists.  */
          if (access (dir, F_OK))
            CreateDirectory (dir, NULL);
        }
      else
        dir = GNUPG_DEFAULT_HOMEDIR;
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

              tmp = read_w32_registry_string (NULL, "Software\\GNU\\GnuPG",
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
static const char *
w32_rootdir (void)
{
  static int got_dir;
  static char dir[MAX_PATH+5];

  if (!got_dir)
    {
      char *p;

      if ( !GetModuleFileName ( NULL, dir, MAX_PATH) )
        {
          log_debug ("GetModuleFileName failed: %s\n", w32_strerror (0));
          *dir = 0;
        }
      got_dir = 1;
      p = strrchr (dir, DIRSEP_C);
      if (p)
        *p = 0;
      else
        {
          log_debug ("bad filename `%s' returned for this process\n", dir);
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
      char path[MAX_PATH];

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
          dir = xstrdup (w32_rootdir ());
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
#ifdef HAVE_W32_SYSTEM
  return w32_rootdir ();
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
  return w32_rootdir ();
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
    {
      const char *s1, *s2;
      s1 = w32_rootdir ();
      s2 = DIRSEP_S "lib" DIRSEP_S "gnupg";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
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
    {
      const char *s1, *s2;
      s1 = w32_rootdir ();
      s2 = DIRSEP_S "share" DIRSEP_S "gnupg";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
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
    {
      const char *s1, *s2;
      s1 = w32_rootdir ();
      s2 = DIRSEP_S "share" DIRSEP_S "locale";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return LOCALEDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Return the default socket name used by DirMngr. */
const char *
dirmngr_socket_name (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    {
      char s1[MAX_PATH];
      const char *s2;

      /* We need something akin CSIDL_COMMON_PROGRAMS, but local
	 (non-roaming).  */
      if (w32_shgetfolderpath (NULL, CSIDL_WINDOWS, NULL, 0, s1) < 0)
	strcpy (s1, "C:\\WINDOWS");
      s2 = DIRSEP_S "S.dirmngr";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return "/var/run/dirmngr/socket";
#endif /*!HAVE_W32_SYSTEM*/
}



/* Return the file name of a helper tool.  WHICH is one of the
   GNUPG_MODULE_NAME_foo constants.  */
const char *
gnupg_module_name (int which)
{
  const char *s, *s2;

#define X(a,b) do {                                          \
        static char *name;                                   \
        if (!name)                                           \
          {                                                  \
            s = gnupg_ ## a ();                              \
            s2 = DIRSEP_S b EXEEXT_S;                        \
            name = xmalloc (strlen (s) + strlen (s2) + 1);   \
            strcpy (stpcpy (name, s), s2);                   \
          }                                                  \
        return name;                                         \
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
      return GNUPG_DEFAULT_PINENTRY;
#else
      X(bindir, "pinentry");
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
      X(bindir, "dirmngr");
#endif

    case GNUPG_MODULE_NAME_PROTECT_TOOL:
#ifdef GNUPG_DEFAULT_PROTECT_TOOL
      return GNUPG_DEFAULT_PROTECT_TOOL;
#else
      X(libexecdir, "gpg-protect-tool");
#endif

    case GNUPG_MODULE_NAME_CHECK_PATTERN:
      X(libexecdir, "gpg-check-pattern");

    case GNUPG_MODULE_NAME_GPGSM:
      X(bindir, "gpgsm");

    case GNUPG_MODULE_NAME_GPG:
      X(bindir, "gpg2");

    case GNUPG_MODULE_NAME_CONNECT_AGENT:
      X(bindir, "gpg-connect-agent");

    case GNUPG_MODULE_NAME_GPGCONF:
      X(bindir, "gpgconf");

    default:
      BUG ();
    }
#undef X
}
