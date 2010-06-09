/* get-path.c - Utility functions for the W32 API
   Copyright (C) 1999 Free Software Foundation, Inc
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2007 g10 Code GmbH

   This file is part of DirMngr.
  
   DirMngr is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   DirMngr is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA  */

#error Code has been replaced by common/homedir.c

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#include <shlobj.h>
#include <io.h>
#endif

#include "util.h"

#ifdef HAVE_W32_SYSTEM
#define GNUPG_DEFAULT_HOMEDIR "c:/gnupg"
#elif defined(__VMS)
#define GNUPG_DEFAULT_HOMEDIR "/SYS\$LOGIN/gnupg" 
#else
#define GNUPG_DEFAULT_HOMEDIR "~/.gnupg"
#endif 

#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\'
#define DIRSEP_S "\\"
#else
#define DIRSEP_C '/'
#define DIRSEP_S "/"
#endif


#ifdef HAVE_W32_SYSTEM
#define RTLD_LAZY 0

static __inline__ void *
dlopen (const char * name, int flag)
{
  void * hd = LoadLibrary (name);
  return hd;
}

static __inline__ void *
dlsym (void * hd, const char * sym)
{
  if (hd && sym)
    {
      void * fnc = GetProcAddress (hd, sym);
      if (!fnc)
        return NULL;
      return fnc;
    }
  return NULL;
}

static __inline__ int
dlclose (void * hd)
{
  if (hd)
    {
      FreeLibrary (hd);
      return 0;
    }
  return -1;
}  


/* Return a string from the W32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn. */
static char *
read_w32_registry_string (const char *root, const char *dir, const char *name)
{
  HKEY root_key, key_handle;
  DWORD n1, nbytes, type;
  char *result = NULL;
	
  if ( !root )
    root_key = HKEY_CURRENT_USER;
  else if ( !strcmp( root, "HKEY_CLASSES_ROOT" ) )
    root_key = HKEY_CLASSES_ROOT;
  else if ( !strcmp( root, "HKEY_CURRENT_USER" ) )
    root_key = HKEY_CURRENT_USER;
  else if ( !strcmp( root, "HKEY_LOCAL_MACHINE" ) )
    root_key = HKEY_LOCAL_MACHINE;
  else if ( !strcmp( root, "HKEY_USERS" ) )
    root_key = HKEY_USERS;
  else if ( !strcmp( root, "HKEY_PERFORMANCE_DATA" ) )
    root_key = HKEY_PERFORMANCE_DATA;
  else if ( !strcmp( root, "HKEY_CURRENT_CONFIG" ) )
    root_key = HKEY_CURRENT_CONFIG;
  else
    return NULL;
	
  if ( RegOpenKeyEx ( root_key, dir, 0, KEY_READ, &key_handle ) )
    {
      if (root)
        return NULL; /* no need for a RegClose, so return direct */
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
        return NULL; /* still no need for a RegClose, so return direct */
    }

  nbytes = 1;
  if ( RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes ) )
    {
      if (root)
        goto leave;
      /* Try to fallback to HKLM also vor a missing value.  */
      RegCloseKey (key_handle);
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
        return NULL; /* Nope.  */
      if (RegQueryValueEx ( key_handle, name, 0, NULL, NULL, &nbytes))
        goto leave;
    }
  result = malloc ( (n1=nbytes+1) );
  if ( !result )
    goto leave;
  if ( RegQueryValueEx ( key_handle, name, 0, &type, result, &n1 ) )
    {
      free(result); result = NULL;
      goto leave;
    }
  result[nbytes] = 0; /* Make sure it is really a string.  */
  if (type == REG_EXPAND_SZ && strchr (result, '%')) 
    {
      char *tmp;
        
      n1 += 1000;
      tmp = malloc (n1+1);
      if (!tmp)
        goto leave;
      nbytes = ExpandEnvironmentStrings (result, tmp, n1);
      if (nbytes && nbytes > n1)
        {
          free (tmp);
          n1 = nbytes;
          tmp = malloc (n1 + 1);
          if (!tmp)
            goto leave;
          nbytes = ExpandEnvironmentStrings (result, tmp, n1);
          if (nbytes && nbytes > n1) {
            free (tmp); /* Oops - truncated, better don't expand at all. */
            goto leave;
          }
          tmp[nbytes] = 0;
          free (result);
          result = tmp;
        }
      else if (nbytes)  /* Okay, reduce the length. */
        {
          tmp[nbytes] = 0;
          free (result);
          result = malloc (strlen (tmp)+1);
          if (!result)
            result = tmp;
          else 
            {
              strcpy (result, tmp);
              free (tmp);
            }
        }
      else  /* Error - don't expand. */
        {
          free (tmp);
        }
    }

 leave:
  RegCloseKey( key_handle );
  return result;
}


/* This is a helper function to load and run a Windows function from
   either of one DLLs. */
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


#if 0
static char *
find_program_in_inst_dir (const char *name)
{
  char *result = NULL;
  char *tmp;

  tmp = read_w32_registry_string ("HKEY_LOCAL_MACHINE",
				  "Software\\GNU\\GnuPG",
				  "Install Directory");
  if (!tmp)
    return NULL;

  result = malloc (strlen (tmp) + 1 + strlen (name) + 1);
  if (!result)
    {
      free (tmp);
      return NULL;
    }

  strcpy (stpcpy (stpcpy (result, tmp), "\\"), name);
  free (tmp);
  if (access (result, F_OK))
    {
      free (result);
      return NULL;
    }

  return result;
}


static char *
find_program_at_standard_place (const char *name)
{
  char path[MAX_PATH];
  char *result = NULL;
      
  if (w32_shgetfolderpath (NULL, CSIDL_PROGRAM_FILES, NULL, 0, path) >= 0) 
    {
      result = malloc (strlen (path) + 1 + strlen (name) + 1);
      if (result)
        {
          strcpy (stpcpy (stpcpy (result, path), "\\"), name);
          if (access (result, F_OK))
            {
              free (result);
              result = NULL;
            }
        }
    }
  return result;
}
#endif
#endif


const char *
get_dirmngr_ldap_path (void)
{
  static char *pgmname;

#ifdef HAVE_W32_SYSTEM
  if (! pgmname)
    {
      const char *dir = dirmngr_libexecdir ();
      const char *exe = "\\dirmngr_ldap.exe";
      pgmname = malloc (strlen (dir) + strlen (exe) + 1);
      if (pgmname)
	strcpy (stpcpy (pgmname, dir), exe);
    }
#endif
  if (!pgmname)
    pgmname = DIRMNGR_LIBEXECDIR "/dirmngr_ldap";
  return pgmname;
}



/* Home directory.  */

#ifdef HAVE_W32_SYSTEM
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
              if (tmp && *tmp)
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
  return DIRMNGR_LIBEXECDIR;
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
dirmngr_sysconfdir (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    {
      const char *s1, *s2;
      s1 = w32_commondir ();
      s2 = DIRSEP_S "etc" DIRSEP_S "dirmngr";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return DIRMNGR_SYSCONFDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Return the name of the libexec directory.  The name is allocated in
   a static area on the first use.  This function won't fail. */
const char *
dirmngr_libexecdir (void)
{
#ifdef HAVE_W32_SYSTEM
  return w32_rootdir ();
#else /*!HAVE_W32_SYSTEM*/
  return DIRMNGR_LIBEXECDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


const char *
dirmngr_datadir (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    {
      const char *s1, *s2;
      s1 = w32_commondir ();
      s2 = DIRSEP_S "lib" DIRSEP_S "dirmngr";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return DIRMNGR_DATADIR;
#endif /*!HAVE_W32_SYSTEM*/
}


const char *
dirmngr_cachedir (void)
{
#ifdef HAVE_W32_SYSTEM
  static const char *dir;

  if (!dir)
    {
      char path[MAX_PATH];
      const char *s1[] = { "GNU", "cache", "dirmngr", NULL };
      int s1_len;
      const char **comp;

      s1_len = 0;
      for (comp = s1; *comp; comp++)
	{
	  /* Take account for the separator.  */
	  s1_len += 1 + strlen (*comp);
	}

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
		CreateDirectory (tmp, NULL);
	    }

          dir = tmp;
        }
      else
        dir = "c:\\temp\\cache\\dirmngr";
    }
  return dir;
#else /*!HAVE_W32_SYSTEM*/
  return DIRMNGR_CACHEDIR;
#endif /*!HAVE_W32_SYSTEM*/
}


const char *
default_socket_name (void)
{
#ifdef HAVE_W32_SYSTEM
  static char *name;

  if (!name)
    {
      char s1[MAX_PATH];
      const char *s2;

      /* We need something akin CSIDL_COMMON_PROGRAMS, but local
	 (non-roaming).  This is becuase the file needs to be on the
	 local machine and makes only sense on that machine.
	 CSIDL_WINDOWS seems to be the only location which guarantees
	 that. */
      if (w32_shgetfolderpath (NULL, CSIDL_WINDOWS, NULL, 0, s1) < 0)
	strcpy (s1, "C:\\WINDOWS");
      s2 = DIRSEP_S "S.dirmngr";
      name = xmalloc (strlen (s1) + strlen (s2) + 1);
      strcpy (stpcpy (name, s1), s2);
    }
  return name;
#else /*!HAVE_W32_SYSTEM*/
  return DIRMNGR_SOCKETDIR "/socket";
#endif /*!HAVE_W32_SYSTEM*/
}
