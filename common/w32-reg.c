/* w32-reg.c -  MS-Windows Registry access
 * Copyright (C) 1999, 2002, 2007 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#ifdef HAVE_W32_SYSTEM
 /* This module is only used in this environment */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#include <windows.h>

#include "util.h"
#include "common-defs.h"
#include "utf8conv.h"
#include "w32help.h"


static HKEY
get_root_key(const char *root)
{
  HKEY root_key;

  if (!root)
    root_key = HKEY_CURRENT_USER;
  else if (!strcmp( root, "HKEY_CLASSES_ROOT" ) )
    root_key = HKEY_CLASSES_ROOT;
  else if (!strcmp( root, "HKEY_CURRENT_USER" ) )
    root_key = HKEY_CURRENT_USER;
  else if (!strcmp( root, "HKEY_LOCAL_MACHINE" ) )
    root_key = HKEY_LOCAL_MACHINE;
  else if (!strcmp( root, "HKEY_USERS" ) )
    root_key = HKEY_USERS;
  else if (!strcmp( root, "HKEY_PERFORMANCE_DATA" ) )
    root_key = HKEY_PERFORMANCE_DATA;
  else if (!strcmp( root, "HKEY_CURRENT_CONFIG" ) )
    root_key = HKEY_CURRENT_CONFIG;
  else
    return NULL;

  return root_key;
}


/* Return a string from the Win32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn.  */
char *
read_w32_registry_string (const char *root, const char *dir, const char *name)
{
#ifdef HAVE_W32CE_SYSTEM
  HKEY root_key, key_handle;
  DWORD n1, nbytes, type;
  char *result = NULL;
  wchar_t *wdir, *wname;

  if ( !(root_key = get_root_key(root) ) )
    return NULL;

  wdir = utf8_to_wchar (dir);
  if (!wdir)
    return NULL;

  if (RegOpenKeyEx (root_key, wdir, 0, KEY_READ, &key_handle) )
    {
      if (root)
        {
          xfree (wdir);
          return NULL; /* No need for a RegClose, so return immediately. */
        }
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, wdir, 0, KEY_READ, &key_handle) )
        {
          xfree (wdir);
          return NULL; /* Still no need for a RegClose. */
        }
    }
  xfree (wdir);

  if (name)
    {
      wname = utf8_to_wchar (name);
      if (!wname)
        goto leave;
    }
  else
    wname = NULL;

  nbytes = 2;
  if (RegQueryValueEx (key_handle, wname, 0, NULL, NULL, &nbytes))
    goto leave;
  result = xtrymalloc ((n1=nbytes+2));
  if (!result)
    goto leave;
  if (RegQueryValueEx (key_handle, wname, 0, &type, result, &n1))
    {
      xfree (result);
      result = NULL;
      goto leave;
    }
  result[nbytes] = 0;   /* Make sure it is a string.  */
  result[nbytes+1] = 0;
  if (type == REG_SZ || type == REG_EXPAND_SZ)
    {
      wchar_t *tmp = (void*)result;
      result = wchar_to_utf8 (tmp);
      xfree (tmp);
    }

 leave:
  xfree (wname);
  RegCloseKey (key_handle);
  return result;
#else /*!HAVE_W32CE_SYSTEM*/
  HKEY root_key, key_handle;
  DWORD n1, nbytes, type;
  char *result = NULL;

  if ( !(root_key = get_root_key(root) ) )
    return NULL;

  if (RegOpenKeyEx (root_key, dir, 0, KEY_READ, &key_handle) )
    {
      if (root)
        return NULL; /* No need for a RegClose, so return immediately. */
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
        return NULL; /* Still no need for a RegClose. */
    }

  nbytes = 1;
  if (RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes ) )
    goto leave;
  result = xtrymalloc ((n1=nbytes+1));
  if (!result)
    goto leave;
  if (RegQueryValueEx( key_handle, name, 0, &type, result, &n1 ))
    {
      xfree (result);
      result = NULL;
      goto leave;
    }
  result[nbytes] = 0; /* Make sure it is a string.  */
  if (type == REG_EXPAND_SZ && strchr (result, '%'))
    {
      char *tmp;

      n1 += 1000;
      tmp = xtrymalloc (n1+1);
      if (!tmp)
        goto leave;
      nbytes = ExpandEnvironmentStrings (result, tmp, n1);
      if (nbytes && nbytes > n1)
        {
          xfree (tmp);
          n1 = nbytes;
          tmp = xtrymalloc (n1 + 1);
          if (!tmp)
            goto leave;
          nbytes = ExpandEnvironmentStrings (result, tmp, n1);
          if (nbytes && nbytes > n1)
            {
              /* Oops - truncated, better don't expand at all.  */
              xfree (tmp);
              goto leave;
            }
          tmp[nbytes] = 0;
          xfree (result);
          result = tmp;
        }
      else if (nbytes)
        {
          /* Okay, reduce the length.  */
          tmp[nbytes] = 0;
          xfree (result);
          result = xtrymalloc (strlen (tmp)+1);
          if (!result)
            result = tmp;
            else
              {
                strcpy (result, tmp);
                xfree (tmp);
              }
        }
      else
        {
          /* Error - don't expand.  */
          xfree (tmp);
        }
    }

 leave:
  RegCloseKey (key_handle);
  return result;
#endif /*!HAVE_W32CE_SYSTEM*/
}


#endif /*HAVE_W32_SYSTEM*/
