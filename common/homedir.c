/* homedir.c - Setup the home directory.
 *	Copyright (C) 2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_W32_SYSTEM
#include <shlobj.h>
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CSIDL_FLAG_CREATE
#define CSIDL_FLAG_CREATE 0x8000
#endif
#endif /*HAVE_W32_SYSTEM*/



#include "util.h"
#include "sysutils.h"

/* Set up the default home directory.  The usual --homedir option
   should be parsed later. */
const char *
default_homedir (void)
{
  const char *dir;

  dir = getenv("GNUPGHOME");
#ifdef HAVE_W32_SYSTEM
  if (!dir || !*dir)
    dir = read_w32_registry_string (NULL, "Software\\GNU\\GnuPG", "HomeDir");
  if (!dir || !*dir)
    {
      char path[MAX_PATH];
      
      /* fixme: It might be better to use LOCAL_APPDATA because this
         is defined as "non roaming" and thus more likely to be kept
         locally.  For private keys this is desired.  However, given
         that many users copy private keys anyway forth and back,
         using a system roaming serives might be better than to let
         them do it manually.  A security conscious user will anyway
         use the registry entry to have better control.  */
      if (SHGetFolderPath(NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE, 
                          NULL, 0, path) >= 0) 
        {
          char *tmp = xmalloc (strlen (path) + 6 +1);
          strcpy (stpcpy (tmp, path), "\\gnupg");
          dir = tmp;
          
          /* Try to create the directory if it does not yet
             exists.  */
          if (access (dir, F_OK))
            CreateDirectory (dir, NULL);
        }
    }
#endif /*HAVE_W32_SYSTEM*/
  if (!dir || !*dir)
    dir = GNUPG_DEFAULT_HOMEDIR;

  return dir;
}
