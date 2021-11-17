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


/* Return a string from the Win32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn.  */
char *
read_w32_registry_string (const char *root, const char *dir, const char *name)
{
  return gpgrt_w32_reg_query_string (root, dir, name);
}


/* Compact version of read_w32_registry_string.  This version expects
 * a single string as key described here using an example:
 *
 *    HKCU\Software\GNU\GnuPG:HomeDir
 *
 * HKCU := the class, other supported classes are HKLM, HKCR, HKU, and
 *         HKCC.  If no class is given and the string thus starts with
 *         a backslash HKCU with a fallback to HKLM is used.
 * Software\GNU\GnuPG := The actual key.
 * HomeDir := the name of the item.  The name is optional to use the default
 *            value.
 *
 * Note that the first backslash and the first colon act as delimiters.
 *
 * Returns a malloced string or NULL if not found.
 */
char *
read_w32_reg_string (const char *key_arg)
{
  char *key;
  char *p1, *p2;
  char *result;

  if (!key_arg)
    return NULL;
  key = xtrystrdup (key_arg);
  if (!key)
    {
      log_info ("warning: malloc failed while reading registry key\n");
      return NULL;
    }

  p1 = strchr (key, '\\');
  if (!p1)
    {
      xfree (key);
      return NULL;
    }
  *p1++ = 0;
  p2 = strchr (p1, ':');
  if (p2)
    *p2++ = 0;

  result = gpgrt_w32_reg_query_string (*key? key : NULL, p1, p2);
  xfree (key);
  return result;
}

#endif /*HAVE_W32_SYSTEM*/
