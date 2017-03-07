/* helptext.c  - English help texts
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2004, 2007 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "../common/ttyio.h"
#include "main.h"
#include "../common/i18n.h"




/* Helper to get the help through the configurable GnuPG help
   system.  */
static char *
get_help_from_file (const char *keyword)
{
  char *key, *result;

  key = xtrymalloc (4 + strlen (keyword) + 1);
  if (key)
    {
      strcpy (stpcpy (key, "gpg."), keyword);
      result = gnupg_get_help_string (key, 0);
      xfree (key);
      if (result && !is_native_utf8 ())
        {
          char *tmp = utf8_to_native (result, strlen (result), -1);
          if (tmp)
            {
              xfree (result);
              result = tmp;
            }
        }
    }
  else
    result = NULL;
  return result;
}


void
display_online_help( const char *keyword )
{
  char *result;
  int need_final_lf = 1;

  tty_kill_prompt();
  if ( !keyword )
    tty_printf (_("No help available") );
  else if ( (result = get_help_from_file (keyword)) )
    {
      tty_printf ("%s", result);
      if (*result && result[strlen (result)-1] == '\n')
        need_final_lf = 0;
      xfree (result);
    }
  else
    {
      tty_printf (_("No help available for '%s'"), keyword );
    }
  if (need_final_lf)
    tty_printf("\n");
}
