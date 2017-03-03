/* http-common.c - Common support for TLS implementations.
 * Copyright (C) 2017  Werner Koch
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

#include "dirmngr.h"
#include "http-common.h"


/* Return a static string with the default keyserver.  If NAME_ONLY is
 * given only the name part is returned.  */
const char *
get_default_keyserver (int name_only)
{
  static const char *result;

  if (!name_only)
    return DIRMNGR_DEFAULT_KEYSERVER;

  if (!result)
    {
      /* Strip the scheme from the constant. */
      result = strstr (DIRMNGR_DEFAULT_KEYSERVER, "://");
      log_assert (result && strlen (result) > 3);
      result += 3;
      /* Assert that there is no port given.  */
      log_assert (!strchr (result, ':'));
    }
  return result;
}
