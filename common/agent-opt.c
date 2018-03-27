/* agent-opt.c - Helper for certain agent options
 * Copyright (C) 2013 Free Software Foundation, Inc.
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
#include <string.h>

#include "shareddefs.h"


/* Parse VALUE and return an integer representing a pinentry_mode_t.
   (-1) is returned for an invalid VALUE.  */
int
parse_pinentry_mode (const char *value)
{
  int result;

  if (!strcmp (value, "ask") || !strcmp (value, "default"))
    result = PINENTRY_MODE_ASK;
  else if (!strcmp (value, "cancel"))
    result = PINENTRY_MODE_CANCEL;
  else if (!strcmp (value, "error"))
    result = PINENTRY_MODE_ERROR;
  else if (!strcmp (value, "loopback"))
    result = PINENTRY_MODE_LOOPBACK;
  else
    result = -1;

  return result;
}

/* Return the string representation for the pinentry MODE.  Returns
   "?" for an invalid mode.  */
const char *
str_pinentry_mode (pinentry_mode_t mode)
{
  switch (mode)
    {
    case PINENTRY_MODE_ASK:      return "ask";
    case PINENTRY_MODE_CANCEL:   return "cancel";
    case PINENTRY_MODE_ERROR:    return "error";
    case PINENTRY_MODE_LOOPBACK: return "loopback";
    }
 return "?";
}


/* Parse VALUE and return an integer representing a request_origin_t.
 * (-1) is returned for an invalid VALUE.  */
int
parse_request_origin (const char *value)
{
  int result;

  if (!strcmp (value, "none") || !strcmp (value, "local"))
    result = REQUEST_ORIGIN_LOCAL;
  else if (!strcmp (value, "remote"))
    result = REQUEST_ORIGIN_REMOTE;
  else if (!strcmp (value, "browser"))
    result = REQUEST_ORIGIN_BROWSER;
  else
    result = -1;

  return result;
}


/* Return the string representation for the request origin.  Returns
 * "?" for an invalid mode.  */
const char *
str_request_origin (request_origin_t mode)
{
  switch (mode)
    {
    case REQUEST_ORIGIN_LOCAL:   return "local";
    case REQUEST_ORIGIN_REMOTE:  return "remote";
    case REQUEST_ORIGIN_BROWSER: return "browser";
    }
 return "?";
}
