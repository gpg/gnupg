/* status.c - status code helper functions
 *	Copyright (C) 2007 Free Software Foundation, Inc.
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

#include "util.h"
#include "status.h"
#include "status-codes.h"


/* Return the status string for code NO. */
const char *
get_status_string ( int no ) 
{
  int idx = statusstr_msgidxof (no);
  if (idx == -1)
    return "?";
  else
    return statusstr_msgstr + statusstr_msgidx[idx];
}

