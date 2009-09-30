/* utils.c - Utility functions
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "g13.h"
#include "utils.h"


/* Append the TAG and the VALUE to the MEMBUF.  There is no error
   checking here; this is instead done while getting the value back
   from the membuf. */
void
append_tuple (membuf_t *membuf, int tag, const void *value, size_t length)
{
  unsigned char buf[2];

  assert (tag >= 0 && tag <= 0xffff);
  assert (length <= 0xffff);

  buf[0] = tag >> 8;
  buf[1] = tag;
  put_membuf (membuf, buf, 2);
  buf[0] = length >> 8;
  buf[1] = length;
  put_membuf (membuf, buf, 2);
  if (length)
    put_membuf (membuf, value, length);
}

