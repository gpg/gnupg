/* membuf.c - A simple implementation of a dynamic buffer
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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
#include <string.h>

#include "util.h"


/* A simple implementation of a dynamic buffer.  Use init_membuf() to
   create a buffer, put_membuf to append bytes and get_membuf to
   release and return the buffer.  Allocation errors are detected but
   only returned at the final get_membuf(), this helps not to clutter
   the code with out of core checks.  */

void
init_membuf (membuf_t *mb, int initiallen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->buf = xmalloc (initiallen);
  if (!mb->buf)
      mb->out_of_core = errno;
}


void
put_membuf (membuf_t *mb, const void *buf, size_t len)
{
  if (mb->out_of_core)
    return;

  if (mb->len + len >= mb->size)
    {
      char *p;
      
      mb->size += len + 1024;
      p = xrealloc (mb->buf, mb->size);
      mb->buf = p;
    }
  memcpy (mb->buf + mb->len, buf, len);
  mb->len += len;
}


void *
get_membuf (membuf_t *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core)
    {
      xfree (mb->buf);
      mb->buf = NULL;
      return NULL;
    }

  p = mb->buf;
  *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = ENOMEM; /* hack to make sure it won't get reused. */
  return p;
}
