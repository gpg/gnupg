/* xasprintf.c
 *	Copyright (C) 2003, 2005 Free Software Foundation, Inc.
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

#include "util.h"
#include "iobuf.h"
#include "estream-printf.h"

#if !defined(_ESTREAM_PRINTF_MALLOC) || !defined(_ESTREAM_PRINTF_FREE)
#error Need to define ESTREAM_PRINTF_MALLOC and _FREE
#endif

/* Same as asprintf but return an allocated buffer suitable to be
   freed using xfree.  This function simply dies on memory failure,
   thus no extra check is required. */
char *
xasprintf (const char *fmt, ...)
{
  va_list ap;
  char *buf;

  va_start (ap, fmt);
  if (estream_vasprintf (&buf, fmt, ap) < 0)
    log_fatal ("estream_asprintf failed: %s\n", strerror (errno));
  va_end (ap);
  return buf;
}

/* Same as above but return NULL on memory failure.  */
char *
xtryasprintf (const char *fmt, ...)
{
  int rc;
  va_list ap;
  char *buf;

  va_start (ap, fmt);
  rc = estream_vasprintf (&buf, fmt, ap);
  va_end (ap);
  if (rc < 0)
    return NULL;
  return buf;
}
