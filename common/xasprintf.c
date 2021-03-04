/* xasprintf.c
 *	Copyright (C) 2003, 2005 Free Software Foundation, Inc.
 *      Copyright (C) 2020 g10 Code GmbH
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
#include <errno.h>

#include "util.h"

/* Same as asprintf but return an allocated buffer suitable to be
   freed using xfree.  This function simply dies on memory failure,
   thus no extra check is required.

   FIXME: We should remove these functions in favor of gpgrt_bsprintf
   and a xgpgrt_bsprintf or rename them to xbsprintf and
   xtrybsprintf.  */
char *
xasprintf (const char *fmt, ...)
{
  va_list ap;
  char *buf;

  va_start (ap, fmt);
  if (gpgrt_vasprintf (&buf, fmt, ap) < 0)
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
  rc = gpgrt_vasprintf (&buf, fmt, ap);
  va_end (ap);
  if (rc < 0)
    return NULL;
  return buf;
}


/* This is safe version of realloc useful for reallocing a calloced
 * array.  There are two ways to call it:  The first example
 * reallocates the array A to N elements each of SIZE but does not
 * clear the newly allocated elements:
 *
 *  p = xtryreallocarray (a, n, n, nsize);
 *
 * Note that when NOLD is larger than N no cleaning is needed anyway.
 * The second example reallocates an array of size NOLD to N elements
 * each of SIZE but clear the newly allocated elements:
 *
 *  p = xtryreallocarray (a, nold, n, nsize);
 *
 * Note that xtryreallocarray (NULL, 0, n, nsize) is equivalent to
 * xtrycalloc (n, nsize).
 *
 * The same function under the name gpgrt_reallocarray exists in
 * libgpg-error but only since version 1.38 and thus we use a copy
 * here.
 */
void *
xtryreallocarray (void *a, size_t oldnmemb, size_t nmemb, size_t size)
{
  size_t oldbytes, bytes;
  char *p;

  bytes = nmemb * size; /* size_t is unsigned so the behavior on overflow
                         * is defined. */
  if (size && bytes / size != nmemb)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }

  p = xtryrealloc (a, bytes);
  if (p && oldnmemb < nmemb)
    {
      /* OLDNMEMBS is lower than NMEMB thus the user asked for a
         calloc.  Clear all newly allocated members.  */
      oldbytes = oldnmemb * size;
      if (size && oldbytes / size != oldnmemb)
        {
          xfree (p);
          gpg_err_set_errno (ENOMEM);
          return NULL;
        }
      memset (p + oldbytes, 0, bytes - oldbytes);
    }
  return p;
}
