/* membuf.c - A simple implementation of a dynamic buffer.
 * Copyright (C) 2001, 2003, 2009, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 Werner Koch
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
#include <stdarg.h>

#include "util.h"
#include "membuf.h"


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
  mb->buf = xtrymalloc (initiallen);
  if (!mb->buf)
    mb->out_of_core = errno;
}

/* Same as init_membuf but allocates the buffer in secure memory.  */
void
init_membuf_secure (membuf_t *mb, int initiallen)
{
  mb->len = 0;
  mb->size = initiallen;
  mb->out_of_core = 0;
  mb->buf = xtrymalloc_secure (initiallen);
  if (!mb->buf)
    mb->out_of_core = errno;
}


/* Shift the content of the membuf MB by AMOUNT bytes.  The next
   operation will then behave as if AMOUNT bytes had not been put into
   the buffer.  If AMOUNT is greater than the actual accumulated
   bytes, the membuf is basically reset to its initial state.  */
void
clear_membuf (membuf_t *mb, size_t amount)
{
  /* No need to clear if we are already out of core.  */
  if (mb->out_of_core)
    return;
  if (amount >= mb->len)
    mb->len = 0;
  else
    {
      mb->len -= amount;
      memmove (mb->buf, mb->buf+amount, mb->len);
    }
}


void
put_membuf (membuf_t *mb, const void *buf, size_t len)
{
  if (mb->out_of_core || !len)
    return;

  if (mb->len + len >= mb->size)
    {
      char *p;

      mb->size += len + 1024;
      p = xtryrealloc (mb->buf, mb->size);
      if (!p)
        {
          mb->out_of_core = errno ? errno : ENOMEM;
          /* Wipe out what we already accumulated.  This is required
             in case we are storing sensitive data here.  The membuf
             API does not provide another way to cleanup after an
             error. */
          wipememory (mb->buf, mb->len);
          return;
        }
      mb->buf = p;
    }
  if (buf)
    memcpy (mb->buf + mb->len, buf, len);
  else
    memset (mb->buf + mb->len, 0, len);
  mb->len += len;
}


/* A variant of put_membuf accepting a void * and returning a
   gpg_error_t (which will always return 0) to be used as a generic
   callback handler.  This function also allows buffer to be NULL.  */
gpg_error_t
put_membuf_cb (void *opaque, const void *buf, size_t len)
{
  membuf_t *data = opaque;

  if (buf)
    put_membuf (data, buf, len);
  return 0;
}


void
put_membuf_str (membuf_t *mb, const char *string)
{
  put_membuf (mb, string, strlen (string));
}


void
put_membuf_printf (membuf_t *mb, const char *format, ...)
{
  int rc;
  va_list arg_ptr;
  char *buf;

  va_start (arg_ptr, format);
  rc = gpgrt_vasprintf (&buf, format, arg_ptr);
  if (rc < 0)
    mb->out_of_core = errno ? errno : ENOMEM;
  va_end (arg_ptr);
  if (rc >= 0)
    {
      put_membuf (mb, buf, strlen (buf));
      xfree (buf);
    }
}


void *
get_membuf (membuf_t *mb, size_t *len)
{
  char *p;

  if (mb->out_of_core)
    {
      if (mb->buf)
        {
          wipememory (mb->buf, mb->len);
          xfree (mb->buf);
          mb->buf = NULL;
        }
      gpg_err_set_errno (mb->out_of_core);
      return NULL;
    }

  p = mb->buf;
  if (len)
    *len = mb->len;
  mb->buf = NULL;
  mb->out_of_core = ENOMEM; /* hack to make sure it won't get reused. */
  return p;
}


/* Same as get_membuf but shrinks the reallocated space to the
   required size.  */
void *
get_membuf_shrink (membuf_t *mb, size_t *len)
{
  void *p, *pp;
  size_t dummylen;

  if (!len)
    len = &dummylen;

  p = get_membuf (mb, len);
  if (!p)
    return NULL;
  if (*len)
    {
      pp = xtryrealloc (p, *len);
      if (pp)
        p = pp;
    }

  return p;
}


/* Peek at the membuf MB.  On success a pointer to the buffer is
   returned which is valid until the next operation on MB.  If LEN is
   not NULL the current LEN of the buffer is stored there.  On error
   NULL is returned and ERRNO is set.  */
const void *
peek_membuf (membuf_t *mb, size_t *len)
{
  const char *p;

  if (mb->out_of_core)
    {
      gpg_err_set_errno (mb->out_of_core);
      return NULL;
    }

  p = mb->buf;
  if (len)
    *len = mb->len;
  return p;
}

/* To assist using membuf with function returning an error, this
 * function sets the membuf into the error state.  */
void
set_membuf_err (membuf_t *mb, gpg_error_t err)
{
  if (!mb->out_of_core)
    {
      int myerr = gpg_err_code_to_errno (gpg_err_code (err));
      mb->out_of_core = myerr? myerr : EINVAL;
    }
}
