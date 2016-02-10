/* utils.c - Utility functions
 * Copyright (C) 2009 Free Software Foundation, Inc.
 * Copyright (C) 2009, 2015, 2016  Werner Koch
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


/* Definition of the tuple descriptor object.  */
struct tupledesc_s
{
  unsigned char *data; /* The tuple data.  */
  size_t datalen;      /* The length of the data.  */
  size_t pos;          /* The current position as used by next_tuple.  */
  int refcount;        /* Number of references hold. */
};



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


/* Append the unsigned integer VALUE under TAG to MEMBUF.  We make
 * sure that the most significant bit is always cleared to explicitly
 * flag the value as unsigned.  */
void
append_tuple_uint (membuf_t *membuf, int tag, unsigned long long value)
{
  unsigned char buf[16];
  unsigned char *p;
  unsigned int len;

  p = buf + sizeof buf;
  len = 0;
  do
    {
      if (p == buf)
        BUG () ;
      *--p = (value & 0xff);
      value >>= 8;
      len++;
    }
  while (value);

  /* Prepend a zero byte if the first byte has its MSB set.  */
  if ((*p & 0x80))
    {
      if (p == buf)
        BUG () ;
      *--p = 0;
      len++;
    }

  append_tuple (membuf, tag, p, len);
}


/* Create a tuple object by moving the ownership of (DATA,DATALEN) to
 * a new object.  Returns 0 on success and stores the new object at
 * R_TUPLEHD.  The return object must be released using
 * destroy_tuples().  */
gpg_error_t
create_tupledesc (tupledesc_t *r_desc, void *data, size_t datalen)
{
  if (datalen < 5 || memcmp (data, "\x00\x00\x00\x01\x01", 5))
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  *r_desc = xtrymalloc (sizeof **r_desc);
  if (!*r_desc)
    return gpg_error_from_syserror ();
  (*r_desc)->data = data;
  (*r_desc)->datalen = datalen;
  (*r_desc)->pos = 0;
  (*r_desc)->refcount++;
  return 0;
}

/* Unref a tuple descriptor and if the refcount is down to 0 release
   its allocated storage.  */
void
destroy_tupledesc (tupledesc_t tupledesc)
{
  if (!tupledesc)
    return;

  if (!--tupledesc->refcount)
    {
      xfree (tupledesc->data);
      xfree (tupledesc);
    }
}


tupledesc_t
ref_tupledesc (tupledesc_t tupledesc)
{
  if (tupledesc)
    tupledesc->refcount++;
  return tupledesc;
}


/* Find the first tuple with tag TAG.  On success return a pointer to
   its value and store the length of the value at R_LENGTH.  If no
   tuple was found return NULL.  For use by next_tuple, the last
   position is stored in the descriptor.  */
const void *
find_tuple (tupledesc_t tupledesc, unsigned int tag, size_t *r_length)
{
  const unsigned char *s;
  const unsigned char *s_end; /* Points right behind the data. */
  unsigned int t;
  size_t n;

  s = tupledesc->data;
  if (!s)
    return NULL;
  s_end = s + tupledesc->datalen;
  while (s < s_end)
    {
      /* We use addresses for the overflow check to avoid undefined
         behaviour.  size_t should work with all flat memory models.  */
      if ((size_t)s+3 >= (size_t)s_end || (size_t)s + 3 < (size_t)s)
        break;
      t  = s[0] << 8;
      t |= s[1];
      n  = s[2] << 8;
      n |= s[3];
      s += 4;
      if ((size_t)s + n > (size_t)s_end || (size_t)s + n < (size_t)s)
        break;
      if (t == tag)
        {
          tupledesc->pos = (s + n) - tupledesc->data;
          *r_length = n;
          return s;
        }
      s += n;
    }
  return NULL;
}


/* Similar to find-tuple but expects an unsigned int value and stores
 * that at R_VALUE.  If the tag was not found GPG_ERR_NOT_FOUND is
 * returned and 0 stored at R_VALUE.  If the value cannot be converted
 * to an unsigned integer GPG_ERR_ERANGE is returned.  */
gpg_error_t
find_tuple_uint (tupledesc_t tupledesc, unsigned int tag,
                 unsigned long long *r_value)
{
  const unsigned char *s;
  size_t n;
  unsigned long long value = 0;

  *r_value = 0;

  s = find_tuple (tupledesc, tag, &n);
  if (!s)
    return gpg_error (GPG_ERR_NOT_FOUND);
  if (!n || (*s & 0x80)) /* No bytes or negative.  */
    return gpg_error (GPG_ERR_ERANGE);
  if (n && !*s) /* Skip a leading zero.  */
    {
      n--;
      s++;
    }
  if (n > sizeof value)
    return gpg_error (GPG_ERR_ERANGE);
  for (; n; n--, s++)
    {
      value <<= 8;
      value |= *s;
    }

  *r_value = value;
  return 0;
}


const void *
next_tuple (tupledesc_t tupledesc, unsigned int *r_tag, size_t *r_length)
{
  const unsigned char *s;
  const unsigned char *s_end; /* Points right behind the data.  */
  unsigned int t;
  size_t n;

  s = tupledesc->data;
  if (!s)
    return NULL;
  s_end = s + tupledesc->datalen;
  s += tupledesc->pos;
  if (s < s_end
      && !((size_t)s + 3 >= (size_t)s_end || (size_t)s + 3 < (size_t)s))
    {
      t  = s[0] << 8;
      t |= s[1];
      n  = s[2] << 8;
      n |= s[3];
      s += 4;
      if (!((size_t)s + n > (size_t)s_end || (size_t)s + n < (size_t)s))
        {
          tupledesc->pos = (s + n) - tupledesc->data;
          *r_tag = t;
          *r_length = n;
          return s;
        }
    }

  return NULL;
}
