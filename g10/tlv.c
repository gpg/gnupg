/* tlv.c - Tag-Length-Value Utilities
 *	Copyright (C) 2003, 2004, 2005 Free Software Foundation, Inc.
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
#include <assert.h>

#if GNUPG_MAJOR_VERSION == 1
#define GPG_ERR_EOF               (-1)
#define GPG_ERR_BAD_BER           (1)  /*G10ERR_GENERAL*/
#define GPG_ERR_INV_SEXP          (45) /*G10ERR_INV_ARG*/
typedef int gpg_error_t;
#define gpg_error(n) (n)
#else
#include <gpg-error.h>
#endif


#include "tlv.h"

static const unsigned char *
do_find_tlv (const unsigned char *buffer, size_t length,
             int tag, size_t *nbytes, int nestlevel)
{
  const unsigned char *s = buffer;
  size_t n = length;
  size_t len;
  int this_tag;
  int composite;
    
  for (;;)
    {
      buffer = s;
      if (n < 2)
        return NULL; /* Buffer definitely too short for tag and length. */
      if (!*s || *s == 0xff)
        { /* Skip optional filler between TLV objects. */
          s++;
          n--;
          continue;
        }
      composite = !!(*s & 0x20);
      if ((*s & 0x1f) == 0x1f)
        { /* more tag bytes to follow */
          s++;
          n--;
          if (n < 2)
            return NULL; /* buffer definitely too short for tag and length. */
          if ((*s & 0x1f) == 0x1f)
            return NULL; /* We support only up to 2 bytes. */
          this_tag = (s[-1] << 8) | (s[0] & 0x7f);
        }
      else
        this_tag = s[0];
      len = s[1];
      s += 2; n -= 2;
      if (len < 0x80)
        ;
      else if (len == 0x81)
        { /* One byte length follows. */
          if (!n)
            return NULL; /* we expected 1 more bytes with the length. */
          len = s[0];
          s++; n--;
        }
      else if (len == 0x82)
        { /* Two byte length follows. */
          if (n < 2)
            return NULL; /* We expected 2 more bytes with the length. */
          len = (s[0] << 8) | s[1];
          s += 2; n -= 2;
        }
      else
        return NULL; /* APDU limit is 65535, thus it does not make
                        sense to assume longer length fields. */

      if (composite && nestlevel < 100)
        { /* Dive into this composite DO after checking for a too deep
             nesting. */
          const unsigned char *tmp_s;
          size_t tmp_len;
          
          tmp_s = do_find_tlv (s, len, tag, &tmp_len, nestlevel+1);
          if (tmp_s)
            {
              *nbytes = tmp_len;
              return tmp_s;
            }
        }

      if (this_tag == tag)
        {
          *nbytes = len;
          return s;
        }
      if (len > n)
        return NULL; /* Buffer too short to skip to the next tag. */
      s += len; n -= len;
    }
}


/* Locate a TLV encoded data object in BUFFER of LENGTH and
   return a pointer to value as well as its length in NBYTES.  Return
   NULL if it was not found or if the object does not fit into the buffer. */
const unsigned char *
find_tlv (const unsigned char *buffer, size_t length,
          int tag, size_t *nbytes)
{
  const unsigned char *p;

  p = do_find_tlv (buffer, length, tag, nbytes, 0);
  if (p && *nbytes > (length - (p-buffer)))
    p = NULL; /* Object longer than buffer. */
  return p;
}



/* Locate a TLV encoded data object in BUFFER of LENGTH and
   return a pointer to value as well as its length in NBYTES.  Return
   NULL if it was not found.  Note, that the function does not check
   whether the value fits into the provided buffer. */
const unsigned char *
find_tlv_unchecked (const unsigned char *buffer, size_t length,
                    int tag, size_t *nbytes)
{
  return do_find_tlv (buffer, length, tag, nbytes, 0);
}


/* ASN.1 BER parser: Parse BUFFER of length SIZE and return the tag
   and the length part from the TLV triplet.  Update BUFFER and SIZE
   on success. */
gpg_error_t
parse_ber_header (unsigned char const **buffer, size_t *size,
                  int *r_class, int *r_tag, 
                  int *r_constructed, int *r_ndef,
                  size_t *r_length, size_t *r_nhdr)
{
  int c;
  unsigned long tag;
  const unsigned char *buf = *buffer;
  size_t length = *size;

  *r_ndef = 0;
  *r_length = 0;
  *r_nhdr = 0;

  /* Get the tag. */
  if (!length)
    return gpg_error (GPG_ERR_EOF);
  c = *buf++; length--; ++*r_nhdr;

  *r_class = (c & 0xc0) >> 6;
  *r_constructed = !!(c & 0x20);
  tag = c & 0x1f;

  if (tag == 0x1f)
    {
      tag = 0;
      do
        {
          tag <<= 7;
          if (!length)
            return gpg_error (GPG_ERR_EOF);
          c = *buf++; length--; ++*r_nhdr;
          tag |= c & 0x7f;

        }
      while (c & 0x80);
    }
  *r_tag = tag;

  /* Get the length. */
  if (!length)
    return gpg_error (GPG_ERR_EOF);
  c = *buf++; length--; ++*r_nhdr;

  if ( !(c & 0x80) )
    *r_length = c;
  else if (c == 0x80)
    *r_ndef = 1;
  else if (c == 0xff)
    return gpg_error (GPG_ERR_BAD_BER);
  else
    {
      unsigned long len = 0;
      int count = c & 0x7f;

      if (count > sizeof (len) || count > sizeof (size_t))
        return gpg_error (GPG_ERR_BAD_BER);

      for (; count; count--)
        {
          len <<= 8;
          if (!length)
            return gpg_error (GPG_ERR_EOF);
          c = *buf++; length--; ++*r_nhdr;
          len |= c & 0xff;
        }
      *r_length = len;
    }
  
  /* Without this kludge some example certs can't be parsed. */
  if (*r_class == CLASS_UNIVERSAL && !*r_tag)
    *r_length = 0;
  
  *buffer = buf;
  *size = length;
  return 0;
}


/* FIXME: The following function should not go into this file but for
   now it is easier to keep it here. */

/* Return the next token of an canconical encoded S-expression.  BUF
   is the pointer to the S-expression and BUFLEN is a pointer to the
   length of this S-expression (used to validate the syntax).  Both
   are updated to reflect the new position.  The token itself is
   returned as a pointer into the orginal buffer at TOK and TOKLEN.
   If a parentheses is the next token, TOK will be set to NULL.
   TOKLEN is checked to be within the bounds.  On error a error code
   is returned and all pointers should are not guaranteed to point to
   a meanigful value. DEPTH should be initialized to 0 and will
   reflect on return the actual depth of the tree. To detect the end
   of the S-expression it is advisable to check DEPTH after a
   successful return:

   depth = 0;
   while (!(err = parse_sexp (&buf, &buflen, &depth, &tok, &toklen))
          && depth)
     process_token (tok, toklen);
   if (err)  
     handle_error ();
 */
gpg_error_t
parse_sexp (unsigned char const **buf, size_t *buflen,
            int *depth, unsigned char const **tok, size_t *toklen)
{
  const unsigned char *s;
  size_t n, vlen;

  s = *buf;
  n = *buflen;
  *tok = NULL;
  *toklen = 0;
  if (!n)
    return *depth ? gpg_error (GPG_ERR_INV_SEXP) : 0;
  if (*s == '(')
    {
      s++; n--;
      (*depth)++;
      *buf = s;
      *buflen = n;
      return 0;
    }
  if (*s == ')')
    {
      if (!*depth)
        return gpg_error (GPG_ERR_INV_SEXP);
      *toklen = 1;
      s++; n--;
      (*depth)--;
      *buf = s;
      *buflen = n;
      return 0;
    }
  for (vlen=0; n && *s && *s != ':' && (*s >= '0' && *s <= '9'); s++, n--)
    vlen = vlen*10 + (*s - '0');
  if (!n || *s != ':')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++; n--;
  if (vlen > n)
    return gpg_error (GPG_ERR_INV_SEXP);
  *tok = s;
  *toklen = vlen;
  s += vlen;
  n -= vlen;
  *buf = s;
  *buflen = n;
  return 0;
}

