/* convert.c - Hex conversion functions.
 *	Copyright (C) 2006 Free Software Foundation, Inc.
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
#include <ctype.h>

#include "util.h"


#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))


/* Convert STRING consisting of hex characters into its binary
   representation and store that at BUFFER.  BUFFER needs to be of
   LENGTH bytes.  The function check that the STRING will convert
   exactly to LENGTH bytes. The string is delimited by either end of
   string or a white space character.  The function returns -1 on
   error or the length of the parsed string.  */
int
hex2bin (const char *string, void *buffer, size_t length)
{
  int i;
  const char *s = string;

  for (i=0; i < length; )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return -1;           /* Invalid hex digits. */
      ((unsigned char*)buffer)[i++] = xtoi_2 (s);
      s += 2;
    }
  if (*s && (!isascii (*s) || !isspace (*s)) )
    return -1;             /* Not followed by Nul or white space.  */
  if (i != length)
    return -1;             /* Not of expected length.  */
  if (*s)
    s++; /* Skip the delimiter. */
  return s - string;
}


/* Convert STRING consisting of hex characters into its binary representation
   and store that at BUFFER.  BUFFER needs to be of LENGTH bytes.  The
   function check that the STRING will convert exactly to LENGTH
   bytes. Colons inbetween the hex digits are allowed, if one colon
   has been given a colon is expected very 2 characters. The string
   is delimited by either end of string or a white space character.
   The function returns -1 on error or the length of the parsed
   string.  */
int
hexcolon2bin (const char *string, void *buffer, size_t length)
{
  int i;
  const char *s = string;
  int need_colon = 0;

  for (i=0; i < length; )
    {
      if (i==1 && *s == ':')  /* Skip colons between hex digits.  */
        {
          need_colon = 1;
          s++;
        }
      else if (need_colon && *s == ':')
        s++;
      else if (need_colon)
        return -1;           /* Colon expected. */
      if (!hexdigitp (s) || !hexdigitp (s+1))
        return -1;           /* Invalid hex digits. */
      ((unsigned char*)buffer)[i++] = xtoi_2 (s);
      s += 2;
    }
  if (*s == ':')
    return -1;             /* Trailing colons are not allowed.  */
  if (*s && (!isascii (*s) || !isspace (*s)) )
    return -1;             /* Not followed by Nul or white space.  */
  if (i != length)
    return -1;             /* Not of expected length.  */
  if (*s)
    s++; /* Skip the delimiter. */
  return s - string;
}


static char *
do_bin2hex (const void *buffer, size_t length, char *stringbuf, int with_colon)
{
  const unsigned char *s;
  char *p;
  
  if (!stringbuf)
    {
      /* Not really correct for with_colon but we don't care about the
         one wasted byte. */
      size_t n = with_colon? 3:2; 
      size_t nbytes = n * length + 1; 
      if (length &&  (nbytes-1) / n != length) 
        {
          errno = ENOMEM;
          return NULL;
        }
      stringbuf = xtrymalloc (nbytes);
      if (!stringbuf)
        return NULL;
    }
  
  for (s = buffer, p = stringbuf; length; length--, s++)
    {
      if (with_colon && s != buffer)
        *p++ = ':';
      *p++ = tohex ((*s>>4)&15);
      *p++ = tohex (*s&15);
    }
  *p = 0;

  return stringbuf;
}


/* Convert LENGTH bytes of data in BUFFER into hex encoding and store
   that at the provided STRINGBUF.  STRINGBUF must be allocated of at
   least (2*LENGTH+1) bytes or be NULL so that the function mallocs an
   appropriate buffer.  Returns STRINGBUF or NULL on error (which may
   only occur if STRINGBUF has been NULL and the internal malloc
   failed). */
char *
bin2hex (const void *buffer, size_t length, char *stringbuf)
{
  return do_bin2hex (buffer, length, stringbuf, 0);
}

/* Convert LENGTH bytes of data in BUFFER into hex encoding and store
   that at the provided STRINGBUF.  STRINGBUF must be allocated of at
   least (3*LENGTH+1) bytes or be NULL so that the function mallocs an
   appropriate buffer.  Returns STRINGBUF or NULL on error (which may
   only occur if STRINGBUF has been NULL and the internal malloc
   failed). */
char *
bin2hexcolon (const void *buffer, size_t length, char *stringbuf)
{
  return do_bin2hex (buffer, length, stringbuf, 1);
}


