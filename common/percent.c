/* percent.c - Percent escaping
 * Copyright (C) 2008, 2009 Free Software Foundation, Inc.
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
#include <ctype.h>
#include <assert.h>

#include "util.h"


/* Create a newly alloced string from STRING with all spaces and
   control characters converted to plus signs or %xx sequences.  The
   function returns the new string or NULL in case of a malloc
   failure.

   Note that we also escape the quote character to work around a bug
   in the mingw32 runtime which does not correcty handle command line
   quoting.  We correctly double the quote mark when calling a program
   (i.e. gpg-protect-tool), but the pre-main code does not notice the
   double quote as an escaped quote.  We do this also on POSIX systems
   for consistency.  */
char *
percent_plus_escape (const char *string)
{
  char *buffer, *p;
  const char *s;
  size_t length;

  for (length=1, s=string; *s; s++)
    {
      if (*s == '+' || *s == '\"' || *s == '%'
          || *(const unsigned char *)s < 0x20)
        length += 3;
      else
        length++;
    }

  buffer = p = xtrymalloc (length);
  if (!buffer)
    return NULL;

  for (s=string; *s; s++)
    {
      if (*s == '+' || *s == '\"' || *s == '%'
          || *(const unsigned char *)s < 0x20)
        {
          snprintf (p, 4, "%%%02X", *(unsigned char *)s);
          p += 3;
        }
      else if (*s == ' ')
        *p++ = '+';
      else
        *p++ = *s;
    }
  *p = 0;

  return buffer;

}


/* Create a newly malloced string from (DATA,DATALEN) with embedded
 * nuls quoted as %00.  The standard percent unescaping can be used to
 * reverse this encoding.  With PLUS_ESCAPE set plus-escaping (spaces
 * are replaced by a '+') and escaping of characters with values less
 * than 0x20 is used.  If PREFIX is not NULL it will be prepended to
 * the output in standard escape format; that is PLUS_ESCAPING is
 * ignored for PREFIX. */
char *
percent_data_escape (int plus_escape, const char *prefix,
                     const void *data, size_t datalen)
{
  char *buffer, *p;
  const unsigned char *s;
  size_t n;
  size_t length = 1;

  if (prefix)
    {
      for (s = prefix; *s; s++)
        {
          if (*s == '%' || *s < 0x20)
            length += 3;
          else
            length++;
        }
    }

  for (s=data, n=datalen; n; s++, n--)
    {
      if (!*s || *s == '%' || (plus_escape && (*s < ' ' || *s == '+')))
        length += 3;
      else
        length++;
    }

  buffer = p = xtrymalloc (length);
  if (!buffer)
    return NULL;

  if (prefix)
    {
      for (s = prefix; *s; s++)
        {
          if (*s == '%' || *s < 0x20)
            {
              snprintf (p, 4, "%%%02X", *s);
              p += 3;
            }
          else
            *p++ = *s;
        }
    }

  for (s=data, n=datalen; n; s++, n--)
    {
      if (!*s)
        {
          memcpy (p, "%00", 3);
          p += 3;
        }
      else if (*s == '%')
        {
          memcpy (p, "%25", 3);
          p += 3;
        }
      else if (plus_escape && *s == ' ')
        {
          *p++ = '+';
        }
      else if (plus_escape && (*s < ' ' || *s == '+'))
        {
          snprintf (p, 4, "%%%02X", *s);
          p += 3;
        }
      else
        *p++ = *s;
    }
  *p = 0;

  return buffer;
}


/* Do the percent and plus/space unescaping from STRING to BUFFER and
   return the length of the valid buffer.  Plus unescaping is only
   done if WITHPLUS is true.  An escaped Nul character will be
   replaced by NULREPL.  */
static size_t
do_unescape (unsigned char *buffer, const unsigned char *string,
             int withplus, int nulrepl)
{
  unsigned char *p = buffer;

  while (*string)
    {
      if (*string == '%' && string[1] && string[2])
        {
          string++;
          *p = xtoi_2 (string);
          if (!*p)
            *p = nulrepl;
          string++;
        }
      else if (*string == '+' && withplus)
        *p = ' ';
      else
        *p = *string;
      p++;
      string++;
    }

  return (p - buffer);
}


/* Count space required after unescaping STRING.  Note that this will
   never be larger than strlen (STRING).  */
static size_t
count_unescape (const unsigned char *string)
{
  size_t n = 0;

  while (*string)
    {
      if (*string == '%' && string[1] && string[2])
        {
          string++;
          string++;
        }
      string++;
      n++;
    }

  return n;
}


/* Helper.  */
static char *
do_plus_or_plain_unescape (const char *string, int withplus, int nulrepl)
{
  size_t nbytes, n;
  char *newstring;

  nbytes = count_unescape (string);
  newstring = xtrymalloc (nbytes+1);
  if (newstring)
    {
      n = do_unescape (newstring, string, withplus, nulrepl);
      assert (n == nbytes);
      newstring[n] = 0;
    }
  return newstring;
}


/* Create a new allocated string from STRING with all "%xx" sequences
   decoded and all plus signs replaced by a space.  Embedded Nul
   characters are replaced by the value of NULREPL.  The function
   returns the new string or NULL in case of a malloc failure.  */
char *
percent_plus_unescape (const char *string, int nulrepl)
{
  return do_plus_or_plain_unescape (string, 1, nulrepl);
}


/* Create a new allocated string from STRING with all "%xx" sequences
   decoded.  Embedded Nul characters are replaced by the value of
   NULREPL.  The function returns the new string or NULL in case of a
   malloc failure.  */
char *
percent_unescape (const char *string, int nulrepl)
{
  return do_plus_or_plain_unescape (string, 0, nulrepl);
}


static size_t
do_unescape_inplace (char *string, int withplus, int nulrepl)
{
  unsigned char *p, *p0;

  p = p0 = string;
  while (*string)
    {
      if (*string == '%' && string[1] && string[2])
        {
          string++;
          *p = xtoi_2 (string);
          if (!*p)
            *p = nulrepl;
          string++;
        }
      else if (*string == '+' && withplus)
        *p = ' ';
      else
        *p = *string;
      p++;
      string++;
    }

  return (p - p0);
}


/* Perform percent and plus unescaping in STRING and return the new
   valid length of the string.  Embedded Nul characters are replaced
   by the value of NULREPL.  A terminating Nul character is not
   inserted; the caller might want to call this function this way:

      foo[percent_plus_unescape_inplace (foo, 0)] = 0;
 */
size_t
percent_plus_unescape_inplace (char *string, int nulrepl)
{
  return do_unescape_inplace (string, 1, nulrepl);
}


/* Perform percent unescaping in STRING and return the new valid
   length of the string.  Embedded Nul characters are replaced by the
   value of NULREPL.  A terminating Nul character is not inserted; the
   caller might want to call this function this way:

      foo[percent_unescape_inplace (foo, 0)] = 0;
 */
size_t
percent_unescape_inplace (char *string, int nulrepl)
{
  return do_unescape_inplace (string, 0, nulrepl);
}
