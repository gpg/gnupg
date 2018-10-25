/* sexp-parse.h - S-expression helper functions
 * Copyright (C) 2002, 2003, 2007 Free Software Foundation, Inc.
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

#ifndef SEXP_PARSE_H
#define SEXP_PARSE_H

#include <gpg-error.h>


/* Return the length of the next S-Exp part and update the pointer to
   the first data byte.  0 is returned on error */
static inline size_t
snext (unsigned char const **buf)
{
  const unsigned char *s;
  int n;

  s = *buf;
  for (n=0; *s && *s != ':' && (*s >= '0' && *s <= '9'); s++)
    n = n*10 + (*s - '0');
  if (!n || *s != ':')
    return 0; /* we don't allow empty lengths */
  *buf = s+1;
  return n;
}

/* Skip over the S-Expression BUF points to and update BUF to point to
   the character right behind.  DEPTH gives the initial number of open
   lists and may be passed as a positive number to skip over the
   remainder of an S-Expression if the current position is somewhere
   in an S-Expression.  The function may return an error code if it
   encounters an impossible condition.  */
static inline gpg_error_t
sskip (unsigned char const **buf, int *depth)
{
  const unsigned char *s = *buf;
  size_t n;
  int d = *depth;

  while (d > 0)
    {
      if (*s == '(')
        {
          d++;
          s++;
        }
      else if (*s == ')')
        {
          d--;
          s++;
        }
      else
        {
          if (!d)
            return gpg_error (GPG_ERR_INV_SEXP);
          n = snext (&s);
          if (!n)
            return gpg_error (GPG_ERR_INV_SEXP);
          s += n;
        }
    }
  *buf = s;
  *depth = d;
  return 0;
}


/* Check whether the string at the address BUF points to matches
   the token.  Return true on match and update BUF to point behind the
   token.  Return false and do not update the buffer if it does not
   match. */
static inline int
smatch (unsigned char const **buf, size_t buflen, const char *token)
{
  size_t toklen = strlen (token);

  if (buflen != toklen || memcmp (*buf, token, toklen))
    return 0;
  *buf += toklen;
  return 1;
}

/* Format VALUE for use as the length indicatior of an S-expression.
   The caller needs to provide a buffer HELP_BUFFER with a length of
   HELP_BUFLEN.  The return value is a pointer into HELP_BUFFER with
   the formatted length string.  The colon and a trailing nul are
   appended.  HELP_BUFLEN must be at least 3 - a more useful value is
   15.  If LENGTH is not NULL, the LENGTH of the resulting string
   (excluding the terminating nul) is stored at that address. */
static inline char *
smklen (char *help_buffer, size_t help_buflen, size_t value, size_t *length)
{
  char *p = help_buffer + help_buflen;

  if (help_buflen >= 3)
    {
      *--p = 0;
      *--p = ':';
      do
        {
          *--p = '0' + (value % 10);
          value /= 10;
        }
      while (value && p > help_buffer);
    }

  if (length)
    *length = (help_buffer + help_buflen) - p;
  return p;
}


#endif /*SEXP_PARSE_H*/
