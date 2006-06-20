/* sexp-parse.h - S-Exp helper functions
 *	Copyright (C) 2002, 2003 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
   the chacter right behind.  DEPTH gives the initial number of open
   lists and may be passed as a positive number to skip over the
   remainder of an S-Expression if the current position is somewhere
   in an S-Expression.  The function may return an error code if it
   encounters an impossible conditions */
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


/* Check whether the the string at the address BUF points to matches
   the token.  Return true on match and update BUF to point behind the
   token.  Return false and dont update tha buffer if it does not
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

#endif /*SEXP_PARSE_H*/
