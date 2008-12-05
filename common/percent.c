/* percent.c - Percent escaping
 *	Copyright (C) 2008 Free Software Foundation, Inc.
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
