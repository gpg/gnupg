/* xreadline.c - fgets replacement function
 * Copyright (C) 1999, 2004 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "util.h"


/* Same as fgets() but if the provided buffer is too short a larger
   one will be allocated.  This is similar to getline. A line is
   considered a byte stream ending in a LF.

   If MAX_LENGTH is not NULL, it shall point to a value with the
   maximum allowed allocation.

   Returns the length of the line. EOF is indicated by a line of
   length zero. A truncated line is indicated by setting the value at
   MAX_LENGTH to 0.  If the returned value is less then 0 not enough
   memory was enable and ERRNO is set accordingly.

   If a line has been truncated, the file pointer is moved forward to
   the end of the line so that the next read starts with the next
   line.  Note that MAX_LENGTH must be re-initialzied in this case.

   Note: The returned buffer is allocated with enough extra space to
   append a CR,LF,Nul
 */
ssize_t
read_line (FILE *fp,
           char **addr_of_buffer, size_t *length_of_buffer,
           size_t *max_length)
{
  int c;
  char  *buffer = *addr_of_buffer;
  size_t length = *length_of_buffer;
  size_t nbytes = 0;
  size_t maxlen = max_length? *max_length : 0;
  char *p;

  if (!buffer)
    { /* No buffer given - allocate a new one. */
      length = 256;
      buffer = xtrymalloc (length);
      *addr_of_buffer = buffer;
      if (!buffer)
        {
          *length_of_buffer = 0;
          if (max_length)
            *max_length = 0;
          return -1;
        }
      *length_of_buffer = length;
    }

  length -= 3; /* Reserve 3 bytes for CR,LF,EOL. */
  p = buffer;
  while  ((c = getc (fp)) != EOF)
    {
      if (nbytes == length)
        { /* Enlarge the buffer. */
          if (maxlen && length > maxlen) /* But not beyond our limit. */
            {
              /* Skip the rest of the line. */
              while (c != '\n' && (c=getc (fp)) != EOF)
                ;
              *p++ = '\n'; /* Always append a LF (we reserved some space). */
              nbytes++;
              if (max_length)
                *max_length = 0; /* Indicate truncation. */
              break; /* the while loop. */
            }
          length += 3; /* Adjust for the reserved bytes. */
          length += length < 1024? 256 : 1024;
          *addr_of_buffer = xtryrealloc (buffer, length);
          if (!*addr_of_buffer)
            {
              int save_errno = errno;
              xfree (buffer);
              *length_of_buffer = 0;
              if (max_length)
                *max_length = 0;
              gpg_err_set_errno (save_errno);
              return -1;
            }
          buffer = *addr_of_buffer;
          *length_of_buffer = length;
          length -= 3;
          p = buffer + nbytes;
	}
      *p++ = c;
      nbytes++;
      if (c == '\n')
        break;
    }
  *p = 0; /* Make sure the line is a string. */

  return nbytes;
}
