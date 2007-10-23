/* memrchr.c - libc replacement function
 * Copyright (C) 2005 Free Software Foundation, Inc.
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

/*
  memrchr() is a GNU function that might not be available everywhere.
  It's basically the inverse of memchr() - search backwards in a
  memory block for a particular character.
*/

#include <config.h>
#include <string.h>

/* There are many ways to optimize this, but this is a simple
   unoptimized implementation. */
void *
memrchr(const void *s, int c, size_t n)
{
  const unsigned char *start=s,*end=s;

  end+=n-1;

  while(end>=start)
    {
      if(*end==c)
	return (void *)end;
      else
	end--;
    }

  return NULL;
}
