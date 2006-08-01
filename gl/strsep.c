/* Copyright (C) 2004 Free Software Foundation, Inc.

   Written by Yoann Vandoorselaere <yoann@prelude-ids.org>.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* Specification.  */
#include "strsep.h"

#include <string.h>

#include "strpbrk.h"

char *
strsep (char **stringp, const char *delim)
{
  char *start = *stringp;
  char *ptr;

  if (!start)
    return NULL;

  if (!*delim)
    ptr = start + strlen (start);
  else
    {
      ptr = strpbrk (start, delim);
      if (!ptr)
	{
	  *stringp = NULL;
	  return start;
	}
    }

  *ptr = '\0';
  *stringp = ptr + 1;

  return start;
}
