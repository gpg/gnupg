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

#ifndef GNULIB_STRSEP_H_
#define GNULIB_STRSEP_H_

#if HAVE_STRSEP

/*
 * Get strsep() declaration.
 */
#include <string.h>

#else

/* Searches the next delimiter (char listed in DELIM) starting at *STRINGP.
   If one is found, it is overwritten with a NUL, and *STRINGP is advanced
   to point to the next char after it.  Otherwise, *STRINGP is set to NULL.
   If *STRINGP was already NULL, nothing happens.
   Returns the old value of *STRINGP.

   This is a variant of strtok() that is multithread-safe and supports
   empty fields.

   Caveat: It modifies the original string.
   Caveat: These functions cannot be used on constant strings.
   Caveat: The identity of the delimiting character is lost.
   Caveat: It doesn't work with multibyte strings unless all of the delimiter
           characters are ASCII characters < 0x30.

   See also strtok_r().  */

extern char *strsep (char **stringp, const char *delim);

#endif

#endif /* GNULIB_STRSEP_H_ */
