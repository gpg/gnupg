/* stringhelp.h
 * Copyright (C) 1998,1999,2000,2001,2003 Free Software Foundation, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef LIBJNLIB_STRINGHELP_H
#define LIBJNLIB_STRINGHELP_H

#include "types.h"

const char *memistr( const char *buf, size_t buflen, const char *sub );
char *mem2str( char *, const void *, size_t);
char *trim_spaces( char *string );
char *trim_trailing_spaces( char *string );
unsigned int trim_trailing_chars( unsigned char *line, unsigned len,
					      const char *trimchars);
unsigned int trim_trailing_ws( unsigned char *line, unsigned len );
size_t length_sans_trailing_chars (const unsigned char *line, size_t len,
                                   const char *trimchars );
size_t length_sans_trailing_ws (const unsigned char *line, size_t len);


char *make_basename(const char *filepath);
char *make_dirname(const char *filepath);
char *make_filename( const char *first_part, ... );
int compare_filenames( const char *a, const char *b );

size_t print_sanitized_buffer (FILE *fp, const void *buffer, size_t length,
                               int delim);
size_t print_sanitized_utf8_buffer (FILE *fp, const void *buffer,
                                    size_t length, int delim);
size_t print_sanitized_string (FILE *fp, const char *string, int delim);
size_t print_sanitized_utf8_string (FILE *fp, const char *string, int delim);
char *sanitize_buffer (const unsigned char *p, size_t n, int delim);


const char *ascii_memistr( const char *buf, size_t buflen, const char *sub );
int ascii_isupper (int c);
int ascii_islower (int c);
int ascii_toupper (int c);
int ascii_tolower (int c);
int ascii_strcasecmp( const char *a, const char *b );
int ascii_strncasecmp (const char *a, const char *b, size_t n);
int ascii_memcasecmp( const char *a, const char *b, size_t n );
const char *ascii_memistr ( const char *buf, size_t buflen, const char *sub);
void *ascii_memcasemem (const void *haystack, size_t nhaystack,
                        const void *needle, size_t nneedle);


#ifndef HAVE_MEMICMP
int memicmp( const char *a, const char *b, size_t n );
#endif
#ifndef HAVE_STPCPY
char *stpcpy(char *a,const char *b);
#endif
#ifndef HAVE_STRLWR
char *strlwr(char *a);
#endif
#ifndef HAVE_STRTOUL
  #define strtoul(a,b,c)  ((unsigned long)strtol((a),(b),(c)))
#endif
#ifndef HAVE_MEMMOVE
  #define memmove(d, s, n) bcopy((s), (d), (n))
#endif
#ifndef HAVE_STRICMP
  #define stricmp(a,b)	 strcasecmp( (a), (b) )
#endif

#ifndef STR
  #define STR(v) #v
#endif
#define STR2(v) STR(v)


#endif /*LIBJNLIB_STRINGHELP_H*/
