/* stringhelp.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2006, 2007, 2009  Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBJNLIB_STRINGHELP_H
#define LIBJNLIB_STRINGHELP_H

#include "types.h"

const char *memistr (const void *buf, size_t buflen, const char *sub);
char *mem2str( char *, const void *, size_t);
char *trim_spaces( char *string );
char *trim_trailing_spaces( char *string );
unsigned int trim_trailing_chars( unsigned char *line, unsigned len,
					      const char *trimchars);
unsigned int trim_trailing_ws( unsigned char *line, unsigned len );
size_t length_sans_trailing_chars (const unsigned char *line, size_t len,
                                   const char *trimchars );
size_t length_sans_trailing_ws (const unsigned char *line, size_t len);


char *make_basename(const char *filepath, const char *inputpath);
char *make_dirname(const char *filepath);
char *make_filename( const char *first_part, ... ) GNUPG_GCC_A_SENTINEL(0);
char *make_filename_try (const char *first_part, ... ) GNUPG_GCC_A_SENTINEL(0);
int compare_filenames( const char *a, const char *b );

int hextobyte (const char *s);

size_t print_sanitized_buffer (FILE *fp, const void *buffer, size_t length,
                               int delim);
size_t print_sanitized_buffer2 (FILE *fp, const void *buffer, size_t length,
                                int delim, int delim2);
size_t print_sanitized_utf8_buffer (FILE *fp, const void *buffer,
                                    size_t length, int delim);
size_t print_sanitized_string (FILE *fp, const char *string, int delim);
size_t print_sanitized_string2 (FILE *fp, const char *string,
                                int delim, int delim2);
size_t print_sanitized_utf8_string (FILE *fp, const char *string, int delim);
char *sanitize_buffer (const void *p, size_t n, int delim);


size_t utf8_charcount (const char *s);


#ifdef HAVE_W32_SYSTEM
const char *w32_strerror (int ec);
#endif


int ascii_isupper (int c);
int ascii_islower (int c);
int ascii_toupper (int c);
int ascii_tolower (int c);
int ascii_strcasecmp( const char *a, const char *b );
int ascii_strncasecmp (const char *a, const char *b, size_t n);
int ascii_memcasecmp( const void *a, const void *b, size_t n );
const char *ascii_memistr ( const void *buf, size_t buflen, const char *sub);
void *ascii_memcasemem (const void *haystack, size_t nhaystack,
                        const void *needle, size_t nneedle);


#ifndef HAVE_MEMICMP
int memicmp( const char *a, const char *b, size_t n );
#endif
#ifndef HAVE_STPCPY
char *stpcpy(char *a,const char *b);
#endif
#ifndef HAVE_STRSEP
char *strsep (char **stringp, const char *delim);
#endif
#ifndef HAVE_STRLWR
char *strlwr(char *a);
#endif
#ifndef HAVE_STRTOUL
#  define strtoul(a,b,c)  ((unsigned long)strtol((a),(b),(c)))
#endif
#ifndef HAVE_MEMMOVE
#  define memmove(d, s, n) bcopy((s), (d), (n))
#endif
#ifndef HAVE_STRICMP
#  define stricmp(a,b)	 strcasecmp( (a), (b) )
#endif
#ifndef HAVE_MEMRCHR
void *memrchr (const void *buffer, int c, size_t n);
#endif


#ifndef HAVE_ISASCII
static inline int 
isascii (int c)
{
  return (((c) & ~0x7f) == 0);
}
#endif /* !HAVE_ISASCII */


#ifndef STR
#  define STR(v) #v
#endif
#define STR2(v) STR(v)

/* Percent-escape the string STR by replacing colons with '%3a'.  If
   EXTRA is not NULL, also replace all characters given in EXTRA.  The
   "try_" variant fails with NULL if not enough memory can be
   allocated.  */
char *percent_escape (const char *str, const char *extra);
char *try_percent_escape (const char *str, const char *extra);


/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer with the new string or NULL on a
   malloc error or if too many arguments are given.  */
char *strconcat (const char *s1, ...) GNUPG_GCC_A_SENTINEL(0);
/* Ditto, but die on error.  */
char *xstrconcat (const char *s1, ...) GNUPG_GCC_A_SENTINEL(0);



#endif /*LIBJNLIB_STRINGHELP_H*/
