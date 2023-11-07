/* stringhelp.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2006, 2007, 2009  Free Software Foundation, Inc.
 *               2015  g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
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
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_STRINGHELP_H
#define GNUPG_COMMON_STRINGHELP_H

#include <stdint.h>
#include "types.h"

/*-- stringhelp.c --*/
char *has_leading_keyword (const char *string, const char *keyword);

const char *memistr (const void *buf, size_t buflen, const char *sub);
const char *gnupg_memstr (const void *buffer, size_t buflen, const char *sub);
char *mem2str( char *, const void *, size_t);
char *trim_spaces( char *string );
char *ascii_trim_spaces (char *string);
char *trim_trailing_spaces( char *string );
unsigned int trim_trailing_chars( unsigned char *line, unsigned len,
					      const char *trimchars);
unsigned int trim_trailing_ws( unsigned char *line, unsigned len );
size_t length_sans_trailing_chars (const unsigned char *line, size_t len,
                                   const char *trimchars );
size_t length_sans_trailing_ws (const unsigned char *line, size_t len);


char *make_basename(const char *filepath, const char *inputpath);
char *make_dirname(const char *filepath);
char *make_filename( const char *first_part, ... ) GPGRT_ATTR_SENTINEL(0);
char *make_filename_try (const char *first_part, ... ) GPGRT_ATTR_SENTINEL(0);
char *make_absfilename (const char *first_part, ...) GPGRT_ATTR_SENTINEL(0);
char *make_absfilename_try (const char *first_part,
                            ...) GPGRT_ATTR_SENTINEL(0);
int compare_filenames( const char *a, const char *b );

uint64_t string_to_u64 (const char *string);
int hextobyte (const char *s);

size_t utf8_charcount (const char *s, int len);


#ifdef HAVE_W32_SYSTEM
const char *w32_strerror (int ec);
#endif


int ascii_isupper (int c);
int ascii_islower (int c);
int ascii_toupper (int c);
int ascii_tolower (int c);
char *ascii_strlwr (char *s);
char *ascii_strupr (char *s);
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
#ifndef HAVE_STRPBRK
char *strpbrk (const char *s, const char *accept);
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
char *strconcat (const char *s1, ...) GPGRT_ATTR_SENTINEL(0);
/* Same but taking a va_list.  */
char *vstrconcat (const char *s1, va_list arg_ptr);
/* Ditto, but die on error.  */
char *xstrconcat (const char *s1, ...) GPGRT_ATTR_SENTINEL(0);


char **strsplit (char *string, char delim, char replacement, int *count);

/* Tokenize STRING using the set of delimiters in DELIM.  */
char **strtokenize (const char *string, const char *delim);
/* Tokenize STRING using the set of delimiters in DELIM but do not
 * trim the tokens.  */
char **strtokenize_nt (const char *string, const char *delim);

/* Split STRING into space delimited fields and store them in the
 * provided ARRAY.  */
int split_fields (char *string, const char **array, int arraysize);

/* Split STRING into colon delimited fields and store them in the
 * provided ARRAY.  */
int split_fields_colon (char *string, const char **array, int arraysize);

/* Return True if MYVERSION is greater or equal than REQ_VERSION.  */
int compare_version_strings (const char *my_version, const char *req_version);

/* Format a string so that it fits within about TARGET_COLS columns.  */
char *format_text (const char *text, int target_cols, int max_cols);

/* Substitute variables in STRING.  */
char *substitute_vars (const char *string,
                       const char *(*getval)(void *cookie, const char *name),
                       void *cookie);
char *substitute_envvars (const char *string);


/*-- mapstrings.c --*/
const char *map_static_macro_string (const char *string);
const char *map_static_strings (const char *domain, int key1, int key2,
                                const char *string1, ...);

#endif /*GNUPG_COMMON_STRINGHELP_H*/
