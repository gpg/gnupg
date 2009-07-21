/* estream-printf.h - Versatile C-99 compliant printf formatting.
 * Copyright (C) 2007 g10 Code GmbH
 *
 * This file is part of Libestream.
 *
 * Libestream is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Libestream is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Libestream; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ESTREAM_PRINTF_H
#define ESTREAM_PRINTF_H

#include <stdarg.h>
#include <stdio.h>

/* To use this file with libraries the following macro is useful:

     #define _ESTREAM_EXT_SYM_PREFIX _foo_
   
       This prefixes all external symbols with "_foo_".

   For the implementation of the code (estream-printf.c) the following
   macros may be used to tune the implementation for certain systems:

     #define _ESTREAM_PRINTF_MALLOC foo_malloc
     #define _ESTREAM_PRINTF_FREE   foo_free

       Make estream_asprintf and estream_vasprintf use foo_malloc and
       foo_free instead of the standard malloc and free functions to
       allocate the memory returned to the caller.

     #define  _ESTREAM_PRINTF_EXTRA_INCLUDE "foo.h"

       This includes the file "foo.h" which may provide prototypes for
       the custom memory allocation functions.
 */


#ifdef _ESTREAM_EXT_SYM_PREFIX
#ifndef _ESTREAM_PREFIX
#define _ESTREAM_PREFIX1(x,y)  x ## y
#define _ESTREAM_PREFIX2(x,y) _ESTREAM_PREFIX1(x,y)
#define _ESTREAM_PREFIX(x)    _ESTREAM_PREFIX2(_ESTREAM_EXT_SYM_PREFIX,x)
#endif /*_ESTREAM_PREFIX*/
#define estream_printf_out_t  _ESTREAM_PREFIX(estream_printf_out_t)
#define estream_format        _ESTREAM_PREFIX(estream_format)
#define estream_printf        _ESTREAM_PREFIX(estream_printf)
#define estream_fprintf       _ESTREAM_PREFIX(estream_fprintf)
#define estream_vfprintf      _ESTREAM_PREFIX(estream_vfprintf)
#define estream_snprintf      _ESTREAM_PREFIX(estream_snprintf)
#define estream_vsnprintf     _ESTREAM_PREFIX(estream_vsnprintf)
#define estream_asprintf      _ESTREAM_PREFIX(estream_asprintf)
#define estream_vasprintf     _ESTREAM_PREFIX(estream_vasprintf)
#endif /*_ESTREAM_EXT_SYM_PREFIX*/

#ifndef _ESTREAM_GCC_A_PRINTF
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define _ESTREAM_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
#else
# define _ESTREAM_GCC_A_PRINTF( f, a )
#endif
#endif /*_ESTREAM_GCC_A_PRINTF*/


#ifdef __cplusplus
extern "C"
{
#if 0
}
#endif
#endif


typedef int (*estream_printf_out_t)
     (void *outfncarg,  const char *buf, size_t buflen);

int estream_format (estream_printf_out_t outfnc, void *outfncarg,
                    const char *format, va_list vaargs) 
     _ESTREAM_GCC_A_PRINTF(3,0);
int estream_printf (const char *format, ...) 
     _ESTREAM_GCC_A_PRINTF(1,2);
int estream_fprintf (FILE *fp, const char *format, ... )
     _ESTREAM_GCC_A_PRINTF(2,3);
int estream_vfprintf (FILE *fp, const char *format, va_list arg_ptr)
     _ESTREAM_GCC_A_PRINTF(2,0);
int estream_snprintf (char *buf, size_t bufsize, const char *format, ...)
     _ESTREAM_GCC_A_PRINTF(3,4);
int estream_vsnprintf (char *buf,size_t bufsize, 
                       const char *format, va_list arg_ptr) 
     _ESTREAM_GCC_A_PRINTF(3,0);
int estream_asprintf (char **bufp, const char *format, ...)
     _ESTREAM_GCC_A_PRINTF(2,3);
int estream_vasprintf (char **bufp, const char *format, va_list arg_ptr)
     _ESTREAM_GCC_A_PRINTF(2,0);


#ifdef __cplusplus
}
#endif
#endif /*ESTREAM_PRINTF_H*/
