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
 * along with Libestream; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * $Id: estream-printf.h 54 2007-05-15 14:12:06Z wk $
 */

#ifndef ESTREAM_PRINTF_H
#define ESTREAM_PRINTF_H

#include <stdarg.h>
#include <stdio.h>

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define ESTREAM_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
#else
# define ESTREAM_GCC_A_PRINTF( f, a )
#endif


typedef int (*estream_printf_out_t)
     (void *outfncarg,  const char *buf, size_t buflen);

int estream_format (estream_printf_out_t outfnc, void *outfncarg,
                    const char *format, va_list vaargs) 
     ESTREAM_GCC_A_PRINTF(3,0);
int estream_printf (const char *format, ...) 
     ESTREAM_GCC_A_PRINTF(1,2);
int estream_fprintf (FILE *fp, const char *format, ... )
     ESTREAM_GCC_A_PRINTF(2,3);
int estream_vfprintf (FILE *fp, const char *format, va_list arg_ptr)
     ESTREAM_GCC_A_PRINTF(2,0);
int estream_snprintf (char *buf, size_t bufsize, const char *format, ...)
     ESTREAM_GCC_A_PRINTF(3,4);
int estream_vsnprintf (char *buf,size_t bufsize, 
                       const char *format, va_list arg_ptr) 
     ESTREAM_GCC_A_PRINTF(3,0);
int estream_asprintf (char **bufp, const char *format, ...)
     ESTREAM_GCC_A_PRINTF(2,3);
int estream_vasprintf (char **bufp, const char *format, va_list arg_ptr)
     ESTREAM_GCC_A_PRINTF(2,0);


#endif /*ESTREAM_PRINTF_H*/
