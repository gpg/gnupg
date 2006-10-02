/* mischelp.h - Miscellaneous helper macros and functions
 * Copyright (C) 1999, 2000, 2001, 2002, 2003,
 *               2006  Free Software Foundation, Inc.
 *
 * This file is part of JNLIB.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef LIBJNLIB_MISCHELP_H
#define LIBJNLIB_MISCHHELP_H


#ifndef HAVE_TIMEGM
#include <time.h>
time_t timegm (struct tm *tm);
#endif /*!HAVE_TIMEGM*/


#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)


#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define JNLIB_GCC_M_FUNCTION 1
# define JNLIB_GCC_A_NR 	     __attribute__ ((noreturn))
# define JNLIB_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
# define JNLIB_GCC_A_NR_PRINTF( f, a ) \
			    __attribute__ ((noreturn, format (printf,f,a)))
#else
# define JNLIB_GCC_A_NR
# define JNLIB_GCC_A_PRINTF( f, a )
# define JNLIB_GCC_A_NR_PRINTF( f, a )
#endif


/* To avoid that a compiler optimizes certain memset calls away, these
   macros may be used instead. */
#define wipememory2(_ptr,_set,_len) do { \
              volatile char *_vptr=(volatile char *)(_ptr); \
              size_t _vlen=(_len); \
              while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } \
                  } while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)



#endif /*LIBJNLIB_MISCHELP_H*/
