/* mischelp.h
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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

#ifndef LIBUTIL_MISCHELP_H
#define LIBUTIL_MISCHHELP_H


#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)


#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define LIBUTIL_GCC_A_NR	       __attribute__ ((noreturn))
# define LIBUTIL_GCC_A_PRINTF( f, a )  __attribute__ ((format (printf,f,a)))
# define LIBUTIL_GCC_A_NR_PRINTF( f, a ) \
			    __attribute__ ((noreturn, format (printf,f,a)))
#else
# define LIBUTIL_GCC_A_NR
# define LIBUTIL_GCC_A_PRINTF( f, a )
# define LIBUTIL_GCC_A_NR_PRINTF( f, a )
#endif



#endif /*LIBUTIL_MISCHELP_H*/
