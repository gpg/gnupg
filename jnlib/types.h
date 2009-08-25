/* types.h - define some extra types
 *	Copyright (C) 1999, 2000, 2001, 2006 Free Software Foundation, Inc.
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

#ifndef LIBJNLIB_TYPES_H
#define LIBJNLIB_TYPES_H

/* The AC_CHECK_SIZEOF() in configure fails for some machines.
 * we provide some fallback values here */
#if !SIZEOF_UNSIGNED_SHORT
#  undef SIZEOF_UNSIGNED_SHORT
#  define SIZEOF_UNSIGNED_SHORT 2
#endif
#if !SIZEOF_UNSIGNED_INT
#  undef SIZEOF_UNSIGNED_INT
#  define SIZEOF_UNSIGNED_INT 4
#endif
#if !SIZEOF_UNSIGNED_LONG
#  undef SIZEOF_UNSIGNED_LONG
#  define SIZEOF_UNSIGNED_LONG 4
#endif


#include <sys/types.h>


#ifndef HAVE_BYTE_TYPEDEF
#  undef byte	    /* There might be a macro with this name.  */
/* Windows typedefs byte in the rpc headers.  Avoid warning about
   double definition.  */
#if !(defined(_WIN32) && defined(cbNDRContext))
  typedef unsigned char byte;
#endif
#  define HAVE_BYTE_TYPEDEF
#endif

#ifndef HAVE_USHORT_TYPEDEF
#  undef ushort     /* There might be a macro with this name.  */
   typedef unsigned short ushort;
#  define HAVE_USHORT_TYPEDEF
#endif

#ifndef HAVE_ULONG_TYPEDEF
#  undef ulong	    /* There might be a macro with this name.  */
   typedef unsigned long ulong;
#  define HAVE_ULONG_TYPEDEF
#endif

#ifndef HAVE_U16_TYPEDEF
#  undef u16	    /* There might be a macro with this name.  */
#  if SIZEOF_UNSIGNED_INT == 2
     typedef unsigned int   u16;
#  elif SIZEOF_UNSIGNED_SHORT == 2
     typedef unsigned short u16;
#  else
#    error no typedef for u16
#  endif
#  define HAVE_U16_TYPEDEF
#endif

#ifndef HAVE_U32_TYPEDEF
#  undef u32        /* There might be a macro with this name.  */
#  if SIZEOF_UNSIGNED_INT == 4
     typedef unsigned int u32;
#  elif SIZEOF_UNSIGNED_LONG == 4
     typedef unsigned long u32;
#  else
#    error no typedef for u32
#  endif
#  define HAVE_U32_TYPEDEF
#endif

#ifndef HAVE_U64_TYPEDEF
#  undef u64        /* There might be a macro with this name.  */
#  if SIZEOF_UNSIGNED_INT == 8
     typedef unsigned int u64;
#    define HAVE_U64_TYPEDEF
#  elif SIZEOF_UNSIGNED_LONG == 8
     typedef unsigned long u64;
#    define HAVE_U64_TYPEDEF
#  elif __GNUC__ >= 2 || defined(__SUNPRO_C)
     typedef unsigned long long u64;
#    define HAVE_U64_TYPEDEF
#  endif
#endif


/* Some GCC attributes.  Note that we use also define some in
   mischelp.h, but this header and types.h are not always included.
   Should eventually be put into one file (e.g. nlib-common.h).  */
#if __GNUC__ >= 4 
# define GNUPG_GCC_A_SENTINEL(a) __attribute__ ((sentinel(a)))
#else
# define GNUPG_GCC_A_SENTINEL(a) 
#endif



#endif /*LIBJNLIB_TYPES_H*/
