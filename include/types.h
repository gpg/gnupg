/* types.h - some common typedefs
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef G10_TYPES_H
#define G10_TYPES_H

#include <sys/types.h>


#ifndef HAVE_BYTE_TYPEDEF
  #undef byte	    /* maybe there is a macro with this name */
  typedef unsigned char byte;
  #define HAVE_BYTE_TYPEDEF
#endif

#ifndef HAVE_USHORT_TYPEDEF
  #undef ushort     /* maybe there is a macro with this name */
  typedef unsigned short ushort;
  #define HAVE_USHORT_TYPEDEF
#endif

#ifndef HAVE_ULONG_TYPEDEF
  #undef ulong	    /* maybe there is a macro with this name */
  typedef unsigned long ulong;
  #define HAVE_ULONG_TYPEDEF
#endif

#ifndef HAVE_U16_TYPEDEF
  #undef u16	    /* maybe there is a macro with this name */
  #if SIZEOF_UNSIGNED_INT == 2
    typedef unsigned int   u16;
  #elif SIZEOF_UNSIGNED_SHORT == 2
    typedef unsigned short u16;
  #else
    #error no typedef for u16
  #endif
  #define HAVE_U16_TYPEDEF
#endif

#ifndef HAVE_U32_TYPEDEF
  #undef u32	    /* maybe there is a macro with this name */
  #if SIZEOF_UNSIGNED_INT == 4
    typedef unsigned int u32;
  #elif SIZEOF_UNSIGNED_LONG == 4
    typedef unsigned long u32;
  #else
    #error no typedef for u32
  #endif
  #define HAVE_U32_TYPEDEF
#endif




typedef struct string_list {
    struct string_list *next;
    char d[1];
} *STRLIST;


#endif /*G10_TYPES_H*/
