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

#ifdef __linux__
  #include <linux/types.h>
  #define HAVE_ULONG_TYPEDEF
  #define HAVE_USHORT_TYPEDEF
#endif


/* Common code */
#ifndef HAVE_ULONG_TYPEDEF
  #define HAVE_ULONG_TYPEDEF
  typedef unsigned long ulong;
#endif
#ifndef HAVE_USHORT_TYPEDEF
  #define HAVE_USHORT_TYPEDEF
  typedef unsigned short ushort;
#endif


typedef struct string_list {
    struct string_list *next;
    char d[1];
} *STRLIST;



/****************************************
 ******** machine dependent stuff *******
 ****************************************/

#if defined(__hpux)
  #define HAVE_BIG_ENDIAN 1
#else
  #define HAVE_LITTLE_ENDIAN 1
#endif


/*** some defaults ***/
#ifndef HAVE_BYTE_TYPEDEF
  #define HAVE_BYTE_TYPEDEF
  typedef unsigned char byte;
#endif
#ifndef HAVE_U16_TYPEDEF
  #define HAVE_U16_TYPEDEF
  typedef unsigned short u16;
#endif
#ifndef HAVE_U32_TYPEDEF
  #define HAVE_U32_TYPEDEF
  typedef unsigned long u32;
#endif



#endif /*G10_TYPES_H*/
