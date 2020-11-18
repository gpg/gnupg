/* types.h - define some extra types
 *	Copyright (C) 1999, 2000, 2001, 2006 Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_TYPES_H
#define GNUPG_COMMON_TYPES_H

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif

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


/* We use byte as an abbreviation for unsigned char.  On some
   platforms this needs special treatment:

   - RISC OS:
     Norcroft C treats char  = unsigned char  as legal assignment
                   but char* = unsigned char* as illegal assignment
     and the same applies to the signed variants as well.  Thus we use
     char which is anyway unsigned.

   - Windows:
     Windows typedefs byte in the RPC headers but we need to avoid a
     warning about a double definition.
 */
#ifndef HAVE_TYPE_BYTE
#  undef byte	    /* There might be a macro with this name.  */
#  ifdef __riscos__
     typedef char byte;
#  elif !(defined(_WIN32) && defined(cbNDRContext))
     typedef unsigned char byte;
#  endif
#  define HAVE_TYPE_BYTE
#endif /*!HAVE_TYPE_BYTE*/

#ifndef HAVE_TYPE_USHORT
#  undef ushort     /* There might be a macro with this name.  */
   typedef unsigned short ushort;
#  define HAVE_TYPE_USHORT
#endif

#ifndef HAVE_TYPE_ULONG
#  undef ulong	    /* There might be a macro with this name.  */
   typedef unsigned long ulong;
#  define HAVE_TYPE_ULONG
#endif

#ifndef HAVE_TYPE_U16
#  undef u16	    /* There might be a macro with this name.  */
#  if SIZEOF_UNSIGNED_INT == 2
     typedef unsigned int   u16;
#  elif SIZEOF_UNSIGNED_SHORT == 2
     typedef unsigned short u16;
#  else
#    error no typedef for u16
#  endif
#  define HAVE_TYPE_U16
#endif

#ifndef HAVE_TYPE_U32
#  undef u32        /* There might be a macro with this name.  */
#  if SIZEOF_UNSIGNED_INT == 4
     typedef unsigned int u32;
#  elif SIZEOF_UNSIGNED_LONG == 4
     typedef unsigned long u32;
#  else
#    error no typedef for u32
#  endif
#  define HAVE_TYPE_U32
#endif

#endif /*GNUPG_COMMON_TYPES_H*/
