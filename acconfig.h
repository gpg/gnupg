/* acconfig.h - used by autoheader to make config.h.in
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_CONFIG_H
#define G10_CONFIG_H

/* need this, because some autoconf tests rely on this (e.g. stpcpy)
 * and it should be used for new programs
 */
#define _GNU_SOURCE  1

@TOP@

#undef M_DEBUG
#undef VERSION
#undef PACKAGE
#undef G10_LOCALEDIR
#undef PRINTABLE_OS_NAME

/* Define if your locale.h file contains LC_MESSAGES.  */
#undef HAVE_LC_MESSAGES

/* Define to 1 if NLS is requested.  */
#undef ENABLE_NLS

/* Define as 1 if you have catgets and don't want to use GNU gettext.  */
#undef HAVE_CATGETS

/* Define as 1 if you have gettext and don't want to use GNU gettext.  */
#undef HAVE_GETTEXT

/* libintl.h is available; this is obsolete because if we don't have
 * this header we use a symlink to the one in intl/ */
#undef HAVE_LIBINTL_H


#undef HAVE_STPCPY


#undef BIG_ENDIAN_HOST
#undef LITTLE_ENDIAN_HOST

#undef HAVE_BYTE_TYPEDEF
#undef HAVE_USHORT_TYPEDEF
#undef HAVE_ULONG_TYPEDEF
#undef HAVE_U16_TYPEDEF
#undef HAVE_U32_TYPEDEF


/* defined if we have a /dev/random and /dev/urandom */
#undef HAVE_DEV_RANDOM

/* RSA is only compiled in if you have these files. You can use
 * RSA without any restrictions, if your not in the U.S. or
 * wait until sep 20, 2000
 */
#undef HAVE_RSA_CIPHER


@BOTTOM@


/* The AC_CHECK_SIZEOF() fails for some machines.
 * we provide some fallback values here */
#if !SIZEOF_UNSIGNED_SHORT
  #undef SIZEOF_UNSIGNED_SHORT
  #define SIZEOF_UNSIGNED_SHORT 2
#endif
#if !SIZEOF_UNSIGNED_INT
  #undef SIZEOF_UNSIGNED_INT
  #define SIZEOF_UNSIGNED_INT 4
#endif
#if !SIZEOF_UNSIGNED_LONG
  #undef SIZEOF_UNSIGNED_LONG
  #define SIZEOF_UNSIGNED_LONG 4
#endif


#endif /*G10_CONFIG_H*/
