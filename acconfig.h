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
#undef M_GUARD
#undef PRINTABLE_OS_NAME
#undef IS_DEVELOPMENT_VERSION

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

#undef HAVE_MLOCK

#undef BIG_ENDIAN_HOST
#undef LITTLE_ENDIAN_HOST

#undef HAVE_BYTE_TYPEDEF
#undef HAVE_USHORT_TYPEDEF
#undef HAVE_ULONG_TYPEDEF
#undef HAVE_U16_TYPEDEF
#undef HAVE_U32_TYPEDEF

#undef HAVE_BROKEN_MLOCK

/* defined if we have a /dev/random and /dev/urandom */
#undef HAVE_DEV_RANDOM
/* and the real names of the random devices */
#undef NAME_OF_DEV_RANDOM
#undef NAME_OF_DEV_URANDOM
/* Linux has an ioctl */
#undef HAVE_DEV_RANDOM_IOCTL


#undef USE_DYNAMIC_LINKING
#undef HAVE_DL_DLOPEN
#undef HAVE_DL_SHL_LOAD
#undef HAVE_DLD_DLD_LINK

#undef USE_SHM_COPROCESSING

#undef IPC_HAVE_SHM_LOCK
#undef IPC_RMID_DEFERRED_RELEASE

/* set this to limit filenames to the 8.3 format */
#undef USE_ONLY_8DOT3
/* defined if we must run on a stupid file system */
#undef HAVE_DRIVE_LETTERS
/* defined if we run on some of the PCDOS like systems (DOS, Windoze. OS/2)
 * with special properties like no file modes */
#undef HAVE_DOSISH_SYSTEM
/* because the Unix gettext has to much overhead on MingW32 systems
 * and these systems lack Posix functions, we use a simplified version
 * of gettext */
#undef USE_SIMPLE_GETTEXT
/* At some point in the system we need to know that we use the Windows
 * random module. */
#undef USE_STATIC_RNDW32

#undef USE_CAPABILITIES

/* Some systems have mkdir that takes a single argument. */
#undef MKDIR_TAKES_ONE_ARG


@BOTTOM@

#include "g10defs.h"

#endif /*G10_CONFIG_H*/
