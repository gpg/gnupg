/* mischelp.h - Miscellaneous helper macros and functions
 * Copyright (C) 1999, 2000, 2001, 2002, 2003,
 *               2006, 2007, 2009  Free Software Foundation, Inc.
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

#ifndef GNUPG_COMMON_MISCHELP_H
#define GNUPG_COMMON_MISCHELP_H


/* Check whether the files NAME1 and NAME2 are identical.  This is for
   example achieved by comparing the inode numbers of the files.  */
int same_file_p (const char *name1, const char *name2);


#ifndef HAVE_TIMEGM
#include <time.h>
time_t timegm (struct tm *tm);
#endif /*!HAVE_TIMEGM*/


#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

/* To avoid that a compiler optimizes certain memset calls away, these
   macros may be used instead. */
#define wipememory2(_ptr,_set,_len) do { \
              volatile char *_vptr=(volatile char *)(_ptr); \
              size_t _vlen=(_len); \
              while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } \
                  } while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)


/* Include hacks which are mainly required for Slowaris.  */
#ifdef GNUPG_COMMON_NEED_AFLOCAL
#ifndef HAVE_W32_SYSTEM
# include <sys/socket.h>
# include <sys/un.h>
#else
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif

#ifndef PF_LOCAL
# ifdef PF_UNIX
#  define PF_LOCAL PF_UNIX
# else
#  define PF_LOCAL AF_UNIX
# endif
#endif /*PF_LOCAL*/
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif /*AF_UNIX*/

/* We used to avoid this macro in GnuPG and inlined the AF_LOCAL name
   length computation directly with the little twist of adding 1 extra
   byte.  It seems that this was needed once on an old HP/UX box and
   there are also rumours that 4.3 Reno and DEC systems need it.  This
   one-off buglet did not harm any current system until it came to Mac
   OS X where the kernel (as of May 2009) exhibited a strange bug: The
   systems basically froze in the connect call if the passed name
   contained an invalid directory part.  Ignore the old Unices.  */
#ifndef SUN_LEN
# define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path) \
	               + strlen ((ptr)->sun_path))
#endif /*SUN_LEN*/
#endif /*GNUPG_COMMON_NEED_AFLOCAL*/


#endif /*GNUPG_COMMON_MISCHELP_H*/
