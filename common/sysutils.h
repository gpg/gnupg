/* sysutils.h - System utility functions for Gnupg
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_SYSUTILS_H
#define GNUPG_COMMON_SYSUTILS_H

/* Because we use system handles and not libc low level file
   descriptors on W32, we need to declare them as HANDLE (which
   actually is a plain pointer).  This is required to eventually
   support 64 bits Windows systems.  */
#ifdef HAVE_W32_SYSTEM
typedef void *gnupg_fd_t;
#define GNUPG_INVALID_FD ((void*)(-1))
#define INT2FD(s) ((void *)(s))
#define FD2INT(h) ((unsigned int)(h))
#else
typedef int gnupg_fd_t;
#define GNUPG_INVALID_FD (-1)
#define INT2FD(s) (s)
#define FD2INT(h) (h)
#endif


void trap_unaligned (void);
int  disable_core_dumps (void);
int  enable_core_dumps (void);
const unsigned char *get_session_marker (size_t *rlen);
/*int check_permissions (const char *path,int extension,int checkonly);*/
void gnupg_sleep (unsigned int seconds);
int translate_sys2libc_fd (gnupg_fd_t fd, int for_write);
int translate_sys2libc_fd_int (int fd, int for_write);
FILE *gnupg_tmpfile (void);
void gnupg_reopen_std (const char *pgmname);
void gnupg_allow_set_foregound_window (pid_t pid);


#ifdef HAVE_W32_SYSTEM

#include "../jnlib/w32help.h"

#endif /*HAVE_W32_SYSTEM*/

#endif /*GNUPG_COMMON_SYSUTILS_H*/
