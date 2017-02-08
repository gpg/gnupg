/* sysutils.h - System utility functions for Gnupg
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
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
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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
void enable_special_filenames (void);
const unsigned char *get_session_marker (size_t *rlen);
unsigned int get_uint_nonce (void);
/*int check_permissions (const char *path,int extension,int checkonly);*/
void gnupg_sleep (unsigned int seconds);
void gnupg_usleep (unsigned int usecs);
int translate_sys2libc_fd (gnupg_fd_t fd, int for_write);
int translate_sys2libc_fd_int (int fd, int for_write);
int check_special_filename (const char *fname, int for_write, int notranslate);
FILE *gnupg_tmpfile (void);
void gnupg_reopen_std (const char *pgmname);
void gnupg_allow_set_foregound_window (pid_t pid);
int  gnupg_remove (const char *fname);
gpg_error_t gnupg_rename_file (const char *oldname, const char *newname,
                               int *block_signals);
int  gnupg_mkdir (const char *name, const char *modestr);
int gnupg_chmod (const char *name, const char *modestr);
char *gnupg_mkdtemp (char *template);
int  gnupg_setenv (const char *name, const char *value, int overwrite);
int  gnupg_unsetenv (const char *name);
char *gnupg_getcwd (void);
char *gnupg_get_socket_name (int fd);
int gnupg_fd_valid (int fd);

gpg_error_t gnupg_inotify_watch_socket (int *r_fd, const char *socket_name);
int gnupg_inotify_has_name (int fd, const char *name);


#ifdef HAVE_W32_SYSTEM
void *w32_get_user_sid (void);

#include "../common/w32help.h"

#endif /*HAVE_W32_SYSTEM*/

#endif /*GNUPG_COMMON_SYSUTILS_H*/
