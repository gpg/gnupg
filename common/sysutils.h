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

#ifdef HAVE_STAT
# include <sys/stat.h>
#endif

struct gnupg_dir_s;
typedef struct gnupg_dir_s *gnupg_dir_t;
struct gnupg_dirent_s
{
  /* We don't have a d_ino because that can't be used on Windows
   * anyway.  D_NAME is a pointer into the gnupg_dir_s which has a
   * static buffer or allocates sufficient space as needed.  This is
   * only valid after gnupg_readdir. */
  char *d_name;
};
typedef struct gnupg_dirent_s *gnupg_dirent_t;


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
void gnupg_inhibit_set_foregound_window (int yes);
void gnupg_allow_set_foregound_window (pid_t pid);
int  gnupg_remove (const char *fname);
gpg_error_t gnupg_rename_file (const char *oldname, const char *newname,
                               int *block_signals);
int gnupg_mkdir (const char *name, const char *modestr);
int gnupg_chdir (const char *name);
int gnupg_rmdir (const char *name);
int gnupg_chmod (const char *name, const char *modestr);
char *gnupg_mkdtemp (char *template);
int  gnupg_setenv (const char *name, const char *value, int overwrite);
int  gnupg_unsetenv (const char *name);
char *gnupg_getcwd (void);
gpg_err_code_t gnupg_access (const char *name, int mode);
#ifdef HAVE_STAT
int gnupg_stat (const char *name, struct stat *statbuf);
#endif /*HAVE_STAT*/
int gnupg_open (const char *name, int flags, unsigned int mode);

gnupg_dir_t gnupg_opendir (const char *name);
gnupg_dirent_t gnupg_readdir (gnupg_dir_t gdir);
int gnupg_closedir (gnupg_dir_t gdir);

gpg_error_t gnupg_chuid (const char *user, int silent);
char *gnupg_get_socket_name (int fd);
int gnupg_fd_valid (int fd);

gpg_error_t gnupg_inotify_watch_delete_self (int *r_fd, const char *fname);
gpg_error_t gnupg_inotify_watch_socket (int *r_fd, const char *socket_name);
int gnupg_inotify_has_name (int fd, const char *name);


#ifdef HAVE_W32_SYSTEM
int gnupg_w32_set_errno (int ec);
void *w32_get_user_sid (void);

#include "../common/w32help.h"

#endif /*HAVE_W32_SYSTEM*/

#endif /*GNUPG_COMMON_SYSUTILS_H*/
