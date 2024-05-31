/* exechelp.h - Definitions for the fork and exec helpers
 * Copyright (C) 2004, 2009, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2004, 2006-2012, 2014-2017 g10 Code GmbH
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
 * SPDX-License-Identifier: (LGPL-3.0+ OR GPL-2.0+)
 */

#ifndef GNUPG_COMMON_EXECHELP_H
#define GNUPG_COMMON_EXECHELP_H


/* Return the maximum number of currently allowed file descriptors.
   Only useful on POSIX systems.  */
int get_max_fds (void);


/* Close all file descriptors starting with descriptor FIRST.  If
   EXCEPT is not NULL, it is expected to be a list of file descriptors
   which are not to close.  This list shall be sorted in ascending
   order with its end marked by -1.  */
void close_all_fds (int first, const int *except);


/* Returns an array with all currently open file descriptors.  The end
   of the array is marked by -1.  The caller needs to release this
   array using the *standard free* and not with xfree.  This allow the
   use of this function right at startup even before libgcrypt has
   been initialized.  Returns NULL on error and sets ERRNO accordingly.  */
int *get_all_open_fds (void);


/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  If R_FP is not NULL, an estream is created for the
   write end and stored at R_FP.  */
gpg_error_t gnupg_create_inbound_pipe (int filedes[2],
                                       estream_t *r_fp, int nonblock);

/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  If R_FP is not NULL, an estream is created for the
   write end and stored at R_FP.  */
gpg_error_t gnupg_create_outbound_pipe (int filedes[2],
                                        estream_t *r_fp, int nonblock);

/* Portable function to create a pipe.  Under Windows both ends are
   inheritable.  */
gpg_error_t gnupg_create_pipe (int filedes[2]);

/* Close the end of a pipe.  */
void gnupg_close_pipe (int fd);


/* The opaque type for a subprocess.  */
typedef struct gnupg_process *gnupg_process_t;
typedef struct gnupg_spawn_actions *gnupg_spawn_actions_t;
gpg_err_code_t gnupg_spawn_actions_new (gnupg_spawn_actions_t *r_act);
void gnupg_spawn_actions_release (gnupg_spawn_actions_t act);
#ifdef HAVE_W32_SYSTEM
void gnupg_spawn_actions_set_envvars (gnupg_spawn_actions_t, char *);
void gnupg_spawn_actions_set_redirect (gnupg_spawn_actions_t,
                                       void *, void *, void *);
void gnupg_spawn_actions_set_inherit_handles (gnupg_spawn_actions_t, void **);
#else
void gnupg_spawn_actions_set_environ (gnupg_spawn_actions_t, char **);
void gnupg_spawn_actions_set_redirect (gnupg_spawn_actions_t, int, int, int);
void gnupg_spawn_actions_set_inherit_fds (gnupg_spawn_actions_t,
                                          const int *);
void gnupg_spawn_actions_set_atfork (gnupg_spawn_actions_t,
                                      void (*atfork)(void *), void *arg);
#endif

#define GNUPG_PROCESS_DETACHED            (1 << 1)

/* Specify how to keep/connect standard fds.  */
#define GNUPG_PROCESS_STDIN_PIPE          (1 << 8)
#define GNUPG_PROCESS_STDOUT_PIPE         (1 << 9)
#define GNUPG_PROCESS_STDERR_PIPE         (1 << 10)
#define GNUPG_PROCESS_STDINOUT_SOCKETPAIR (1 << 11)
#define GNUPG_PROCESS_STDIN_KEEP          (1 << 12)
#define GNUPG_PROCESS_STDOUT_KEEP         (1 << 13)
#define GNUPG_PROCESS_STDERR_KEEP         (1 << 14)
#define GNUPG_PROCESS_STDFDS_SETTING  ( GNUPG_PROCESS_STDIN_PIPE  \
  | GNUPG_PROCESS_STDOUT_PIPE         | GNUPG_PROCESS_STDERR_PIPE \
  | GNUPG_PROCESS_STDINOUT_SOCKETPAIR | GNUPG_PROCESS_STDIN_KEEP  \
  | GNUPG_PROCESS_STDOUT_KEEP         | GNUPG_PROCESS_STDERR_KEEP)

#define GNUPG_PROCESS_STREAM_NONBLOCK     (1 << 16)

/* Spawn PGMNAME.  */
gpg_err_code_t gnupg_process_spawn (const char *pgmname, const char *argv1[],
                                    unsigned int flags,
                                    gnupg_spawn_actions_t act,
                                    gnupg_process_t *r_process);

/* Get FDs for subprocess I/O.  It is the caller which should care
   FDs (closing FDs).  */
gpg_err_code_t gnupg_process_get_fds (gnupg_process_t process,
                                      unsigned int flags,
                                      int *r_fd_in, int *r_fd_out,
                                      int *r_fd_err);

/* Get STREAMs for subprocess I/O.  It is the caller which should care
   STREAMs (closing STREAMs).  */
gpg_err_code_t gnupg_process_get_streams (gnupg_process_t process,
                                          unsigned int flags,
                                          gpgrt_stream_t *r_fp_in,
                                          gpgrt_stream_t *r_fp_out,
                                          gpgrt_stream_t *r_fp_err);

enum gnupg_process_requests
  {
    /* Portable requests */
    GNUPG_PROCESS_NOP           = 0,
    GNUPG_PROCESS_GET_PROC_ID   = 1,
    GNUPG_PROCESS_GET_EXIT_ID   = 2,

    /* POSIX only */
    GNUPG_PROCESS_GET_PID       = 16,
    GNUPG_PROCESS_GET_WSTATUS   = 17,
    GNUPG_PROCESS_KILL          = 18,

    /* Windows only */
    GNUPG_PROCESS_GET_P_HANDLE  = 32,
    GNUPG_PROCESS_GET_HANDLES   = 33,
    GNUPG_PROCESS_GET_EXIT_CODE = 34,
    GNUPG_PROCESS_KILL_WITH_EC  = 35
  };

/* Control of a process.  */
gpg_err_code_t gnupg_process_ctl (gnupg_process_t process,
                                  unsigned int request, ...);

/* Wait for a single PROCESS.  */
gpg_err_code_t gnupg_process_wait (gnupg_process_t process, int hang);

/* Terminate a PROCESS.  */
gpg_err_code_t gnupg_process_terminate (gnupg_process_t process);

/* Release PROCESS resources.  */
void gnupg_process_release (gnupg_process_t process);

/* Wait for a multiple processes.  */
gpg_err_code_t gnupg_process_wait_list (gnupg_process_t *process_list,
                                        int count, int hang);


#endif /*GNUPG_COMMON_EXECHELP_H*/
