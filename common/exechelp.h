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
   inheritable.  Pipe is created and the read end is stored at R_FD.
   An estream is created for the write end and stored at R_FP.  */
gpg_error_t gnupg_create_inbound_pipe (gnupg_fd_t *r_fd,
                                       estream_t *r_fp, int nonblock);

/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  Pipe is created and the write end is stored at R_FD.
   An estream is created for the write end and stored at R_FP.  */
gpg_error_t gnupg_create_outbound_pipe (gnupg_fd_t *r_fd,
                                        estream_t *r_fp, int nonblock);

enum {
  GNUPG_PIPE_DONTCARE=0,
  GNUPG_PIPE_INBOUND=1,
  GNUPG_PIPE_OUTBOUND=2,
  GNUPG_PIPE_BOTH=3
};

/* Portable function to create a pipe.  FLAGS=GNUPG_PIPE_INBOUND for
   ihneritable write-end for Windows, GNUPG_PIPE_OUTBOUND for
   inheritable read-end for Windows, GNUPG_PIPE_BOTH to specify
   both ends may be inheritable.  */
gpg_error_t gnupg_create_pipe (int filedes[2], int flags);

#endif /*GNUPG_COMMON_EXECHELP_H*/
