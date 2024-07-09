/* exechelp-w32.c - Fork and exec helpers for W32.
 * Copyright (C) 2004, 2007-2009, 2010 Free Software Foundation, Inc.
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

#include <config.h>

#if !defined(HAVE_W32_SYSTEM)
#error This code is only used on W32.
#else
#define _WIN32_WINNT 0x600
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <unistd.h>
#include <fcntl.h>

#ifdef WITHOUT_NPTH /* Give the Makefile a chance to build without Pth.  */
#undef HAVE_NPTH
#undef USE_NPTH
#endif

#ifdef HAVE_NPTH
#include <npth.h>
#endif

#ifdef HAVE_STAT
# include <sys/stat.h>
#endif


#include "util.h"
#include "i18n.h"
#include "sysutils.h"
#include "exechelp.h"

#include <windows.h>
#include <processthreadsapi.h>

/* Define to 1 do enable debugging.  */
#define DEBUG_W32_SPAWN 0


/* It seems Vista doesn't grok X_OK and so fails access() tests.
   Previous versions interpreted X_OK as F_OK anyway, so we'll just
   use F_OK directly. */
#undef X_OK
#define X_OK F_OK

/* We assume that a HANDLE can be represented by an intptr_t which
   should be true for all systems (HANDLE is defined as void *).
   Further we assume that -1 denotes an invalid handle.  */
# define fd_to_handle(a)  ((HANDLE)(a))
# define handle_to_fd(a)  ((intptr_t)(a))
# define pid_to_handle(a) ((HANDLE)(a))
# define handle_to_pid(a) ((int)(a))


/* Helper */
static inline gpg_error_t
my_error_from_syserror (void)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
}

static inline gpg_error_t
my_error (int errcode)
{
  return gpg_err_make (default_errsource, errcode);
}


/* Return the maximum number of currently allowed open file
   descriptors.  Only useful on POSIX systems but returns a value on
   other systems too.  */
int
get_max_fds (void)
{
  int max_fds = -1;

#ifdef OPEN_MAX
  if (max_fds == -1)
    max_fds = OPEN_MAX;
#endif

  if (max_fds == -1)
    max_fds = 256;  /* Arbitrary limit.  */

  return max_fds;
}


/* Under Windows this is a dummy function.  */
void
close_all_fds (int first, const int *except)
{
  (void)first;
  (void)except;
}


/* Returns an array with all currently open file descriptors.  The end
 * of the array is marked by -1.  The caller needs to release this
 * array using the *standard free* and not with xfree.  This allow the
 * use of this function right at startup even before libgcrypt has
 * been initialized.  Returns NULL on error and sets ERRNO
 * accordingly.  Note that fstat prints a warning to DebugView for all
 * invalid fds which is a bit annoying.  We actually do not need this
 * function in real code (close_all_fds is a dummy anyway) but we keep
 * it for use by t-exechelp.c.  */
int *
get_all_open_fds (void)
{
  int *array;
  size_t narray;
  int fd, max_fd, idx;
#ifndef HAVE_STAT
  array = calloc (1, sizeof *array);
  if (array)
    array[0] = -1;
#else /*HAVE_STAT*/
  struct stat statbuf;

  max_fd = get_max_fds ();
  narray = 32;  /* If you change this change also t-exechelp.c.  */
  array = calloc (narray, sizeof *array);
  if (!array)
    return NULL;

  /* Note:  The list we return is ordered.  */
  for (idx=0, fd=0; fd < max_fd; fd++)
    if (!(fstat (fd, &statbuf) == -1 && errno == EBADF))
      {
        if (idx+1 >= narray)
          {
            int *tmp;

            narray += (narray < 256)? 32:256;
            tmp = realloc (array, narray * sizeof *array);
            if (!tmp)
              {
                free (array);
                return NULL;
              }
            array = tmp;
          }
        array[idx++] = fd;
      }
  array[idx] = -1;
#endif /*HAVE_STAT*/
  return array;
}

#define INHERIT_READ	1
#define INHERIT_WRITE	2
#define INHERIT_BOTH	(INHERIT_READ|INHERIT_WRITE)

/* Create pipe.  FLAGS indicates which ends are inheritable.  */
static int
create_inheritable_pipe (HANDLE filedes[2], int flags)
{
  HANDLE r, w;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = TRUE;

  if (!CreatePipe (&r, &w, &sec_attr, 0))
    return -1;

  if ((flags & INHERIT_READ) == 0)
    if (! SetHandleInformation (r, HANDLE_FLAG_INHERIT, 0))
      goto fail;

  if ((flags & INHERIT_WRITE) == 0)
    if (! SetHandleInformation (w, HANDLE_FLAG_INHERIT, 0))
      goto fail;

  filedes[0] = r;
  filedes[1] = w;
  return 0;

 fail:
  log_error ("SetHandleInformation failed: %s\n", w32_strerror (-1));
  CloseHandle (r);
  CloseHandle (w);
  return -1;
}


static gpg_error_t
create_pipe_and_estream (gnupg_fd_t *r_fd, int flags,
                         estream_t *r_fp, int outbound, int nonblock)
{
  gpg_error_t err = 0;
  es_syshd_t syshd;
  gnupg_fd_t fds[2];
  int inherit_flags = 0;

  if (flags == GNUPG_PIPE_OUTBOUND)
    inherit_flags = INHERIT_READ;
  else if (flags == GNUPG_PIPE_INBOUND)
    inherit_flags = INHERIT_WRITE;
  else
    inherit_flags = INHERIT_BOTH;

  if (create_inheritable_pipe (fds, inherit_flags) < 0)
    {
      err = my_error_from_syserror ();
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      *r_fd = GNUPG_INVALID_FD;
      *r_fp = NULL;
      return err;
    }

  syshd.type = ES_SYSHD_HANDLE;
  if (!outbound)
    {
      syshd.u.handle = fds[0];
      *r_fd = fds[1];
      *r_fp = es_sysopen (&syshd, nonblock? "r,nonblock" : "r");
    }
  else
    {
      syshd.u.handle = fds[1];
      *r_fd = fds[0];
      *r_fp = es_sysopen (&syshd, nonblock? "w,nonblock" : "w");
    }
  if (!*r_fp)
    {
      err = my_error_from_syserror ();
      log_error (_("error creating a stream for a pipe: %s\n"),
                 gpg_strerror (err));
      CloseHandle (fds[0]);
      CloseHandle (fds[1]);
      *r_fd = GNUPG_INVALID_FD;
      return err;
    }

  return 0;
}

/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  Pipe is created and the read end is stored at R_FD.
   An estream is created for the write end and stored at R_FP.  */
gpg_error_t
gnupg_create_inbound_pipe (gnupg_fd_t *r_fd, estream_t *r_fp, int nonblock)
{
  if (!r_fd || !r_fp)
    gpg_error (GPG_ERR_INV_ARG);

  return create_pipe_and_estream (r_fd, GNUPG_PIPE_INBOUND, r_fp, 0, nonblock);
}


/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  Pipe is created and the write end is stored at R_FD.
   An estream is created for the write end and stored at R_FP.  */
gpg_error_t
gnupg_create_outbound_pipe (gnupg_fd_t *r_fd, estream_t *r_fp, int nonblock)
{
  if (!r_fd || !r_fp)
    gpg_error (GPG_ERR_INV_ARG);

  return create_pipe_and_estream (r_fd, GNUPG_PIPE_OUTBOUND, r_fp, 1, nonblock);
}


/* Portable function to create a pipe.  FLAGS=GNUPG_PIPE_INBOUND for
   ihneritable write-end for Windows, GNUPG_PIPE_OUTBOUND for
   inheritable read-end for Windows, GNUPG_PIPE_BOTH to specify
   both ends may be inheritable.  */
gpg_error_t
gnupg_create_pipe (int filedes[2], int flags)
{
  gnupg_fd_t fds[2];
  gpg_error_t err = 0;
  int inherit_flags = 0;

  if (flags == GNUPG_PIPE_OUTBOUND)
    inherit_flags = INHERIT_READ;
  else if (flags == GNUPG_PIPE_INBOUND)
    inherit_flags = INHERIT_WRITE;
  else
    inherit_flags = INHERIT_BOTH;

  if (create_inheritable_pipe (fds, inherit_flags) < 0)
    return my_error_from_syserror ();

  filedes[0] = _open_osfhandle (handle_to_fd (fds[0]), O_RDONLY);
  if (filedes[0] == -1)
    {
      log_error ("failed to translate osfhandle %p\n", fds[0]);
      CloseHandle (fds[0]);
      CloseHandle (fds[1]);
      filedes[1] = -1;
      err = my_error (GPG_ERR_GENERAL);
    }
  else
    {
      filedes[1] = _open_osfhandle (handle_to_fd (fds[1]), O_APPEND);
      if (filedes[1] == -1)
        {
          log_error ("failed to translate osfhandle %p\n", fds[1]);
          close (filedes[0]);
          filedes[0] = -1;
          CloseHandle (fds[1]);
          err = my_error (GPG_ERR_GENERAL);
        }
      else
        err = 0;
    }

  return err;
}


/* Close the end of a pipe.  */
void
gnupg_close_pipe (int fd)
{
  if (fd != -1)
    close (fd);
}
