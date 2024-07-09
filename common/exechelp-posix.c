/* exechelp.c - Fork and exec helpers for POSIX
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

#if defined(HAVE_W32_SYSTEM)
#error This code is only used on POSIX
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
#include <sys/wait.h>

#ifdef HAVE_GETRLIMIT
#include <sys/time.h>
#include <sys/resource.h>
#endif /*HAVE_GETRLIMIT*/

#ifdef HAVE_STAT
# include <sys/stat.h>
#endif

#if __linux__
# include <sys/types.h>
# include <dirent.h>
#endif /*__linux__ */

#include "util.h"
#include "i18n.h"
#include "sysutils.h"
#include "exechelp.h"


/* Helper */
static inline gpg_error_t
my_error_from_syserror (void)
{
  return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
}


/* Return the maximum number of currently allowed open file
   descriptors.  Only useful on POSIX systems but returns a value on
   other systems too.  */
int
get_max_fds (void)
{
  int max_fds = -1;
#ifdef HAVE_GETRLIMIT
  struct rlimit rl;

  /* Under Linux we can figure out the highest used file descriptor by
   * reading /proc/PID/fd.  This is in the common cases much fast than
   * for example doing 4096 close calls where almost all of them will
   * fail.  On a system with a limit of 4096 files and only 8 files
   * open with the highest number being 10, we speedup close_all_fds
   * from 125ms to 0.4ms including readdir.
   *
   * Another option would be to close the file descriptors as returned
   * from reading that directory - however then we need to snapshot
   * that list before starting to close them.  */
#ifdef __linux__
  {
    DIR *dir = NULL;
    struct dirent *dir_entry;
    const char *s;
    int x;

    dir = opendir ("/proc/self/fd");
    if (dir)
      {
        while ((dir_entry = readdir (dir)))
          {
            s = dir_entry->d_name;
            if ( *s < '0' || *s > '9')
              continue;
            x = atoi (s);
            if (x > max_fds)
              max_fds = x;
          }
        closedir (dir);
      }
    if (max_fds != -1)
      return max_fds + 1;
    }
#endif /* __linux__ */


# ifdef RLIMIT_NOFILE
  if (!getrlimit (RLIMIT_NOFILE, &rl))
    max_fds = rl.rlim_max;
# endif

# ifdef RLIMIT_OFILE
  if (max_fds == -1 && !getrlimit (RLIMIT_OFILE, &rl))
    max_fds = rl.rlim_max;

# endif
#endif /*HAVE_GETRLIMIT*/

#ifdef _SC_OPEN_MAX
  if (max_fds == -1)
    {
      long int scres = sysconf (_SC_OPEN_MAX);
      if (scres >= 0)
        max_fds = scres;
    }
#endif

#ifdef _POSIX_OPEN_MAX
  if (max_fds == -1)
    max_fds = _POSIX_OPEN_MAX;
#endif

#ifdef OPEN_MAX
  if (max_fds == -1)
    max_fds = OPEN_MAX;
#endif

  if (max_fds == -1)
    max_fds = 256;  /* Arbitrary limit.  */

  /* AIX returns INT32_MAX instead of a proper value.  We assume that
     this is always an error and use an arbitrary limit.  */
#ifdef INT32_MAX
  if (max_fds == INT32_MAX)
    max_fds = 256;
#endif

  return max_fds;
}


/* Close all file descriptors starting with descriptor FIRST.  If
   EXCEPT is not NULL, it is expected to be a list of file descriptors
   which shall not be closed.  This list shall be sorted in ascending
   order with the end marked by -1.  */
void
close_all_fds (int first, const int *except)
{
  int max_fd = get_max_fds ();
  int fd, i, except_start;

  if (except)
    {
      except_start = 0;
      for (fd=first; fd < max_fd; fd++)
        {
          for (i=except_start; except[i] != -1; i++)
            {
              if (except[i] == fd)
                {
                  /* If we found the descriptor in the exception list
                     we can start the next compare run at the next
                     index because the exception list is ordered.  */
                except_start = i + 1;
                break;
                }
            }
          if (except[i] == -1)
            close (fd);
        }
    }
  else
    {
      for (fd=first; fd < max_fd; fd++)
        close (fd);
    }

  gpg_err_set_errno (0);
}


/* Returns an array with all currently open file descriptors.  The end
   of the array is marked by -1.  The caller needs to release this
   array using the *standard free* and not with xfree.  This allow the
   use of this function right at startup even before libgcrypt has
   been initialized.  Returns NULL on error and sets ERRNO
   accordingly.  */
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


static gpg_error_t
do_create_pipe (int filedes[2])
{
  gpg_error_t err = 0;

  if (pipe (filedes) == -1)
    {
      err = my_error_from_syserror ();
      filedes[0] = filedes[1] = -1;
    }

  return err;
}


static gpg_error_t
create_pipe_and_estream (gnupg_fd_t *r_fd, estream_t *r_fp,
                         int outbound, int nonblock)
{
  gpg_error_t err;
  int filedes[2];

  if (pipe (filedes) == -1)
    {
      err = my_error_from_syserror ();
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      *r_fd = -1;
      *r_fp = NULL;
      return err;
    }

  if (!outbound)
    {
      *r_fd = filedes[1];
      *r_fp = es_fdopen (filedes[0], nonblock? "r,nonblock" : "r");
    }
  else
    {
      *r_fd = filedes[0];
      *r_fp = es_fdopen (filedes[1], nonblock? "w,nonblock" : "w");
    }
  if (!*r_fp)
    {
      err = my_error_from_syserror ();
      log_error (_("error creating a stream for a pipe: %s\n"),
                 gpg_strerror (err));
      close (filedes[0]);
      close (filedes[1]);
      *r_fd = -1;
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

  return create_pipe_and_estream (r_fd, r_fp, 0, nonblock);
}


/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  Pipe is created and the write end is stored at R_FD.
   An estream is created for the write end and stored at R_FP.  */
gpg_error_t
gnupg_create_outbound_pipe (gnupg_fd_t *r_fd, estream_t *r_fp, int nonblock)
{
  if (!r_fd || !r_fp)
    gpg_error (GPG_ERR_INV_ARG);

  return create_pipe_and_estream (r_fd, r_fp, 1, nonblock);
}


/* Portable function to create a pipe.  FLAGS=GNUPG_PIPE_INBOUND for
   ihneritable write-end for Windows, GNUPG_PIPE_OUTBOUND for
   inheritable read-end for Windows, GNUPG_PIPE_BOTH to specify
   both ends may be inheritable.  */
gpg_error_t
gnupg_create_pipe (int filedes[2], int flags)
{
  (void)flags;
  return do_create_pipe (filedes);
}


/* Close the end of a pipe.  */
void
gnupg_close_pipe (int fd)
{
  if (fd != -1)
    close (fd);
}
