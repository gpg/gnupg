/* exechelp.c - Fork and exec helpers for POSIX
 * Copyright (C) 2004, 2007, 2008, 2009,
 *               2010 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#if defined(HAVE_W32_SYSTEM) || defined (HAVE_W32CE_SYSTEM)
#error This code is only used on POSIX
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
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

#include "util.h"
#include "i18n.h"
#include "sysutils.h"
#include "exechelp.h"


/* Return the maximum number of currently allowed open file
   descriptors.  Only useful on POSIX systems but returns a value on
   other systems too.  */
int
get_max_fds (void)
{
  int max_fds = -1;
#ifdef HAVE_GETRLIMIT
  struct rlimit rl;

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
close_all_fds (int first, int *except)
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


/* The exec core used right after the fork. This will never return. */
static void
do_exec (const char *pgmname, const char *argv[],
         int fd_in, int fd_out, int fd_err,
         void (*preexec)(void) )
{
  char **arg_list;
  int i, j;
  int fds[3];

  fds[0] = fd_in;
  fds[1] = fd_out;
  fds[2] = fd_err;

  /* Create the command line argument array.  */
  i = 0;
  if (argv)
    while (argv[i])
      i++;
  arg_list = xcalloc (i+2, sizeof *arg_list);
  arg_list[0] = strrchr (pgmname, '/');
  if (arg_list[0])
    arg_list[0]++;
  else
    arg_list[0] = xstrdup (pgmname);
  if (argv)
    for (i=0,j=1; argv[i]; i++, j++)
      arg_list[j] = (char*)argv[i];

  /* Assign /dev/null to unused FDs. */
  for (i=0; i <= 2; i++)
    {
      if (fds[i] == -1 )
        {
          fds[i] = open ("/dev/null", i? O_WRONLY : O_RDONLY);
          if (fds[i] == -1)
            log_fatal ("failed to open '%s': %s\n",
                       "/dev/null", strerror (errno));
        }
    }

  /* Connect the standard files.  */
  for (i=0; i <= 2; i++)
    {
      if (fds[i] != i && dup2 (fds[i], i) == -1)
        log_fatal ("dup2 std%s failed: %s\n",
                   i==0?"in":i==1?"out":"err", strerror (errno));
    }

  /* Close all other files. */
  close_all_fds (3, NULL);

  if (preexec)
    preexec ();
  execv (pgmname, arg_list);
  /* No way to print anything, as we have closed all streams. */
  _exit (127);
}


static gpg_error_t
do_create_pipe (int filedes[2])
{
  gpg_error_t err = 0;

  if (pipe (filedes) == -1)
    {
      err = gpg_error_from_syserror ();
      filedes[0] = filedes[1] = -1;
    }

  return err;
}

/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  */
gpg_error_t
gnupg_create_inbound_pipe (int filedes[2])
{
  return do_create_pipe (filedes);
}


/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  */
gpg_error_t
gnupg_create_outbound_pipe (int filedes[2])
{
  return do_create_pipe (filedes);
}



static gpg_error_t
create_pipe_and_estream (int filedes[2], estream_t *r_fp,
                         int outbound, int nonblock,
                         gpg_err_source_t errsource)
{
  gpg_error_t err;

  if (pipe (filedes) == -1)
    {
      err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      filedes[0] = filedes[1] = -1;
      *r_fp = NULL;
      return err;
    }

  if (outbound)
    *r_fp = es_fdopen (filedes[0], nonblock? "r,nonblock" : "r");
  else
    *r_fp = es_fdopen (filedes[1], nonblock? "w,nonblock" : "w");
  if (!*r_fp)
    {
      err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
      log_error (_("error creating a stream for a pipe: %s\n"),
                 gpg_strerror (err));
      close (filedes[0]);
      close (filedes[1]);
      filedes[0] = filedes[1] = -1;
      return err;
    }
  return 0;
}



/* Fork and exec the PGMNAME, see exechelp.h for details.  */
gpg_error_t
gnupg_spawn_process (const char *pgmname, const char *argv[],
                     gpg_err_source_t errsource,
                     void (*preexec)(void), unsigned int flags,
                     estream_t *r_infp,
                     estream_t *r_outfp,
                     estream_t *r_errfp,
                     pid_t *pid)
{
  gpg_error_t err;
  int inpipe[2] = {-1, -1};
  int outpipe[2] = {-1, -1};
  int errpipe[2] = {-1, -1};
  estream_t infp = NULL;
  estream_t outfp = NULL;
  estream_t errfp = NULL;
  int nonblock = !!(flags & GNUPG_SPAWN_NONBLOCK);

  if (r_infp)
    *r_infp = NULL;
  if (r_outfp)
    *r_outfp = NULL;
  if (r_errfp)
    *r_errfp = NULL;
  *pid = (pid_t)(-1); /* Always required.  */

  if (r_infp)
    {
      err = create_pipe_and_estream (inpipe, &infp, 0, nonblock, errsource);
      if (err)
        return err;
    }

  if (r_outfp)
    {
      err = create_pipe_and_estream (outpipe, &outfp, 1, nonblock, errsource);
      if (err)
        {
          if (infp)
            es_fclose (infp);
          else if (inpipe[1] != -1)
            close (inpipe[1]);
          if (inpipe[0] != -1)
            close (inpipe[0]);

          return err;
        }
    }

  if (r_errfp)
    {
      err = create_pipe_and_estream (errpipe, &errfp, 1, nonblock, errsource);
      if (err)
        {
          if (infp)
            es_fclose (infp);
          else if (inpipe[1] != -1)
            close (inpipe[1]);
          if (inpipe[0] != -1)
            close (inpipe[0]);

          if (outfp)
            es_fclose (outfp);
          else if (outpipe[0] != -1)
            close (outpipe[0]);
          if (outpipe[1] != -1)
            close (outpipe[1]);

          return err;
        }
    }


  *pid = fork ();
  if (*pid == (pid_t)(-1))
    {
      err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
      log_error (_("error forking process: %s\n"), gpg_strerror (err));

      if (infp)
        es_fclose (infp);
      else if (inpipe[1] != -1)
        close (inpipe[1]);
      if (inpipe[0] != -1)
        close (inpipe[0]);

      if (outfp)
        es_fclose (outfp);
      else if (outpipe[0] != -1)
        close (outpipe[0]);
      if (outpipe[1] != -1)
        close (outpipe[1]);

      if (errfp)
        es_fclose (errfp);
      else if (errpipe[0] != -1)
        close (errpipe[0]);
      if (errpipe[1] != -1)
        close (errpipe[1]);
      return err;
    }

  if (!*pid)
    {
      /* This is the child. */
      gcry_control (GCRYCTL_TERM_SECMEM);
      es_fclose (outfp);
      es_fclose (errfp);
      do_exec (pgmname, argv, inpipe[0], outpipe[1], errpipe[1], preexec);
      /*NOTREACHED*/
    }

  /* This is the parent. */
  if (inpipe[0] != -1)
    close (inpipe[0]);
  if (outpipe[1] != -1)
    close (outpipe[1]);
  if (errpipe[1] != -1)
    close (errpipe[1]);

  if (r_infp)
    *r_infp = infp;
  if (r_outfp)
    *r_outfp = outfp;
  if (r_errfp)
    *r_errfp = errfp;

  return 0;
}



/* Simplified version of gnupg_spawn_process.  This function forks and
   then execs PGMNAME, while connecting INFD to stdin, OUTFD to stdout
   and ERRFD to stderr (any of them may be -1 to connect them to
   /dev/null).  The arguments for the process are expected in the NULL
   terminated array ARGV.  The program name itself should not be
   included there.  Calling gnupg_wait_process is required.

   Returns 0 on success or an error code. */
gpg_error_t
gnupg_spawn_process_fd (const char *pgmname, const char *argv[],
                        int infd, int outfd, int errfd, pid_t *pid)
{
  gpg_error_t err;

  *pid = fork ();
  if (*pid == (pid_t)(-1))
    {
      err = gpg_error_from_syserror ();
      log_error (_("error forking process: %s\n"), strerror (errno));
      return err;
    }

  if (!*pid)
    {
      gcry_control (GCRYCTL_TERM_SECMEM);
      /* Run child. */
      do_exec (pgmname, argv, infd, outfd, errfd, NULL);
      /*NOTREACHED*/
    }

  return 0;
}


/* See exechelp.h for the description.  */
gpg_error_t
gnupg_wait_process (const char *pgmname, pid_t pid, int hang, int *r_exitcode)
{
  gpg_err_code_t ec;
  int i, status;

  if (r_exitcode)
    *r_exitcode = -1;

  if (pid == (pid_t)(-1))
    return gpg_error (GPG_ERR_INV_VALUE);

#ifdef USE_NPTH
  i = npth_waitpid (pid, &status, hang? 0:WNOHANG);
#else
  while ((i=waitpid (pid, &status, hang? 0:WNOHANG)) == (pid_t)(-1)
	 && errno == EINTR);
#endif

  if (i == (pid_t)(-1))
    {
      ec = gpg_err_code_from_errno (errno);
      log_error (_("waiting for process %d to terminate failed: %s\n"),
                 (int)pid, strerror (errno));
    }
  else if (!i)
    {
      ec = GPG_ERR_TIMEOUT; /* Still running.  */
    }
  else if (WIFEXITED (status) && WEXITSTATUS (status) == 127)
    {
      log_error (_("error running '%s': probably not installed\n"), pgmname);
      ec = GPG_ERR_CONFIGURATION;
    }
  else if (WIFEXITED (status) && WEXITSTATUS (status))
    {
      if (!r_exitcode)
        log_error (_("error running '%s': exit status %d\n"), pgmname,
                   WEXITSTATUS (status));
      else
        *r_exitcode = WEXITSTATUS (status);
      ec = GPG_ERR_GENERAL;
    }
  else if (!WIFEXITED (status))
    {
      log_error (_("error running '%s': terminated\n"), pgmname);
      ec = GPG_ERR_GENERAL;
    }
  else
    {
      if (r_exitcode)
        *r_exitcode = 0;
      ec = 0;
    }

  return gpg_err_make (GPG_ERR_SOURCE_DEFAULT, ec);
}


void
gnupg_release_process (pid_t pid)
{
  (void)pid;
}


/* Spawn a new process and immediately detach from it.  The name of
   the program to exec is PGMNAME and its arguments are in ARGV (the
   programname is automatically passed as first argument).
   Environment strings in ENVP are set.  An error is returned if
   pgmname is not executable; to make this work it is necessary to
   provide an absolute file name.  All standard file descriptors are
   connected to /dev/null. */
gpg_error_t
gnupg_spawn_process_detached (const char *pgmname, const char *argv[],
                              const char *envp[] )
{
  pid_t pid;
  int i;

  if (getuid() != geteuid())
    return gpg_error (GPG_ERR_BUG);

  if (access (pgmname, X_OK))
    return gpg_error_from_syserror ();

  pid = fork ();
  if (pid == (pid_t)(-1))
    {
      log_error (_("error forking process: %s\n"), strerror (errno));
      return gpg_error_from_syserror ();
    }
  if (!pid)
    {
      pid_t pid2;

      gcry_control (GCRYCTL_TERM_SECMEM);
      if (setsid() == -1 || chdir ("/"))
        _exit (1);

      pid2 = fork (); /* Double fork to let init take over the new child. */
      if (pid2 == (pid_t)(-1))
        _exit (1);
      if (pid2)
        _exit (0);  /* Let the parent exit immediately. */

      if (envp)
        for (i=0; envp[i]; i++)
          putenv (xstrdup (envp[i]));

      do_exec (pgmname, argv, -1, -1, -1, NULL);

      /*NOTREACHED*/
    }

  if (waitpid (pid, NULL, 0) == -1)
    log_error ("waitpid failed in gnupg_spawn_process_detached: %s",
               strerror (errno));

  return 0;
}


/* Kill a process; that is send an appropriate signal to the process.
   gnupg_wait_process must be called to actually remove the process
   from the system.  An invalid PID is ignored.  */
void
gnupg_kill_process (pid_t pid)
{
  if (pid != (pid_t)(-1))
    {
      kill (pid, SIGTERM);
    }
}
