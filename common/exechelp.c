/* exechelp.c - fork and exec helpers
 *	Copyright (C) 2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h> 
#ifdef USE_GNU_PTH      
#include <pth.h>
#endif
#ifdef _WIN32
#else
#include <sys/wait.h>
#endif

#include "util.h"
#include "i18n.h"
#include "exechelp.h"


#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

/* We have the usual problem here: Some modules are linked against pth
   and some are not.  However we want to use pth_fork and pth_waitpid
   here. Using a weak symbol works but is not portable - we should
   provide a an explicit dummy pth module instead of using the
   pragma.  */ 
#ifndef _WIN32
#pragma weak pth_fork
#pragma weak pth_waitpid
#endif



/* Fork and exec the PGMNAME, connect the file descriptor of INFILE to
   stdin, write the output to OUTFILE, return a new stream in
   STATUSFILE for stderr and the pid of the process in PID. The
   arguments for the process are expected in the NULL terminated array
   ARGV.  The program name itself should not be included there.  if
   PREEXEC is not NULL, that function will be called right before the
   exec.

   Returns 0 on success or an error code. */
gpg_error_t
gnupg_spawn_process (const char *pgmname, const char *argv[],
                     FILE *infile, FILE *outfile,
                     void (*preexec)(void),
                     FILE **statusfile, pid_t *pid)
{
#ifdef _WIN32
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

#else /* !_WIN32 */
  gpg_error_t err;
  int fd, fdout, rp[2];

  *statusfile = NULL;
  *pid = (pid_t)(-1);
  fflush (infile);
  rewind (infile);
  fd = fileno (infile);
  fdout = fileno (outfile);
  if (fd == -1 || fdout == -1)
    log_fatal ("no file descriptor for file passed"
               " to gnupg_spawn_process: %s\n",  strerror (errno) );

  if (pipe (rp) == -1)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error creating a pipe: %s\n"), strerror (errno));
      return err;
    }

#ifdef USE_GNU_PTH      
  *pid = pth_fork? pth_fork () : fork ();
#else
  *pid = fork ();
#endif
  if (*pid == (pid_t)(-1))
    {
      err = gpg_error_from_errno (errno);
      log_error (_("error forking process: %s\n"), strerror (errno));
      close (rp[0]);
      close (rp[1]);
      return err;
    }

  if (!*pid)
    { 
      /* Child. */
      char **arg_list;
      int n, i, j;

      /* Create the command line argument array.  */
      for (i=0; argv[i]; i++)
        ;
      arg_list = xcalloc (i+2, sizeof *arg_list);
      arg_list[0] = strrchr (pgmname, '/');
      if (arg_list[0])
        arg_list[0]++;
      else
        arg_list[0] = xstrdup (pgmname);
      for (i=0,j=1; argv[i]; i++, j++)
        arg_list[j] = (char*)argv[i];

      /* Connect the infile to stdin. */
      if (fd != 0 && dup2 (fd, 0) == -1)
        log_fatal ("dup2 stdin failed: %s\n", strerror (errno));

      /* Connect the outfile to stdout. */
      if (fdout != 1 && dup2 (fdout, 1) == -1)
        log_fatal ("dup2 stdout failed: %s\n", strerror (errno));
      
      /* Connect stderr to our pipe. */
      if (rp[1] != 2 && dup2 (rp[1], 2) == -1)
        log_fatal ("dup2 stderr failed: %s\n", strerror (errno));

      /* Close all other files. */
      n = sysconf (_SC_OPEN_MAX);
      if (n < 0)
        n = MAX_OPEN_FDS;
      for (i=3; i < n; i++)
        close(i);
      errno = 0;

      if (preexec)
        preexec ();
      execv (pgmname, arg_list);
      /* No way to print anything, as we have closed all streams. */
      _exit (127);
    }

  /* Parent. */
  close (rp[1]);

  *statusfile = fdopen (rp[0], "r");
  if (!*statusfile)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("can't fdopen pipe for reading: %s\n"), strerror (errno));
      kill (*pid, SIGTERM);
      *pid = (pid_t)(-1);
      return err;
    }

  return 0;
#endif /* !_WIN32 */
}


/* Wait for the process identified by PID to terminate. PGMNAME should
   be the same as suplieed to the spawn fucntion and is only used for
   diagnostics. Returns 0 if the process succeded, GPG_ERR_GENERAL for
   any failures of the spawned program or other error codes.*/
gpg_error_t
gnupg_wait_process (const char *pgmname, pid_t pid)
{
  gpg_err_code_t ec;

#ifdef _WIN32
  ec = GPG_ERR_NOT_IMPLEMENTED;

#else /* !_WIN32 */
  int i, status;

  if (pid == (pid_t)(-1))
    return gpg_error (GPG_ERR_INV_VALUE);

#ifdef USE_GNU_PTH
  i = pth_waitpid ? pth_waitpid (pid, &status, 0) : waitpid (pid, &status, 0);
#else
  while ( (i=waitpid (pid, &status, 0)) == -1 && errno == EINTR)
    ;
#endif
  if (i == (pid_t)(-1))
    {
      log_error (_("waiting for process %d to terminate failed: %s\n"),
                 (int)pid, strerror (errno));
      ec = gpg_err_code_from_errno (errno);
    }
  else if (WIFEXITED (status) && WEXITSTATUS (status) == 127)
    {
      log_error (_("error running `%s': probably not installed\n"), pgmname);
      ec = GPG_ERR_CONFIGURATION;
    }
  else if (WIFEXITED (status) && WEXITSTATUS (status))
    {
      log_error (_("error running `%s': exit status %d\n"), pgmname,
                 WEXITSTATUS (status));
      ec = GPG_ERR_GENERAL;
    }
  else if (!WIFEXITED (status))
    {
      log_error (_("error running `%s': terminated\n"), pgmname);
      ec = GPG_ERR_GENERAL;
    }
  else 
    ec = 0;
#endif /* !_WIN32 */

  return gpg_err_make (GPG_ERR_SOURCE_DEFAULT, ec);

}

