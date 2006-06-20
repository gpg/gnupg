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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
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
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif

#include "util.h"
#include "i18n.h"
#include "exechelp.h"

/* Define to 1 do enable debugging.  */
#define DEBUG_W32_SPAWN 1


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


#ifdef HAVE_W32_SYSTEM
/* We assume that a HANDLE can be represented by an int which should
   be true for all i386 systems (HANDLE is defined as void *) and
   these are the only systems for which Windows is available.  Further
   we assume that -1 denotes an invalid handle.  */
# define fd_to_handle(a)  ((HANDLE)(a))
# define handle_to_fd(a)  ((int)(a))
# define pid_to_handle(a) ((HANDLE)(a))
# define handle_to_pid(a) ((int)(a))
#endif


#ifdef HAVE_W32_SYSTEM
/* Build a command line for use with W32's CreateProcess.  On success
   CMDLINE gets the address of a newly allocated string.  */
static gpg_error_t
build_w32_commandline (const char *pgmname, const char **argv, char **cmdline)
{
  int i, n;
  const char *s;
  char *buf, *p;

  *cmdline = NULL;
  n = strlen (pgmname);
  for (i=0; (s=argv[i]); i++)
    {
      n += strlen (s) + 1 + 2;  /* (1 space, 2 quoting */
      for (; *s; s++)
        if (*s == '\"')
          n++;  /* Need to double inner quotes.  */
    }
  n++;

  buf = p = xtrymalloc (n);
  if (!buf)
    return gpg_error_from_errno (errno);

  /* fixme: PGMNAME may not contain spaces etc. */
  p = stpcpy (p, pgmname);
  for (i=0; argv[i]; i++) 
    {
      if (!*argv[i]) /* Empty string. */
        p = stpcpy (p, " \"\"");
      else if (strpbrk (argv[i], " \t\n\v\f\""))
        {
          p = stpcpy (p, " \"");
          for (s=argv[i]; *s; s++)
            {
              *p++ = *s;
              if (*s == '\"')
                *p++ = *s;
            }
          *p++ = '\"';
          *p = 0;
        }
      else
        p = stpcpy (stpcpy (p, " "), argv[i]);
    }

  *cmdline= buf;
  return 0;
}
#endif /*HAVE_W32_SYSTEM*/


#ifdef HAVE_W32_SYSTEM
/* Create  pipe where the write end is inheritable.  */
static int
create_inheritable_pipe (int filedes[2])
{
  HANDLE r, w, h;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;
    
  if (!CreatePipe (&r, &w, &sec_attr, 0))
    return -1;

  if (!DuplicateHandle (GetCurrentProcess(), w,
                        GetCurrentProcess(), &h, 0,
                        TRUE, DUPLICATE_SAME_ACCESS ))
    {
      log_error ("DuplicateHandle failed: %s\n", w32_strerror (-1));
      CloseHandle (r);
      CloseHandle (w);
      return -1;
    }
  CloseHandle (w);
  w = h;

  filedes[0] = handle_to_fd (r);
  filedes[1] = handle_to_fd (w);
  return 0;
}
#endif /*HAVE_W32_SYSTEM*/



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
#ifdef HAVE_W32_SYSTEM
  gpg_error_t err;
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi = 
    {
      NULL,      /* Returns process handle.  */
      0,         /* Returns primary thread handle.  */
      0,         /* Returns pid.  */
      0          /* Returns tid.  */
    };
  STARTUPINFO si;
  int cr_flags;
  char *cmdline;
  int fd, fdout, rp[2];

  /* Setup return values.  */
  *statusfile = NULL;
  *pid = (pid_t)(-1);
  fflush (infile);
  rewind (infile);
  fd = _get_osfhandle (fileno (infile));
  fdout = _get_osfhandle (fileno (outfile));
  if (fd == -1 || fdout == -1)
    log_fatal ("no file descriptor for file passed to gnupg_spawn_process\n");

  /* Prepare security attributes.  */
  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;
  
  /* Build the command line.  */
  err = build_w32_commandline (pgmname, argv, &cmdline);
  if (err)
    return err; 

  /* Create a pipe.  */
  if (create_inheritable_pipe (rp))
    {
      err = gpg_error (GPG_ERR_GENERAL);
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      xfree (cmdline);
      return err;
    }
  
  /* Start the process.  Note that we can't run the PREEXEC function
     because this would change our own environment. */
  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = DEBUG_W32_SPAWN? SW_SHOW : SW_MINIMIZE;
  si.hStdInput  = fd_to_handle (fd);
  si.hStdOutput = fd_to_handle (fdout);
  si.hStdError  = fd_to_handle (rp[1]);

  cr_flags = (CREATE_DEFAULT_ERROR_MODE
              | GetPriorityClass (GetCurrentProcess ())
              | CREATE_SUSPENDED); 
  log_debug ("CreateProcess, path=`%s' cmdline=`%s'\n", pgmname, cmdline);
  if (!CreateProcess (pgmname,       /* Program to start.  */
                      cmdline,       /* Command line arguments.  */
                      &sec_attr,     /* Process security attributes.  */
                      &sec_attr,     /* Thread security attributes.  */
                      TRUE,          /* Inherit handles.  */
                      cr_flags,      /* Creation flags.  */
                      NULL,          /* Environment.  */
                      NULL,          /* Use current drive/directory.  */
                      &si,           /* Startup information. */
                      &pi            /* Returns process information.  */
                      ))
    {
      log_error ("CreateProcess failed: %s\n", w32_strerror (-1));
      xfree (cmdline);
      CloseHandle (fd_to_handle (rp[0]));
      CloseHandle (fd_to_handle (rp[1]));
      return gpg_error (GPG_ERR_GENERAL);
    }
  xfree (cmdline);
  cmdline = NULL;

  /* Close the other end of the pipe.  */
  CloseHandle (fd_to_handle (rp[1]));
  
  log_debug ("CreateProcess ready: hProcess=%p hThread=%p"
             " dwProcessID=%d dwThreadId=%d\n",
             pi.hProcess, pi.hThread,
             (int) pi.dwProcessId, (int) pi.dwThreadId);

  /* Process ha been created suspended; resume it now. */
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread); 

  {
    int x;

    x = _open_osfhandle (rp[0], 0);
    if (x == -1)
      log_error ("failed to translate osfhandle %p\n", (void*)rp[0] );
    else 
      {
        log_debug ("_open_osfhandle %p yields %d\n", (void*)fd, x );
        *statusfile = fdopen (x, "r");
      }
  }
  if (!*statusfile)
    {
      err = gpg_error_from_errno (errno);
      log_error (_("can't fdopen pipe for reading: %s\n"), gpg_strerror (err));
      CloseHandle (pi.hProcess);
      return err;
    }

  *pid = handle_to_pid (pi.hProcess);
  return 0;

#else /* !HAVE_W32_SYSTEM */
  gpg_error_t err;
  int fd, fdout, rp[2];

  *statusfile = NULL;
  *pid = (pid_t)(-1);
  fflush (infile);
  rewind (infile);
  fd = fileno (infile);
  fdout = fileno (outfile);
  if (fd == -1 || fdout == -1)
    log_fatal ("no file descriptor for file passed to gnupg_spawn_process\n");

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
#endif /* !HAVE_W32_SYSTEM */
}


/* Wait for the process identified by PID to terminate. PGMNAME should
   be the same as suplieed to the spawn fucntion and is only used for
   diagnostics. Returns 0 if the process succeded, GPG_ERR_GENERAL for
   any failures of the spawned program or other error codes.*/
gpg_error_t
gnupg_wait_process (const char *pgmname, pid_t pid)
{
  gpg_err_code_t ec;

#ifdef HAVE_W32_SYSTEM
  HANDLE proc = fd_to_handle (pid);
  int code;
  DWORD exc;

  if (pid == (pid_t)(-1))
    return gpg_error (GPG_ERR_INV_VALUE);

  /* FIXME: We should do a pth_waitpid here.  However this has not yet
     been implemented.  A special W32 pth system call would even be
     better.  */
  code = WaitForSingleObject (proc, INFINITE);
  switch (code) 
    {
      case WAIT_FAILED:
        log_error (_("waiting for process %d to terminate failed: %s\n"),
                   (int)pid, w32_strerror (-1));
        ec = GPG_ERR_GENERAL;
        break;

      case WAIT_OBJECT_0:
        if (!GetExitCodeProcess (proc, &exc))
          {
            log_error (_("error getting exit code of process %d: %s\n"),
                         (int)pid, w32_strerror (-1) );
            ec = GPG_ERR_GENERAL;
          }
        else if (exc)
          {
            log_error (_("error running `%s': exit status %d\n"),
                       pgmname, (int)exc );
            ec = GPG_ERR_GENERAL;
          }
        else
          ec = 0;
        break;

      default:
        log_error ("WaitForSingleObject returned unexpected "
                   "code %d for pid %d\n", code, (int)pid );
        ec = GPG_ERR_GENERAL;
        break;
    }

#else /* !HAVE_W32_SYSTEM */
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
#endif /* !HAVE_W32_SYSTEM */

  return gpg_err_make (GPG_ERR_SOURCE_DEFAULT, ec);

}

