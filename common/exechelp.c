/* exechelp.c - fork and exec helpers
 *	Copyright (C) 2004, 2007, 2008 Free Software Foundation, Inc.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h> 
#include <fcntl.h>

#ifdef WITHOUT_GNU_PTH /* Give the Makefile a chance to build without Pth.  */
#undef HAVE_PTH
#undef USE_GNU_PTH
#endif

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
/* It seems Vista doesn't grok X_OK and so fails access() tests.
   Previous versions interpreted X_OK as F_OK anyway, so we'll just
   use F_OK directly. */
#undef X_OK
#define X_OK F_OK
#endif /* HAVE_W32_SYSTEM */


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
/* Helper function to build_w32_commandline. */
static char *
build_w32_commandline_copy (char *buffer, const char *string)
{
  char *p = buffer;
  const char *s;

  if (!*string) /* Empty string. */
    p = stpcpy (p, "\"\"");
  else if (strpbrk (string, " \t\n\v\f\""))
    {
      /* Need top do some kind of quoting.  */
      p = stpcpy (p, "\"");
      for (s=string; *s; s++)
        {
          *p++ = *s;
          if (*s == '\"')
            *p++ = *s;
        }
      *p++ = '\"';
      *p = 0;
    }
  else
    p = stpcpy (p, string);

  return p;
}

/* Build a command line for use with W32's CreateProcess.  On success
   CMDLINE gets the address of a newly allocated string.  */
static gpg_error_t
build_w32_commandline (const char *pgmname, const char * const *argv, 
                       char **cmdline)
{
  int i, n;
  const char *s;
  char *buf, *p;

  *cmdline = NULL;
  n = 0;
  s = pgmname;
  n += strlen (s) + 1 + 2;  /* (1 space, 2 quoting */
  for (; *s; s++)
    if (*s == '\"')
      n++;  /* Need to double inner quotes.  */
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
    return gpg_error_from_syserror ();

  p = build_w32_commandline_copy (p, pgmname);
  for (i=0; argv[i]; i++) 
    {
      *p++ = ' ';
      p = build_w32_commandline_copy (p, argv[i]);
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


#ifdef HAVE_W32_SYSTEM
static HANDLE
w32_open_null (int for_write)
{
  HANDLE hfile;

  hfile = CreateFile ("nul",
                      for_write? GENERIC_WRITE : GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      NULL, OPEN_EXISTING, 0, NULL);
  if (hfile == INVALID_HANDLE_VALUE)
    log_debug ("can't open `nul': %s\n", w32_strerror (-1));
  return hfile;
}
#endif /*HAVE_W32_SYSTEM*/


#ifndef HAVE_W32_SYSTEM
/* The exec core used right after the fork. This will never return. */
static void
do_exec (const char *pgmname, const char *argv[],
         int fd_in, int fd_out, int fd_err,
         void (*preexec)(void) )
{
  char **arg_list;
  int n, i, j;
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

  /* Connect the standard files. */
  for (i=0; i <= 2; i++)
    {
      if (fds[i] == -1 )
        {
          fds[i] = open ("/dev/null", i? O_WRONLY : O_RDONLY);
          if (fds[i] == -1)
            log_fatal ("failed to open `%s': %s\n",
                       "/dev/null", strerror (errno));
        }
      else if (fds[i] != i && dup2 (fds[i], i) == -1)
        log_fatal ("dup2 std%s failed: %s\n",
                   i==0?"in":i==1?"out":"err", strerror (errno));
    }

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
#endif /*!HAVE_W32_SYSTEM*/


/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  */
gpg_error_t
gnupg_create_inbound_pipe (int filedes[2])
{
  gpg_error_t err = 0;
#if HAVE_W32_SYSTEM
  int fds[2];

  filedes[0] = filedes[1] = -1;
  err = gpg_error (GPG_ERR_GENERAL);
  if (!create_inheritable_pipe (fds))
    {
      filedes[0] = _open_osfhandle (fds[0], 0);
      if (filedes[0] == -1)
        {
          log_error ("failed to translate osfhandle %p\n", (void*)fds[0]);
          CloseHandle (fd_to_handle (fds[1]));
        }
      else 
        {
          filedes[1] = _open_osfhandle (fds[1], 1);
          if (filedes[1] == -1)
            {
              log_error ("failed to translate osfhandle %p\n", (void*)fds[1]);
              close (filedes[0]);
              filedes[0] = -1;
              CloseHandle (fd_to_handle (fds[1]));
            }
          else
            err = 0;
        }
    }
#else
  if (pipe (filedes) == -1)
    {
      err = gpg_error_from_syserror ();
      filedes[0] = filedes[1] = -1;
    }
#endif
  return err;
}


/* Fork and exec the PGMNAME, connect the file descriptor of INFILE to
   stdin, write the output to OUTFILE, return a new stream in
   STATUSFILE for stderr and the pid of the process in PID. The
   arguments for the process are expected in the NULL terminated array
   ARGV.  The program name itself should not be included there.  If
   PREEXEC is not NULL, that function will be called right before the
   exec.  Calling gnupg_wait_process is required.

   FLAGS is a bit vector with just one bit defined for now:

   Bit 7: If set the process will be started as a background process.
          This flag is only useful under W32 systems, so that no new
          console is created and pops up a console window when
          starting the server

   Returns 0 on success or an error code. */
gpg_error_t
gnupg_spawn_process (const char *pgmname, const char *argv[],
                     FILE *infile, FILE *outfile,
                     void (*preexec)(void), unsigned int flags,
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
              | ((flags & 128)? DETACHED_PROCESS : 0)
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

  /* Process has been created suspended; resume it now. */
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread); 

  {
    int x;

    x = _open_osfhandle (rp[0], 0);
    if (x == -1)
      log_error ("failed to translate osfhandle %p\n", (void*)rp[0] );
    else 
      *statusfile = fdopen (x, "r");
  }
  if (!*statusfile)
    {
      err = gpg_error_from_syserror ();
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
      err = gpg_error_from_syserror ();
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
      err = gpg_error_from_syserror ();
      log_error (_("error forking process: %s\n"), strerror (errno));
      close (rp[0]);
      close (rp[1]);
      return err;
    }

  if (!*pid)
    { 
      gcry_control (GCRYCTL_TERM_SECMEM);
      /* Run child. */
      do_exec (pgmname, argv, fd, fdout, rp[1], preexec);
      /*NOTREACHED*/
    }

  /* Parent. */
  close (rp[1]);

  *statusfile = fdopen (rp[0], "r");
  if (!*statusfile)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't fdopen pipe for reading: %s\n"), strerror (errno));
      kill (*pid, SIGTERM);
      *pid = (pid_t)(-1);
      return err;
    }

  return 0;
#endif /* !HAVE_W32_SYSTEM */
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
#ifdef HAVE_W32_SYSTEM
  gpg_error_t err;
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi = { NULL, 0, 0, 0 };
  STARTUPINFO si;
  char *cmdline;
  int i;
  HANDLE stdhd[3];

  /* Setup return values.  */
  *pid = (pid_t)(-1);

  /* Prepare security attributes.  */
  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;
  
  /* Build the command line.  */
  err = build_w32_commandline (pgmname, argv, &cmdline);
  if (err)
    return err; 

  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = DEBUG_W32_SPAWN? SW_SHOW : SW_MINIMIZE;
  stdhd[0] = infd  == -1? w32_open_null (0) : INVALID_HANDLE_VALUE;
  stdhd[1] = outfd == -1? w32_open_null (1) : INVALID_HANDLE_VALUE;
  stdhd[2] = errfd == -1? w32_open_null (1) : INVALID_HANDLE_VALUE;
  si.hStdInput  = infd  == -1? stdhd[0] : (void*)_get_osfhandle (infd);
  si.hStdOutput = outfd == -1? stdhd[1] : (void*)_get_osfhandle (outfd);
  si.hStdError  = errfd == -1? stdhd[2] : (void*)_get_osfhandle (errfd);

  log_debug ("CreateProcess, path=`%s' cmdline=`%s'\n", pgmname, cmdline);
  if (!CreateProcess (pgmname,       /* Program to start.  */
                      cmdline,       /* Command line arguments.  */
                      &sec_attr,     /* Process security attributes.  */
                      &sec_attr,     /* Thread security attributes.  */
                      TRUE,          /* Inherit handles.  */
                      (CREATE_DEFAULT_ERROR_MODE
                       | GetPriorityClass (GetCurrentProcess ())
                       | CREATE_SUSPENDED | DETACHED_PROCESS),
                      NULL,          /* Environment.  */
                      NULL,          /* Use current drive/directory.  */
                      &si,           /* Startup information. */
                      &pi            /* Returns process information.  */
                      ))
    {
      log_error ("CreateProcess failed: %s\n", w32_strerror (-1));
      err = gpg_error (GPG_ERR_GENERAL);
    }
  else
    err = 0;
  xfree (cmdline);
  for (i=0; i < 3; i++)
    if (stdhd[i] != INVALID_HANDLE_VALUE)
      CloseHandle (stdhd[i]);
  if (err)
    return err;

  log_debug ("CreateProcess ready: hProcess=%p hThread=%p"
             " dwProcessID=%d dwThreadId=%d\n",
             pi.hProcess, pi.hThread,
             (int) pi.dwProcessId, (int) pi.dwThreadId);

  /* Process has been created suspended; resume it now. */
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread); 

  *pid = handle_to_pid (pi.hProcess);
  return 0;

#else /* !HAVE_W32_SYSTEM */
  gpg_error_t err;

#ifdef USE_GNU_PTH      
  *pid = pth_fork? pth_fork () : fork ();
#else
  *pid = fork ();
#endif
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
#endif /* !HAVE_W32_SYSTEM */
}


/* Wait for the process identified by PID to terminate. PGMNAME should
   be the same as supplied to the spawn function and is only used for
   diagnostics. Returns 0 if the process succeeded, GPG_ERR_GENERAL
   for any failures of the spawned program or other error codes.  If
   EXITCODE is not NULL the exit code of the process is stored at this
   address or -1 if it could not be retrieved. */
gpg_error_t
gnupg_wait_process (const char *pgmname, pid_t pid, int *exitcode)
{
  gpg_err_code_t ec;

#ifdef HAVE_W32_SYSTEM
  HANDLE proc = fd_to_handle (pid);
  int code;
  DWORD exc;

  if (exitcode)
    *exitcode = -1;

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
            if (exitcode)
              *exitcode = (int)exc;
            ec = GPG_ERR_GENERAL;
          }
        else
          {
            if (exitcode)
              *exitcode = 0;
            ec = 0;
          }
        CloseHandle (proc);
        break;

      default:
        log_error ("WaitForSingleObject returned unexpected "
                   "code %d for pid %d\n", code, (int)pid );
        ec = GPG_ERR_GENERAL;
        break;
    }

#else /* !HAVE_W32_SYSTEM */
  int i, status;

  if (exitcode)
    *exitcode = -1;

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
      if (exitcode)
        *exitcode = WEXITSTATUS (status);
      ec = GPG_ERR_GENERAL;
    }
  else if (!WIFEXITED (status))
    {
      log_error (_("error running `%s': terminated\n"), pgmname);
      ec = GPG_ERR_GENERAL;
    }
  else 
    {
      if (exitcode)
        *exitcode = 0;
      ec = 0;
    }
#endif /* !HAVE_W32_SYSTEM */

  return gpg_err_make (GPG_ERR_SOURCE_DEFAULT, ec);
}


/* Spawn a new process and immediatley detach from it.  The name of
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


  /* FIXME: We don't make use of ENVP yet.  It is currently only used
     to pass the GPG_AGENT_INFO variable to gpg-agent.  As the default
     on windows is to use a standard socket, this does not really
     matter.  */


  if (access (pgmname, X_OK))
    return gpg_error_from_syserror ();

  /* Prepare security attributes.  */
  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;
  
  /* Build the command line.  */
  err = build_w32_commandline (pgmname, argv, &cmdline);
  if (err)
    return err; 

  /* Start the process.  */
  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = DEBUG_W32_SPAWN? SW_SHOW : SW_MINIMIZE;

  cr_flags = (CREATE_DEFAULT_ERROR_MODE
              | GetPriorityClass (GetCurrentProcess ())
              | CREATE_NEW_PROCESS_GROUP
              | DETACHED_PROCESS); 
  log_debug ("CreateProcess(detached), path=`%s' cmdline=`%s'\n",
             pgmname, cmdline);
  if (!CreateProcess (pgmname,       /* Program to start.  */
                      cmdline,       /* Command line arguments.  */
                      &sec_attr,     /* Process security attributes.  */
                      &sec_attr,     /* Thread security attributes.  */
                      FALSE,         /* Inherit handles.  */
                      cr_flags,      /* Creation flags.  */
                      NULL,          /* Environment.  */
                      NULL,          /* Use current drive/directory.  */
                      &si,           /* Startup information. */
                      &pi            /* Returns process information.  */
                      ))
    {
      log_error ("CreateProcess(detached) failed: %s\n", w32_strerror (-1));
      xfree (cmdline);
      return gpg_error (GPG_ERR_GENERAL);
    }
  xfree (cmdline);
  cmdline = NULL;

  log_debug ("CreateProcess(detached) ready: hProcess=%p hThread=%p"
             " dwProcessID=%d dwThreadId=%d\n",
             pi.hProcess, pi.hThread,
             (int) pi.dwProcessId, (int) pi.dwThreadId);

  CloseHandle (pi.hThread); 

  return 0;

#else
  pid_t pid;
  int i;

  if (getuid() != geteuid())
    return gpg_error (GPG_ERR_BUG);

  if (access (pgmname, X_OK))
    return gpg_error_from_syserror ();

#ifdef USE_GNU_PTH      
  pid = pth_fork? pth_fork () : fork ();
#else
  pid = fork ();
#endif
  if (pid == (pid_t)(-1))
    {
      log_error (_("error forking process: %s\n"), strerror (errno));
      return gpg_error_from_syserror ();
    }
  if (!pid)
    {
      gcry_control (GCRYCTL_TERM_SECMEM);
      if (setsid() == -1 || chdir ("/"))
        _exit (1);
      pid = fork (); /* Double fork to let init takes over the new child. */
      if (pid == (pid_t)(-1))
        _exit (1);
      if (pid)
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
#endif /* !HAVE_W32_SYSTEM*/
}
