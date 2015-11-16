/* exechelp-w32.c - Fork and exec helpers for W32.
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

#if !defined(HAVE_W32_SYSTEM) || defined (HAVE_W32CE_SYSTEM)
#error This code is only used on W32.
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

/* Define to 1 do enable debugging.  */
#define DEBUG_W32_SPAWN 1


/* It seems Vista doesn't grok X_OK and so fails access() tests.
   Previous versions interpreted X_OK as F_OK anyway, so we'll just
   use F_OK directly. */
#undef X_OK
#define X_OK F_OK

/* We assume that a HANDLE can be represented by an int which should
   be true for all i386 systems (HANDLE is defined as void *) and
   these are the only systems for which Windows is available.  Further
   we assume that -1 denotes an invalid handle.  */
# define fd_to_handle(a)  ((HANDLE)(a))
# define handle_to_fd(a)  ((int)(a))
# define pid_to_handle(a) ((HANDLE)(a))
# define handle_to_pid(a) ((int)(a))


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
close_all_fds (int first, int *except)
{
  (void)first;
  (void)except;
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
      /* Need to do some kind of quoting.  */
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


/* Create pipe where one end is inheritable: With an INHERIT_IDX of 0
   the read end is inheritable, with 1 the write end is inheritable.  */
static int
create_inheritable_pipe (HANDLE filedes[2], int inherit_idx)
{
  HANDLE r, w, h;
  SECURITY_ATTRIBUTES sec_attr;

  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  if (!CreatePipe (&r, &w, &sec_attr, 0))
    return -1;

  if (!DuplicateHandle (GetCurrentProcess(), inherit_idx? w : r,
                        GetCurrentProcess(), &h, 0,
                        TRUE, DUPLICATE_SAME_ACCESS ))
    {
      log_error ("DuplicateHandle failed: %s\n", w32_strerror (-1));
      CloseHandle (r);
      CloseHandle (w);
      return -1;
    }

  if (inherit_idx)
    {
      CloseHandle (w);
      w = h;
    }
  else
    {
      CloseHandle (r);
      r = h;
    }

  filedes[0] = r;
  filedes[1] = w;
  return 0;
}


static HANDLE
w32_open_null (int for_write)
{
  HANDLE hfile;

  hfile = CreateFileW (L"nul",
                       for_write? GENERIC_WRITE : GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
  if (hfile == INVALID_HANDLE_VALUE)
    log_debug ("can't open 'nul': %s\n", w32_strerror (-1));
  return hfile;
}


static gpg_error_t
do_create_pipe (int filedes[2], int inherit_idx)
{
  gpg_error_t err = 0;
  HANDLE fds[2];

  filedes[0] = filedes[1] = -1;
  err = gpg_error (GPG_ERR_GENERAL);
  if (!create_inheritable_pipe (fds, inherit_idx))
    {
      filedes[0] = _open_osfhandle (handle_to_fd (fds[0]), 0);
      if (filedes[0] == -1)
        {
          log_error ("failed to translate osfhandle %p\n", fds[0]);
          CloseHandle (fds[1]);
        }
      else
        {
          filedes[1] = _open_osfhandle (handle_to_fd (fds[1]), 1);
          if (filedes[1] == -1)
            {
              log_error ("failed to translate osfhandle %p\n", fds[1]);
              close (filedes[0]);
              filedes[0] = -1;
              CloseHandle (fds[1]);
            }
          else
            err = 0;
        }
    }
  return err;
}

/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  */
gpg_error_t
gnupg_create_inbound_pipe (int filedes[2])
{
  return do_create_pipe (filedes, 1);
}


/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  */
gpg_error_t
gnupg_create_outbound_pipe (int filedes[2])
{
  return do_create_pipe (filedes, 0);
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
  HANDLE inpipe[2]  = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
  HANDLE outpipe[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
  HANDLE errpipe[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
  estream_t infp = NULL;
  estream_t outfp = NULL;
  estream_t errfp = NULL;
  HANDLE nullhd[3] = {INVALID_HANDLE_VALUE,
                      INVALID_HANDLE_VALUE,
                      INVALID_HANDLE_VALUE};
  int i;
  es_syshd_t syshd;

  if (r_infp)
    *r_infp = NULL;
  if (r_outfp)
    *r_outfp = NULL;
  if (r_errfp)
    *r_errfp = NULL;
  *pid = (pid_t)(-1); /* Always required.  */

  if (infp)
    {
      if (create_inheritable_pipe (inpipe, 0))
        {
          err = gpg_err_make (errsource, GPG_ERR_GENERAL);
          log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
          return err;
        }

      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = inpipe[1];
      infp = es_sysopen (&syshd, "w");
      if (!infp)
        {
          err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
          log_error (_("error creating a stream for a pipe: %s\n"),
                     gpg_strerror (err));
          CloseHandle (inpipe[0]);
          CloseHandle (inpipe[1]);
          inpipe[0] = inpipe[1] = INVALID_HANDLE_VALUE;
          return err;
        }
    }

  if (r_outfp)
    {
      if (create_inheritable_pipe (outpipe, 1))
        {
          err = gpg_err_make (errsource, GPG_ERR_GENERAL);
          log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
          return err;
        }

      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = outpipe[0];
      outfp = es_sysopen (&syshd, "r");
      if (!outfp)
        {
          err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
          log_error (_("error creating a stream for a pipe: %s\n"),
                     gpg_strerror (err));
          CloseHandle (outpipe[0]);
          CloseHandle (outpipe[1]);
          outpipe[0] = outpipe[1] = INVALID_HANDLE_VALUE;
          if (infp)
            es_fclose (infp);
          else if (inpipe[1] != INVALID_HANDLE_VALUE)
            CloseHandle (outpipe[1]);
          if (inpipe[0] != INVALID_HANDLE_VALUE)
            CloseHandle (inpipe[0]);
          return err;
        }
    }

  if (r_errfp)
    {
      if (create_inheritable_pipe (errpipe, 1))
        {
          err = gpg_err_make (errsource, GPG_ERR_GENERAL);
          log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
          return err;
        }

      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = errpipe[0];
      errfp = es_sysopen (&syshd, "r");
      if (!errfp)
        {
          err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
          log_error (_("error creating a stream for a pipe: %s\n"),
                     gpg_strerror (err));
          CloseHandle (errpipe[0]);
          CloseHandle (errpipe[1]);
          errpipe[0] = errpipe[1] = INVALID_HANDLE_VALUE;
          if (outfp)
            es_fclose (outfp);
          else if (outpipe[0] != INVALID_HANDLE_VALUE)
            CloseHandle (outpipe[0]);
          if (outpipe[1] != INVALID_HANDLE_VALUE)
            CloseHandle (outpipe[1]);
          if (infp)
            es_fclose (infp);
          else if (inpipe[1] != INVALID_HANDLE_VALUE)
            CloseHandle (outpipe[1]);
          if (inpipe[0] != INVALID_HANDLE_VALUE)
            CloseHandle (inpipe[0]);
          return err;
        }
    }

  /* Prepare security attributes.  */
  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  /* Build the command line.  */
  err = build_w32_commandline (pgmname, argv, &cmdline);
  if (err)
    return err;

  if (inpipe[0] != INVALID_HANDLE_VALUE)
    nullhd[0] = w32_open_null (0);
  if (outpipe[1] != INVALID_HANDLE_VALUE)
    nullhd[1] = w32_open_null (0);
  if (errpipe[1] != INVALID_HANDLE_VALUE)
    nullhd[2] = w32_open_null (0);

  /* Start the process.  Note that we can't run the PREEXEC function
     because this might change our own environment. */
  (void)preexec;

  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = DEBUG_W32_SPAWN? SW_SHOW : SW_MINIMIZE;
  si.hStdInput  = inpipe[0]  == INVALID_HANDLE_VALUE? nullhd[0] : inpipe[0];
  si.hStdOutput = outpipe[1] == INVALID_HANDLE_VALUE? nullhd[1] : outpipe[1];
  si.hStdError  = errpipe[1] == INVALID_HANDLE_VALUE? nullhd[2] : errpipe[1];

  cr_flags = (CREATE_DEFAULT_ERROR_MODE
              | ((flags & GNUPG_SPAWN_DETACHED)? DETACHED_PROCESS : 0)
              | GetPriorityClass (GetCurrentProcess ())
              | CREATE_SUSPENDED);
/*   log_debug ("CreateProcess, path='%s' cmdline='%s'\n", pgmname, cmdline); */
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
      if (infp)
        es_fclose (infp);
      else if (inpipe[1] != INVALID_HANDLE_VALUE)
        CloseHandle (outpipe[1]);
      if (inpipe[0] != INVALID_HANDLE_VALUE)
        CloseHandle (inpipe[0]);
      if (outfp)
        es_fclose (outfp);
      else if (outpipe[0] != INVALID_HANDLE_VALUE)
        CloseHandle (outpipe[0]);
      if (outpipe[1] != INVALID_HANDLE_VALUE)
        CloseHandle (outpipe[1]);
      if (errfp)
        es_fclose (errfp);
      else if (errpipe[0] != INVALID_HANDLE_VALUE)
        CloseHandle (errpipe[0]);
      if (errpipe[1] != INVALID_HANDLE_VALUE)
        CloseHandle (errpipe[1]);
      return gpg_err_make (errsource, GPG_ERR_GENERAL);
    }
  xfree (cmdline);
  cmdline = NULL;

  /* Close the inherited handles to /dev/null.  */
  for (i=0; i < DIM (nullhd); i++)
    if (nullhd[i] != INVALID_HANDLE_VALUE)
      CloseHandle (nullhd[i]);

  /* Close the inherited ends of the pipes.  */
  if (inpipe[0] != INVALID_HANDLE_VALUE)
    CloseHandle (inpipe[0]);
  if (outpipe[1] != INVALID_HANDLE_VALUE)
    CloseHandle (outpipe[1]);
  if (errpipe[1] != INVALID_HANDLE_VALUE)
    CloseHandle (errpipe[1]);

  /* log_debug ("CreateProcess ready: hProcess=%p hThread=%p" */
  /*            " dwProcessID=%d dwThreadId=%d\n", */
  /*            pi.hProcess, pi.hThread, */
  /*            (int) pi.dwProcessId, (int) pi.dwThreadId); */
  /* log_debug ("                     outfp=%p errfp=%p\n", outfp, errfp); */

  /* Fixme: For unknown reasons AllowSetForegroundWindow returns an
     invalid argument error if we pass it the correct processID.  As a
     workaround we use -1 (ASFW_ANY).  */
  if ((flags & GNUPG_SPAWN_RUN_ASFW))
    gnupg_allow_set_foregound_window ((pid_t)(-1)/*pi.dwProcessId*/);

  /* Process has been created suspended; resume it now. */
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread);

  if (r_infp)
    *r_infp = infp;
  if (r_outfp)
    *r_outfp = outfp;
  if (r_errfp)
    *r_errfp = errfp;

  *pid = handle_to_pid (pi.hProcess);
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

/*   log_debug ("CreateProcess, path='%s' cmdline='%s'\n", pgmname, cmdline); */
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

/*   log_debug ("CreateProcess ready: hProcess=%p hThread=%p" */
/*              " dwProcessID=%d dwThreadId=%d\n", */
/*              pi.hProcess, pi.hThread, */
/*              (int) pi.dwProcessId, (int) pi.dwThreadId); */

  /* Process has been created suspended; resume it now. */
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread);

  *pid = handle_to_pid (pi.hProcess);
  return 0;

}


/* See exechelp.h for a description.  */
gpg_error_t
gnupg_wait_process (const char *pgmname, pid_t pid, int hang, int *r_exitcode)
{
  gpg_err_code_t ec;
  HANDLE proc = fd_to_handle (pid);
  int code;
  DWORD exc;

  if (r_exitcode)
    *r_exitcode = -1;

  if (pid == (pid_t)(-1))
    return gpg_error (GPG_ERR_INV_VALUE);

  /* FIXME: We should do a pth_waitpid here.  However this has not yet
     been implemented.  A special W32 pth system call would even be
     better.  */
  code = WaitForSingleObject (proc, hang? INFINITE : 0);
  switch (code)
    {
    case WAIT_TIMEOUT:
      ec = GPG_ERR_TIMEOUT;
      break;

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
          log_error (_("error running '%s': exit status %d\n"),
                     pgmname, (int)exc );
          if (r_exitcode)
            *r_exitcode = (int)exc;
          ec = GPG_ERR_GENERAL;
        }
      else
        {
          if (r_exitcode)
            *r_exitcode = 0;
          ec = 0;
        }
      break;

    default:
      log_error ("WaitForSingleObject returned unexpected "
                 "code %d for pid %d\n", code, (int)pid );
      ec = GPG_ERR_GENERAL;
      break;
    }

  return gpg_err_make (GPG_ERR_SOURCE_DEFAULT, ec);
}



void
gnupg_release_process (pid_t pid)
{
  if (pid != (pid_t)INVALID_HANDLE_VALUE)
    {
      HANDLE process = (HANDLE)pid;

      CloseHandle (process);
    }
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


  /* We don't use ENVP.  */
  (void)envp;

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
/*   log_debug ("CreateProcess(detached), path='%s' cmdline='%s'\n", */
/*              pgmname, cmdline); */
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

/*   log_debug ("CreateProcess(detached) ready: hProcess=%p hThread=%p" */
/*              " dwProcessID=%d dwThreadId=%d\n", */
/*              pi.hProcess, pi.hThread, */
/*              (int) pi.dwProcessId, (int) pi.dwThreadId); */

  CloseHandle (pi.hThread);

  return 0;
}


/* Kill a process; that is send an appropriate signal to the process.
   gnupg_wait_process must be called to actually remove the process
   from the system.  An invalid PID is ignored.  */
void
gnupg_kill_process (pid_t pid)
{
  if (pid != (pid_t) INVALID_HANDLE_VALUE)
    {
      HANDLE process = (HANDLE) pid;

      /* Arbitrary error code.  */
      TerminateProcess (process, 1);
    }
}
