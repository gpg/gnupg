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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
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
#define DEBUG_W32_SPAWN 0


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
close_all_fds (int first, int *except)
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
    return my_error_from_syserror ();

  p = build_w32_commandline_copy (p, pgmname);
  for (i=0; argv[i]; i++)
    {
      *p++ = ' ';
      p = build_w32_commandline_copy (p, argv[i]);
    }

  *cmdline= buf;
  return 0;
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
create_pipe_and_estream (int filedes[2], int flags,
                         estream_t *r_fp, int outbound, int nonblock)
{
  gpg_error_t err = 0;
  HANDLE fds[2];
  es_syshd_t syshd;

  filedes[0] = filedes[1] = -1;
  err = my_error (GPG_ERR_GENERAL);
  if (!create_inheritable_pipe (fds, flags))
    {
      filedes[0] = _open_osfhandle (handle_to_fd (fds[0]), O_RDONLY);
      if (filedes[0] == -1)
        {
          log_error ("failed to translate osfhandle %p\n", fds[0]);
          CloseHandle (fds[1]);
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
            }
          else
            err = 0;
        }
    }

  if (! err && r_fp)
    {
      syshd.type = ES_SYSHD_HANDLE;
      if (!outbound)
        {
          syshd.u.handle = fds[0];
          *r_fp = es_sysopen (&syshd, nonblock? "r,nonblock" : "r");
        }
      else
        {
          syshd.u.handle = fds[1];
          *r_fp = es_sysopen (&syshd, nonblock? "w,nonblock" : "w");
        }
      if (!*r_fp)
        {
          err = my_error_from_syserror ();
          log_error (_("error creating a stream for a pipe: %s\n"),
                     gpg_strerror (err));
          close (filedes[0]);
          close (filedes[1]);
          filedes[0] = filedes[1] = -1;
          return err;
        }
    }

  return err;
}

/* Portable function to create a pipe.  Under Windows the write end is
   inheritable.  If R_FP is not NULL, an estream is created for the
   read end and stored at R_FP.  */
gpg_error_t
gnupg_create_inbound_pipe (int filedes[2], estream_t *r_fp, int nonblock)
{
  return create_pipe_and_estream (filedes, INHERIT_WRITE,
                                  r_fp, 0, nonblock);
}


/* Portable function to create a pipe.  Under Windows the read end is
   inheritable.  If R_FP is not NULL, an estream is created for the
   write end and stored at R_FP.  */
gpg_error_t
gnupg_create_outbound_pipe (int filedes[2], estream_t *r_fp, int nonblock)
{
  return create_pipe_and_estream (filedes, INHERIT_READ,
                                  r_fp, 1, nonblock);
}


/* Portable function to create a pipe.  Under Windows both ends are
   inheritable.  */
gpg_error_t
gnupg_create_pipe (int filedes[2])
{
  return create_pipe_and_estream (filedes, INHERIT_BOTH,
                                  NULL, 0, 0);
}


/* Fork and exec the PGMNAME, see exechelp.h for details.  */
gpg_error_t
gnupg_spawn_process (const char *pgmname, const char *argv[],
                     int *except, void (*preexec)(void), unsigned int flags,
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
  STARTUPINFOW si;
  int cr_flags;
  char *cmdline;
  wchar_t *wcmdline = NULL;
  wchar_t *wpgmname = NULL;
  HANDLE inpipe[2]  = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
  HANDLE outpipe[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
  HANDLE errpipe[2] = {INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE};
  estream_t infp = NULL;
  estream_t outfp = NULL;
  estream_t errfp = NULL;
  HANDLE nullhd[3] = {INVALID_HANDLE_VALUE,
                      INVALID_HANDLE_VALUE,
                      INVALID_HANDLE_VALUE};
  int i, rc;
  es_syshd_t syshd;
  gpg_err_source_t errsource = default_errsource;
  int nonblock = !!(flags & GNUPG_SPAWN_NONBLOCK);

  (void)except; /* Not yet used.  */

  if (r_infp)
    *r_infp = NULL;
  if (r_outfp)
    *r_outfp = NULL;
  if (r_errfp)
    *r_errfp = NULL;
  *pid = (pid_t)(-1); /* Always required.  */

  if (r_infp)
    {
      if (create_inheritable_pipe (inpipe, INHERIT_READ))
        {
          err = gpg_err_make (errsource, GPG_ERR_GENERAL);
          log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
          return err;
        }

      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = inpipe[1];
      infp = es_sysopen (&syshd, nonblock? "w,nonblock" : "w");
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
      if (create_inheritable_pipe (outpipe, INHERIT_WRITE))
        {
          err = gpg_err_make (errsource, GPG_ERR_GENERAL);
          log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
          return err;
        }

      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = outpipe[0];
      outfp = es_sysopen (&syshd, nonblock? "r,nonblock" : "r");
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
            CloseHandle (inpipe[1]);
          if (inpipe[0] != INVALID_HANDLE_VALUE)
            CloseHandle (inpipe[0]);
          return err;
        }
    }

  if (r_errfp)
    {
      if (create_inheritable_pipe (errpipe, INHERIT_WRITE))
        {
          err = gpg_err_make (errsource, GPG_ERR_GENERAL);
          log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
          return err;
        }

      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = errpipe[0];
      errfp = es_sysopen (&syshd, nonblock? "r,nonblock" : "r");
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
            CloseHandle (inpipe[1]);
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

  if (inpipe[0] == INVALID_HANDLE_VALUE)
    nullhd[0] = ((flags & GNUPG_SPAWN_KEEP_STDIN)?
                 GetStdHandle (STD_INPUT_HANDLE) : w32_open_null (0));
  if (outpipe[1] == INVALID_HANDLE_VALUE)
    nullhd[1] = ((flags & GNUPG_SPAWN_KEEP_STDOUT)?
                 GetStdHandle (STD_OUTPUT_HANDLE) : w32_open_null (1));
  if (errpipe[1] == INVALID_HANDLE_VALUE)
    nullhd[2] = ((flags & GNUPG_SPAWN_KEEP_STDOUT)?
                 GetStdHandle (STD_ERROR_HANDLE) : w32_open_null (1));

  /* Start the process.  Note that we can't run the PREEXEC function
     because this might change our own environment. */
  (void)preexec;

  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = DEBUG_W32_SPAWN? SW_SHOW : SW_HIDE;
  si.hStdInput  = inpipe[0]  == INVALID_HANDLE_VALUE? nullhd[0] : inpipe[0];
  si.hStdOutput = outpipe[1] == INVALID_HANDLE_VALUE? nullhd[1] : outpipe[1];
  si.hStdError  = errpipe[1] == INVALID_HANDLE_VALUE? nullhd[2] : errpipe[1];

  cr_flags = (CREATE_DEFAULT_ERROR_MODE
              | ((flags & GNUPG_SPAWN_DETACHED)? DETACHED_PROCESS : 0)
              | GetPriorityClass (GetCurrentProcess ())
              | CREATE_SUSPENDED);
  /*   log_debug ("CreateProcess, path='%s' cmdline='%s'\n", */
  /*              pgmname, cmdline); */
  /* Take care: CreateProcessW may modify wpgmname */
  if (!(wpgmname = utf8_to_wchar (pgmname)))
    rc = 0;
  else if (!(wcmdline = utf8_to_wchar (cmdline)))
    rc = 0;
  else
    rc = CreateProcessW (wpgmname,      /* Program to start.  */
                         wcmdline,      /* Command line arguments.  */
                         &sec_attr,     /* Process security attributes.  */
                         &sec_attr,     /* Thread security attributes.  */
                         TRUE,          /* Inherit handles.  */
                         cr_flags,      /* Creation flags.  */
                         NULL,          /* Environment.  */
                         NULL,          /* Use current drive/directory.  */
                         &si,           /* Startup information. */
                         &pi            /* Returns process information.  */
                         );
  if (!rc)
    {
      if (!wpgmname || !wcmdline)
        log_error ("CreateProcess failed (utf8_to_wchar): %s\n",
                   strerror (errno));
      else
        log_error ("CreateProcess failed: %s\n", w32_strerror (-1));
      xfree (wpgmname);
      xfree (wcmdline);
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
  xfree (wpgmname);
  xfree (wcmdline);
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
  STARTUPINFOW si;
  char *cmdline;
  wchar_t *wcmdline = NULL;
  wchar_t *wpgmname = NULL;
  int i, rc;
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
  /* Take care: CreateProcessW may modify wpgmname */
  if (!(wpgmname = utf8_to_wchar (pgmname)))
    rc = 0;
  else if (!(wcmdline = utf8_to_wchar (cmdline)))
    rc = 0;
  else
    rc = CreateProcessW (wpgmname,      /* Program to start.  */
                         wcmdline,      /* Command line arguments.  */
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
                         );
  if (!rc)
    {
      if (!wpgmname || !wcmdline)
        log_error ("CreateProcess failed (utf8_to_wchar): %s\n",
                   strerror (errno));
      else
        log_error ("CreateProcess failed: %s\n", w32_strerror (-1));
      err = my_error (GPG_ERR_GENERAL);
    }
  else
    err = 0;
  xfree (wpgmname);
  xfree (wcmdline);
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
  return gnupg_wait_processes (&pgmname, &pid, 1, hang, r_exitcode);
}

/* See exechelp.h for a description.  */
gpg_error_t
gnupg_wait_processes (const char **pgmnames, pid_t *pids, size_t count,
                      int hang, int *r_exitcodes)
{
  gpg_err_code_t ec = 0;
  size_t i;
  HANDLE *procs;
  int code;

  procs = xtrycalloc (count, sizeof *procs);
  if (procs == NULL)
    return my_error_from_syserror ();

  for (i = 0; i < count; i++)
    {
      if (r_exitcodes)
        r_exitcodes[i] = -1;

      if (pids[i] == (pid_t)(-1))
        return my_error (GPG_ERR_INV_VALUE);

      procs[i] = fd_to_handle (pids[i]);
    }

  /* FIXME: We should do a pth_waitpid here.  However this has not yet
     been implemented.  A special W32 pth system call would even be
     better.  */
  code = WaitForMultipleObjects (count, procs, TRUE, hang? INFINITE : 0);
  switch (code)
    {
    case WAIT_TIMEOUT:
      ec = GPG_ERR_TIMEOUT;
      goto leave;

    case WAIT_FAILED:
      log_error (_("waiting for processes to terminate failed: %s\n"),
                 w32_strerror (-1));
      ec = GPG_ERR_GENERAL;
      goto leave;

    case WAIT_OBJECT_0:
      for (i = 0; i < count; i++)
        {
          DWORD exc;

          if (! GetExitCodeProcess (procs[i], &exc))
            {
              log_error (_("error getting exit code of process %d: %s\n"),
                         (int) pids[i], w32_strerror (-1) );
              ec = GPG_ERR_GENERAL;
            }
          else if (exc)
            {
              if (!r_exitcodes)
                log_error (_("error running '%s': exit status %d\n"),
                           pgmnames[i], (int)exc);
              else
                r_exitcodes[i] = (int)exc;
              ec = GPG_ERR_GENERAL;
            }
          else
            {
              if (r_exitcodes)
                r_exitcodes[i] = 0;
            }
        }
      break;

    default:
      log_error ("WaitForMultipleObjects returned unexpected "
                 "code %d\n", code);
      ec = GPG_ERR_GENERAL;
      break;
    }

 leave:
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
  STARTUPINFOW si;
  int cr_flags;
  char *cmdline;
  wchar_t *wcmdline = NULL;
  wchar_t *wpgmname = NULL;
  BOOL in_job = FALSE;
  gpg_err_code_t ec;
  int rc;
  int jobdebug;

  /* We don't use ENVP.  */
  (void)envp;

  cmdline = getenv ("GNUPG_EXEC_DEBUG_FLAGS");
  jobdebug = (cmdline && (atoi (cmdline) & 1));

  if ((ec = gnupg_access (pgmname, X_OK)))
    return gpg_err_make (default_errsource, ec);

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

  /* Check if we were spawned as part of a Job.
   * In a job we need to add CREATE_BREAKAWAY_FROM_JOB
   * to the cr_flags, otherwise our child processes
   * are killed when we terminate. */
  if (!IsProcessInJob (GetCurrentProcess(), NULL, &in_job))
    {
      log_error ("IsProcessInJob() failed: %s\n", w32_strerror (-1));
      in_job = FALSE;
    }

  if (in_job)
    {
      /* Only try to break away from job if it is allowed, otherwise
       * CreateProcess() would fail with an "Access is denied" error. */
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
      if (!QueryInformationJobObject (NULL, JobObjectExtendedLimitInformation,
                                      &info, sizeof info, NULL))
        {
          log_error ("QueryInformationJobObject() failed: %s\n",
                     w32_strerror (-1));
        }
      else if ((info.BasicLimitInformation.LimitFlags &
                JOB_OBJECT_LIMIT_BREAKAWAY_OK))
        {
          if (jobdebug)
            log_debug ("Using CREATE_BREAKAWAY_FROM_JOB flag\n");
          cr_flags |= CREATE_BREAKAWAY_FROM_JOB;
        }
      else if ((info.BasicLimitInformation.LimitFlags &
                JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))
        {
          /* The child process should automatically detach from the job. */
          if (jobdebug)
            log_debug ("Not using CREATE_BREAKAWAY_FROM_JOB flag; "
                       "JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK is set\n");
        }
      else
        {
          /* It seems that the child process must remain in the job.
           * This is not necessarily an error, although it can cause premature
           * termination of the child process when the job is closed. */
          if (jobdebug)
            log_debug ("Not using CREATE_BREAKAWAY_FROM_JOB flag\n");
        }
    }
  else
    {
      if (jobdebug)
        log_debug ("Process is not in a Job\n");
    }

  /*   log_debug ("CreateProcess(detached), path='%s' cmdline='%s'\n", */
  /*              pgmname, cmdline); */
  /* Take care: CreateProcessW may modify wpgmname */
  if (!(wpgmname = utf8_to_wchar (pgmname)))
    rc = 0;
  else if (!(wcmdline = utf8_to_wchar (cmdline)))
    rc = 0;
  else
    rc = CreateProcessW (wpgmname,      /* Program to start.  */
                         wcmdline,      /* Command line arguments.  */
                         &sec_attr,     /* Process security attributes.  */
                         &sec_attr,     /* Thread security attributes.  */
                         FALSE,         /* Inherit handles.  */
                         cr_flags,      /* Creation flags.  */
                         NULL,          /* Environment.  */
                         NULL,          /* Use current drive/directory.  */
                         &si,           /* Startup information. */
                         &pi            /* Returns process information.  */
                         );
  if (!rc)
    {
      if (!wpgmname || !wcmdline)
        log_error ("CreateProcess failed (utf8_to_wchar): %s\n",
                   strerror (errno));
      else
        log_error ("CreateProcess(detached) failed: %s\n", w32_strerror (-1));
      xfree (wpgmname);
      xfree (wcmdline);
      xfree (cmdline);
      return my_error (GPG_ERR_GENERAL);
    }
  xfree (wpgmname);
  xfree (wcmdline);
  xfree (cmdline);
  cmdline = NULL;

/*   log_debug ("CreateProcess(detached) ready: hProcess=%p hThread=%p" */
/*              " dwProcessID=%d dwThreadId=%d\n", */
/*              pi.hProcess, pi.hThread, */
/*              (int) pi.dwProcessId, (int) pi.dwThreadId); */

  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

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
