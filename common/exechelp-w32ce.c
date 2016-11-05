/* exechelp-w32.c - Fork and exec helpers for W32CE.
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

#if !defined(HAVE_W32_SYSTEM) && !defined (HAVE_W32CE_SYSTEM)
#error This code is only used on W32CE.
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

#include <assuan.h>

#include "util.h"
#include "i18n.h"
#include "sysutils.h"
#include "exechelp.h"


/* It seems Vista doesn't grok X_OK and so fails access() tests.
   Previous versions interpreted X_OK as F_OK anyway, so we'll just
   use F_OK directly. */
#undef X_OK
#define X_OK F_OK


/* We assume that a HANDLE can be represented by an int which should
   be true for all i386 systems (HANDLE is defined as void *) and
   these are the only systems for which Windows is available.  Further
   we assume that -1 denotes an invalid handle.  */
#define fd_to_handle(a)  ((HANDLE)(a))
#define handle_to_fd(a)  ((int)(a))
#define pid_to_handle(a) ((HANDLE)(a))
#define handle_to_pid(a) ((int)(a))


#ifdef USE_NPTH
/* The data passed to the feeder_thread.  */
struct feeder_thread_parms
{
  estream_t stream;
  volatile int stream_valid;
  HANDLE hd;
  int direction;
};


/* The thread started by start_feede3.  */
static void *
feeder_thread (void *arg)
{
  struct feeder_thread_parms *parm = arg;
  char buffer[4096];
  int rc;

  if (parm->direction)
    {
      size_t nread = 0;
      DWORD nwritten;

      log_debug ("feeder_thread estream->pipe: stream=%p pipe=%p\n",
                 parm->stream, parm->hd);
      while (parm->stream_valid
             && !es_read (parm->stream, buffer, sizeof buffer, &nread))
        {
          do
            {
              pth_enter ();
              rc = WriteFile (parm->hd, buffer, nread, &nwritten, NULL);
              pth_leave ();
              if (!rc)
                {
                  log_debug ("feeder(%p): WriteFile error: rc=%d\n",
                             parm->hd, (int)GetLastError ());
                  goto leave;
                }
              nread -= nwritten;
            }
          while (nread);
        }
      if (!parm->stream_valid)
        log_debug ("feeder(%p): closed by other thread\n", parm->hd);
      else if (nread)
        log_debug ("feeder(%p): es_read error: %s\n",
                   parm->hd, strerror (errno));
    }
  else
    {
      DWORD nread = 0;
      size_t nwritten;

      log_debug ("feeder_thread pipe->estream: stream=%p pipe=%p\n",
                 parm->stream, parm->hd);
      while ( (pth_enter (),
               (rc = ReadFile (parm->hd, buffer, sizeof buffer, &nread, NULL)),
               pth_leave (),
               rc) && nread)
        {
          log_debug ("feeder_thread pipe->estream: read %d bytes\n",
                     (int)nread);
          do
            {
              if (parm->stream_valid
                  && es_write (parm->stream, buffer, nread, &nwritten))
                {
                  log_debug ("feeder(%p): es_write error: %s\n",
                             parm->hd, strerror (errno));
                  goto leave;
                }
              log_debug ("feeder_thread pipe->estream: es_wrote %d bytes\n",
                         (int)nwritten);
              nread -= nwritten;
            }
          while (nread && parm->stream_valid);
        }
      if (!parm->stream_valid)
        log_debug ("feeder(%p): closed by other thread\n", parm->hd);
      else if (nread)
        log_debug ("feeder(%p): ReadFile error: rc=%d\n",
                   parm->hd, (int)GetLastError ());
      else
        log_debug ("feeder(%p): eof\n", parm->hd);
    }

leave:
  log_debug ("feeder(%p): waiting for es_fclose\n", parm->hd);
  while (parm->stream_valid)
    pth_yield (NULL);
  log_debug ("feeder(%p): about to close the pipe handle\n", parm->hd);
  CloseHandle (parm->hd);
  log_debug ("feeder(%p): pipe handle closed\n", parm->hd);
  xfree (parm);
  return NULL;
}
#endif /*USE_NPTH*/

#ifdef USE_NPTH
static void
feeder_onclose_notification (estream_t stream, void *opaque)
{
  struct feeder_thread_parms *parm = opaque;
  (void)stream;
  log_debug ("feeder(%p): received onclose note\n", parm->hd);
  parm->stream_valid = 0;
}
#endif /*USE_NPTH*/

/* Fire up a thread to copy data between STREAM and a pipe's
   descriptor FD.  With DIRECTION set to true the copy takes place
   from the stream to the pipe, otherwise from the pipe to the
   stream.  */
static gpg_error_t
start_feeder (estream_t stream, HANDLE hd, int direction)
{
#ifdef USE_NPTH
  gpg_error_t err;
  struct feeder_thread_parms *parm;
  pth_attr_t tattr;

  parm = xtrymalloc (sizeof *parm);
  if (!parm)
    return gpg_error_from_syserror ();
  parm->stream = stream;
  parm->stream_valid = 1;
  parm->hd = hd;
  parm->direction = direction;

  if (es_onclose (stream, 1, feeder_onclose_notification, parm))
    {
      err = gpg_error_from_syserror ();
      xfree (parm);
      return err;
    }

  tattr = pth_attr_new ();
  pth_attr_set (tattr, PTH_ATTR_JOINABLE, 0);
  pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 64*1024);
  pth_attr_set (tattr, PTH_ATTR_NAME, "exec-feeder");

  log_debug ("spawning new feeder(%p, %p, %d)\n", stream, hd, direction);
  if(!pth_spawn (tattr, feeder_thread, parm))
    {
      err = gpg_error_from_syserror ();
      es_onclose (stream, 0, feeder_onclose_notification, parm);
      xfree (parm);
    }
  else
    err = 0;
  pth_attr_destroy (tattr);

  return err;
#else
  (void)stream;
  (void)hd;
  (void)direction;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);  /* No Pth.  */
#endif
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



static char *
copy_quoted (char *p, const char *string)
{
  const char *s;

  if (!*string) /* Empty string. */
    p = stpcpy (p, "\"\"");
  else if (strpbrk (string, " \t\n\v\f\"")) /* Need quotes.  */
    {
      p = stpcpy (p, "\"");
      for (s = string; *s; s++)
        {
          *p++ = *s;
          if (*s == '\"')
            *p++ = *s;
        }
      *p++ = '\"';
      *p = 0;
    }
  else /* Copy verbatim.  */
    p = stpcpy (p, string);

  return p;
}


/* Build a command line for use with W32's CreateProcess.  On success
   CMDLINE gets the address of a newly allocated string.  */
static int
build_w32_commandline (const char * const *argv,
		       int rvid0, int rvid1, int rvid2,
                       char **cmdline)
{
  int i, n;
  const char *s;
  char *buf, *p;
  char fdbuf[3*30];

  p = fdbuf;
  *p = 0;

  if (rvid0)
    snprintf (p, 25, "-&S0=%d ", rvid0);
  else
    strcpy (p, "-&S0=null ");
  p += strlen (p);

  if (rvid1)
    snprintf (p, 25, "-&S1=%d ", rvid1);
  else
    strcpy (p, "-&S1=null ");
  p += strlen (p);

  if (rvid2)
    snprintf (p, 25, "-&S2=%d ", rvid2);
  else
    strcpy (p, "-&S2=null ");
  p += strlen (p);

  *cmdline = NULL;
  n = strlen (fdbuf);
  for (i=0; (s = argv[i]); i++)
    {
      n += strlen (s) + 1 + 2;  /* (1 space, 2 quoting) */
      for (; *s; s++)
        if (*s == '\"')
          n++;  /* Need to double inner quotes.  */
    }
  n++;

  buf = p = xtrymalloc (n);
  if (! buf)
    return -1;

  p = stpcpy (p, fdbuf);
  for (i = 0; argv[i]; i++)
    {
      *p++ = ' ';
      p = copy_quoted (p, argv[i]);
    }

  *cmdline = buf;
  return 0;
}


/* Create pipe where one end is inheritable: With an INHERIT_IDX of 0
   the read end is inheritable, with 1 the write end is inheritable.
   Note that the inheritable ends are rendezvous ids and no file
   descriptors or handles. */
static gpg_error_t
create_inheritable_pipe (int filedes[2], int inherit_idx)
{
  HANDLE hd;
  int rvid;

  filedes[0] = filedes[1] = -1;
  hd = _assuan_w32ce_prepare_pipe (&rvid, !inherit_idx);
  if (hd == INVALID_HANDLE_VALUE)
    {
      log_error ("_assuan_w32ce_prepare_pipe failed: %s\n", w32_strerror (-1));
      gpg_err_set_errno (EIO);
      return gpg_error_from_syserror ();
    }

  if (inherit_idx)
    {
      filedes[0] = handle_to_fd (hd);
      filedes[1] = rvid;
    }
  else
    {
      filedes[0] = rvid;
      filedes[1] = handle_to_fd (hd);
    }
  return 0;
}


/* Portable function to create a pipe.  Under Windows the write end is
   inheritable (i.e. an rendezvous id).  */
gpg_error_t
gnupg_create_inbound_pipe (int filedes[2], estream_t *r_fp, int nonblock)
{
  if (r_fp)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else
    return create_inheritable_pipe (filedes, 1);
}


/* Portable function to create a pipe.  Under Windows the read end is
   inheritable (i.e. an rendezvous id).  */
gpg_error_t
gnupg_create_outbound_pipe (int filedes[2], estream_t *r_fp, int nonblock)
{
  if (r_fp)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else
    return create_inheritable_pipe (filedes, 0);
}


/* Portable function to create a pipe.  Under Windows both ends are
   inheritable.  */
gpg_error_t
gnupg_create_pipe (int filedes[2])
{
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static int
create_process (const char *pgmname, const char *cmdline,
                PROCESS_INFORMATION *pi)
{
  int res;
  wchar_t *wpgmname, *wcmdline;

  wpgmname = utf8_to_wchar (pgmname);
  if (!wpgmname)
    return 0;
  wcmdline = utf8_to_wchar (cmdline);
  if (!wcmdline)
    {
      xfree (wpgmname);
      return 0;
    }
  res = CreateProcess (wpgmname,      /* Program to start.  */
                       wcmdline,      /* Command line arguments.  */
                       NULL,          /* Process security attributes.  */
                       NULL,          /* Thread security attributes.  */
                       FALSE,          /* Inherit handles.  */
                       CREATE_SUSPENDED, /* Creation flags.  */
                       NULL,          /* Environment.  */
                       NULL,          /* Use current drive/directory.  */
                       NULL,          /* Startup information. */
                       pi);           /* Returns process information.  */
  xfree (wcmdline);
  xfree (wpgmname);
  return res;
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
  PROCESS_INFORMATION pi = {NULL };
  char *cmdline;
  es_syshd_t syshd;
  struct {
    HANDLE hd;
    int rvid;
  } inpipe = {INVALID_HANDLE_VALUE, 0};
  struct {
    HANDLE hd;
    int rvid;
  } outpipe = {INVALID_HANDLE_VALUE, 0};
  struct {
    HANDLE hd;
    int rvid;
  } errpipe = {INVALID_HANDLE_VALUE, 0};
  estream_t outfp = NULL;
  estream_t errfp = NULL;
  gpg_err_source_t errsource = default_errsource;

  (void)except; /* Not yet used.  */
  (void)preexec;
  (void)flags;

  /* Setup return values.  */
  if (r_outfp)
    *r_outfp = NULL;
  if (r_errfp)
    *r_errfp = NULL;
  *pid = (pid_t)(-1); /* Always required.  */

  log_debug ("%s: enter\n", __func__);
  if (infp)
    {
      es_fflush (infp);
      es_rewind (infp);

      /* Create a pipe to copy our infile to the stdin of the child
         process.  On success inpipe.hd is owned by the feeder.  */
      inpipe.hd = _assuan_w32ce_prepare_pipe (&inpipe.rvid, 1);
      if (inpipe.hd == INVALID_HANDLE_VALUE)
        {
          log_error ("_assuan_w32ce_prepare_pipe failed: %s\n",
                     w32_strerror (-1));
          gpg_err_set_errno (EIO);
          return gpg_error_from_syserror ();
        }
      log_debug ("%s: inpipe %p created; hd=%p rvid=%d\n", __func__,
                 infp, inpipe.hd, inpipe.rvid);
      err = start_feeder (infp, inpipe.hd, 1);
      if (err)
        {
          log_error ("error spawning feeder: %s\n", gpg_strerror (err));
          CloseHandle (inpipe.hd);
          return err;
        }
      inpipe.hd = INVALID_HANDLE_VALUE; /* Now owned by the feeder.  */
      log_debug ("%s: inpipe %p created; feeder started\n", __func__,
                 infp);
    }

  if (r_outfp)
    {
      /* Create a pipe to make the stdout of the child process
         available as a stream.  */
      outpipe.hd = _assuan_w32ce_prepare_pipe (&outpipe.rvid, 0);
      if (outpipe.hd == INVALID_HANDLE_VALUE)
        {
          log_error ("_assuan_w32ce_prepare_pipe failed: %s\n",
                     w32_strerror (-1));
          gpg_err_set_errno (EIO);
          /* Fixme release other stuff/kill feeder.  */
          return gpg_error_from_syserror ();
        }
      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = outpipe.hd;
      err = 0;
      outfp = es_sysopen (&syshd, "r");
      if (!outfp)
        {
          err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
          log_error ("error opening pipe stream: %s\n", gpg_strerror (err));
          CloseHandle (outpipe.hd);
          return err;
        }
      log_debug ("%s: outpipe %p created; hd=%p rvid=%d\n", __func__,
                 outfp, outpipe.hd, outpipe.rvid);
      outpipe.hd = INVALID_HANDLE_VALUE; /* Now owned by the OUTFP.  */
    }

  if (r_errfp)
    {
      /* Create a pipe to make the stderr of the child process
         available as a stream.  */
      errpipe.hd = _assuan_w32ce_prepare_pipe (&errpipe.rvid, 0);
      if (errpipe.hd == INVALID_HANDLE_VALUE)
        {
          log_error ("_assuan_w32ce_prepare_pipe failed: %s\n",
                     w32_strerror (-1));
          gpg_err_set_errno (EIO);
          /* Fixme release other stuff/kill feeder.  */
          return gpg_error_from_syserror ();
        }
      syshd.type = ES_SYSHD_HANDLE;
      syshd.u.handle = errpipe.hd;
      err = 0;
      errfp = es_sysopen (&syshd, "r");
      if (!errfp)
        {
          err = gpg_err_make (errsource, gpg_err_code_from_syserror ());
          log_error ("error opening pipe stream: %s\n", gpg_strerror (err));
          CloseHandle (errpipe.hd);
          return err;
        }
      log_debug ("%s: errpipe %p created; hd=%p rvid=%d\n", __func__,
                 errfp, errpipe.hd, errpipe.rvid);
      errpipe.hd = INVALID_HANDLE_VALUE; /* Now owned by the ERRFP.  */
    }



  /* Build the command line.  */
  err = build_w32_commandline (argv, inpipe.rvid, outpipe.rvid, errpipe.rvid,
                               &cmdline);
  if (err)
    {
      /* Fixme release other stuff/kill feeder.  */
      CloseHandle (errpipe.hd);
      return err;
    }

  log_debug ("CreateProcess, path='%s' cmdline='%s'\n", pgmname, cmdline);
  if (!create_process (pgmname, cmdline, &pi))
    {
      log_error ("CreateProcess failed: %s\n", w32_strerror (-1));
      xfree (cmdline);
      /* Fixme release other stuff/kill feeder.  */
      CloseHandle (errpipe.hd);
      return gpg_error (GPG_ERR_GENERAL);
    }
  xfree (cmdline);
  cmdline = NULL;

  /* Note: The other end of the pipe is a rendezvous id and thus there
     is no need for a close.  */

  log_debug ("CreateProcess ready: hProcess=%p hThread=%p"
             " dwProcessID=%d dwThreadId=%d\n",
             pi.hProcess, pi.hThread,
             (int) pi.dwProcessId, (int) pi.dwThreadId);


  /* Process has been created suspended; resume it now. */
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread);

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
  PROCESS_INFORMATION pi = {NULL};
  char *cmdline;

  /* Setup return values.  */
  *pid = (pid_t)(-1);

  if (infd != -1 || outfd != -1 || errfd != -1)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  /* Build the command line.  */
  err = build_w32_commandline (argv, 0, 0, 0, &cmdline);
  if (err)
    return err;

  log_debug ("CreateProcess, path='%s' cmdline='%s'\n", pgmname, cmdline);
  if (!create_process (pgmname, cmdline, &pi))
    {
      log_error ("CreateProcess(fd) failed: %s\n", w32_strerror (-1));
      xfree (cmdline);
      return gpg_error (GPG_ERR_GENERAL);
    }
  xfree (cmdline);
  cmdline = NULL;

  log_debug ("CreateProcess(fd) ready: hProcess=%p hThread=%p"
             " dwProcessID=%d dwThreadId=%d\n",
             pi.hProcess, pi.hThread,
             (int) pi.dwProcessId, (int) pi.dwThreadId);

  /* Process has been created suspended; resume it now. */
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread);

  *pid = handle_to_pid (pi.hProcess);
  return 0;
}


/* See exechelp.h for a description.  */
gpg_error_t
gnupg_wait_process (const char *pgmname, pid_t pid, int hang, int *exitcode)
{
  gpg_err_code_t ec;
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
      break;

    default:
      log_error ("WaitForSingleObject returned unexpected "
                 "code %d for pid %d\n", code, (int)pid );
      ec = GPG_ERR_GENERAL;
      break;
    }

  return gpg_err_make (GPG_ERR_SOURCE_DEFAULT, ec);
}


/* See exechelp.h for a description.  */
gpg_error_t
gnupg_wait_processes (const char **pgmnames, pid_t *pids, size_t count,
                      int hang, int *r_exitcodes)
{
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
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
  char *cmdline;
  PROCESS_INFORMATION pi = {NULL };

  (void)envp;

  /* Build the command line.  */
  err = build_w32_commandline (argv, 0, 0, 0, &cmdline);
  if (err)
    return err;

  /* Note: There is no detached flag under CE.  */
  log_debug ("CreateProcess, path='%s' cmdline='%s'\n", pgmname, cmdline);
  if (!create_process (pgmname, cmdline, &pi))
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

  /* Process has been created suspended; resume it now. */
  ResumeThread (pi.hThread);
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
