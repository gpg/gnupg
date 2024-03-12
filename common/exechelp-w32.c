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
#define NEED_STRUCT_SPAWN_CB_ARG
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


/* Close the end of a pipe.  */
void
gnupg_close_pipe (int fd)
{
  if (fd != -1)
    close (fd);
}

struct gnupg_process {
  const char *pgmname;
  unsigned int terminated   :1; /* or detached */
  unsigned int flags;
  HANDLE hProcess;
  HANDLE hd_in;
  HANDLE hd_out;
  HANDLE hd_err;
  int exitcode;
};

static int gnupg_process_syscall_func_initialized;

/* Functions called before and after blocking syscalls.  */
static void (*pre_syscall_func) (void);
static void (*post_syscall_func) (void);

static void
check_syscall_func (void)
{
  if (!gnupg_process_syscall_func_initialized)
    {
      gpgrt_get_syscall_clamp (&pre_syscall_func, &post_syscall_func);
      gnupg_process_syscall_func_initialized = 1;
    }
}


static void
pre_syscall (void)
{
  if (pre_syscall_func)
    pre_syscall_func ();
}


static void
post_syscall (void)
{
  if (post_syscall_func)
    post_syscall_func ();
}


/*
 * Check if STARTUPINFOEXW supports PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
 */
static int
check_windows_version (void)
{
  static int is_vista_or_later = -1;

  OSVERSIONINFO osvi;

  if (is_vista_or_later == -1)
    {
      memset (&osvi,0,sizeof(osvi));
      osvi.dwOSVersionInfoSize = sizeof(osvi);
      GetVersionEx (&osvi);

      /* The feature is available on Vista or later.  */
      is_vista_or_later = (osvi.dwMajorVersion >= 6);
    }

  return is_vista_or_later;
}


static gpg_err_code_t
spawn_detached (const char *pgmname, char *cmdline,
                void (*spawn_cb) (struct spawn_cb_arg *), void *spawn_cb_arg)
{
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi = { NULL, 0, 0, 0 };
  STARTUPINFOEXW si;
  int cr_flags;
  wchar_t *wcmdline = NULL;
  wchar_t *wpgmname = NULL;
  gpg_err_code_t ec;
  int ret;
  struct spawn_cb_arg sca;
  BOOL ask_inherit = FALSE;

  ec = gnupg_access (pgmname, X_OK);
  if (ec)
    {
      xfree (cmdline);
      return ec;
    }

  memset (&si, 0, sizeof si);

  sca.allow_foreground_window = FALSE;
  sca.hd[0] = INVALID_HANDLE_VALUE;
  sca.hd[1] = INVALID_HANDLE_VALUE;
  sca.hd[2] = INVALID_HANDLE_VALUE;
  sca.inherit_hds = NULL;
  sca.arg = spawn_cb_arg;
  if (spawn_cb)
    (*spawn_cb) (&sca);

  if (sca.inherit_hds)
    {
      SIZE_T attr_list_size = 0;
      HANDLE hd[16];
      HANDLE *hd_p = sca.inherit_hds;
      int j = 0;

      if (hd_p)
        {
          while (*hd_p != INVALID_HANDLE_VALUE)
            if (j < DIM (hd))
              hd[j++] = *hd_p++;
            else
              {
                log_error ("Too much handles\n");
                break;
              }
        }

      if (j)
	{
	  if (check_windows_version ())
	    {
	      InitializeProcThreadAttributeList (NULL, 1, 0, &attr_list_size);
	      si.lpAttributeList = xtrymalloc (attr_list_size);
	      if (si.lpAttributeList == NULL)
		{
		  xfree (cmdline);
		  return gpg_err_code_from_syserror ();
		}
	      InitializeProcThreadAttributeList (si.lpAttributeList, 1, 0,
						 &attr_list_size);
	      UpdateProcThreadAttribute (si.lpAttributeList, 0,
					 PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
					 hd, sizeof (HANDLE) * j, NULL, NULL);
	    }

	  ask_inherit = TRUE;
	}
    }

  /* Prepare security attributes.  */
  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  /* Start the process.  */
  si.StartupInfo.cb = sizeof (si);
  si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  si.StartupInfo.wShowWindow = DEBUG_W32_SPAWN? SW_SHOW : SW_MINIMIZE;

  cr_flags = (CREATE_DEFAULT_ERROR_MODE
              | GetPriorityClass (GetCurrentProcess ())
              | CREATE_NEW_PROCESS_GROUP
              | DETACHED_PROCESS);

  /* Take care: CreateProcessW may modify wpgmname */
  if (!(wpgmname = utf8_to_wchar (pgmname)))
    ret = 0;
  else if (!(wcmdline = utf8_to_wchar (cmdline)))
    ret = 0;
  else
    ret = CreateProcessW (wpgmname,      /* Program to start.  */
                          wcmdline,      /* Command line arguments.  */
                          &sec_attr,     /* Process security attributes.  */
                          &sec_attr,     /* Thread security attributes.  */
                          ask_inherit,   /* Inherit handles.  */
                          cr_flags,      /* Creation flags.  */
                          NULL,          /* Environment.  */
                          NULL,          /* Use current drive/directory.  */
                          (STARTUPINFOW *)&si,    /* Startup information. */
                          &pi            /* Returns process information.  */
                          );
  if (!ret)
    {
      if (!wpgmname || !wcmdline)
        log_error ("CreateProcess failed (utf8_to_wchar): %s\n",
                   strerror (errno));
      else
        log_error ("CreateProcess(detached) failed: %d\n",
                   (int)GetLastError ());
      xfree (wpgmname);
      xfree (wcmdline);
      xfree (cmdline);
      return GPG_ERR_GENERAL;
    }
  if (si.lpAttributeList)
    DeleteProcThreadAttributeList (si.lpAttributeList);
  xfree (wpgmname);
  xfree (wcmdline);
  xfree (cmdline);

  /* log_debug ("CreateProcess(detached) ready: hProcess=%p hThread=%p" */
  /*           " dwProcessID=%d dwThreadId=%d\n", */
  /*           pi.hProcess, pi.hThread, */
  /*          (int) pi.dwProcessId, (int) pi.dwThreadId); */

  /* Note: AllowSetForegroundWindow doesn't make sense for background
     process.  */

  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);
  return 0;
}


void
gnupg_spawn_helper (struct spawn_cb_arg *sca)
{
  HANDLE *user_except = sca->arg;
  sca->inherit_hds = user_except;
}

gpg_err_code_t
gnupg_process_spawn (const char *pgmname, const char *argv[],
                     unsigned int flags,
                     void (*spawn_cb) (struct spawn_cb_arg *),
                     void *spawn_cb_arg,
                     gnupg_process_t *r_process)
{
  gpg_err_code_t ec;
  gnupg_process_t process;
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi = { NULL, 0, 0, 0 };
  STARTUPINFOEXW si;
  int cr_flags;
  char *cmdline;
  wchar_t *wcmdline = NULL;
  wchar_t *wpgmname = NULL;
  int ret;
  HANDLE hd_in[2];
  HANDLE hd_out[2];
  HANDLE hd_err[2];
  struct spawn_cb_arg sca;
  int i;
  BOOL ask_inherit = FALSE;

  check_syscall_func ();

  /* Build the command line.  */
  ec = build_w32_commandline (pgmname, argv, &cmdline);
  if (ec)
    return ec;

  if ((flags & GNUPG_PROCESS_DETACHED))
    {
      if ((flags & GNUPG_PROCESS_STDFDS_SETTING))
        {
          xfree (cmdline);
          return GPG_ERR_INV_FLAG;
        }

      /* In detached case, it must be no R_PROCESS.  */
      if (r_process)
        {
          xfree (cmdline);
          return GPG_ERR_INV_ARG;
        }

      return spawn_detached (pgmname, cmdline, spawn_cb, spawn_cb_arg);
    }

  if (r_process)
    *r_process = NULL;

  process = xtrymalloc (sizeof (struct gnupg_process));
  if (process == NULL)
    {
      xfree (cmdline);
      return gpg_err_code_from_syserror ();
    }

  process->pgmname = pgmname;
  process->flags = flags;

  if ((flags & GNUPG_PROCESS_STDINOUT_SOCKETPAIR))
    {
      xfree (process);
      xfree (cmdline);
      return GPG_ERR_NOT_SUPPORTED;
    }

  if ((flags & GNUPG_PROCESS_STDIN_PIPE))
    {
      ec = create_inheritable_pipe (hd_in, INHERIT_READ);
      if (ec)
        {
          xfree (process);
          xfree (cmdline);
          return ec;
        }
    }
  else if ((flags & GNUPG_PROCESS_STDIN_KEEP))
    {
      hd_in[0] = GetStdHandle (STD_INPUT_HANDLE);
      hd_in[1] = INVALID_HANDLE_VALUE;
    }
  else
    {
      hd_in[0] = w32_open_null (0);
      hd_in[1] = INVALID_HANDLE_VALUE;
    }

  if ((flags & GNUPG_PROCESS_STDOUT_PIPE))
    {
      ec = create_inheritable_pipe (hd_out, INHERIT_WRITE);
      if (ec)
        {
          if (hd_in[0] != INVALID_HANDLE_VALUE)
            CloseHandle (hd_in[0]);
          if (hd_in[1] != INVALID_HANDLE_VALUE)
            CloseHandle (hd_in[1]);
          xfree (process);
          xfree (cmdline);
          return ec;
        }
    }
  else if ((flags & GNUPG_PROCESS_STDOUT_KEEP))
    {
      hd_out[0] = INVALID_HANDLE_VALUE;
      hd_out[1] = GetStdHandle (STD_OUTPUT_HANDLE);
    }
  else
    {
      hd_out[0] = INVALID_HANDLE_VALUE;
      hd_out[1] = w32_open_null (1);
    }

  if ((flags & GNUPG_PROCESS_STDERR_PIPE))
    {
      ec = create_inheritable_pipe (hd_err, INHERIT_WRITE);
      if (ec)
        {
          if (hd_in[0] != INVALID_HANDLE_VALUE)
            CloseHandle (hd_in[0]);
          if (hd_in[1] != INVALID_HANDLE_VALUE)
            CloseHandle (hd_in[1]);
          if (hd_out[0] != INVALID_HANDLE_VALUE)
            CloseHandle (hd_out[0]);
          if (hd_out[1] != INVALID_HANDLE_VALUE)
            CloseHandle (hd_out[1]);
          xfree (process);
          xfree (cmdline);
          return ec;
        }
    }
  else if ((flags & GNUPG_PROCESS_STDERR_KEEP))
    {
      hd_err[0] = INVALID_HANDLE_VALUE;
      hd_err[1] = GetStdHandle (STD_ERROR_HANDLE);
    }
  else
    {
      hd_err[0] = INVALID_HANDLE_VALUE;
      hd_err[1] = w32_open_null (1);
    }

  memset (&si, 0, sizeof si);

  sca.allow_foreground_window = FALSE;
  sca.hd[0] = hd_in[0];
  sca.hd[1] = hd_out[1];
  sca.hd[2] = hd_err[1];
  sca.inherit_hds = NULL;
  sca.arg = spawn_cb_arg;
  if (spawn_cb)
    (*spawn_cb) (&sca);

  i = 0;
  if (sca.hd[0] != INVALID_HANDLE_VALUE)
    i++;
  if (sca.hd[1] != INVALID_HANDLE_VALUE)
    i++;
  if (sca.hd[2] != INVALID_HANDLE_VALUE)
    i++;

  if (i != 0 || sca.inherit_hds)
    {
      SIZE_T attr_list_size = 0;
      HANDLE hd[16];
      HANDLE *hd_p = sca.inherit_hds;
      int j = 0;

      if (sca.hd[0] != INVALID_HANDLE_VALUE)
        hd[j++] = sca.hd[0];
      if (sca.hd[1] != INVALID_HANDLE_VALUE)
        hd[j++] = sca.hd[1];
      if (sca.hd[1] != INVALID_HANDLE_VALUE)
        hd[j++] = sca.hd[2];
      if (hd_p)
        {
          while (*hd_p != INVALID_HANDLE_VALUE)
            if (j < DIM (hd))
              hd[j++] = *hd_p++;
            else
              {
                log_error ("Too much handles\n");
                break;
              }
        }

      if (j)
	{
	  if (check_windows_version ())
	    {
	      InitializeProcThreadAttributeList (NULL, 1, 0, &attr_list_size);
	      si.lpAttributeList = xtrymalloc (attr_list_size);
	      if (si.lpAttributeList == NULL)
		{
		  if ((flags & GNUPG_PROCESS_STDIN_PIPE)
		      || !(flags & GNUPG_PROCESS_STDIN_KEEP))
		    CloseHandle (hd_in[0]);
		  if ((flags & GNUPG_PROCESS_STDIN_PIPE))
		    CloseHandle (hd_in[1]);
		  if ((flags & GNUPG_PROCESS_STDOUT_PIPE))
		    CloseHandle (hd_out[0]);
		  if ((flags & GNUPG_PROCESS_STDOUT_PIPE)
		      || !(flags & GNUPG_PROCESS_STDOUT_KEEP))
		    CloseHandle (hd_out[1]);
		  if ((flags & GNUPG_PROCESS_STDERR_PIPE))
		    CloseHandle (hd_err[0]);
		  if ((flags & GNUPG_PROCESS_STDERR_PIPE)
		      || !(flags & GNUPG_PROCESS_STDERR_KEEP))
		    CloseHandle (hd_err[1]);
		  xfree (process);
		  xfree (cmdline);
		  return gpg_err_code_from_syserror ();
		}
	      InitializeProcThreadAttributeList (si.lpAttributeList, 1, 0,
						 &attr_list_size);
	      UpdateProcThreadAttribute (si.lpAttributeList, 0,
					 PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
					 hd, sizeof (HANDLE) * j, NULL, NULL);
	    }
	  ask_inherit = TRUE;
	}
    }

  /* Prepare security attributes.  */
  memset (&sec_attr, 0, sizeof sec_attr );
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  /* Start the process.  */
  si.StartupInfo.cb = sizeof (si);
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.StartupInfo.wShowWindow = DEBUG_W32_SPAWN? SW_SHOW : SW_HIDE;
  si.StartupInfo.hStdInput  = sca.hd[0];
  si.StartupInfo.hStdOutput = sca.hd[1];
  si.StartupInfo.hStdError  = sca.hd[2];

  /* log_debug ("CreateProcess, path='%s' cmdline='%s'\n", pgmname, cmdline); */
  cr_flags = (CREATE_DEFAULT_ERROR_MODE
              | GetPriorityClass (GetCurrentProcess ())
              | CREATE_SUSPENDED);
  if (!(wpgmname = utf8_to_wchar (pgmname)))
    ret = 0;
  else if (!(wcmdline = utf8_to_wchar (cmdline)))
    ret = 0;
  else
    ret = CreateProcessW (wpgmname,      /* Program to start.  */
                          wcmdline,      /* Command line arguments.  */
                          &sec_attr,     /* Process security attributes.  */
                          &sec_attr,     /* Thread security attributes.  */
                          ask_inherit,   /* Inherit handles.  */
                          cr_flags,      /* Creation flags.  */
                          NULL,          /* Environment.  */
                          NULL,          /* Use current drive/directory.  */
                          (STARTUPINFOW *)&si,           /* Startup information. */
                          &pi            /* Returns process information.  */
                          );
  if (!ret)
    {
      if (!wpgmname || !wcmdline)
        log_error ("CreateProcess failed (utf8_to_wchar): %s\n",
                          strerror (errno));
      else
        log_error ("CreateProcess failed: ec=%d\n",
                          (int)GetLastError ());
      if ((flags & GNUPG_PROCESS_STDIN_PIPE)
          || !(flags & GNUPG_PROCESS_STDIN_KEEP))
        CloseHandle (hd_in[0]);
      if ((flags & GNUPG_PROCESS_STDIN_PIPE))
        CloseHandle (hd_in[1]);
      if ((flags & GNUPG_PROCESS_STDOUT_PIPE))
        CloseHandle (hd_out[0]);
      if ((flags & GNUPG_PROCESS_STDOUT_PIPE)
          || !(flags & GNUPG_PROCESS_STDOUT_KEEP))
        CloseHandle (hd_out[1]);
      if ((flags & GNUPG_PROCESS_STDERR_PIPE))
        CloseHandle (hd_err[0]);
      if ((flags & GNUPG_PROCESS_STDERR_PIPE)
          || !(flags & GNUPG_PROCESS_STDERR_KEEP))
        CloseHandle (hd_err[1]);
      xfree (wpgmname);
      xfree (wcmdline);
      xfree (process);
      xfree (cmdline);
      return GPG_ERR_GENERAL;
    }

  if (si.lpAttributeList)
    DeleteProcThreadAttributeList (si.lpAttributeList);
  xfree (wpgmname);
  xfree (wcmdline);
  xfree (cmdline);

  if ((flags & GNUPG_PROCESS_STDIN_PIPE)
      || !(flags & GNUPG_PROCESS_STDIN_KEEP))
    CloseHandle (hd_in[0]);
  if ((flags & GNUPG_PROCESS_STDOUT_PIPE)
      || !(flags & GNUPG_PROCESS_STDOUT_KEEP))
    CloseHandle (hd_out[1]);
  if ((flags & GNUPG_PROCESS_STDERR_PIPE)
      || !(flags & GNUPG_PROCESS_STDERR_KEEP))
    CloseHandle (hd_err[1]);

  /* log_debug ("CreateProcess ready: hProcess=%p hThread=%p" */
  /*           " dwProcessID=%d dwThreadId=%d\n", */
  /*           pi.hProcess, pi.hThread, */
  /*           (int) pi.dwProcessId, (int) pi.dwThreadId); */

  if (sca.allow_foreground_window)
    {
      /* Fixme: For unknown reasons AllowSetForegroundWindow returns
       * an invalid argument error if we pass it the correct
       * processID.  As a workaround we use -1 (ASFW_ANY).  */
      if (!AllowSetForegroundWindow (ASFW_ANY /*pi.dwProcessId*/))
        log_info ("AllowSetForegroundWindow() failed: ec=%d\n",
                  (int)GetLastError ());
    }

  /* Process has been created suspended; resume it now. */
  pre_syscall ();
  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread);
  post_syscall ();

  process->hProcess = pi.hProcess;
  process->hd_in = hd_in[1];
  process->hd_out = hd_out[0];
  process->hd_err = hd_err[0];
  process->exitcode = -1;
  process->terminated = 0;

  if (r_process == NULL)
    {
      ec = gnupg_process_wait (process, 1);
      gnupg_process_release (process);
      return ec;
    }

  *r_process = process;
  return 0;
}

gpg_err_code_t
gnupg_process_get_fds (gnupg_process_t process, unsigned int flags,
                        int *r_fd_in, int *r_fd_out, int *r_fd_err)
{
  (void)flags;
  if (r_fd_in)
    {
      *r_fd_in = _open_osfhandle ((intptr_t)process->hd_in, O_APPEND);
      process->hd_in = INVALID_HANDLE_VALUE;
    }
  if (r_fd_out)
    {
      *r_fd_out = _open_osfhandle ((intptr_t)process->hd_out, O_RDONLY);
      process->hd_out = INVALID_HANDLE_VALUE;
    }
  if (r_fd_err)
    {
      *r_fd_err = _open_osfhandle ((intptr_t)process->hd_err, O_RDONLY);
      process->hd_err = INVALID_HANDLE_VALUE;
    }

  return 0;
}

gpg_err_code_t
gnupg_process_get_streams (gnupg_process_t process, unsigned int flags,
                           estream_t *r_fp_in, estream_t *r_fp_out,
                           estream_t *r_fp_err)
{
  int nonblock = (flags & GNUPG_PROCESS_STREAM_NONBLOCK)? 1: 0;
  es_syshd_t syshd;

  syshd.type = ES_SYSHD_HANDLE;
  if (r_fp_in)
    {
      syshd.u.handle = process->hd_in;
      *r_fp_in = es_sysopen (&syshd, nonblock? "w,nonblock" : "w");
      process->hd_in = INVALID_HANDLE_VALUE;
    }
  if (r_fp_out)
    {
      syshd.u.handle = process->hd_out;
      *r_fp_out = es_sysopen (&syshd, nonblock? "r,nonblock" : "r");
      process->hd_out = INVALID_HANDLE_VALUE;
    }
  if (r_fp_err)
    {
      syshd.u.handle = process->hd_err;
      *r_fp_err = es_sysopen (&syshd, nonblock? "r,nonblock" : "r");
      process->hd_err = INVALID_HANDLE_VALUE;
    }
  return 0;
}

static gpg_err_code_t
process_kill (gnupg_process_t process, unsigned int exitcode)
{
  gpg_err_code_t ec = 0;

  pre_syscall ();
  if (TerminateProcess (process->hProcess, exitcode))
    ec = gpg_err_code_from_syserror ();
  post_syscall ();
  return ec;
}

static gpg_err_code_t
process_vctl (gnupg_process_t process, unsigned int request, va_list arg_ptr)
{
  switch (request)
    {
    case GNUPG_PROCESS_NOP:
      return 0;

    case GNUPG_PROCESS_GET_PROC_ID:
      {
        int *r_id = va_arg (arg_ptr, int *);

        if (r_id == NULL)
          return GPG_ERR_INV_VALUE;

        *r_id = (int)GetProcessId (process->hProcess);
        return 0;
      }

    case GNUPG_PROCESS_GET_EXIT_ID:
      {
        int *r_exit_status = va_arg (arg_ptr, int *);
        unsigned long exit_code;

        *r_exit_status = -1;

        if (!process->terminated)
          return GPG_ERR_UNFINISHED;

        if (process->hProcess == INVALID_HANDLE_VALUE)
          return 0;

        if (GetExitCodeProcess (process->hProcess, &exit_code) == 0)
          return gpg_err_code_from_syserror ();

        *r_exit_status = (int)exit_code;
        return 0;
      }

    case GNUPG_PROCESS_GET_P_HANDLE:
      {
        HANDLE *r_hProcess = va_arg (arg_ptr, HANDLE *);

        if (r_hProcess == NULL)
          return GPG_ERR_INV_VALUE;

        *r_hProcess = process->hProcess;
        process->hProcess = INVALID_HANDLE_VALUE;
        return 0;
      }

    case GNUPG_PROCESS_GET_HANDLES:
      {
        HANDLE *r_hd_in = va_arg (arg_ptr, HANDLE *);
        HANDLE *r_hd_out = va_arg (arg_ptr, HANDLE *);
        HANDLE *r_hd_err = va_arg (arg_ptr, HANDLE *);

        if (r_hd_in)
          {
            *r_hd_in = process->hd_in;
            process->hd_in = INVALID_HANDLE_VALUE;
          }
        if (r_hd_out)
          {
            *r_hd_out = process->hd_out;
            process->hd_out = INVALID_HANDLE_VALUE;
          }
        if (r_hd_err)
          {
            *r_hd_err = process->hd_err;
            process->hd_err = INVALID_HANDLE_VALUE;
          }
        return 0;
      }

    case GNUPG_PROCESS_GET_EXIT_CODE:
      {
        unsigned long *r_exitcode = va_arg (arg_ptr, unsigned long *);

        if (!process->terminated)
          return GPG_ERR_UNFINISHED;

        if (process->hProcess == INVALID_HANDLE_VALUE)
          {
            *r_exitcode = (unsigned long)-1;
            return 0;
          }

        if (GetExitCodeProcess (process->hProcess, r_exitcode) == 0)
          return gpg_err_code_from_syserror ();
        return 0;
      }

    case GNUPG_PROCESS_KILL_WITH_EC:
      {
        unsigned int exitcode = va_arg (arg_ptr, unsigned int);

        if (process->terminated)
          return 0;

        if (process->hProcess == INVALID_HANDLE_VALUE)
          return 0;

        return process_kill (process, exitcode);
      }

    default:
      break;
    }

  return GPG_ERR_UNKNOWN_COMMAND;
}

gpg_err_code_t
gnupg_process_ctl (gnupg_process_t process, unsigned int request, ...)
{
  va_list arg_ptr;
  gpg_err_code_t ec;

  va_start (arg_ptr, request);
  ec = process_vctl (process, request, arg_ptr);
  va_end (arg_ptr);
  return ec;
}

gpg_err_code_t
gnupg_process_wait (gnupg_process_t process, int hang)
{
  gpg_err_code_t ec;
  int code;

  if (process->hProcess == INVALID_HANDLE_VALUE)
    return 0;

  pre_syscall ();
  code = WaitForSingleObject (process->hProcess, hang? INFINITE : 0);
  post_syscall ();

  switch (code)
    {
    case WAIT_TIMEOUT:
      ec = GPG_ERR_TIMEOUT; /* Still running.  */
      break;

    case WAIT_FAILED:
      log_error (_("waiting for process to terminate failed: ec=%d\n"),
                 (int)GetLastError ());
      ec = GPG_ERR_GENERAL;
      break;

    case WAIT_OBJECT_0:
      process->terminated = 1;
      ec = 0;
      break;

    default:
      log_debug ("WaitForSingleObject returned unexpected code %d\n", code);
      ec = GPG_ERR_GENERAL;
      break;
    }

  return ec;
}

gpg_err_code_t
gnupg_process_terminate (gnupg_process_t process)
{
  return process_kill (process, 1);
}

void
gnupg_process_release (gnupg_process_t process)
{
  if (!process)
    return;

  if (process->terminated)
    {
      gnupg_process_terminate (process);
      gnupg_process_wait (process, 1);
    }

  CloseHandle (process->hProcess);
  xfree (process);
}

gpg_err_code_t
gnupg_process_wait_list (gnupg_process_t *process_list, int count, int hang)
{
  gpg_err_code_t ec = 0;
  int i;

  for (i = 0; i < count; i++)
    {
      if (process_list[i]->terminated)
        continue;

      ec = gnupg_process_wait (process_list[i], hang);
      if (ec)
        break;
    }

  return ec;
}
