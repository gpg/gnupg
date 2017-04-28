/* ldap-wrapper.c - LDAP access via a wrapper process
 * Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
 * Copyright (C) 2010 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
   We can't use LDAP directly for these reasons:

   1. On some systems the LDAP library uses (indirectly) pthreads and
      that is not compatible with PTh.

   2. It is huge library in particular if TLS comes into play.  So
      problems with unfreed memory might turn up and we don't want
      this in a long running daemon.

   3. There is no easy way for timeouts. In particular the timeout
      value does not work for DNS lookups (well, this is usual) and it
      seems not to work while loading a large attribute like a
      CRL. Having a separate process allows us to either tell the
      process to commit suicide or have our own housekepping function
      kill it after some time.  The latter also allows proper
      cancellation of a query at any point of time.

   4. Given that we are going out to the network and usually get back
      a long response, the fork/exec overhead is acceptable.

   Note that under WindowsCE the number of processes is strongly
   limited (32 processes including the kernel processes) and thus we
   don't use the process approach but implement a different wrapper in
   ldap-wrapper-ce.c.
*/


#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <npth.h>

#include "dirmngr.h"
#include "../common/exechelp.h"
#include "misc.h"
#include "ldap-wrapper.h"


#ifdef HAVE_W32_SYSTEM
#define setenv(a,b,c) SetEnvironmentVariable ((a),(b))
#else
#define pth_close(fd) close(fd)
#endif

#ifndef USE_LDAPWRAPPER
# error This module is not expected to be build.
#endif

/* In case sysconf does not return a value we need to have a limit. */
#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

#define INACTIVITY_TIMEOUT (opt.ldaptimeout + 60*5)  /* seconds */

#define TIMERTICK_INTERVAL 2

/* To keep track of the LDAP wrapper state we use this structure.  */
struct wrapper_context_s
{
  struct wrapper_context_s *next;

  pid_t pid;    /* The pid of the wrapper process. */
  int printable_pid; /* Helper to print diagnostics after the process has
                        been cleaned up. */
  int fd;       /* Connected with stdout of the ldap wrapper.  */
  gpg_error_t fd_error; /* Set to the gpg_error of the last read error
                           if any.  */
  int log_fd;   /* Connected with stderr of the ldap wrapper.  */
  ctrl_t ctrl;  /* Connection data. */
  int ready;    /* Internally used to mark to be removed contexts. */
  ksba_reader_t reader; /* The ksba reader object or NULL. */
  char *line;     /* Used to print the log lines (malloced). */
  size_t linesize;/* Allocated size of LINE.  */
  size_t linelen; /* Use size of LINE.  */
  time_t stamp;   /* The last time we noticed ativity.  */
};



/* We keep a global list of spawned wrapper process.  A separate thread
   makes use of this list to log error messages and to watch out for
   finished processes. */
static struct wrapper_context_s *wrapper_list;

/* We need to know whether we are shutting down the process.  */
static int shutting_down;

/* Close the pth file descriptor FD and set it to -1.  */
#define SAFE_CLOSE(fd) \
  do { int _fd = fd; if (_fd != -1) { close (_fd); fd = -1;} } while (0)




/* Read a fixed amount of data from READER into BUFFER.  */
static gpg_error_t
read_buffer (ksba_reader_t reader, unsigned char *buffer, size_t count)
{
  gpg_error_t err;
  size_t nread;

  while (count)
    {
      err = ksba_reader_read (reader, buffer, count, &nread);
      if (err)
        return err;
      buffer += nread;
      count -= nread;
    }
  return 0;
}


/* Release the wrapper context and kill a running wrapper process. */
static void
destroy_wrapper (struct wrapper_context_s *ctx)
{
  if (ctx->pid != (pid_t)(-1))
    {
      gnupg_kill_process (ctx->pid);
      gnupg_release_process (ctx->pid);
    }
  ksba_reader_release (ctx->reader);
  SAFE_CLOSE (ctx->fd);
  SAFE_CLOSE (ctx->log_fd);
  xfree (ctx->line);
  xfree (ctx);
}


/* Print the content of LINE to thye log stream but make sure to only
   print complete lines.  Using NULL for LINE will flush any pending
   output.  LINE may be modified by this function. */
static void
print_log_line (struct wrapper_context_s *ctx, char *line)
{
  char *s;
  size_t n;

  if (!line)
    {
      if (ctx->line && ctx->linelen)
        {

          log_info ("%s\n", ctx->line);
          ctx->linelen = 0;
        }
      return;
    }

  while ((s = strchr (line, '\n')))
    {
      *s = 0;
      if (ctx->line && ctx->linelen)
        {
          log_info ("%s", ctx->line);
          ctx->linelen = 0;
          log_printf ("%s\n", line);
        }
      else
        log_info ("%s\n", line);
      line = s + 1;
    }
  n = strlen (line);
  if (n)
    {
      if (ctx->linelen + n + 1 >= ctx->linesize)
        {
          char *tmp;
          size_t newsize;

          newsize = ctx->linesize + ((n + 255) & ~255) + 1;
          tmp = (ctx->line ? xtryrealloc (ctx->line, newsize)
                           : xtrymalloc (newsize));
          if (!tmp)
            {
              log_error (_("error printing log line: %s\n"), strerror (errno));
              return;
            }
          ctx->line = tmp;
          ctx->linesize = newsize;
        }
      memcpy (ctx->line + ctx->linelen, line, n);
      ctx->linelen += n;
      ctx->line[ctx->linelen] = 0;
    }
}


/* Read data from the log stream.  Returns true if the log stream
   indicated EOF or error.  */
static int
read_log_data (struct wrapper_context_s *ctx)
{
  int n;
  char line[256];

  /* We must use the npth_read function for pipes, always.  */
  do
    n = npth_read (ctx->log_fd, line, sizeof line - 1);
  while (n < 0 && errno == EINTR);

  if (n <= 0) /* EOF or error. */
    {
      if (n < 0)
        log_error (_("error reading log from ldap wrapper %d: %s\n"),
                   (int)ctx->pid, strerror (errno));
      print_log_line (ctx, NULL);
      SAFE_CLOSE (ctx->log_fd);
      return 1;
    }

  line[n] = 0;
  print_log_line (ctx, line);
  if (ctx->stamp != (time_t)(-1))
    ctx->stamp = time (NULL);
  return 0;
}


/* This function is run by a separate thread to maintain the list of
   wrappers and to log error messages from these wrappers.  */
void *
ldap_wrapper_thread (void *dummy)
{
  int nfds;
  struct wrapper_context_s *ctx;
  struct wrapper_context_s *ctx_prev;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
  fd_set fdset;
  int ret;
  time_t exptime;

  (void)dummy;

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL;

  for (;;)
    {
      int any_action = 0;

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  /* Inactivity is checked below.  Nothing else to do.  */
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL;
	}
      npth_timersub (&abstime, &curtime, &timeout);

      FD_ZERO (&fdset);
      nfds = -1;
      for (ctx = wrapper_list; ctx; ctx = ctx->next)
        {
          if (ctx->log_fd != -1)
            {
              FD_SET (ctx->log_fd, &fdset);
              if (ctx->log_fd > nfds)
                nfds = ctx->log_fd;
            }
        }
      nfds++;

      /* FIXME: For Windows, we have to use a reader thread on the
	 pipe that signals an event (and a npth_select_ev variant).  */
      ret = npth_pselect (nfds + 1, &fdset, NULL, NULL, &timeout, NULL);
      if (ret == -1)
	{
          if (errno != EINTR)
            {
              log_error (_("npth_select failed: %s - waiting 1s\n"),
                         strerror (errno));
              npth_sleep (1);
            }
          continue;
	}

      /* All timestamps before exptime should be considered expired.  */
      exptime = time (NULL);
      if (exptime > INACTIVITY_TIMEOUT)
        exptime -= INACTIVITY_TIMEOUT;

      /* Note that there is no need to lock the list because we always
         add entries at the head (with a pending event status) and
         thus traversing the list will even work if we have a context
         switch in waitpid (which should anyway only happen with Pth's
         hard system call mapping).  */
      for (ctx = wrapper_list; ctx; ctx = ctx->next)
        {
          /* Check whether there is any logging to be done. */
          if (nfds && ctx->log_fd != -1 && FD_ISSET (ctx->log_fd, &fdset))
            {
              if (read_log_data (ctx))
                {
                  SAFE_CLOSE (ctx->log_fd);
                  any_action = 1;
                }
            }

          /* Check whether the process is still running.  */
          if (ctx->pid != (pid_t)(-1))
            {
              gpg_error_t err;
	      int status;

	      err = gnupg_wait_process ("[dirmngr_ldap]", ctx->pid, 0,
                                        &status);
              if (!err)
                {
		  log_info (_("ldap wrapper %d ready"), (int)ctx->pid);
                  ctx->ready = 1;
		  gnupg_release_process (ctx->pid);
                  ctx->pid = (pid_t)(-1);
                  any_action = 1;
                }
              else if (gpg_err_code (err) == GPG_ERR_GENERAL)
                {
                  if (status == 10)
                    log_info (_("ldap wrapper %d ready: timeout\n"),
                              (int)ctx->pid);
                  else
                    log_info (_("ldap wrapper %d ready: exitcode=%d\n"),
                              (int)ctx->pid, status);
                  ctx->ready = 1;
		  gnupg_release_process (ctx->pid);
                  ctx->pid = (pid_t)(-1);
                  any_action = 1;
                }
              else if (gpg_err_code (err) != GPG_ERR_TIMEOUT)
                {
                  log_error (_("waiting for ldap wrapper %d failed: %s\n"),
                             (int)ctx->pid, gpg_strerror (err));
                  any_action = 1;
                }
            }

          /* Check whether we should terminate the process. */
          if (ctx->pid != (pid_t)(-1)
              && ctx->stamp != (time_t)(-1) && ctx->stamp < exptime)
            {
              gnupg_kill_process (ctx->pid);
              ctx->stamp = (time_t)(-1);
              log_info (_("ldap wrapper %d stalled - killing\n"),
                        (int)ctx->pid);
              /* We need to close the log fd because the cleanup loop
                 waits for it.  */
              SAFE_CLOSE (ctx->log_fd);
              any_action = 1;
            }
        }

      /* If something has been printed to the log file or we got an
         EOF from a wrapper, we now print the list of active
         wrappers.  */
      if (any_action && DBG_LOOKUP)
        {
          log_info ("ldap worker stati:\n");
          for (ctx = wrapper_list; ctx; ctx = ctx->next)
            log_info ("  c=%p pid=%d/%d rdr=%p ctrl=%p/%d la=%lu rdy=%d\n",
                      ctx,
                      (int)ctx->pid, (int)ctx->printable_pid,
                      ctx->reader,
                      ctx->ctrl, ctx->ctrl? ctx->ctrl->refcount:0,
                      (unsigned long)ctx->stamp, ctx->ready);
        }


      /* Use a separate loop to check whether ready marked wrappers
         may be removed.  We may only do so if the ksba reader object
         is not anymore in use or we are in shutdown state.  */
     again:
      for (ctx_prev=NULL, ctx=wrapper_list; ctx; ctx_prev=ctx, ctx=ctx->next)
        if (ctx->ready
            && ((ctx->log_fd == -1 && !ctx->reader) || shutting_down))
          {
            if (ctx_prev)
              ctx_prev->next = ctx->next;
            else
              wrapper_list = ctx->next;
            destroy_wrapper (ctx);
            /* We need to restart because destroy_wrapper might have
               done a context switch. */
            goto again;
          }
    }
  /*NOTREACHED*/
  return NULL; /* Make the compiler happy.  */
}



/* Start the reaper thread for the ldap wrapper.  */
void
ldap_wrapper_launch_thread (void)
{
  static int done;
  npth_attr_t tattr;
  npth_t thread;
  int err;

  if (done)
    return;
  done = 1;

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

  err = npth_create (&thread, &tattr, ldap_wrapper_thread, NULL);
  if (err)
    {
      log_error (_("error spawning ldap wrapper reaper thread: %s\n"),
                 strerror (err) );
      dirmngr_exit (1);
    }
  npth_setname_np (thread, "ldap-reaper");
  npth_attr_destroy (&tattr);
}





/* Wait until all ldap wrappers have terminated.  We assume that the
   kill has already been sent to all of them.  */
void
ldap_wrapper_wait_connections ()
{
  shutting_down = 1;
  /* FIXME: This is a busy wait.  */
  while (wrapper_list)
    npth_usleep (200);
}


/* This function is to be used to release a context associated with the
   given reader object. */
void
ldap_wrapper_release_context (ksba_reader_t reader)
{
  struct wrapper_context_s *ctx;

  if (!reader )
    return;

  for (ctx=wrapper_list; ctx; ctx=ctx->next)
    if (ctx->reader == reader)
      {
        if (DBG_LOOKUP)
          log_info ("releasing ldap worker c=%p pid=%d/%d rdr=%p ctrl=%p/%d\n",
                    ctx,
                    (int)ctx->pid, (int)ctx->printable_pid,
                    ctx->reader,
                    ctx->ctrl, ctx->ctrl? ctx->ctrl->refcount:0);

        ctx->reader = NULL;
        SAFE_CLOSE (ctx->fd);
        if (ctx->ctrl)
          {
            ctx->ctrl->refcount--;
            ctx->ctrl = NULL;
          }
        if (ctx->fd_error)
          log_info (_("reading from ldap wrapper %d failed: %s\n"),
                    ctx->printable_pid, gpg_strerror (ctx->fd_error));
        break;
      }
}

/* Cleanup all resources held by the connection associated with
   CTRL.  This is used after a cancel to kill running wrappers.  */
void
ldap_wrapper_connection_cleanup (ctrl_t ctrl)
{
  struct wrapper_context_s *ctx;

  for (ctx=wrapper_list; ctx; ctx=ctx->next)
    if (ctx->ctrl && ctx->ctrl == ctrl)
      {
        ctx->ctrl->refcount--;
        ctx->ctrl = NULL;
        if (ctx->pid != (pid_t)(-1))
          gnupg_kill_process (ctx->pid);
        if (ctx->fd_error)
          log_info (_("reading from ldap wrapper %d failed: %s\n"),
                    ctx->printable_pid, gpg_strerror (ctx->fd_error));
      }
}


/* This is the callback used by the ldap wrapper to feed the ksba
   reader with the wrappers stdout.  See the description of
   ksba_reader_set_cb for details.  */
static int
reader_callback (void *cb_value, char *buffer, size_t count,  size_t *nread)
{
  struct wrapper_context_s *ctx = cb_value;
  size_t nleft = count;
  int nfds;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
  int saved_errno;
  fd_set fdset, read_fdset;
  int ret;

  /* FIXME: We might want to add some internal buffering because the
     ksba code does not do any buffering for itself (because a ksba
     reader may be detached from another stream to read other data and
     the it would be cumbersome to get back already buffered
     stuff).  */

  if (!buffer && !count && !nread)
    return -1; /* Rewind is not supported. */

  /* If we ever encountered a read error, don't continue (we don't want to
     possibly overwrite the last error cause).  Bail out also if the
     file descriptor has been closed. */
  if (ctx->fd_error || ctx->fd == -1)
    {
      *nread = 0;
      return -1;
    }

  FD_ZERO (&fdset);
  FD_SET (ctx->fd, &fdset);
  nfds = ctx->fd + 1;

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL;

  while (nleft > 0)
    {
      int n;
      gpg_error_t err;

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  err = dirmngr_tick (ctx->ctrl);
          if (err)
            {
              ctx->fd_error = err;
              SAFE_CLOSE (ctx->fd);
              return -1;
            }
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL;
	}
      npth_timersub (&abstime, &curtime, &timeout);

      read_fdset = fdset;
      ret = npth_pselect (nfds, &read_fdset, NULL, NULL, &timeout, NULL);
      saved_errno = errno;

      if (ret == -1 && saved_errno != EINTR)
	{
          ctx->fd_error = gpg_error_from_errno (errno);
          SAFE_CLOSE (ctx->fd);
          return -1;
        }
      if (ret <= 0)
	/* Timeout.  Will be handled when calculating the next timeout.  */
	continue;

      /* This should not block now that select returned with a file
	 descriptor.  So it shouldn't be necessary to use npth_read
	 (and it is slightly dangerous in the sense that a concurrent
	 thread might (accidentially?) change the status of ctx->fd
	 before we read.  FIXME: Set ctx->fd to nonblocking?  */
      n = read (ctx->fd, buffer, nleft);
      if (n < 0)
        {
          ctx->fd_error = gpg_error_from_errno (errno);
          SAFE_CLOSE (ctx->fd);
          return -1;
        }
      else if (!n)
        {
          if (nleft == count)
	    return -1; /* EOF. */
          break;
        }
      nleft -= n;
      buffer += n;
      if (n > 0 && ctx->stamp != (time_t)(-1))
        ctx->stamp = time (NULL);
    }
  *nread = count - nleft;

  return 0;
}

/* Fork and exec the LDAP wrapper and return a new libksba reader
   object at READER.  ARGV is a NULL terminated list of arguments for
   the wrapper.  The function returns 0 on success or an error code.

   Special hack to avoid passing a password through the command line
   which is globally visible: If the first element of ARGV is "--pass"
   it will be removed and instead the environment variable
   DIRMNGR_LDAP_PASS will be set to the next value of ARGV.  On modern
   OSes the environment is not visible to other users.  For those old
   systems where it can't be avoided, we don't want to go into the
   hassle of passing the password via stdin; it's just too complicated
   and an LDAP password used for public directory lookups should not
   be that confidential.  */
gpg_error_t
ldap_wrapper (ctrl_t ctrl, ksba_reader_t *reader, const char *argv[])
{
  gpg_error_t err;
  pid_t pid;
  struct wrapper_context_s *ctx;
  int i;
  int j;
  const char **arg_list;
  const char *pgmname;
  int outpipe[2], errpipe[2];

  /* It would be too simple to connect stderr just to our logging
     stream.  The problem is that if we are running multi-threaded
     everything gets intermixed.  Clearly we don't want this.  So the
     only viable solutions are either to have another thread
     responsible for logging the messages or to add an option to the
     wrapper module to do the logging on its own.  Given that we anyway
     need a way to reap the child process and this is best done using a
     general reaping thread, that thread can do the logging too. */
  ldap_wrapper_launch_thread ();

  *reader = NULL;

  /* Files: We need to prepare stdin and stdout.  We get stderr from
     the function.  */
  if (!opt.ldap_wrapper_program || !*opt.ldap_wrapper_program)
    pgmname = gnupg_module_name (GNUPG_MODULE_NAME_DIRMNGR_LDAP);
  else
    pgmname = opt.ldap_wrapper_program;

  /* Create command line argument array.  */
  for (i = 0; argv[i]; i++)
    ;
  arg_list = xtrycalloc (i + 2, sizeof *arg_list);
  if (!arg_list)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error allocating memory: %s\n"), strerror (errno));
      return err;
    }
  for (i = j = 0; argv[i]; i++, j++)
    if (!i && argv[i + 1] && !strcmp (*argv, "--pass"))
      {
	arg_list[j] = "--env-pass";
	setenv ("DIRMNGR_LDAP_PASS", argv[1], 1);
	i++;
      }
    else
      arg_list[j] = (char*) argv[i];

  ctx = xtrycalloc (1, sizeof *ctx);
  if (!ctx)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error allocating memory: %s\n"), strerror (errno));
      xfree (arg_list);
      return err;
    }

  err = gnupg_create_inbound_pipe (outpipe, NULL, 0);
  if (!err)
    {
      err = gnupg_create_inbound_pipe (errpipe, NULL, 0);
      if (err)
        {
          close (outpipe[0]);
          close (outpipe[1]);
        }
    }
  if (err)
    {
      log_error (_("error creating a pipe: %s\n"), gpg_strerror (err));
      xfree (arg_list);
      xfree (ctx);
      return err;
    }

  err = gnupg_spawn_process_fd (pgmname, arg_list,
                                -1, outpipe[1], errpipe[1], &pid);
  xfree (arg_list);
  close (outpipe[1]);
  close (errpipe[1]);
  if (err)
    {
      close (outpipe[0]);
      close (errpipe[0]);
      xfree (ctx);
      return err;
    }

  ctx->pid = pid;
  ctx->printable_pid = (int) pid;
  ctx->fd = outpipe[0];
  ctx->log_fd = errpipe[0];
  ctx->ctrl = ctrl;
  ctrl->refcount++;
  ctx->stamp = time (NULL);

  err = ksba_reader_new (reader);
  if (!err)
    err = ksba_reader_set_cb (*reader, reader_callback, ctx);
  if (err)
    {
      log_error (_("error initializing reader object: %s\n"),
                 gpg_strerror (err));
      destroy_wrapper (ctx);
      ksba_reader_release (*reader);
      *reader = NULL;
      return err;
    }

  /* Hook the context into our list of running wrappers.  */
  ctx->reader = *reader;
  ctx->next = wrapper_list;
  wrapper_list = ctx;
  if (opt.verbose)
    log_info ("ldap wrapper %d started (reader %p)\n",
              (int)ctx->pid, ctx->reader);

  /* Need to wait for the first byte so we are able to detect an empty
     output and not let the consumer see an EOF without further error
     indications.  The CRL loading logic assumes that after return
     from this function, a failed search (e.g. host not found ) is
     indicated right away. */
  {
    unsigned char c;

    err = read_buffer (*reader, &c, 1);
    if (err)
      {
        ldap_wrapper_release_context (*reader);
        ksba_reader_release (*reader);
        *reader = NULL;
        if (gpg_err_code (err) == GPG_ERR_EOF)
          return gpg_error (GPG_ERR_NO_DATA);
        else
          return err;
      }
    ksba_reader_unread (*reader, &c, 1);
  }

  return 0;
}
