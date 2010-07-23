/* ldap-wrapper-ce.c - LDAP access via W32 threads
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* 
   Alternative wrapper for use with WindowsCE.  Under WindowsCE the
   number of processes is strongly limited (32 processes including the
   kernel processes) and thus we don't use the process approach but
   implement a wrapper based on native threads.

   See ldap-wrapper.c for  the standard wrapper interface.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pth.h>

#include "dirmngr.h"
#include "misc.h"
#include "ldap-wrapper.h"



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
  pth_event_t log_ev;
  ctrl_t ctrl;  /* Connection data. */
  int ready;    /* Internally used to mark to be removed contexts. */
  ksba_reader_t reader; /* The ksba reader object or NULL. */
  char *line;     /* Used to print the log lines (malloced). */
  size_t linesize;/* Allocated size of LINE.  */
  size_t linelen; /* Use size of LINE.  */
  time_t stamp;   /* The last time we noticed ativity.  */
};



/* We keep a global list of spawed wrapper process.  A separate thread
   makes use of this list to log error messages and to watch out for
   finished processes. */
static struct wrapper_context_s *wrapper_list;

/* We need to know whether we are shutting down the process.  */
static int shutting_down;



/* Start the reaper thread for this wrapper.  */
void
ldap_wrapper_launch_thread (void)
{
  static int done;
  pth_attr_t tattr;

  if (done)
    return;
  done = 1;

  tattr = pth_attr_new();
  pth_attr_set (tattr, PTH_ATTR_JOINABLE, 0);
  pth_attr_set (tattr, PTH_ATTR_STACK_SIZE, 256*1024);
  pth_attr_set (tattr, PTH_ATTR_NAME, "ldap-reaper");

  if (!pth_spawn (tattr, ldap_wrapper_thread, NULL))
    {
      log_error (_("error spawning ldap wrapper reaper thread: %s\n"),
                 strerror (errno) );
      dirmngr_exit (1);
    }
  pth_attr_destroy (tattr);
}





/* Wait until all ldap wrappers have terminated.  We assume that the
   kill has already been sent to all of them.  */
void
ldap_wrapper_wait_connections ()
{
  shutting_down = 1;
  while (wrapper_list)
    pth_yield (NULL);
}


/* This function is to be used to release a context associated with the
   given reader object. */
void
ldap_wrapper_release_context (ksba_reader_t reader)
{
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
        SAFE_PTH_CLOSE (ctx->fd);
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

/* Fork and exec the LDAP wrapper and returns a new libksba reader
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
     need a way to rip the child process and this is best done using a
     general ripping thread, that thread can do the logging too. */

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

  err = gnupg_create_inbound_pipe (outpipe);
  if (!err)
    {
      err = gnupg_create_inbound_pipe (errpipe);
      if (err)
        {
          close (outpipe[0]);
          close (outpipe[1]);
        }
    }
  if (err)
    {
      log_error (_("error creating pipe: %s\n"), gpg_strerror (err));
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
  ctx->log_ev = pth_event (PTH_EVENT_FD | PTH_UNTIL_FD_READABLE, ctx->log_fd);
  if (! ctx->log_ev)
    {
      xfree (ctx);
      return gpg_error_from_syserror ();
    }
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
