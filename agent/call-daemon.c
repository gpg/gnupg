/* call-daemon - Common code for the call-XXX.c modules
 * Copyright (C) 2001, 2002, 2005, 2007, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 2013 Werner Koch
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif
#include <npth.h>

#include "agent.h"
#include <assuan.h>
#include "../common/strlist.h"

/* Daemon type to module mapping.  Make sure that they are added in the
 * same order as given by the daemon_type enum.  */
static const int daemon_modules[DAEMON_MAX_TYPE] =
  {
    GNUPG_MODULE_NAME_SCDAEMON,
    GNUPG_MODULE_NAME_TPM2DAEMON
  };

/* Definition of module local data of the CTRL structure.  */
struct daemon_local_s
{
  /* We keep a list of all allocated context with an anchor at
     DAEMON_LOCAL_LIST (see below). */
  struct daemon_local_s *next_local;

  /* Link back to the global structure.  */
  struct daemon_global_s *g;

  assuan_context_t ctx;   /* NULL or session context for the daemon
                             used with this connection. */
  unsigned int in_use: 1; /* CTX is in use.  */
  unsigned int invalid:1; /* CTX is invalid, should be released.  */
};


/* Primary holder of all the started daemons */
struct daemon_global_s
{
  /* To keep track of all active daemon contexts, we keep a linked list
     anchored at this variable. */
  struct daemon_local_s *local_list;
  /* A malloced string with the name of the socket to be used for
     additional connections.  May be NULL if not provided by
     daemon. */
  char *socket_name;

  /* The context of the primary connection.  This is also used as a flag
     to indicate whether the daemon has been started. */
  assuan_context_t primary_ctx;

  /* To allow reuse of the primary connection, the following flag is set
     to true if the primary context has been reset and is not in use by
     any connection. */
  int primary_ctx_reusable;
};

static struct daemon_global_s daemon_global[DAEMON_MAX_TYPE];


/* A Mutex used inside the start_daemon function. */
static npth_mutex_t start_daemon_lock;


/* Communication object for wait_child_thread.  */
struct wait_child_thread_parm_s
{
  enum daemon_type type;
  pid_t pid;
};


/* Thread to wait for daemon termination and cleanup of resources.  */
static void *
wait_child_thread (void *arg)
{
  int err;
  struct wait_child_thread_parm_s *parm = arg;
  enum daemon_type type = parm->type;
  pid_t pid =  parm->pid;
#ifndef HAVE_W32_SYSTEM
  int wstatus;
#endif
  const char *name = opt.daemon_program[type];
  struct daemon_global_s *g = &daemon_global[type];
  struct daemon_local_s *sl;

  xfree (parm);  /* We have copied all data to the stack.  */

#ifdef HAVE_W32_SYSTEM
  npth_unprotect ();
  /* Note that although we use a pid_t here, it is actually a HANDLE.  */
  WaitForSingleObject ((HANDLE)pid, INFINITE);
  npth_protect ();
  log_info ("daemon %s finished\n", name);
#else /* !HAVE_W32_SYSTEM*/

 again:
  npth_unprotect ();
  err = waitpid (pid, &wstatus, 0);
  npth_protect ();

  if (err < 0)
    {
      if (errno == EINTR)
        goto again;
      log_error ("waitpid for %s failed: %s\n", name, strerror (errno));
      return NULL;
    }
  else
    {
      if (WIFEXITED (wstatus))
        log_info ("daemon %s finished (status %d)\n",
                  name, WEXITSTATUS (wstatus));
      else if (WIFSIGNALED (wstatus))
        log_info ("daemon %s killed by signal %d\n", name, WTERMSIG (wstatus));
      else
        {
          if (WIFSTOPPED (wstatus))
            log_info ("daemon %s stopped by signal %d\n",
                      name, WSTOPSIG (wstatus));
          goto again;
        }

      assuan_set_flag (g->primary_ctx, ASSUAN_NO_WAITPID, 1);
    }
#endif /*!HAVE_W32_SYSTEM*/

  agent_flush_cache (1);  /* Flush the PIN cache.  */

  err = npth_mutex_lock (&start_daemon_lock);
  if (err)
    {
      log_error ("failed to acquire the start_daemon lock: %s\n",
                 strerror (err));
    }
  else
    {
      for (sl = g->local_list; sl; sl = sl->next_local)
        {
          sl->invalid = 1;
          if (!sl->in_use && sl->ctx)
            {
              assuan_release (sl->ctx);
              sl->ctx = NULL;
            }
        }

      g->primary_ctx = NULL;
      g->primary_ctx_reusable = 0;

      xfree (g->socket_name);
      g->socket_name = NULL;

      err = npth_mutex_unlock (&start_daemon_lock);
      if (err)
        log_error ("failed to release the start_daemon lock"
                   " after waitpid for %s: %s\n", name, strerror (err));
    }

  return NULL;
}


/* This function shall be called after having accessed the daemon.  It
 * is currently not very useful but gives an opportunity to keep track
 * of connections currently calling daemon.  Note that the "lock"
 * operation is done by the daemon_start function which must be called
 * and error checked before any daemon operation.  CTRL is the usual
 * connection context and RC the error code to be passed through the
 * function. */
gpg_error_t
daemon_unlock (enum daemon_type type, ctrl_t ctrl, gpg_error_t rc)
{
  gpg_error_t err;

  if (ctrl->d_local[type]->in_use == 0)
    {
      log_error ("%s: CTX for type %d is not in use\n", __func__, (int)type);
      if (!rc)
        rc = gpg_error (GPG_ERR_INTERNAL);
    }
  err = npth_mutex_lock (&start_daemon_lock);
  if (err)
    {
      log_error ("failed to acquire the start_daemon lock: %s\n",
                 strerror (err));
      return gpg_error (GPG_ERR_INTERNAL);
    }
  ctrl->d_local[type]->in_use = 0;
  if (ctrl->d_local[type]->invalid)
    {
      assuan_release (ctrl->d_local[type]->ctx);
      ctrl->d_local[type]->ctx = NULL;
      ctrl->d_local[type]->invalid = 0;
    }
  err = npth_mutex_unlock (&start_daemon_lock);
  if (err)
    {
      log_error ("failed to release the start_daemon lock: %s\n",
                 strerror (err));
      return gpg_error (GPG_ERR_INTERNAL);
    }
  return rc;
}


/* To make sure we leave no secrets in our image after forking of the
   daemon, we use this callback. */
static void
atfork_cb (void *opaque, int where)
{
  (void)opaque;

  if (!where)
    gcry_control (GCRYCTL_TERM_SECMEM);
}


/* Fork off the daemon if this has not already been done.  Lock the
 * daemon and make sure that a proper context has been setup in CTRL.
 * This function might also lock the daemon, which means that the
 * caller must call unlock_daemon after this function has returned
 * success and the actual Assuan transaction been done. */
gpg_error_t
daemon_start (enum daemon_type type, ctrl_t ctrl)
{
  gpg_error_t err = 0;
  const char *pgmname;
  assuan_context_t ctx = NULL;
  const char *argv[5];
  assuan_fd_t no_close_list[3];
  int i;
  int rc;
  char *abs_homedir = NULL;
  struct daemon_global_s *g = &daemon_global[type];
  const char *name = gnupg_module_name (daemon_modules[type]);

  log_assert (type < DAEMON_MAX_TYPE);
  /* if this fails, you forgot to add your new type to daemon_modules */
  log_assert (DAEMON_MAX_TYPE == DIM (daemon_modules));

  if (opt.disable_daemon[type])
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  if (ctrl->d_local[type] && ctrl->d_local[type]->ctx)
    {
      ctrl->d_local[type]->in_use = 1;
      return 0; /* Okay, the context is fine.  */
    }

  if (ctrl->d_local[type] && ctrl->d_local[type]->in_use)
    {
      log_error ("%s: CTX of type %d is in use\n", __func__, type);
      return gpg_error (GPG_ERR_INTERNAL);
    }

  /* We need to serialize the access to scd_local_list and primary_scd_ctx. */
  rc = npth_mutex_lock (&start_daemon_lock);
  if (rc)
    {
      log_error ("failed to acquire the start_daemon lock: %s\n",
                 strerror (rc));
      return gpg_error (GPG_ERR_INTERNAL);
    }

  /* If this is the first call for this session, setup the local data
     structure. */
  if (!ctrl->d_local[type])
    {
      ctrl->d_local[type] = xtrycalloc (1, sizeof *ctrl->d_local[type]);
      if (!ctrl->d_local[type])
        {
          err = gpg_error_from_syserror ();
          rc = npth_mutex_unlock (&start_daemon_lock);
          if (rc)
            log_error ("failed to release the start_daemon lock: %s\n",
                       strerror (rc));
          return err;
        }
      ctrl->d_local[type]->g = g;
      ctrl->d_local[type]->next_local = g->local_list;
      g->local_list = ctrl->d_local[type];  /* FIXME: CHECK the G thing */
    }

  ctrl->d_local[type]->in_use = 1;

  /* Check whether the pipe server has already been started and in
     this case either reuse a lingering pipe connection or establish a
     new socket based one. */
  if (g->primary_ctx && g->primary_ctx_reusable)
    {
      ctx = g->primary_ctx;
      g->primary_ctx_reusable = 0;
      if (opt.verbose)
        log_info ("new connection to %s daemon established (reusing)\n",
		  name);
      goto leave;
    }

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error ("can't allocate assuan context: %s\n", gpg_strerror (rc));
      err = rc;
      goto leave;
    }

  if (g->socket_name)
    {
      rc = assuan_socket_connect (ctx, g->socket_name, 0, 0);
      if (rc)
        {
          log_error ("can't connect to socket '%s': %s\n",
                     g->socket_name, gpg_strerror (rc));
          err = gpg_error (GPG_ERR_NO_SCDAEMON);
          goto leave;
        }

      if (opt.verbose)
        log_info ("new connection to %s daemon established\n",
		  name);
      goto leave;
    }

  if (g->primary_ctx)
    {
      log_info ("%s daemon is running but won't accept further connections\n",
		name);
      err = gpg_error (GPG_ERR_NO_SCDAEMON);
      goto leave;
    }

  /* Nope, it has not been started.  Fire it up now. */
  if (opt.verbose)
    log_info ("no running %s daemon - starting it\n", name);

  agent_flush_cache (1);  /* Make sure the PIN cache is flushed.  */

  if (fflush (NULL))
    {
#ifndef HAVE_W32_SYSTEM
      err = gpg_error_from_syserror ();
#endif
      log_error ("error flushing pending output: %s\n", strerror (errno));
      /* At least Windows XP fails here with EBADF.  According to docs
         and Wine an fflush(NULL) is the same as _flushall.  However
         the Wime implementation does not flush stdin,stdout and stderr
         - see above.  Lets try to ignore the error. */
#ifndef HAVE_W32_SYSTEM
      goto leave;
#endif
    }

  /* If the daemon program has not been specified switch to the standard.  */
  if (!opt.daemon_program[type] || !*opt.daemon_program[type])
    opt.daemon_program[type] = gnupg_module_name (daemon_modules[type]);

  if ( !(pgmname = strrchr (opt.daemon_program[type], '/')))
    pgmname = opt.daemon_program[type];
  else
    pgmname++;

  argv[0] = pgmname;
  argv[1] = "--multi-server";
  if (gnupg_default_homedir_p ())
    argv[2] = NULL;
  else
    {
      abs_homedir = make_absfilename_try (gnupg_homedir (), NULL);
      if (!abs_homedir)
        {
          log_error ("error building filename: %s\n",
                     gpg_strerror (gpg_error_from_syserror ()));
          goto leave;
        }

      argv[2] = "--homedir";
      argv[3] = abs_homedir;
      argv[4] = NULL;
    }

  i=0;
  if (!opt.running_detached)
    no_close_list[i++] = assuan_fd_from_posix_fd (fileno (stderr));
  no_close_list[i] = ASSUAN_INVALID_FD;

  /* Connect to the daemon and perform initial handshaking.  Use
     detached flag so that under Windows DAEMON does not show up a
     new window.  */
  rc = assuan_pipe_connect (ctx, opt.daemon_program[type], argv,
			    no_close_list, atfork_cb, NULL,
                            ASSUAN_PIPE_CONNECT_DETACHED);
  if (rc)
    {
      log_error ("can't connect to the daemon %s: %s\n",
                 name, gpg_strerror (rc));
      err = gpg_error (GPG_ERR_NO_SCDAEMON);
      goto leave;
    }

  if (opt.verbose)
    log_info ("first connection to daemon %s established\n", name);


  /* Get the name of the additional socket opened by daemon. */
  {
    membuf_t data;
    unsigned char *databuf;
    size_t datalen;

    xfree (g->socket_name);
    g->socket_name = NULL;
    init_membuf (&data, 256);
    assuan_transact (ctx, "GETINFO socket_name",
                     put_membuf_cb, &data, NULL, NULL, NULL, NULL);

    databuf = get_membuf (&data, &datalen);
    if (databuf && datalen)
      {
        g->socket_name = xtrymalloc (datalen + 1);
        if (!g->socket_name)
          log_error ("warning: can't store socket name: %s\n",
                     strerror (errno));
        else
          {
            memcpy (g->socket_name, databuf, datalen);
            g->socket_name[datalen] = 0;
            if (DBG_IPC)
              log_debug ("additional connections at '%s'\n", g->socket_name);
          }
      }
    xfree (databuf);
  }

  /* Tell the daemon we want him to send us an event signal.  */
  if (opt.sigusr2_enabled)
    {
      char buf[100];

#ifdef HAVE_W32_SYSTEM
      snprintf (buf, sizeof buf, "OPTION event-signal=%lx",
                (unsigned long)get_agent_daemon_notify_event ());
#else
      snprintf (buf, sizeof buf, "OPTION event-signal=%d", SIGUSR2);
#endif
      assuan_transact (ctx, buf, NULL, NULL, NULL, NULL, NULL, NULL);
    }

  g->primary_ctx = ctx;
  g->primary_ctx_reusable = 0;

  {
    npth_t thread;
    npth_attr_t tattr;
    struct wait_child_thread_parm_s *wctp;

    wctp = xtrymalloc (sizeof *wctp);
    if (!wctp)
      {
        err = gpg_error_from_syserror ();
        log_error ("error preparing wait_child_thread: %s\n", strerror (err));
        goto leave;
      }

    wctp->type = type;
    wctp->pid = assuan_get_pid (g->primary_ctx);
    err = npth_attr_init (&tattr);
    if (!err)
      {
        npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);
        err = npth_create (&thread, &tattr, wait_child_thread, wctp);
        if (err)
          log_error ("error spawning wait_child_thread: %s\n", strerror (err));
        npth_attr_destroy (&tattr);
      }
    else
      xfree (wctp);
  }

 leave:
  rc = npth_mutex_unlock (&start_daemon_lock);
  if (rc)
    log_error ("failed to release the start_daemon lock: %s\n", strerror (rc));

  xfree (abs_homedir);
  if (err)
    {
      daemon_unlock (type, ctrl, err);
      if (ctx)
	assuan_release (ctx);
    }
  else
    {
      ctrl->d_local[type]->ctx = ctx;
      ctrl->d_local[type]->invalid = 0;
    }
  return err;
}


/* This function must be called once to initialize this module.  This
   has to be done before a second thread is spawned.  We can't do the
   static initialization because NPth emulation code might not be able
   to do a static init; in particular, it is not possible for W32. */
void
initialize_module_daemon (void)
{
  static int initialized;
  int err;

  if (!initialized)
    {
      err = npth_mutex_init (&start_daemon_lock, NULL);
      if (err)
	log_fatal ("error initializing mutex: %s\n", strerror (err));
      initialized = 1;
    }
}


/* This function may be called to print information pertaining to the
   current state of this module to the log. */
void
agent_daemon_dump_state (void)
{
  int i;

  for (i = 0; i < DAEMON_MAX_TYPE; i++) {
    struct daemon_global_s *g = &daemon_global[i];

    log_info ("%s: name %s primary_ctx=%p pid=%ld reusable=%d\n", __func__,
	      gnupg_module_name (daemon_modules[i]),
	      g->primary_ctx,
	      (long)assuan_get_pid (g->primary_ctx),
	      g->primary_ctx_reusable);
    if (g->socket_name)
      log_info ("%s: socket='%s'\n", __func__, g->socket_name);
  }
}


/* Check whether the daemon is active.  This is a fast check without
 * any locking and might give a wrong result if another thread is
 * about to start the daemon or the daemon is about to be stopped. */
int
agent_daemon_check_running (enum daemon_type type)
{
  return !!daemon_global[type].primary_ctx;
}


/* Send a kill command to the daemon of TYPE */
void
agent_kill_daemon (enum daemon_type type)
{
  struct daemon_global_s *g = &daemon_global[type];

  if (g->primary_ctx == NULL)
    return;
  /* FIXME: This assumes SCdaemon; we should add a new command
   * (e.g. SHUTDOWN) so that there is no need to have a daemon
   * specific command.  */
  assuan_transact (g->primary_ctx, "KILLSCD",
                   NULL, NULL, NULL, NULL, NULL, NULL);
  agent_flush_cache (1);  /* 1 := Flush the PIN cache.  */
}


/* Reset the daemons if they have been used.  Actually it is not a
   reset but a cleanup of resources used by the current connection. */
void
agent_reset_daemon (ctrl_t ctrl)
{
  int i;
  int rc;

  rc = npth_mutex_lock (&start_daemon_lock);
  if (rc)
    {
      log_error ("failed to acquire the start_daemon lock: %s\n",
                 strerror (rc));
      return;
    }


  for (i = 0; i < DAEMON_MAX_TYPE; i++)
    if (ctrl->d_local[i])
      {
        struct daemon_global_s *g = ctrl->d_local[i]->g;

	if (ctrl->d_local[i]->ctx)
	  {
            /* For the primary connection we send a reset and keep
             * that connection open for reuse. */
            if (ctrl->d_local[i]->ctx == g->primary_ctx)
	      {
		/* Send a RESTART to the daemon.  This is required for the
		   primary connection as a kind of virtual EOF; we don't
		   have another way to tell it that the next command
		   should be viewed as if a new connection has been
		   made.  For the non-primary connections this is not
		   needed as we simply close the socket.  We don't check
		   for an error here because the RESTART may fail for
		   example if the daemon has already been terminated.
		   Anyway, we need to set the reusable flag to make sure
		   that the aliveness check can clean it up. */
		assuan_transact (g->primary_ctx, "RESTART",
				 NULL, NULL, NULL, NULL, NULL, NULL);
		g->primary_ctx_reusable = 1;
	      }
	    else /* Secondary connections.  */
	      assuan_release (ctrl->d_local[i]->ctx);
	    ctrl->d_local[i]->ctx = NULL;
	  }

	/* Remove the local context from our list and release it. */
	if (!g->local_list)
	  BUG ();
	else if (g->local_list == ctrl->d_local[i])
	  g->local_list = ctrl->d_local[i]->next_local;
	else
	  {
	    struct daemon_local_s *sl;

	    for (sl=g->local_list; sl->next_local; sl = sl->next_local)
	      if (sl->next_local == ctrl->d_local[i])
		break;
	    if (!sl->next_local)
	      BUG ();
	    sl->next_local = ctrl->d_local[i]->next_local;
	  }
	xfree (ctrl->d_local[i]);
	ctrl->d_local[i] = NULL;
      }


  rc = npth_mutex_unlock (&start_daemon_lock);
  if (rc)
    log_error ("failed to release the start_daemon lock: %s\n", strerror (rc));
}


assuan_context_t
daemon_type_ctx (enum daemon_type type, ctrl_t ctrl)
{
  return ctrl->d_local[type]->ctx;
}
