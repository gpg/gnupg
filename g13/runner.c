/* runner.c - Run and watch the backend engines
 * Copyright (C) 2009 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <npth.h>

#include "g13.h"
#include "../common/i18n.h"
#include "keyblob.h"
#include "runner.h"
#include "../common/exechelp.h"
#include "mountinfo.h"

/* The runner object.  */
struct runner_s
{
  char *name;              /* The name of this runner.  */
  unsigned int identifier; /* The runner identifier.  */

  int spawned;  /* True if runner_spawn has been called.  */
  npth_t thread; /* The TID of the runner thread.  */
  runner_t next_running; /* Builds a list of all running threads.  */
  int canceled;     /* Set if a cancel has already been send once.  */

  int cancel_flag;  /* If set the thread should terminate itself.  */


  /* We use a reference counter to know when it is safe to remove the
     object.  Lacking an explicit ref function this counter will take
     only these two values:

     1 = Thread not running or only the thread is still running.
     2 = Thread is running and someone is holding a reference.  */
  int refcount;

  pid_t pid;  /* PID of the backend's process (the engine).  */
  int in_fd;  /* File descriptors to read from the engine.  */
  int out_fd; /* File descriptors to write to the engine.  */
  engine_handler_fnc_t handler;  /* The handler functions.  */
  engine_handler_cleanup_fnc_t handler_cleanup;
  void *handler_data;  /* Private data of HANDLER and HANDLER_CLEANUP.  */

  /* Instead of IN_FD we use an estream.  Note that the runner thread
     may close the stream and set status_fp to NULL at any time.  Thus
     it won't be a good idea to use it while the runner thread is
     running.  */
  estream_t status_fp;
};


/* The head of the list of all running threads.  */
static runner_t running_threads;




/* Write NBYTES of BUF to file descriptor FD. */
static int
writen (int fd, const void *buf, size_t nbytes)
{
  size_t nleft = nbytes;
  int nwritten;

  while (nleft > 0)
    {
      nwritten = npth_write (fd, buf, nleft);
      if (nwritten < 0)
        {
          if (errno == EINTR)
            nwritten = 0;
          else
            return -1;
        }
      nleft -= nwritten;
      buf = (const char*)buf + nwritten;
    }

  return 0;
}


static int
check_already_spawned (runner_t runner, const char *funcname)
{
  if (runner->spawned)
    {
      log_error ("BUG: runner already spawned - ignoring call to %s\n",
                 funcname);
      return 1;
    }
  else
    return 0;
}


/* Return the number of active threads.  */
unsigned int
runner_get_threads (void)
{
  unsigned int n = 0;
  runner_t r;

  for (r = running_threads; r; r = r->next_running)
    n++;
  return n;
}


/* The public release function. */
void
runner_release (runner_t runner)
{
  gpg_error_t err;

  if (!runner)
    return;

  if (!--runner->refcount)
    return;

  err = mountinfo_del_mount (NULL, NULL, runner->identifier);
  if (err)
    log_error ("failed to remove mount with rid %u from mtab: %s\n",
               runner->identifier, gpg_strerror (err));

  es_fclose (runner->status_fp);
  if (runner->in_fd != -1)
    close (runner->in_fd);
  if (runner->out_fd != -1)
    close (runner->out_fd);

  /* Fixme: close the process. */

  /* Tell the engine to release its data.  */
  if (runner->handler_cleanup)
    runner->handler_cleanup (runner->handler_data);

  if (runner->pid != (pid_t)(-1))
    {
      /* The process has not been cleaned up - do it now.  */
      gnupg_kill_process (runner->pid);
      /* (Actually we should use the program name and not the
          arbitrary NAME of the runner object.  However it does not
          matter because that information is only used for
          diagnostics.)  */
      gnupg_wait_process (runner->name, runner->pid, 1, NULL);
      gnupg_release_process (runner->pid);
    }

  xfree (runner->name);
  xfree (runner);
}


/* Create a new runner context.  On success a new runner object is
   stored at R_RUNNER.  On failure NULL is stored at this address and
   an error code returned.  */
gpg_error_t
runner_new (runner_t *r_runner, const char *name)
{
  static unsigned int namecounter; /* Global name counter.  */
  char *namebuffer;
  runner_t runner, r;

  *r_runner = NULL;

  runner = xtrycalloc (1, sizeof *runner);
  if (!runner)
    return gpg_error_from_syserror ();

  /* Bump up the namecounter.  In case we ever had an overflow we
     check that this number is currently not in use.  The algorithm is
     a bit lame but should be sufficient because such an wrap is not
     very likely: Assuming that we do a mount 10 times a second, then
     we would overwrap on a 32 bit system after 13 years.  */
  do
    {
      namecounter++;
      for (r = running_threads; r; r = r->next_running)
        if (r->identifier == namecounter)
          break;
    }
  while (r);

  runner->identifier = namecounter;
  runner->name = namebuffer = xtryasprintf ("%s-%d", name, namecounter);
  if (!runner->name)
    {
      xfree (runner);
      return gpg_error_from_syserror ();
    }
  runner->refcount = 1;
  runner->pid = (pid_t)(-1);
  runner->in_fd = -1;
  runner->out_fd = -1;

  *r_runner = runner;
  return 0;
}


/* Return the identifier of RUNNER.  */
unsigned int
runner_get_rid (runner_t runner)
{
  return runner->identifier;
}


/* Find a runner by its rid.  Returns the runner object.  The caller
   must release the runner object.  */
runner_t
runner_find_by_rid (unsigned int rid)
{
  runner_t r;

  for (r = running_threads; r; r = r->next_running)
    if (r->identifier == rid)
      {
        r->refcount++;
        return r;
      }
  return NULL;
}


/* A runner usually maintains two file descriptors to control the
   backend engine.  This function is used to set these file
   descriptors.  The function takes ownership of these file
   descriptors.  IN_FD will be used to read from engine and OUT_FD to
   send data to the engine. */
void
runner_set_fds (runner_t runner, int in_fd, int out_fd)
{
  if (check_already_spawned (runner, "runner_set_fds"))
    return;

  if (runner->in_fd != -1)
    close (runner->in_fd);
  if (runner->out_fd != -1)
    close (runner->out_fd);
  runner->in_fd = in_fd;
  runner->out_fd = out_fd;
}


/* Set the PID of the backend engine.  After this call the engine is
   owned by the runner object.  */
void
runner_set_pid (runner_t runner, pid_t pid)
{
  if (check_already_spawned (runner, "runner_set_fds"))
    return;

  runner->pid = pid;
}


/* Register the engine handler fucntions HANDLER and HANDLER_CLEANUP
   and its private HANDLER_DATA with RUNNER.  */
void
runner_set_handler (runner_t runner,
                    engine_handler_fnc_t handler,
                    engine_handler_cleanup_fnc_t handler_cleanup,
                    void *handler_data)
{
  if (check_already_spawned (runner, "runner_set_handler"))
    return;

  runner->handler = handler;
  runner->handler_cleanup = handler_cleanup;
  runner->handler_data = handler_data;
}


/* The thread spawned by runner_spawn.  */
static void *
runner_thread (void *arg)
{
  runner_t runner = arg;
  gpg_error_t err = 0;

  log_debug ("starting runner thread\n");
  /* If a status_fp is available, the thread's main task is to read
     from that stream and invoke the backend's handler function.  This
     is done on a line by line base and the line length is limited to
     a reasonable value (about 1000 characters). Other work will
     continue either due to an EOF of the stream or by demand of the
     engine.  */
  if (runner->status_fp)
    {
      int c, cont_line;
      unsigned int pos;
      char buffer[1024];
      estream_t fp = runner->status_fp;

      pos = 0;
      cont_line = 0;
      while (!err && !runner->cancel_flag && (c=es_getc (fp)) != EOF)
        {
          buffer[pos++] = c;
          if (pos >= sizeof buffer - 5 || c == '\n')
            {
              buffer[pos - (c == '\n')] = 0;
              if (opt.verbose)
                log_info ("%s%s: %s\n",
                          runner->name, cont_line? "(cont)":"", buffer);
              /* We handle only complete lines and ignore any stuff we
                 possibly had to truncate.  That is - at least for the
                 encfs engine - not an issue because our changes to
                 the tool make sure that only relatively short prompt
                 lines are of interest.  */
              if (!cont_line && runner->handler)
                err = runner->handler (runner->handler_data,
                                       runner, buffer);
              pos = 0;
              cont_line = (c != '\n');
            }
        }
      if (!err && runner->cancel_flag)
        log_debug ("runner thread noticed cancel flag\n");
      else
        log_debug ("runner thread saw EOF\n");
      if (pos)
        {
          buffer[pos] = 0;
          if (opt.verbose)
            log_info ("%s%s: %s\n",
                      runner->name, cont_line? "(cont)":"", buffer);
          if (!cont_line && !err && runner->handler)
            err = runner->handler (runner->handler_data,
                                          runner, buffer);
        }
      if (!err && es_ferror (fp))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading from %s: %s\n",
                     runner->name, gpg_strerror (err));
        }

      runner->status_fp = NULL;
      es_fclose (fp);
      log_debug ("runner thread closed status fp\n");
    }

  /* Now wait for the process to finish.  */
  if (!err && runner->pid != (pid_t)(-1))
    {
      int exitcode;

      log_debug ("runner thread waiting ...\n");
      err = gnupg_wait_process (runner->name, runner->pid, 1, &exitcode);
      gnupg_release_process (runner->pid);
      runner->pid = (pid_t)(-1);
      if (err)
        log_error ("running '%s' failed (exitcode=%d): %s\n",
                   runner->name, exitcode, gpg_strerror (err));
      log_debug ("runner thread waiting finished\n");
    }

  /* Get rid of the runner object (note: it is refcounted).  */
  log_debug ("runner thread releasing runner ...\n");
  {
    runner_t r, rprev;

    for (r = running_threads, rprev = NULL; r; rprev = r, r = r->next_running)
      if (r == runner)
        {
          if (!rprev)
            running_threads = r->next_running;
          else
            rprev->next_running = r->next_running;
          r->next_running = NULL;
          break;
        }
  }
  runner_release (runner);
  log_debug ("runner thread runner released\n");

  return NULL;
}


/* Spawn a new thread to let RUNNER work as a coprocess.  */
gpg_error_t
runner_spawn (runner_t runner)
{
  gpg_error_t err;
  npth_attr_t tattr;
  npth_t thread;
  int ret;

  if (check_already_spawned (runner, "runner_spawn"))
    return gpg_error (GPG_ERR_BUG);

  /* In case we have an input fd, open it as an estream so that the
     Pth scheduling will work.  The stdio functions don't work with
     Pth because they don't call the pth counterparts of read and
     write unless linker tricks are used.  */
  if (runner->in_fd != -1)
    {
      estream_t fp;

      fp = es_fdopen (runner->in_fd, "r");
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          log_error ("can't fdopen pipe for reading: %s\n", gpg_strerror (err));
          return err;
        }
      runner->status_fp = fp;
      runner->in_fd = -1;  /* Now owned by status_fp.  */
    }

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

  ret = npth_create (&thread, &tattr, runner_thread, runner);
  if (ret)
    {
      err = gpg_error_from_errno (ret);
      log_error ("error spawning runner thread: %s\n", gpg_strerror (err));
      return err;
    }
  npth_setname_np (thread, runner->name);

  /* The scheduler has not yet kicked in, thus we can safely set the
     spawned flag and the tid.  */
  runner->spawned = 1;
  runner->thread = thread;
  runner->next_running = running_threads;
  running_threads = runner;

  npth_attr_destroy (&tattr);

  /* The runner thread is now runnable.  */

  return 0;
}


/* Cancel a running thread.  */
void
runner_cancel (runner_t runner)
{
  /* Warning: runner_cancel_all has knowledge of this code.  */
  if (runner->spawned)
    {
      runner->canceled = 1;  /* Mark that we canceled this one already.  */
      /* FIXME: This does only work if the thread emits status lines.  We
         need to change the thread to wait on an event.  */
      runner->cancel_flag = 1;
      /* For now we use the brutal way and kill the process. */
      gnupg_kill_process (runner->pid);
    }
}


/* Cancel all runner threads.  */
void
runner_cancel_all (void)
{
  runner_t r;

  do
    {
      for (r = running_threads; r; r = r->next_running)
        if (r->spawned && !r->canceled)
          {
            runner_cancel (r);
            break;
          }
    }
  while (r);
}


/* Send a line of data down to the engine.  This line may not contain
   a binary Nul or a LF character.  This function is used by the
   engine's handler.  */
gpg_error_t
runner_send_line (runner_t runner, const void *data, size_t datalen)
{
  gpg_error_t err = 0;

  if (!runner->spawned)
    {
      log_error ("BUG: runner for %s not spawned\n", runner->name);
      err = gpg_error (GPG_ERR_INTERNAL);
    }
  else if (runner->out_fd == -1)
    {
      log_error ("no output file descriptor for runner %s\n", runner->name);
      err = gpg_error (GPG_ERR_EBADF);
    }
  else if (data && datalen)
    {
      if (memchr (data, '\n', datalen))
        {
          log_error ("LF detected in response data\n");
          err = gpg_error (GPG_ERR_BUG);
        }
      else if (memchr (data, 0, datalen))
        {
          log_error ("Nul detected in response data\n");
          err = gpg_error (GPG_ERR_BUG);
        }
      else if (writen (runner->out_fd, data, datalen))
        err = gpg_error_from_syserror ();
    }

  if (!err)
    if (writen (runner->out_fd, "\n", 1))
      err = gpg_error_from_syserror ();

  return err;
}
