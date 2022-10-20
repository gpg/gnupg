/* ldap-wrapper.c - LDAP access via a wrapper process
 * Copyright (C) 2004, 2005, 2007, 2008, 2018 g10 Code GmbH
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
 * We can't use LDAP directly for these reasons:
 *
 * 1. The LDAP library is linked to separate crypto library like
 *    OpenSSL and even if it is linked to the library we use in dirmngr
 *    (ntbtls or gnutls) it is sometimes a different version of that
 *    library with all the surprising failures you may get due to this.
 *
 * 2. It is huge library in particular if TLS comes into play.  So
 *    problems with unfreed memory might turn up and we don't want
 *    this in a long running daemon.
 *
 * 3. There is no easy way for timeouts. In particular the timeout
 *    value does not work for DNS lookups (well, this is usual) and it
 *    seems not to work while loading a large attribute like a
 *    CRL. Having a separate process allows us to either tell the
 *    process to commit suicide or have our own housekepping function
 *    kill it after some time.  The latter also allows proper
 *    cancellation of a query at any point of time.
 *
 * 4. Given that we are going out to the network and usually get back
 *    a long response, the fork/exec overhead is acceptable.
 *
 * Note that under WindowsCE the number of processes is strongly
 * limited (32 processes including the kernel processes) and thus we
 * don't use the process approach but implement a different wrapper in
 * ldap-wrapper-ce.c.
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

  pid_t pid;           /* The pid of the wrapper process. */
  int printable_pid;   /* Helper to print diagnostics after the process has
                        * been cleaned up. */
  estream_t fp;        /* Connected with stdout of the ldap wrapper.  */
  gpg_error_t fp_err;  /* Set to the gpg_error of the last read error
                        * if any.  */
  estream_t log_fp;    /* Connected with stderr of the ldap wrapper.  */
  ctrl_t ctrl;         /* Connection data. */
  int ready;           /* Internally used to mark to be removed contexts. */
  ksba_reader_t reader;/* The ksba reader object or NULL. */
  char *line;          /* Used to print the log lines (malloced). */
  size_t linesize;     /* Allocated size of LINE.  */
  size_t linelen;      /* Use size of LINE.  */
  time_t stamp;        /* The last time we noticed ativity.  */
  int reaper_idx;      /* Private to ldap_wrapper_thread.   */
};



/* We keep a global list of spawned wrapper process.  A separate
 * thread makes use of this list to log error messages and to watch
 * out for finished processes.  Access to list is protected by a
 * mutex.  The condition variable is used to wakeup the reaper
 * thread.  */
static struct wrapper_context_s *reaper_list;
static npth_mutex_t reaper_list_mutex = NPTH_MUTEX_INITIALIZER;
static npth_cond_t  reaper_run_cond  = NPTH_COND_INITIALIZER;

/* We need to know whether we are shutting down the process.  */
static int shutting_down;



/* Close the estream fp and set it to NULL.  */
#define SAFE_CLOSE(fp) \
  do { estream_t _fp = fp; es_fclose (_fp); fp = NULL; } while (0)





static void
lock_reaper_list (void)
{
  if (npth_mutex_lock (&reaper_list_mutex))
    log_fatal ("%s: failed to acquire mutex: %s\n", __func__,
               gpg_strerror (gpg_error_from_syserror ()));
}


static void
unlock_reaper_list (void)
{
  if (npth_mutex_unlock (&reaper_list_mutex))
    log_fatal ("%s: failed to release mutex: %s\n", __func__,
               gpg_strerror (gpg_error_from_syserror ()));
}



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
  SAFE_CLOSE (ctx->fp);
  SAFE_CLOSE (ctx->log_fp);
  xfree (ctx->line);
  xfree (ctx);
}


/* Print the content of LINE to the log stream but make sure to only
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
 * indicated EOF or error.  */
static int
read_log_data (struct wrapper_context_s *ctx)
{
  int rc;
  size_t n;
  char line[256];

  rc = es_read (ctx->log_fp, line, sizeof line - 1, &n);
  if (rc || !n)  /* Error or EOF.  */
    {
      if (rc)
        {
          gpg_error_t err = gpg_error_from_syserror ();
          if (gpg_err_code (err) == GPG_ERR_EAGAIN)
            return 0;
          log_error (_("error reading log from ldap wrapper %d: %s\n"),
                     (int)ctx->pid, gpg_strerror (err));
        }
      print_log_line (ctx, NULL);  /* Flush.  */
      SAFE_CLOSE (ctx->log_fp);
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
ldap_reaper_thread (void *dummy)
{
  gpg_error_t err;
  struct wrapper_context_s *ctx;
  struct wrapper_context_s *ctx_prev;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
  int millisecs;
  gpgrt_poll_t *fparray = NULL;
  int fparraysize = 0;
  int count, i;
  int ret;
  time_t exptime;

  (void)dummy;

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL;

  for (;;)
    {
      int any_action = 0;

      /* Wait until we are needed and then setup the FPARRAY.  */
      /* Note: There is one unlock inside the block!  */
      lock_reaper_list ();
      {
        while (!reaper_list && !shutting_down)
          {
            if (npth_cond_wait (&reaper_run_cond, &reaper_list_mutex))
              log_error ("ldap-reaper: waiting on condition failed: %s\n",
                         gpg_strerror (gpg_error_from_syserror ()));
          }

        for (count = 0, ctx = reaper_list; ctx; ctx = ctx->next)
          if (ctx->log_fp)
            count++;
        if (count > fparraysize || !fparray)
          {
            /* Need to realloc the array.  We simply discard it and
             * replace it by a new one.  */
            xfree (fparray);
            fparray = xtrycalloc (count? count : 1, sizeof *fparray);
            if (!fparray)
              {
                err = gpg_error_from_syserror ();
                log_error ("ldap-reaper can't allocate poll array: %s"
                           " - waiting 1s\n", gpg_strerror (err));
                /* Note: Here we unlock and continue! */
                unlock_reaper_list ();
                gnupg_sleep (1);
                continue;
            }
            fparraysize = count;
          }
        for (count = 0, ctx = reaper_list; ctx; ctx = ctx->next)
          {
            if (ctx->log_fp)
              {
                log_assert (count < fparraysize);
                fparray[count].stream = ctx->log_fp;
                fparray[count].want_read = 1;
                fparray[count].ignore = 0;
                ctx->reaper_idx = count;
                count++;
              }
            else
              {
                ctx->reaper_idx = -1;
                fparray[count].ignore = 1;
              }
          }
        for (i=count; i < fparraysize; i++)
          fparray[i].ignore = 1;
      }
      unlock_reaper_list (); /* Note the one unlock inside the block.  */

      /* Compute the next timeout.  */
      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  /* Inactivity is checked below.  Nothing else to do.  */
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL;
	}
      npth_timersub (&abstime, &curtime, &timeout);
      millisecs = timeout.tv_sec * 1000;
      millisecs += timeout.tv_nsec / 1000000;
      if (millisecs < 0)
        millisecs = 1;

      if (DBG_EXTPROG)
        {
          log_debug ("ldap-reaper: next run (count=%d size=%d timeout=%d)\n",
                     count, fparraysize, millisecs);
          for (count=0; count < fparraysize; count++)
            if (!fparray[count].ignore)
              log_debug ("ldap-reaper: fp[%d] stream=%p %s\n",
                         count, fparray[count].stream,
                         fparray[count].want_read? "want_read":"");
        }

      ret = es_poll (fparray, fparraysize, millisecs);
      if (ret < 0)
	{
          err = gpg_error_from_syserror ();
          log_error ("ldap-reaper failed to poll: %s"
                     " - waiting 1s\n", gpg_strerror (err));
          /* In case the reason for the error is a too large array, we
           * release it so that it will be allocated smaller in the
           * next round.  */
          xfree (fparray);
          fparray = NULL;
          fparraysize = 0;
          gnupg_sleep (1);
          continue;
	}

      if (DBG_EXTPROG)
        {
          for (count=0; count < fparraysize; count++)
            if (!fparray[count].ignore)
              log_debug ("ldap-reaper: fp[%d] stream=%p rc=%d %c%c%c%c%c%c%c\n",
                         count, fparray[count].stream, ret,
                         fparray[count].got_read? 'r':'-',
                         fparray[count].got_write?'w':'-',
                         fparray[count].got_oob?  'o':'-',
                         fparray[count].got_rdhup?'H':'-',
                         fparray[count].got_err?  'e':'-',
                         fparray[count].got_hup?  'h':'-',
                         fparray[count].got_nval? 'n':'-');
        }

      /* All timestamps before exptime should be considered expired.  */
      exptime = time (NULL);
      if (exptime > INACTIVITY_TIMEOUT)
        exptime -= INACTIVITY_TIMEOUT;

      lock_reaper_list ();
      {
        for (ctx = reaper_list; ctx; ctx = ctx->next)
          {
            /* Check whether there is any logging to be done.  We need
             * to check FPARRAYSIZE because it can be 0 in case
             * es_poll returned a timeout.  */
            if (fparraysize && ctx->log_fp && ctx->reaper_idx >= 0)
              {
                log_assert (ctx->reaper_idx < fparraysize);
                if (fparray[ctx->reaper_idx].got_read)
                  {
                    if (read_log_data (ctx))
                      {
                        SAFE_CLOSE (ctx->log_fp);
                        any_action = 1;
                      }
                  }
              }

            /* Check whether the process is still running.  */
            if (ctx->pid != (pid_t)(-1))
              {
                int status;

                err = gnupg_wait_process ("[dirmngr_ldap]", ctx->pid, 0,
                                          &status);
                if (!err)
                  {
                    if (DBG_EXTPROG)
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
                /* We need to close the log stream because the cleanup
                 * loop waits for it.  */
                SAFE_CLOSE (ctx->log_fp);
                any_action = 1;
              }
          }

        /* If something has been printed to the log file or we got an
         * EOF from a wrapper, we now print the list of active
         * wrappers.  */
        if (any_action && DBG_EXTPROG)
          {
            log_debug ("ldap worker states:\n");
            for (ctx = reaper_list; ctx; ctx = ctx->next)
              log_debug ("  c=%p pid=%d/%d rdr=%p logfp=%p"
                         " ctrl=%p/%d la=%lu rdy=%d\n",
                         ctx,
                         (int)ctx->pid, (int)ctx->printable_pid,
                         ctx->reader, ctx->log_fp,
                         ctx->ctrl, ctx->ctrl? ctx->ctrl->refcount:0,
                         (unsigned long)ctx->stamp, ctx->ready);
          }

        /* An extra loop to check whether ready marked wrappers may be
         * removed.  We may only do so if the ksba reader object is
         * not anymore in use or we are in shutdown state.  */
      again:
        for (ctx_prev=NULL, ctx=reaper_list; ctx; ctx_prev=ctx, ctx=ctx->next)
          {
            if (ctx->ready
                && ((!ctx->log_fp && !ctx->reader) || shutting_down))
              {
                if (ctx_prev)
                  ctx_prev->next = ctx->next;
                else
                  reaper_list = ctx->next;
                destroy_wrapper (ctx);
                goto again;
              }
          }
      }
      unlock_reaper_list ();
    }

  /*NOTREACHED*/
  return NULL; /* Make the compiler happy.  */
}



/* Start the reaper thread for the ldap wrapper.  */
void
ldap_reaper_launch_thread (void)
{
  static int done;
  npth_attr_t tattr;
  npth_t thread;
  int err;

  if (done)
    return;
  done = 1;

#ifdef HAVE_W32_SYSTEM
  /* Static init does not yet work in W32 nPth.  */
  if (npth_cond_init (&reaper_run_cond, NULL))
    log_fatal ("%s: failed to init condition variable: %s\n",
               __func__, gpg_strerror (gpg_error_from_syserror ()));
#endif

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

  if (npth_create (&thread, &tattr, ldap_reaper_thread, NULL))
    {
      err = gpg_error_from_syserror ();
      log_error ("error spawning ldap reaper reaper thread: %s\n",
                 gpg_strerror (err) );
      dirmngr_exit (1);
    }
  npth_setname_np (thread, "ldap-reaper");
  npth_attr_destroy (&tattr);
}



/* Wait until all ldap wrappers have terminated.  We assume that the
   kill has already been sent to all of them.  */
void
ldap_wrapper_wait_connections (void)
{
  lock_reaper_list ();
  {
    shutting_down = 1;
    if (npth_cond_signal (&reaper_run_cond))
      log_error ("%s: Ooops: signaling condition failed: %s\n",
                 __func__, gpg_strerror (gpg_error_from_syserror ()));
  }
  unlock_reaper_list ();
  while (reaper_list)
    gnupg_usleep (200);
}


/* This function is to be used to release a context associated with the
   given reader object. */
void
ldap_wrapper_release_context (ksba_reader_t reader)
{
  struct wrapper_context_s *ctx;

  if (!reader )
    return;

  lock_reaper_list ();
  {
    for (ctx=reaper_list; ctx; ctx=ctx->next)
      if (ctx->reader == reader)
        {
          if (DBG_EXTPROG)
            log_debug ("releasing ldap worker c=%p pid=%d/%d rdr=%p"
                       " ctrl=%p/%d\n", ctx,
                       (int)ctx->pid, (int)ctx->printable_pid,
                       ctx->reader,
                       ctx->ctrl, ctx->ctrl? ctx->ctrl->refcount:0);

          ctx->reader = NULL;
          SAFE_CLOSE (ctx->fp);
          if (ctx->ctrl)
            {
              ctx->ctrl->refcount--;
              ctx->ctrl = NULL;
            }
          if (ctx->fp_err)
            log_info ("%s: reading from ldap wrapper %d failed: %s\n",
                      __func__, ctx->printable_pid, gpg_strerror (ctx->fp_err));
          break;
        }
  }
  unlock_reaper_list ();
}


/* Cleanup all resources held by the connection associated with
   CTRL.  This is used after a cancel to kill running wrappers.  */
void
ldap_wrapper_connection_cleanup (ctrl_t ctrl)
{
  struct wrapper_context_s *ctx;

  lock_reaper_list ();
  {
    for (ctx=reaper_list; ctx; ctx=ctx->next)
      if (ctx->ctrl && ctx->ctrl == ctrl)
        {
          ctx->ctrl->refcount--;
          ctx->ctrl = NULL;
          if (ctx->pid != (pid_t)(-1))
            gnupg_kill_process (ctx->pid);
          if (ctx->fp_err)
            log_info ("%s: reading from ldap wrapper %d failed: %s\n",
                      __func__, ctx->printable_pid, gpg_strerror (ctx->fp_err));
        }
  }
  unlock_reaper_list ();
}


/* This is the callback used by the ldap wrapper to feed the ksba
 * reader with the wrapper's stdout.  See the description of
 * ksba_reader_set_cb for details.  */
static int
reader_callback (void *cb_value, char *buffer, size_t count,  size_t *nread)
{
  struct wrapper_context_s *ctx = cb_value;
  size_t nleft = count;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
  int millisecs;
  gpgrt_poll_t fparray[1];
  int ret;
  gpg_error_t err;


  /* FIXME: We might want to add some internal buffering because the
     ksba code does not do any buffering for itself (because a ksba
     reader may be detached from another stream to read other data and
     then it would be cumbersome to get back already buffered stuff).  */

  if (!buffer && !count && !nread)
    return -1; /* Rewind is not supported. */

  /* If we ever encountered a read error, don't continue (we don't want to
     possibly overwrite the last error cause).  Bail out also if the
     file descriptor has been closed. */
  if (ctx->fp_err || !ctx->fp)
    {
      *nread = 0;
      return -1;
    }

  memset (fparray, 0, sizeof fparray);
  fparray[0].stream = ctx->fp;
  fparray[0].want_read = 1;

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL;

  while (nleft > 0)
    {
      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  err = dirmngr_tick (ctx->ctrl);
          if (err)
            {
              ctx->fp_err = err;
              SAFE_CLOSE (ctx->fp);
              return -1;
            }
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL;
	}
      npth_timersub (&abstime, &curtime, &timeout);
      millisecs = timeout.tv_sec * 1000;
      millisecs += timeout.tv_nsec / 1000000;
      if (millisecs < 0)
        millisecs = 1;

      if (DBG_EXTPROG)
        {
          log_debug ("%s: fp[0] stream=%p %s\n",
                     __func__, fparray[0].stream,
                     fparray[0].want_read?"want_read":"");
        }

      ret = es_poll (fparray, DIM (fparray), millisecs);
      if (ret < 0)
	{
          ctx->fp_err = gpg_error_from_syserror ();
          log_error ("error polling stdout of ldap wrapper %d: %s\n",
                     ctx->printable_pid, gpg_strerror (ctx->fp_err));
          SAFE_CLOSE (ctx->fp);
          return -1;
        }
      if (DBG_EXTPROG)
        {
          log_debug ("%s: fp[0] stream=%p rc=%d %c%c%c%c%c%c%c\n",
                     __func__, fparray[0].stream, ret,
                     fparray[0].got_read? 'r':'-',
                     fparray[0].got_write?'w':'-',
                     fparray[0].got_oob?  'o':'-',
                     fparray[0].got_rdhup?'H':'-',
                     fparray[0].got_err?  'e':'-',
                     fparray[0].got_hup?  'h':'-',
                     fparray[0].got_nval? 'n':'-');
        }
      if (!ret)
        {
          /* Timeout.  Will be handled when calculating the next timeout.  */
          continue;
        }

      if (fparray[0].got_read)
        {
          size_t n;

          if (es_read (ctx->fp, buffer, nleft, &n))
            {
              ctx->fp_err = gpg_error_from_syserror ();
              if (gpg_err_code (ctx->fp_err) == GPG_ERR_EAGAIN)
                ctx->fp_err = 0;
              else
                {
                  log_error ("%s: error reading: %s (%d)\n",
                             __func__, gpg_strerror (ctx->fp_err), ctx->fp_err);
                  SAFE_CLOSE (ctx->fp);
                  return -1;
                }
            }
          else if (!n) /* EOF */
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
  estream_t outfp, errfp;

  /* It would be too simple to connect stderr just to our logging
     stream.  The problem is that if we are running multi-threaded
     everything gets intermixed.  Clearly we don't want this.  So the
     only viable solutions are either to have another thread
     responsible for logging the messages or to add an option to the
     wrapper module to do the logging on its own.  Given that we anyway
     need a way to reap the child process and this is best done using a
     general reaping thread, that thread can do the logging too. */
  ldap_reaper_launch_thread ();

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

  err = gnupg_spawn_process (pgmname, arg_list,
                             NULL, GNUPG_SPAWN_NONBLOCK,
                             NULL, &outfp, &errfp, &pid);
  if (err)
    {
  xfree (arg_list);
      xfree (ctx);
      log_error ("error running '%s': %s\n", pgmname, gpg_strerror (err));
      return err;
    }

  ctx->pid = pid;
  ctx->printable_pid = (int) pid;
  ctx->fp = outfp;
  ctx->log_fp = errfp;
  ctx->ctrl = ctrl;
  ctrl->refcount++;
  ctx->stamp = time (NULL);

  err = ksba_reader_new (reader);
  if (!err)
    err = ksba_reader_set_cb (*reader, reader_callback, ctx);
  if (err)
    {
      xfree (arg_list);
      log_error (_("error initializing reader object: %s\n"),
                 gpg_strerror (err));
      destroy_wrapper (ctx);
      ksba_reader_release (*reader);
      *reader = NULL;
      return err;
    }

  /* Hook the context into our list of running wrappers.  */
  lock_reaper_list ();
  {
    ctx->reader = *reader;
    ctx->next = reaper_list;
    reaper_list = ctx;
    if (npth_cond_signal (&reaper_run_cond))
      log_error ("ldap-wrapper: Ooops: signaling condition failed: %s (%d)\n",
                 gpg_strerror (gpg_error_from_syserror ()), errno);
  }
  unlock_reaper_list ();

  if (DBG_EXTPROG)
    {
      log_debug ("ldap wrapper %d started (%p, %s)",
                 (int)ctx->pid, ctx->reader, pgmname);
      for (i=0; arg_list[i]; i++)
        log_printf (" [%s]", arg_list[i]);
      log_printf ("\n");
    }
  xfree (arg_list);


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
