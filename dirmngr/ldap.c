/* ldap.c - LDAP access
 * Copyright (C) 2002 Klarälvdalens Datakonsult AB
 * Copyright (C) 2003, 2004, 2005, 2007, 2008, 2010 g10 Code GmbH
 *
 * This file is part of DirMngr.
 *
 * DirMngr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DirMngr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
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
#include "exechelp.h"
#include "crlfetch.h"
#include "ldapserver.h"
#include "misc.h"

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

#define UNENCODED_URL_CHARS "abcdefghijklmnopqrstuvwxyz"   \
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"   \
                            "01234567890"                  \
                            "$-_.+!*'(),"
#define USERCERTIFICATE "userCertificate"
#define CACERTIFICATE   "caCertificate"
#define X509CACERT      "x509caCert"
#define USERSMIMECERTIFICATE "userSMIMECertificate"


/* Definition for the context of the cert fetch functions. */
struct cert_fetch_context_s
{
  ksba_reader_t reader;  /* The reader used (shallow copy). */
  unsigned char *tmpbuf; /* Helper buffer.  */
  size_t tmpbufsize;     /* Allocated size of tmpbuf.  */
  int truncated;         /* Flag to indicate a truncated output.  */
};


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

/* Close the pth file descriptor FD and set it to -1.  */
#define SAFE_PTH_CLOSE(fd) \
  do { int _fd = fd; if (_fd != -1) { pth_close (_fd); fd = -1;} } while (0)


/* Prototypes.  */
static gpg_error_t read_buffer (ksba_reader_t reader,
                                unsigned char *buffer, size_t count);




/* Add HOST and PORT to our list of LDAP servers.  Fixme: We should
   better use an extra list of servers. */
static void
add_server_to_servers (const char *host, int port)
{
  ldap_server_t server;
  ldap_server_t last = NULL;
  const char *s;

  if (!port)
    port = 389;

  for (server=opt.ldapservers; server; server = server->next)
    {
      if (!strcmp (server->host, host) && server->port == port)
	  return; /* already in list... */
      last = server;
    }

  /* We assume that the host names are all supplied by our
     configuration files and thus are sane.  To keep this assumption
     we must reject all invalid host names. */
  for (s=host; *s; s++)
    if (!strchr ("abcdefghijklmnopqrstuvwxyz"
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "01234567890.-", *s))
      {
        log_error (_("invalid char 0x%02x in host name - not added\n"), *s);
        return;
      }

  log_info (_("adding `%s:%d' to the ldap server list\n"), host, port);
  server = xtrycalloc (1, sizeof *s);
  if (!server)
    log_error (_("malloc failed: %s\n"), strerror (errno));
  else
    {
      server->host = xstrdup (host);
      server->port = port;
      if (last)
        last->next = server;
      else
        opt.ldapservers = server;
    }
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
  SAFE_PTH_CLOSE (ctx->fd);
  SAFE_PTH_CLOSE (ctx->log_fd);
  if (ctx->log_ev)
    pth_event_free (ctx->log_ev, PTH_FREE_THIS);
  xfree (ctx->line);
  xfree (ctx);
}


/* Print the content of LINE to thye log stream but make sure to only
   print complete lines.  Using NULL for LINE will flush any pending
   output.  LINE may be modified by this fucntion. */
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

  /* We must use the pth_read function for pipes, always.  */
  do 
    n = pth_read (ctx->log_fd, line, sizeof line - 1);
  while (n < 0 && errno == EINTR);

  if (n <= 0) /* EOF or error. */
    {
      if (n < 0)
        log_error (_("error reading log from ldap wrapper %d: %s\n"),
                   ctx->pid, strerror (errno));
      print_log_line (ctx, NULL);
      SAFE_PTH_CLOSE (ctx->log_fd);
      pth_event_free (ctx->log_ev, PTH_FREE_THIS);
      ctx->log_ev = NULL;
      return 1;
    }

  line[n] = 0;
  print_log_line (ctx, line);
  if (ctx->stamp != (time_t)(-1))
    ctx->stamp = time (NULL);
  return 0;
}


/* This function is run by a separate thread to maintain the list of
   wrappers and to log error messages from these wrappers. */
void *
ldap_wrapper_thread (void *dummy)
{
  int nfds;
  struct wrapper_context_s *ctx;
  struct wrapper_context_s *ctx_prev;
  time_t current_time;

  (void)dummy;

  for (;;)
    {
      pth_event_t timeout_ev;
      int any_action = 0;

      timeout_ev = pth_event (PTH_EVENT_TIME, pth_timeout (1, 0));
      if (! timeout_ev)
	{
          log_error (_("pth_event failed: %s\n"), strerror (errno));
          pth_sleep (10);
	  continue;
	}

      for (ctx = wrapper_list; ctx; ctx = ctx->next)
        {
          if (ctx->log_fd != -1)
            {
	      pth_event_isolate (ctx->log_ev);
	      pth_event_concat (timeout_ev, ctx->log_ev, NULL);
            }
        }

      /* Note that the read FDs are actually handles.  Thus, we can
	 not use pth_select, but have to use pth_wait.  */
      nfds = pth_wait (timeout_ev);
      if (nfds < 0)
        {
          pth_event_free (timeout_ev, PTH_FREE_THIS);
          log_error (_("pth_wait failed: %s\n"), strerror (errno));
          pth_sleep (10);
	  continue;
        }
      if (pth_event_status (timeout_ev) == PTH_STATUS_OCCURRED)
	nfds--;
      pth_event_free (timeout_ev, PTH_FREE_THIS);

      current_time = time (NULL);
      if (current_time > INACTIVITY_TIMEOUT)
        current_time -= INACTIVITY_TIMEOUT;

      /* Note that there is no need to lock the list because we always
         add entries at the head (with a pending event status) and
         thus traversing the list will even work if we have a context
         switch in waitpid (which should anyway only happen with Pth's
         hard system call mapping).  */
      for (ctx = wrapper_list; ctx; ctx = ctx->next)
        {
          /* Check whether there is any logging to be done. */
          if (nfds && ctx->log_fd != -1
	      && pth_event_status (ctx->log_ev) == PTH_STATUS_OCCURRED)
            {
              if (read_log_data (ctx))
                any_action = 1;
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
              && ctx->stamp != (time_t)(-1) && ctx->stamp < current_time)
            {
              gnupg_kill_process (ctx->pid);
              ctx->stamp = (time_t)(-1);
              log_info (_("ldap wrapper %d stalled - killing\n"),
                        (int)ctx->pid);
              /* We need to close the log fd because the cleanup loop
                 waits for it.  */
              SAFE_PTH_CLOSE (ctx->log_fd);
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

/* This is the callback used by the ldap wrapper to feed the ksba
   reader with the wrappers stdout.  See the description of
   ksba_reader_set_cb for details.  */
static int 
reader_callback (void *cb_value, char *buffer, size_t count,  size_t *nread)
{
  struct wrapper_context_s *ctx = cb_value;
  size_t nleft = count;

  /* FIXME: We might want to add some internal buffering because the
     ksba code does not do any buffering for itself (because a ksba
     reader may be detached from another stream to read other data and
     the it would be cumbersome to get back already buffered
     stuff).  */

  if (!buffer && !count && !nread)
    return -1; /* Rewind is not supported. */

  /* If we ever encountered a read error don't allow to continue and
     possible overwrite the last error cause.  Bail out also if the
     file descriptor has been closed. */
  if (ctx->fd_error || ctx->fd == -1)
    {
      *nread = 0;
      return -1;
    }

  while (nleft > 0)
    {
      int n;
      pth_event_t evt;
      gpg_error_t err;

      evt = pth_event (PTH_EVENT_TIME, pth_timeout (1, 0));
      n = pth_read_ev (ctx->fd, buffer, nleft, evt);
      if (n < 0 && evt && pth_event_occurred (evt))
        {
          n = 0;
          err = dirmngr_tick (ctx->ctrl);
          if (err)
            {
              ctx->fd_error = err;
              SAFE_PTH_CLOSE (ctx->fd);
              if (evt)
                pth_event_free (evt, PTH_FREE_THIS);
              return -1;
            }

        }
      else if (n < 0)
        {
          ctx->fd_error = gpg_error_from_errno (errno);
          SAFE_PTH_CLOSE (ctx->fd);
          if (evt)
            pth_event_free (evt, PTH_FREE_THIS);
          return -1;
        }
      else if (!n)
        {
          if (nleft == count)
            {
              if (evt)
                pth_event_free (evt, PTH_FREE_THIS);
              return -1; /* EOF. */
            }
          break; 
        }
      nleft -= n;
      buffer += n;
      if (evt)
        pth_event_free (evt, PTH_FREE_THIS);
      if (n > 0 && ctx->stamp != (time_t)(-1))
        ctx->stamp = time (NULL);
    }
  *nread = count - nleft;

  return 0;

}

/* Fork and exec the LDAP wrapper and returns a new libksba reader
   object at READER.  ARGV is a NULL terminated list of arguments for
   the wrapper.  The function returns 0 on success or an error code.

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

   Special hack to avoid passing a password through the command line
   which is globally visible: If the first element of ARGV is "--pass"
   it will be removed and instead the environment variable
   DIRMNGR_LDAP_PASS will be set to the next value of ARGV.  On modern
   OSes the environment is not visible to other users.  For those old
   systems where it can't be avoided, we don't want to go into the
   hassle of passing the password via stdin; it's just too complicated
   and an LDAP password used for public directory lookups should not
   be that confidential.  */
static gpg_error_t
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



/* Perform an LDAP query.  Returns an gpg error code or 0 on success.
   The function returns a new reader object at READER. */
static gpg_error_t
run_ldap_wrapper (ctrl_t ctrl, 
                  int ignore_timeout,
                  int multi_mode,
                  const char *proxy,
                  const char *host, int port, 
                  const char *user, const char *pass,
                  const char *dn, const char *filter, const char *attr,
                  const char *url,
                  ksba_reader_t *reader)
{
  const char *argv[40];
  int argc;
  char portbuf[30], timeoutbuf[30];
  

  *reader = NULL;

  argc = 0;
  if (pass)  /* Note, that the password most be the first item.  */
    {
      argv[argc++] = "--pass";
      argv[argc++] = pass;
    }
  if (opt.verbose)
    argv[argc++] = "-vv";
  argv[argc++] = "--log-with-pid";
  if (multi_mode)
    argv[argc++] = "--multi";
  if (opt.ldaptimeout)
    {
      sprintf (timeoutbuf, "%u", opt.ldaptimeout);
      argv[argc++] = "--timeout";
      argv[argc++] = timeoutbuf;
      if (ignore_timeout)
        argv[argc++] = "--only-search-timeout";
    }
  if (proxy)
    {
      argv[argc++] = "--proxy";
      argv[argc++] = proxy;
    }
  if (host)
    {
      argv[argc++] = "--host";
      argv[argc++] = host;
    }
  if (port)
    {
      sprintf (portbuf, "%d", port);
      argv[argc++] = "--port";
      argv[argc++] = portbuf;
    }
  if (user)
    {
      argv[argc++] = "--user";
      argv[argc++] = user;
    }
  if (dn)
    {
      argv[argc++] = "--dn";
      argv[argc++] = dn;
    }
  if (filter)
    {
      argv[argc++] = "--filter";
      argv[argc++] = filter;
    }
  if (attr)
    {
      argv[argc++] = "--attr";
      argv[argc++] = attr;
    }
  argv[argc++] = url? url : "ldap://";
  argv[argc] = NULL;
    
  return ldap_wrapper (ctrl, reader, argv);
}




/* Perform a LDAP query using a given URL. On success a new ksba
   reader is returned.  If HOST or PORT are not 0, they are used to
   override the values from the URL. */
gpg_error_t
url_fetch_ldap (ctrl_t ctrl, const char *url, const char *host, int port,
                ksba_reader_t *reader)
{
  gpg_error_t err;

  err = run_ldap_wrapper (ctrl,
                          1, /* Ignore explicit timeout because CRLs
                                might be very large. */
                          0,
                          opt.ldap_proxy,
                          host, port,
                          NULL, NULL,
                          NULL, NULL, NULL, url,
                          reader);

  /* FIXME: This option might be used for DoS attacks.  Because it
     will enlarge the list of servers to consult without a limit and
     all LDAP queries w/o a host are will then try each host in
     turn. */
  if (!err && opt.add_new_ldapservers && !opt.ldap_proxy) 
    {
      if (host)
        add_server_to_servers (host, port);
      else if (url)
        {
          char *tmp = host_and_port_from_url (url, &port);
          if (tmp)
            {
              add_server_to_servers (tmp, port);
              xfree (tmp);
            }
        }
    }

  /* If the lookup failed and we are not only using the proxy, we try
     again using our default list of servers.  */
  if (err && !(opt.ldap_proxy && opt.only_ldap_proxy))
    {
      struct ldapserver_iter iter;
      
      if (DBG_LOOKUP)
        log_debug ("no hostname in URL or query failed; "
                   "trying all default hostnames\n");
      
      for (ldapserver_iter_begin (&iter, ctrl);
	   err && ! ldapserver_iter_end_p (&iter);
	   ldapserver_iter_next (&iter))
        {
	  ldap_server_t server = iter.server;

          err = run_ldap_wrapper (ctrl,
                                  0,
                                  0,
                                  NULL,
                                  server->host, server->port,
                                  NULL, NULL,
                                  NULL, NULL, NULL, url,
                                  reader);
          if (!err)
            break;
        }
    }

  return err;
}



/* Perform an LDAP query on all configured servers.  On error the
   error code of the last try is returned.  */
gpg_error_t
attr_fetch_ldap (ctrl_t ctrl,
                 const char *dn, const char *attr, ksba_reader_t *reader)
{
  gpg_error_t err = gpg_error (GPG_ERR_CONFIGURATION);
  struct ldapserver_iter iter;

  *reader = NULL;

  /* FIXME; we might want to look at the Base SN to try matching
     servers first. */
  for (ldapserver_iter_begin (&iter, ctrl); ! ldapserver_iter_end_p (&iter);
       ldapserver_iter_next (&iter))
    {
      ldap_server_t server = iter.server;

      err = run_ldap_wrapper (ctrl,
                              0,
                              0,
                              opt.ldap_proxy,
                              server->host, server->port,
                              server->user, server->pass,
                              dn, "objectClass=*", attr, NULL,
                              reader);
      if (!err)
        break; /* Probably found a result. Ready. */
    }
  return err;
}


/* Parse PATTERN and return a new strlist to be used for the actual
   LDAP query.  Bit 0 of the flags field is set if that pattern is
   actually a base specification.  Caller must release the returned
   strlist.  NULL is returned on error.

 * Possible patterns:
 *
 *   KeyID
 *   Fingerprint
 *   OpenPGP userid
 * x Email address  Indicated by a left angle bracket.
 *   Exact word match in user id or subj. name
 * x Subj. DN  indicated bu a leading slash
 *   Issuer DN
 *   Serial number + subj. DN
 * x Substring match indicated by a leading '*; is also the default.
 */

strlist_t
parse_one_pattern (const char *pattern)
{
  strlist_t result = NULL;
  char *p;

  switch (*pattern)
    {
    case '<':			/* Email. */
      {
        pattern++;
	result = xmalloc (sizeof *result + 5 + strlen (pattern));
        result->next = NULL;
        result->flags = 0;
	p = stpcpy (stpcpy (result->d, "mail="), pattern);
	if (p[-1] == '>')
	  *--p = 0;
        if (!*result->d) /* Error. */
          {
            xfree (result);
            result = NULL;
          }
	break;
      }
    case '/':			/* Subject DN. */
      pattern++;
      if (*pattern)
        {
          result = xmalloc (sizeof *result + strlen (pattern));
          result->next = NULL;
          result->flags = 1; /* Base spec. */
          strcpy (result->d, pattern);
        }
      break;
    case '#':			/* Issuer DN. */
      pattern++;
      if (*pattern == '/')  /* Just issuer DN. */
        {
          pattern++;
	}
      else  /* Serial number + issuer DN */
	{
        }
      break;
    case '*':
      pattern++;
    default:			/* Take as substring match. */
      {
	const char format[] = "(|(sn=*%s*)(|(cn=*%s*)(mail=*%s*)))";
        
        if (*pattern)
          {
            result = xmalloc (sizeof *result
                              + strlen (format) + 3 * strlen (pattern));
            result->next = NULL;
            result->flags = 0; 
            sprintf (result->d, format, pattern, pattern, pattern);
          }
      }
      break;
    }
  
  return result;
}

/* Take the string STRING and escape it accoring to the URL rules.
   Retun a newly allocated string. */
static char *
escape4url (const char *string)
{
  const char *s;
  char *buf, *p;
  size_t n;

  if (!string)
    string = "";

  for (s=string,n=0; *s; s++)
    if (strchr (UNENCODED_URL_CHARS, *s))
      n++;
    else 
      n += 3;
  
  buf = malloc (n+1);
  if (!buf)
    return NULL;

  for (s=string,p=buf; *s; s++)
    if (strchr (UNENCODED_URL_CHARS, *s))
      *p++ = *s;
    else 
      {
        sprintf (p, "%%%02X", *(const unsigned char *)s);
        p += 3;
      }
  *p = 0;

  return buf;
}



/* Create a LDAP URL from DN and FILTER and return it in URL.  We don't
   need the host and port because this will be specified using the
   override options. */
static gpg_error_t
make_url (char **url, const char *dn, const char *filter)
{
  gpg_error_t err;
  char *u_dn, *u_filter;
  char const attrs[] = (USERCERTIFICATE ","
/*                         USERSMIMECERTIFICATE "," */
                        CACERTIFICATE ","
                        X509CACERT );

  *url = NULL;

  u_dn = escape4url (dn);
  if (!u_dn)
      return gpg_error_from_errno (errno);

  u_filter = escape4url (filter);
  if (!u_filter)
    {
      err = gpg_error_from_errno (errno);
      xfree (u_dn);
      return err;
    }
  *url = malloc ( 8 + strlen (u_dn)
                 + 1 + strlen (attrs)
                 + 5 + strlen (u_filter) + 1 );
  if (!*url)
    {
      err = gpg_error_from_errno (errno);
      xfree (u_dn);
      xfree (u_filter);
      return err;
    }
 
  stpcpy (stpcpy (stpcpy (stpcpy (stpcpy (stpcpy (*url, "ldap:///"),
                                          u_dn),
                                  "?"),
                          attrs),
                  "?sub?"),
          u_filter);
  xfree (u_dn);
  xfree (u_filter);
  return 0;
}


/* Prepare an LDAP query to return the attribute ATTR for the DN.  All
   configured default servers are queried until one responds.  This
   function returns an error code or 0 and a CONTEXT on success. */
gpg_error_t
start_default_fetch_ldap (ctrl_t ctrl, cert_fetch_context_t *context,
                          const char *dn, const char *attr)
{
  gpg_error_t err;
  struct ldapserver_iter iter;

  *context = xtrycalloc (1, sizeof **context);
  if (!*context)
    return gpg_error_from_errno (errno);

  /* FIXME; we might want to look at the Base SN to try matching
     servers first. */
  err = gpg_error (GPG_ERR_CONFIGURATION);

  for (ldapserver_iter_begin (&iter, ctrl); ! ldapserver_iter_end_p (&iter);
       ldapserver_iter_next (&iter))
    {
      ldap_server_t server = iter.server;

      err = run_ldap_wrapper (ctrl,
                              0,
                              1,
                              opt.ldap_proxy,
                              server->host, server->port,
                              server->user, server->pass,
                              dn, "objectClass=*", attr, NULL,
                              &(*context)->reader);
      if (!err)
        break; /* Probably found a result. */
    }

  if (err)
    {
      xfree (*context);
      *context = NULL;
    }
  return err;
}


/* Prepare an LDAP query to return certificates maching PATTERNS using
   the SERVER.  This function returns an error code or 0 and a CONTEXT
   on success. */
gpg_error_t
start_cert_fetch_ldap (ctrl_t ctrl, cert_fetch_context_t *context,
                       strlist_t patterns, const ldap_server_t server)
{
  gpg_error_t err;
  const char *host;
  int port;
  const char *user;
  const char *pass;
  const char *base;
  const char *argv[50];
  int argc;
  char portbuf[30], timeoutbuf[30];

  
  *context = NULL;
  if (server)
    {
      host = server->host;
      port = server->port;
      user = server->user;
      pass = server->pass;
      base = server->base;
    }
  else /* Use a default server. */
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  if (!base)
    base = "";

  argc = 0;
  if (pass) /* Note: Must be the first item. */
    {
      argv[argc++] = "--pass";
      argv[argc++] = pass;
    }
  if (opt.verbose)
    argv[argc++] = "-vv";
  argv[argc++] = "--log-with-pid";
  argv[argc++] = "--multi";
  if (opt.ldaptimeout)
    {
      sprintf (timeoutbuf, "%u", opt.ldaptimeout);
      argv[argc++] = "--timeout";
      argv[argc++] = timeoutbuf;
    }
  if (opt.ldap_proxy)
    {
      argv[argc++] = "--proxy";
      argv[argc++] = opt.ldap_proxy;
    }
  if (host)
    {
      argv[argc++] = "--host";
      argv[argc++] = host;
    }
  if (port)
    {
      sprintf (portbuf, "%d", port);
      argv[argc++] = "--port";
      argv[argc++] = portbuf;
    }
  if (user)
    {
      argv[argc++] = "--user";
      argv[argc++] = user;
    }


  for (; patterns; patterns = patterns->next)
    {
      strlist_t sl;
      char *url;

      if (argc >= sizeof argv -1)
        {
          /* Too many patterns.  It does not make sense to allow an
             arbitrary number of patters because the length of the
             command line is limited anyway.  */
          /* fixme: cleanup. */
          return gpg_error (GPG_ERR_RESOURCE_LIMIT);
        }
      sl = parse_one_pattern (patterns->d);
      if (!sl)
        {
          log_error (_("start_cert_fetch: invalid pattern `%s'\n"),
                     patterns->d);
          /* fixme: cleanup argv.  */
          return gpg_error (GPG_ERR_INV_USER_ID);
        }
      if ((sl->flags & 1))
        err = make_url (&url, sl->d, "objectClass=*");
      else
        err = make_url (&url, base, sl->d);
      free_strlist (sl);
      if (err)
        {
          /* fixme: cleanup argv. */
          return err;
        }
      argv[argc++] = url;
    }
  argv[argc] = NULL;

  *context = xtrycalloc (1, sizeof **context);
  if (!*context)
    return gpg_error_from_errno (errno);

  err = ldap_wrapper (ctrl, &(*context)->reader, argv);

  if (err)
    {
      xfree (*context);
      *context = NULL;
    }

  return err;
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


/* Fetch the next certificate. Return 0 on success, GPG_ERR_EOF if no
   (more) certificates are available or any other error
   code. GPG_ERR_TRUNCATED may be returned to indicate that the result
   has been truncated. */
gpg_error_t
fetch_next_cert_ldap (cert_fetch_context_t context,
                      unsigned char **value, size_t *valuelen)
{
  gpg_error_t err;
  unsigned char hdr[5];
  char *p, *pend;
  int n;
  int okay = 0;
  int is_cms = 0;

  *value = NULL;
  *valuelen = 0;

  err = 0;
  while (!err)
    {
      err = read_buffer (context->reader, hdr, 5);
      if (err)
        break;
      n = (hdr[1] << 24)|(hdr[2]<<16)|(hdr[3]<<8)|hdr[4];
      if (*hdr == 'V' && okay)
        {
#if 0  /* That code is not yet ready.  */
       
          if (is_cms)
            {
              /* The certificate needs to be parsed from CMS data. */
              ksba_cms_t cms;
              ksba_stop_reason_t stopreason;
              int i;
          
              err = ksba_cms_new (&cms);
              if (err)
                goto leave;
              err = ksba_cms_set_reader_writer (cms, context->reader, NULL);
              if (err)
                {
                  log_error ("ksba_cms_set_reader_writer failed: %s\n",
                             gpg_strerror (err));
                  goto leave;
                }

              do 
                {
                  err = ksba_cms_parse (cms, &stopreason);
                  if (err)
                    {
                      log_error ("ksba_cms_parse failed: %s\n",
                                 gpg_strerror (err));
                      goto leave;
                    }

                  if (stopreason == KSBA_SR_BEGIN_DATA)
                    log_error ("userSMIMECertificate is not "
                               "a certs-only message\n");
                }
              while (stopreason != KSBA_SR_READY);   
      
              for (i=0; (cert=ksba_cms_get_cert (cms, i)); i++)
                {
                  check_and_store (ctrl, stats, cert, 0);
                  ksba_cert_release (cert); 
                  cert = NULL;
                }
              if (!i)
                log_error ("no certificate found\n");
              else
                any = 1;
            }
          else
#endif
            {
              *value = xtrymalloc (n);
              if (!*value)
                return gpg_error_from_errno (errno);
              *valuelen = n; 
              err = read_buffer (context->reader, *value, n);
              break; /* Ready or error.  */
            }
        }
      else if (!n && *hdr == 'A')
        okay = 0;
      else if (n)
        {
          if (n > context->tmpbufsize)
            {
              xfree (context->tmpbuf);
              context->tmpbufsize = 0;
              context->tmpbuf = xtrymalloc (n+1);
              if (!context->tmpbuf)
                return gpg_error_from_errno (errno);
              context->tmpbufsize = n;
            }  
          err = read_buffer (context->reader, context->tmpbuf, n);
          if (err)
            break;
          if (*hdr == 'A')
            {
              p = context->tmpbuf;
              p[n] = 0; /*(we allocated one extra byte for this.)*/
              is_cms = 0;
              if ( (pend = strchr (p, ';')) )
                *pend = 0; /* Strip off the extension. */
              if (!ascii_strcasecmp (p, USERCERTIFICATE))
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute `%s'\n",
                               USERCERTIFICATE);
                  okay = 1;
                }
              else if (!ascii_strcasecmp (p, CACERTIFICATE))
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute `%s'\n",
                               CACERTIFICATE);
                  okay = 1;
                }
              else if (!ascii_strcasecmp (p, X509CACERT))
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute `%s'\n",
                               CACERTIFICATE);
                  okay = 1;
                }
/*               else if (!ascii_strcasecmp (p, USERSMIMECERTIFICATE)) */
/*                 { */
/*                   if (DBG_LOOKUP) */
/*                     log_debug ("fetch_next_cert_ldap: got attribute `%s'\n", */
/*                                USERSMIMECERTIFICATE); */
/*                   okay = 1; */
/*                   is_cms = 1; */
/*                 } */
              else
                {
                  if (DBG_LOOKUP)
                    log_debug ("fetch_next_cert_ldap: got attribute `%s'"
                               " -  ignored\n", p);
                  okay = 0;
                }
            }
          else if (*hdr == 'E')
            {
              p = context->tmpbuf;
              p[n] = 0; /*(we allocated one extra byte for this.)*/
              if (!strcmp (p, "truncated"))
                {
                  context->truncated = 1;
                  log_info (_("ldap_search hit the size limit of"
                              " the server\n"));
                }
            }
        }
    }

  if (err)
    {
      xfree (*value);
      *value = NULL;
      *valuelen = 0;
      if (gpg_err_code (err) == GPG_ERR_EOF && context->truncated)
        {
          context->truncated = 0; /* So that the next call would return EOF. */
          err = gpg_error (GPG_ERR_TRUNCATED);
        }
    }

  return err;
}


void
end_cert_fetch_ldap (cert_fetch_context_t context)
{
  if (context)
    {
      ksba_reader_t reader = context->reader;

      xfree (context->tmpbuf);
      xfree (context);
      ldap_wrapper_release_context (reader);
      ksba_reader_release (reader);
    }
}
