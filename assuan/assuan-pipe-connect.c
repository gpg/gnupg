/* assuan-pipe-connect.c - Establish a pipe connection (client) 
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "assuan-defs.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

#ifdef HAVE_JNLIB_LOGGING
#include "../jnlib/logging.h"
#define LOGERROR1(a,b)   log_error ((a), (b))
#else
#define LOGERROR1(a,b)   fprintf (stderr, (a), (b))
#endif



static int
writen ( int fd, const char *buffer, size_t length )
{
  while (length)
    {
      int nwritten = write (fd, buffer, length);
      
      if (nwritten < 0)
        {
          if (errno == EINTR)
            continue;
          return -1; /* write error */
        }
      length -= nwritten;
      buffer += nwritten;
    }
  return 0;  /* okay */
}


static int
do_finish (ASSUAN_CONTEXT ctx)
{
  if (ctx->inbound.fd != -1)
    {
      close (ctx->inbound.fd);
      ctx->inbound.fd = -1;
    }
  if (ctx->outbound.fd != -1)
    {
      close (ctx->outbound.fd);
      ctx->outbound.fd = -1;
    }
  if (ctx->pid != -1)
    {
      waitpid (ctx->pid, NULL, 0);  /* FIXME Check return value.  */
      ctx->pid = -1;
    }
  return 0;
}

static void
do_deinit (ASSUAN_CONTEXT ctx)
{
  do_finish (ctx);
}



/* Connect to a server over a pipe, creating the assuan context and
   returning it in CTX.  The server filename is NAME, the argument
   vector in ARGV.  FD_CHILD_LIST is a -1 terminated list of file
   descriptors not to close in the child.  */
AssuanError
assuan_pipe_connect (ASSUAN_CONTEXT *ctx, const char *name, char *const argv[],
		     int *fd_child_list)
{
  static int fixed_signals = 0;
  AssuanError err;
  int rp[2];
  int wp[2];

  if (!ctx || !name || !argv || !argv[0])
    return ASSUAN_Invalid_Value;

  if (!fixed_signals)
    { 
      struct sigaction act;
        
      sigaction (SIGPIPE, NULL, &act);
      if (act.sa_handler == SIG_DFL)
	{
	  act.sa_handler = SIG_IGN;
	  sigemptyset (&act.sa_mask);
	  act.sa_flags = 0;
	  sigaction (SIGPIPE, &act, NULL);
        }
      fixed_signals = 1;
      /* FIXME: This is not MT safe */
    }

  if (pipe (rp) < 0)
    return ASSUAN_General_Error;

  if (pipe (wp) < 0)
    {
      close (rp[0]);
      close (rp[1]);
      return ASSUAN_General_Error;
    }
  
  err = _assuan_new_context (ctx);
  if (err)
    {
      close (rp[0]);
      close (rp[1]);
      close (wp[0]);
      close (wp[1]);
      return err;
    }
  (*ctx)->pipe_mode = 1;
  (*ctx)->inbound.fd  = rp[0];  /* Our inbound is read end of read pipe. */
  (*ctx)->outbound.fd = wp[1];  /* Our outbound is write end of write pipe. */
  (*ctx)->deinit_handler = do_deinit;
  (*ctx)->finish_handler = do_finish;

  (*ctx)->pid = fork ();
  if ((*ctx)->pid < 0)
    {
      close (rp[0]);
      close (rp[1]);
      close (wp[0]);
      close (wp[1]);
      _assuan_release_context (*ctx); 
      return ASSUAN_General_Error;
    }

  if ((*ctx)->pid == 0)
    {
      int i, n;
      char errbuf[512];
#ifdef HAVE_JNLIB_LOGGING
      int log_fd = log_get_fd (); 
#endif
      /* close all files which will not be duped but keep stderr
         and log_stream for now */
      n = sysconf (_SC_OPEN_MAX);
      if (n < 0)
        n = MAX_OPEN_FDS;
      for (i=0; i < n; i++)
        {
	  int *fdp = fd_child_list;

	  if (fdp)
	    {
	      while (*fdp != -1 && *fdp != i)
		fdp++;
	    }

          if (!(fdp && *fdp != -1)
	      && i != fileno (stderr) 
#ifdef HAVE_JNLIB_LOGGING
              && i != log_fd
#endif
              && i != rp[1] && i != wp[0])
            close(i);
        }
      errno = 0;

      /* Dup handles and to stdin/stdout and exec */
      if (rp[1] != STDOUT_FILENO)
        {
          if (dup2 (rp[1], STDOUT_FILENO) == -1)
            {
              LOGERROR1 ("dup2 failed in child: %s\n", strerror (errno));
              _exit (4);
            }
          close (rp[1]);
        }
      if (wp[0] != STDIN_FILENO)
        {
          if (dup2 (wp[0], STDIN_FILENO) == -1)
            {
              LOGERROR1 ("dup2 failed in child: %s\n", strerror (errno));
              _exit (4);
            }
          close (wp[0]);
        }

      execv (name, argv); 
      /* oops - use the pipe to tell the parent about it */
      snprintf (errbuf, sizeof(errbuf)-1, "ERR %d can't exec `%s': %.50s\n",
                ASSUAN_Problem_Starting_Server, name, strerror (errno));
      errbuf[sizeof(errbuf)-1] = 0;
      writen (1, errbuf, strlen (errbuf));
      _exit (4);
    }

  close (rp[1]);
  close (wp[0]);

  /* initial handshake */
  {
    int okay, off;

    err = _assuan_read_from_server (*ctx, &okay, &off);
    if (err)
      {
        LOGERROR1 ("can't connect server: %s\n", assuan_strerror (err));
      }
    else if (okay != 1)
      {
        LOGERROR1 ("can't connect server: `%s'\n", (*ctx)->inbound.line);
        err = ASSUAN_Connect_Failed;
      }
  }

  if (err)
    {
      assuan_disconnect (*ctx);
      *ctx = NULL;
    }

  return err;
}














