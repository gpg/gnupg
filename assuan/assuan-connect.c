/* assuan-connect.c - Establish a connection (client) 
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "assuan-defs.h"

/* Connect to a server over a pipe, creating the assuan context and
   returning it in CTX.  The server filename is NAME, the argument
   vector in ARGV.  */
AssuanError
assuan_pipe_connect (ASSUAN_CONTEXT *ctx, const char *name, char *const argv[])
{
  static int fixed_signals = 0;
  AssuanError err;
  int rp[2];
  int wp[2];
  int fd[2];

  if (!name || !argv || !argv[0])
    return ASSUAN_General_Error;

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

  fd[0] = rp[0];  /* Our inbound is read end of read pipe.  */
  fd[1] = wp[1];  /* Our outbound is write end of write pipe.  */

  err = assuan_init_pipe_server (ctx, fd);  /* FIXME: Common code should be factored out.  */
  if (err)
    {
      close (rp[0]);
      close (rp[1]);
      close (wp[0]);
      close (wp[1]);
      return err;
    }

  (*ctx)->pid = fork ();
  if ((*ctx)->pid < 0)
    {
      close (rp[0]);
      close (rp[1]);
      close (wp[0]);
      close (wp[1]);
      assuan_deinit_pipe_server (*ctx);  /* FIXME: Common code should be factored out.  */
      return ASSUAN_General_Error;
    }

  if ((*ctx)->pid == 0)
    {
      close (rp[0]);
      close (wp[1]);
      if (rp[1] != STDOUT_FILENO)
	{
	  dup2 (rp[1], STDOUT_FILENO);  /* Child's outbound is write end of read pipe.  */
	  close (rp[1]);
	}
      if (wp[0] != STDIN_FILENO)
	{
	  dup2 (wp[0], STDIN_FILENO);  /* Child's inbound is read end of write pipe.  */
	  close (wp[0]);
	}
      execv (name, argv);
      _exit (1);
    }

  close (rp[1]);
  close (wp[0]);
  _assuan_read_line (*ctx); /* FIXME: Handshake.  */
  return 0;
}

void
assuan_pipe_disconnect (ASSUAN_CONTEXT ctx)
{
  _assuan_write_line (ctx, "BYE");
  close (ctx->inbound.fd);
  close (ctx->outbound.fd);
  waitpid (ctx->pid, NULL, 0);  /* FIXME Check return value.  */
  assuan_deinit_pipe_server (ctx);
}

pid_t
assuan_get_pid (ASSUAN_CONTEXT ctx)
{
  return ctx ? ctx->pid : -1;
}
