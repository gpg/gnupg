/* assuan-pipe-server.c - Assuan server working over a pipe 
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA 
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>

#include "assuan-defs.h"

static void
deinit_pipe_server (ASSUAN_CONTEXT ctx)
{
  /* nothing to do for this simple server */
}

static int
accept_connection (ASSUAN_CONTEXT ctx)
{
  /* This is a NOP for a pipe server */
  return 0;
}

static int
finish_connection (ASSUAN_CONTEXT ctx)
{
  /* This is a NOP for a pipe server */
  return 0;
}


/* Create a new context.  Note that the handlers are set up for a pipe
   server/client - this way we don't need extra dummy functions */
int
_assuan_new_context (ASSUAN_CONTEXT *r_ctx)
{
  ASSUAN_CONTEXT ctx;
  int rc;

  *r_ctx = NULL;
  ctx = xtrycalloc (1, sizeof *ctx);
  if (!ctx)
    return ASSUAN_Out_Of_Core;
  ctx->input_fd = -1;
  ctx->output_fd = -1;

  ctx->inbound.fd = -1;
  ctx->outbound.fd = -1;

  ctx->listen_fd = -1;
  ctx->client_pid = (pid_t)-1;
  /* use the pipe server handler as a default */
  ctx->deinit_handler = deinit_pipe_server;
  ctx->accept_handler = accept_connection;
  ctx->finish_handler = finish_connection;

  rc = _assuan_register_std_commands (ctx);
  if (rc)
    xfree (ctx);
  else
    *r_ctx = ctx;
  return rc;
}



int
assuan_init_pipe_server (ASSUAN_CONTEXT *r_ctx, int filedes[2])
{
  int rc;

  rc = _assuan_new_context (r_ctx);
  if (!rc)
    {
      ASSUAN_CONTEXT ctx = *r_ctx;

      ctx->is_server = 1;
      ctx->inbound.fd = filedes[0];
      ctx->outbound.fd = filedes[1];
      ctx->pipe_mode = 1;
    }
  return rc;
}


void
_assuan_release_context (ASSUAN_CONTEXT ctx)
{
  if (ctx)
    {
      xfree (ctx->hello_line);
      xfree (ctx->okay_line);
      xfree (ctx);
    }
}

void
assuan_deinit_server (ASSUAN_CONTEXT ctx)
{
  if (ctx)
    {
      /* We use this function pointer to avoid linking other server
         when not needed but still allow for a generic deinit function */
      ctx->deinit_handler (ctx);
      ctx->deinit_handler = NULL;
      _assuan_release_context (ctx);
    }
}
