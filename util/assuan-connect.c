/* assuan-connect.c - Establish a connection (client) 
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Please note that this is a stripped down and modified version of
   the orginal Assuan code from libassuan. */

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
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif

#include "assuan-defs.h"

/* Create a new context.  */
int
_assuan_new_context (assuan_context_t *r_ctx)
{
  assuan_context_t ctx;

  *r_ctx = NULL;
  ctx = xcalloc (1, sizeof *ctx);

  ctx->input_fd = -1;
  ctx->output_fd = -1;

  ctx->inbound.fd = -1;
  ctx->outbound.fd = -1;
  ctx->io = NULL;

  ctx->listen_fd = -1;
  *r_ctx = ctx;
  return 0;
}


void
_assuan_release_context (assuan_context_t ctx)
{
  if (ctx)
    {
      xfree (ctx->hello_line);
      xfree (ctx->okay_line);
      xfree (ctx);
    }
}


/* Disconnect and release the context CTX. */
void
assuan_disconnect (assuan_context_t ctx)
{
  if (ctx)
    {
      assuan_write_line (ctx, "BYE");
      ctx->finish_handler (ctx);
      ctx->deinit_handler (ctx);
      ctx->deinit_handler = NULL;
      _assuan_release_context (ctx);
    }
}

/* Return the PID of the peer or -1 if not known. */
pid_t
assuan_get_pid (assuan_context_t ctx)
{
  return (ctx && ctx->pid)? ctx->pid : -1;
}

