/* assuan-pipe-server.c - Assuan server working over a pipe 
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

#include "assuan-defs.h"


int
assuan_init_pipe_server (ASSUAN_CONTEXT *r_ctx, int filedes[2])
{
  ASSUAN_CONTEXT ctx;
  int rc;

  *r_ctx = NULL;
  ctx = xtrycalloc (1, sizeof *ctx);
  if (!ctx)
    return ASSUAN_Out_Of_Core;
  ctx->is_server = 1;
  ctx->input_fd = -1;
  ctx->output_fd = -1;

  ctx->inbound.fd = filedes[0];
  ctx->outbound.fd = filedes[1];

  ctx->pipe_mode = 1;

  rc = _assuan_register_std_commands (ctx);
  if (rc)
    xfree (ctx);
  else
    *r_ctx = ctx;
  return rc;
}

void
assuan_deinit_pipe_server (ASSUAN_CONTEXT ctx)
{
  if (ctx)
    {
      xfree (ctx->hello_line);
      xfree (ctx);
    }
}










