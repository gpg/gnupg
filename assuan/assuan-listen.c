/* assuan-listen.c - Wait for a connection (server) 
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

#include "assuan-defs.h"



/**
 * assuan_accept:
 * @ctx: context
 * 
 * Cancel any existing connectiion and wait for a connection from a
 * client.  The initial handshake is performed which may include an
 * initial authentication or encryption negotiation.
 * 
 * Return value: 0 on success or an error if the connection could for
 * some reason not be established.
 **/
int
assuan_accept (ASSUAN_CONTEXT ctx)
{
  int rc;

  if (!ctx)
    return ASSUAN_Invalid_Value;

  /* fixme: cancel existing connection */
  if (ctx->pipe_mode > 1)
    return -1; /* second invocation for pipemode -> terminate */

  if (!ctx->pipe_mode)
    {

      /* fixme: wait for request */
    }

  /* send the hello */
  
  rc = _assuan_write_line (ctx,
                           "OK Hello dear client - what can I do for you?");
  if (rc)
    return rc;
  
  if (ctx->pipe_mode)
    ctx->pipe_mode = 2;
  
  return 0;
}


int
assuan_get_input_fd (ASSUAN_CONTEXT ctx)
{
  return ctx? ctx->input_fd : -1;
}


int
assuan_get_output_fd (ASSUAN_CONTEXT ctx)
{
  return ctx? ctx->output_fd : -1;
}


