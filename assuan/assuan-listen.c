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
#include <unistd.h>

#include "assuan-defs.h"

AssuanError
assuan_set_hello_line (ASSUAN_CONTEXT ctx, const char *line)
{
  if (!ctx)
    return ASSUAN_Invalid_Value;
  if (!line)
    {
      xfree (ctx->hello_line);
      ctx->hello_line = NULL;
    }
  else
    {
      char *buf = xtrymalloc (3+strlen(line)+1);
      if (!buf)
        return ASSUAN_Out_Of_Core;
      strcpy (buf, "OK ");
      strcpy (buf+3, line);
      xfree (ctx->hello_line);
      ctx->hello_line = buf;
    }
  return 0;
}


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
AssuanError
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
  rc = assuan_write_line (ctx, ctx->hello_line? ctx->hello_line
                                              : "OK Your orders please");
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


/* Close the fd descriptor set by the command INPUT FD=n.  We handle
   this fd inside assuan so that we can do some initial checks */
AssuanError
assuan_close_input_fd (ASSUAN_CONTEXT ctx)
{
  if (!ctx || ctx->input_fd == -1)
    return ASSUAN_Invalid_Value;
  close (ctx->input_fd);
  ctx->input_fd = -1;
  return 0;
}

/* Close the fd descriptor set by the command OUTPUT FD=n.  We handle
   this fd inside assuan so that we can do some initial checks */
AssuanError
assuan_close_output_fd (ASSUAN_CONTEXT ctx)
{
  if (!ctx || ctx->output_fd == -1)
    return ASSUAN_Invalid_Value;

  close (ctx->output_fd);
  ctx->output_fd = -1;
  return 0;
}

