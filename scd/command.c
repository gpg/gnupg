/* command.c - SCdaemon command handler
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

/* FIXME: we should not use the default assuan buffering but setup
   some buffering in secure mempory to protect session keys etc. */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "scdaemon.h"
#include "../assuan/assuan.h"

#define set_error(e,t) assuan_set_error (ctx, ASSUAN_ ## e, (t))

/* Data used to associate an Assuan context with local server data */
struct server_local_s {
  ASSUAN_CONTEXT assuan_ctx;
};




static void
reset_notify (ASSUAN_CONTEXT ctx)
{
/*    CTRL ctrl = assuan_get_pointer (ctx); */


}


static int
option_handler (ASSUAN_CONTEXT ctx, const char *key, const char *value)
{
/*    CTRL ctrl = assuan_get_pointer (ctx); */

/*    if (!strcmp (key, "foo")) */
/*      { */
/*      } */
/*    else */
/*      return ASSUAN_Invalid_Option; */

  return 0;
}








/* Tell the assuan library about our commands */
static int
register_commands (ASSUAN_CONTEXT ctx)
{
  static struct {
    const char *name;
    int cmd_id;
    int (*handler)(ASSUAN_CONTEXT, char *line);
  } table[] = {
    { "",     ASSUAN_CMD_INPUT, NULL }, 
    { "",     ASSUAN_CMD_OUTPUT, NULL }, 
    { NULL }
  };
  int i, j, rc;

  for (i=j=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx,
                                    table[i].cmd_id? table[i].cmd_id
                                                   : (ASSUAN_CMD_USER + j++),
                                    table[i].name, table[i].handler);
      if (rc)
        return rc;
    } 
  assuan_set_hello_line (ctx, "GNU Privacy Guard's Smartcard server ready");

  assuan_register_reset_notify (ctx, reset_notify);
  assuan_register_option_handler (ctx, option_handler);
  return 0;
}


/* Startup the server.  If LISTEN_FD is given as -1, this is simple
   piper server, otherwise it is a regular server */
void
scd_command_handler (int listen_fd)
{
  int rc;
  ASSUAN_CONTEXT ctx;
  struct server_control_s ctrl;

  memset (&ctrl, 0, sizeof ctrl);
  scd_init_default_ctrl (&ctrl);
  
  if (listen_fd == -1)
    {
      int filedes[2];

      filedes[0] = 0;
      filedes[1] = 1;
      rc = assuan_init_pipe_server (&ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (&ctx, listen_fd);
    }
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 assuan_strerror(rc));
      scd_exit (2);
    }
  rc = register_commands (ctx);
  if (rc)
    {
      log_error ("failed to register commands with Assuan: %s\n",
                 assuan_strerror(rc));
      scd_exit (2);
    }
  assuan_set_pointer (ctx, &ctrl);
  ctrl.server_local = xcalloc (1, sizeof *ctrl.server_local);
  ctrl.server_local->assuan_ctx = ctx;

  if (DBG_ASSUAN)
    assuan_set_log_stream (ctx, log_get_stream ());

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        {
          break;
        }
      else if (rc)
        {
          log_info ("Assuan accept problem: %s\n", assuan_strerror (rc));
          break;
        }
      
      rc = assuan_process (ctx);
      if (rc)
        {
          log_info ("Assuan processing failed: %s\n", assuan_strerror (rc));
          continue;
        }
    }


  assuan_deinit_server (ctx);
}
