/* server.c - Server mode and main entry point 
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "gpgsm.h"
#include "../assuan/assuan.h"



void
gpgsm_server (void)
{
  int rc;
  int filedes[2];
  ASSUAN_CONTEXT ctx;

  /* For now we use a simple pipe based server so that we can work
     from scripts.  We will later add options to run as a daemon and
     wait for requests on a Unix domain socket */
  filedes[0] = 0;
  filedes[1] = 1;
  rc = assuan_init_pipe_server (&ctx, filedes);
  if (rc)
    {
      log_error ("failed to initialize the server: %s\n",
                 assuan_strerror(rc));
      gpgsm_exit (2);
    }


  assuan_deinit_pipe_server (ctx);
}
