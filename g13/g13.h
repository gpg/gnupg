/* g13.h - Global definitions for G13.
 * Copyright (C) 2009 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef G13_H
#define G13_H

#include "g13-common.h"


/* Forward declaration for an object defined in server.c.  */
struct server_local_s;
/* Forward declaration for an object defined in call-syshelp.c.  */
struct call_syshelp_s;


/* Session control object.  This object is passed down to most
   functions.  The default values for it are set by
   g13_init_default_ctrl(). */
struct server_control_s
{
  int no_server;      /* We are not running under server control */
  int  status_fd;     /* Only for non-server mode */
  struct server_local_s *server_local;
  struct call_syshelp_s *syshelp_local;

  int agent_seen;     /* Flag indicating that the gpg-agent has been
                         accessed.  */

  int with_colons;    /* Use column delimited output format */

  /* Type of the current container.  See the CONTTYPE_ constants.  */
  int conttype;

  strlist_t recipients; /* List of recipients.  */

};


/*-- g13.c --*/
void g13_init_default_ctrl (ctrl_t ctrl);
void g13_deinit_default_ctrl (ctrl_t ctrl);
void g13_request_shutdown (void);

#endif /*G13_H*/
