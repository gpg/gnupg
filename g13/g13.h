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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G13_H
#define G13_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_G13
#include <gpg-error.h>

#include "../common/util.h"
#include "../common/status.h"
#include "../common/session-env.h"

/* A large struct named "opt" to keep global flags.  */
struct
{
  unsigned int debug; /* Debug flags (DBG_foo_VALUE).  */
  int verbose;        /* Verbosity level.  */
  int quiet;          /* Be as quiet as possible.  */
  int dry_run;        /* Don't change any persistent data.  */

  const char *homedir;         /* Configuration directory name.  */
  const char *config_filename; /* Name of the used config file.  */

  /* Filename of the AGENT program.  */
  const char *agent_program;

  /* Filename of the GPG program.  Unless set via an program option it
     is initialzed at the first engine startup to the standard gpg
     filename.  */
  const char *gpg_program;

  /* Environment variables passed along to the engine.  */
  char *display;
  char *ttyname;
  char *ttytype;
  char *lc_ctype;
  char *lc_messages;
  char *xauthority;
  char *pinentry_user_data;
  session_env_t session_env;

  /* Name of the output file - FIXME: what is this?  */
  const char *outfile;

} opt;


/* Debug values and macros.  */
#define DBG_MOUNT_VALUE     1	/* Debug mount or device stuff. */
#define DBG_CRYPTO_VALUE    4	/* Debug low level crypto.  */
#define DBG_MEMORY_VALUE   32	/* Debug memory allocation stuff.  */
#define DBG_MEMSTAT_VALUE 128	/* Show memory statistics.  */
#define DBG_IPC_VALUE    1024   /* Debug assuan communication.  */

#define DBG_MOUNT    (opt.debug & DBG_MOUNT_VALUE)
#define DBG_CRYPTO   (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY   (opt.debug & DBG_MEMORY_VALUE)
#define DBG_IPC      (opt.debug & DBG_IPC_VALUE)

/* Forward declaration for an object defined in server.c.  */
struct server_local_s;

/* Session control object.  This object is passed down to most
   functions.  The default values for it are set by
   g13_init_default_ctrl(). */
struct server_control_s
{
  int no_server;      /* We are not running under server control */
  int  status_fd;     /* Only for non-server mode */
  struct server_local_s *server_local;

  int agent_seen;     /* Flag indicating that the gpg-agent has been
                         accessed.  */

  int with_colons;    /* Use column delimited output format */

  /* Type of the current container.  See the CONTTYPE_ constants.  */
  int conttype;

};



/*-- g13.c --*/
void g13_exit (int rc);
void g13_init_default_ctrl (struct server_control_s *ctrl);

/*-- server.c (commonly used, thus declared here) --*/
gpg_error_t g13_status (ctrl_t ctrl, int no, ...) GPGRT_ATTR_SENTINEL(0);


#endif /*G13_H*/
