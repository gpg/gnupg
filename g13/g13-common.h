/* g13.h - Global definitions for G13.
 * Copyright (C) 2009 Free Software Foundation, Inc.
 * Copyright (C) 2009, 2015 Werner Koch.
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

#ifndef G13_COMMON_H
#define G13_COMMON_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_G13
#include <gpg-error.h>

#include "../common/util.h"
#include "../common/status.h"
#include "../common/session-env.h"
#include "../common/strlist.h"


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

/* A large struct named "opt" to keep global flags.  Note that this
   struct is used by g13 and g13-syshelp and thus some fields may only
   make sense for one of them.  */
struct
{
  unsigned int debug; /* Debug flags (DBG_foo_VALUE).  */
  int verbose;        /* Verbosity level.  */
  int quiet;          /* Be as quiet as possible.  */
  int dry_run;        /* Don't change any persistent data.  */

  const char *config_filename; /* Name of the used config file.  */

  /* Filename of the AGENT program.  */
  const char *agent_program;

  /* Filename of the GPG program.  Unless set via an program option it
     is initialized at the first engine startup to the standard gpg
     filename.  */
  const char *gpg_program;

  /* GPG arguments.  XXX: Currently it is not possible to set them.  */
  strlist_t gpg_arguments;

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


/*-- g13-common.c --*/
void g13_init_signals (void);
void g13_install_emergency_cleanup (void);
void g13_exit (int rc);

/*-- server.c and g13-sh-cmd.c --*/
gpg_error_t g13_status (ctrl_t ctrl, int no, ...) GPGRT_ATTR_SENTINEL(0);


#endif /*G13_COMMON_H*/
