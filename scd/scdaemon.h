/* scdaemon.h - Global definitions for the SCdaemon
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

#ifndef SCDAEMON_H
#define SCDAEMON_H

#include <time.h>
#include <gcrypt.h>
#include "../common/util.h"
#include "../common/errors.h"

#define MAX_DIGEST_LEN 24 

/* A large struct name "opt" to keep global flags */
struct {
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int verbose;      /* verbosity level */
  int quiet;        /* be as quiet as possible */
  int dry_run;      /* don't change any persistent data */
  int batch;        /* batch mode */
  const char *homedir; /* configuration directory name */
} opt;


#define DBG_COMMAND_VALUE 1	/* debug commands i/o */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_ASSUAN_VALUE 1024   

#define DBG_COMMAND (opt.debug & DBG_COMMAND_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_ASSUAN  (opt.debug & DBG_ASSUAN_VALUE)

struct server_local_s;
struct card_ctx_s;

struct server_control_s {
  struct server_local_s *server_local;
  struct card_ctx_s *card_ctx;

};
typedef struct server_control_s *CTRL;
typedef struct card_ctx_s *CARD;

/*-- scdaemon.c --*/
void scd_exit (int rc);
void scd_init_default_ctrl (CTRL ctrl);

/*-- command.c --*/
void scd_command_handler (int);

/*-- card.c --*/
int card_open (CARD *rcard);
void card_close (CARD card);
int card_get_serial_and_stamp (CARD card, char **serial, time_t *stamp);



#endif /*SCDAEMON_H*/
