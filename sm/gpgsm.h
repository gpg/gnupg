/* gpgsm.h - Global definitions for GpgSM
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

#ifndef GPGSM_H
#define GPGSM_H

#include "util.h"

/* A large struct name "opt" to keep global flags */
struct {
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int verbose;      /* verbosity level */
  int quiet;        /* be as quiet as possible */
  int batch;        /* run in batch mode, i.e w/o any user interaction */
  int answer_yes;   /* assume yes on most questions */
  int answer_no;    /* assume no on most questions */
  int dry_run;      /* don't change any persistent data */

  const char *homedir; /* configuration directory name */
  char *outfile;    /* name of output file */

  int with_colons;  /* use column delimited output format */
  int with_key_data;/* include raw key in the column delimted output */

  int fingerprint;  /* list fingerprints in all key listings */

  int armor;        /* force base64 armoring */
  int no_armor;     /* don't try to figure out whether data is base64 armored*/

  int def_cipher_algo;    /* cipher algorithm to use if nothing else is know */
  int def_digest_algo;    /* Ditto for hash algorithm */
  int def_compress_algo;  /* Ditto for compress algorithm */

  char *def_recipient;    /* userID of the default recipient */
  int def_recipient_self; /* The default recipient is the default key */

  int always_trust;       /* Trust the given keys even if there is no
                             valid certification path */
  int skip_verify;        /* do not check signatures on data */

  int lock_once;          /* Keep lock once they are set */

  int ignore_time_conflict; /* Ignore certain time conflicts */

} opt;


#define DBG_X509_VALUE    1	/* debug x.509 data reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CIPHER_VALUE  4	/* debug cipher handling */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */

#define DBG_X509    (opt.debug & DBG_X509_VALUE)
#define DBG_CIPHER  (opt.debug & DBG_CIPHER_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)

/*-- gpgsm.c --*/
void gpgsm_exit (int rc);

/*-- server.c --*/
void gpgsm_server (void);


#endif /*GPGSM_H*/
