/* scdaemon.h - Global definitions for the SCdaemon
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#ifndef SCDAEMON_H
#define SCDAEMON_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_SCD
#include <gpg-error.h>

#include <time.h>
#include <gcrypt.h>
#include "../common/util.h"
#include "../common/errors.h"


/* To convey some special hash algorithms we use algorithm numbers
   reserved for application use. */
#ifndef GCRY_MD_USER
#define GCRY_MD_USER 1024
#endif
#define GCRY_MD_USER_TLS_MD5SHA1 (GCRY_MD_USER+1)

/* Maximum length of a digest.  */
#define MAX_DIGEST_LEN 36



/* A large struct name "opt" to keep global flags. */
struct
{
  unsigned int debug; /* Debug flags (DBG_foo_VALUE). */
  int verbose;        /* Verbosity level. */
  int quiet;          /* Be as quiet as possible. */
  int dry_run;        /* Don't change any persistent data. */
  int batch;          /* Batch mode. */
  const char *homedir;      /* Configuration directory name. */
  const char *ctapi_driver; /* Library to access the ctAPI. */
  const char *pcsc_driver;  /* Library to access the PC/SC system. */
  const char *reader_port;  /* NULL or reder port to use. */
  int disable_ccid;    /* Disable the use of the internal CCID driver. */
  int disable_keypad;  /* Do not use a keypad. */
  int allow_admin;     /* Allow the use of admin commands for certain
                          cards. */
  strlist_t disabled_applications;  /* Card applications we do not
                                       want to use. */
} opt;


#define DBG_COMMAND_VALUE 1	/* debug commands i/o */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_ASSUAN_VALUE 1024   
#define DBG_CARD_IO_VALUE 2048

#define DBG_COMMAND (opt.debug & DBG_COMMAND_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_ASSUAN  (opt.debug & DBG_ASSUAN_VALUE)
#define DBG_CARD_IO (opt.debug & DBG_CARD_IO_VALUE)

struct server_local_s;
struct app_ctx_s;

struct server_control_s 
{
  /* Local data of the server; used only in command.c. */
  struct server_local_s *server_local;

  /* Slot of the open reader or -1 if not open. */
  int reader_slot; 

  /* The application context used with this connection or NULL if none
     associated.  Note that this is shared with the other connections:
     All connections accessing the same reader are using the same
     application context. */
  struct app_ctx_s *app_ctx;

  /* Helper to store the value we are going to sign */
  struct 
  {
    unsigned char *value;  
    int valuelen;
  } in_data;  
};

typedef struct server_control_s *ctrl_t;
typedef struct app_ctx_s *app_t;

/*-- scdaemon.c --*/
void scd_exit (int rc);
void scd_init_default_ctrl (ctrl_t ctrl);
const char *scd_get_socket_name (void);

/*-- command.c --*/
void scd_command_handler (int);
void send_status_info (ctrl_t ctrl, const char *keyword, ...)
     GNUPG_GCC_A_SENTINEL(1);
void scd_update_reader_status_file (void);


#endif /*SCDAEMON_H*/
