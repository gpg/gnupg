/* scdaemon.h - Global definitions for the SCdaemon
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
#include "../common/sysutils.h"
#include "app-common.h"


/* To convey some special hash algorithms we use algorithm numbers
   reserved for application use. */
#ifndef GCRY_MODULE_ID_USER
#define GCRY_MODULE_ID_USER 1024
#endif
#define MD_USER_TLS_MD5SHA1 (GCRY_MODULE_ID_USER+1)

/* Maximum length of a digest.  */
#define MAX_DIGEST_LEN 64



/* A large struct name "opt" to keep global flags. */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  unsigned int debug; /* Debug flags (DBG_foo_VALUE). */
  int verbose;        /* Verbosity level. */
  int quiet;          /* Be as quiet as possible. */
  int dry_run;        /* Don't change any persistent data. */
  int batch;          /* Batch mode. */
  const char *ctapi_driver; /* Library to access the ctAPI. */
  const char *pcsc_driver;  /* Library to access the PC/SC system. */
  const char *reader_port;  /* NULL or reder port to use. */
  int disable_ccid;    /* Disable the use of the internal CCID driver. */
  int disable_pinpad;  /* Do not use a pinpad. */
  int enable_pinpad_varlen;  /* Use variable length input for pinpad. */
  int allow_admin;     /* Allow the use of admin commands for certain
                          cards. */
  int pcsc_shared;     /* Use shared PC/SC access.  */
  strlist_t disabled_applications;  /* Card applications we do not
                                       want to use. */
  unsigned long card_timeout; /* Disconnect after N seconds of inactivity.  */
} opt;


#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_CARD_VALUE    16    /* debug card info  */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_IPC_VALUE     1024
#define DBG_CARD_IO_VALUE 2048  /* debug card I/O (e.g. APDUs).  */
#define DBG_READER_VALUE  4096  /* Trace reader related functions.  */

#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)
#define DBG_CARD    (opt.debug & DBG_CARD_VALUE)
#define DBG_CARD_IO (opt.debug & DBG_CARD_IO_VALUE)
#define DBG_READER  (opt.debug & DBG_READER_VALUE)

struct server_local_s;
struct app_ctx_s;

struct server_control_s
{
  /* Private data used to fire up the connection thread.  We use this
     structure do avoid an extra allocation for just a few bytes. */
  struct {
    gnupg_fd_t fd;
  } thread_startup;

  /* Local data of the server; used only in command.c. */
  struct server_local_s *server_local;

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


/*-- scdaemon.c --*/
void scd_exit (int rc);
const char *scd_get_socket_name (void);

/*-- command.c --*/
gpg_error_t initialize_module_command (void);
int  scd_command_handler (ctrl_t, int);
void send_keyinfo (ctrl_t ctrl, int data, const char *keygrip_str,
                   const char *serialno, const char *idstr);
void send_status_info (ctrl_t ctrl, const char *keyword, ...)
     GPGRT_ATTR_SENTINEL(1);
gpg_error_t send_status_direct (ctrl_t ctrl, const char *keyword,
                                const char *args);
gpg_error_t send_status_printf (ctrl_t ctrl, const char *keyword,
                                const char *format, ...) GPGRT_ATTR_PRINTF(3,4);

void popup_prompt (void *opaque, int on);
void send_client_notifications (app_t app, int removal);
void scd_kick_the_loop (void);
int get_active_connection_count (void);

/*-- app.c --*/
int scd_update_reader_status_file (void);

#endif /*SCDAEMON_H*/
