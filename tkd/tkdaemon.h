/* tkdaemon.h - Global definitions for the TKdaemon
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef TKDAEMON_H
#define TKDAEMON_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  18 // GPG_ERR_SOURCE_TKD
#include <gpg-error.h>
#include <assuan.h>

#include <time.h>
#include <gcrypt.h>
#include "../common/util.h"
#include "../common/sysutils.h"

typedef struct token_ctx_s *token_t;

/* A large struct name "opt" to keep global flags. */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  unsigned int debug; /* Debug flags (DBG_foo_VALUE). */
  int verbose;        /* Verbosity level. */
  int quiet;          /* Be as quiet as possible. */
  int dry_run;        /* Don't change any persistent data. */
  int batch;          /* Batch mode. */
  const char *pkcs11_driver; /* Library to access the PKCS#1 module. */
} opt;


#define DBG_APP_VALUE     1     /* Debug app specific stuff.  */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_TOKEN_VALUE   16    /* debug token info  */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_IPC_VALUE     1024
#define DBG_TOKEN_IO_VALUE 2048  /* debug token I/O.  */

#define DBG_APP     (opt.debug & DBG_APP_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)
#define DBG_TOKEN    (opt.debug & DBG_TOKEN_VALUE)
#define DBG_TOKEN_IO (opt.debug & DBG_TOKEN_IO_VALUE)

struct server_local_s;

struct server_control_s
{
  /* Private data used to fire up the connection thread.  We use this
     structure do avoid an extra allocation for just a few bytes. */
  struct {
    gnupg_fd_t fd;
  } thread_startup;

  /* Local data of the server; used only in command.c. */
  struct server_local_s *server_local;

  /* Helper to store the value we are going to sign */
  struct
  {
    unsigned char *value;
    int valuelen;
  } in_data;
};


/*-- tkdaemon.c --*/
void tkd_exit (int rc);
void tkd_kick_the_loop (void);
const char *tkd_get_socket_name (void);
int get_active_connection_count (void);

/*-- command.c --*/
gpg_error_t initialize_module_command (void);
int  tkd_command_handler (ctrl_t, gnupg_fd_t);
void send_status_info (ctrl_t ctrl, const char *keyword, ...)
     GPGRT_ATTR_SENTINEL(1);
gpg_error_t send_status_direct (ctrl_t ctrl,
                                const char *keyword, const char *args);
gpg_error_t send_status_printf (ctrl_t ctrl, const char *keyword,
                                const char *format, ...) GPGRT_ATTR_PRINTF(3,4);
void send_keyinfo (ctrl_t ctrl, int data, const char *keygrip_str,
                   const char *serialno, const char *idstr,
                   const char *usage);

/*-- pkcs11.c --*/
gpg_error_t tkd_init (ctrl_t ctrl, assuan_context_t ctx, int rescan);
gpg_error_t tkd_fini (ctrl_t ctrl, assuan_context_t ctx);

gpg_error_t tkd_sign (ctrl_t ctrl, assuan_context_t ctx,
                      const char *keygrip, int hash_algo,
                      unsigned char **r_outdata,
                      size_t *r_outdatalen);
gpg_error_t tkd_readkey (ctrl_t ctrl, assuan_context_t ctx,
                         const char *keygrip);
gpg_error_t tkd_keyinfo (ctrl_t ctrl, assuan_context_t ctx,
                         const char *keygrip, int opt_data, int cap);
gpg_error_t tkd_readcert (ctrl_t ctrl, assuan_context_t ctx,
                          const char *keygrip);

#endif /*TKDAEMON_H*/
