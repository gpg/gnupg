/* tpm2daemon.h - Global definitions for the TPM2D
 * Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
 * Copyright (C) 2021 James Bottomley <James.Bottomley@HansenPartnership.com>
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

#ifndef TPM2DAEMON_H
#define TPM2DAEMON_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
/* FIXME: Replace this hard coded value as soon as we require a newer
 *        libgpg-error.  */
#define GPG_ERR_SOURCE_DEFAULT  16 /* GPG_ERR_SOURCE_TPM2 */
#include <gpg-error.h>

#include <time.h>
#include <gcrypt.h>
#include "../common/util.h"
#include "../common/sysutils.h"

/* Maximum length of a digest.  */
#define MAX_DIGEST_LEN 64



/* A large struct name "opt" to keep global flags. */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  unsigned int debug; /* Debug flags (DBG_foo_VALUE). */
  int verbose;        /* Verbosity level. */
  int quiet;          /* Be as quiet as possible. */
  unsigned long parent;	      /* TPM parent */
} opt;


#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_IPC_VALUE     1024

#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)

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

  /* The application context used with this connection or NULL if none
     associated.  Note that this is shared with the other connections:
     All connections accessing the same reader are using the same
     application context. */
  struct assuan_context_s *ctx;

  /* Helper to store the value we are going to sign */
  struct
  {
    unsigned char *value;
    int valuelen;
  } in_data;
};

typedef struct app_ctx_s *app_t;

/*-- tpm2daemon.c --*/
void tpm2d_exit (int rc);

/*-- command.c --*/
gpg_error_t initialize_module_command (void);
int  tpm2d_command_handler (ctrl_t, gnupg_fd_t);
void send_client_notifications (app_t app, int removal);
void tpm2d_kick_the_loop (void);
int get_active_connection_count (void);

#endif /*TPM2DAEMON_H*/
