/* gpg-wks.h - Common definitions for wks server and client.
 * Copyright (C) 2016 g10 Code GmbH
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

#ifndef GNUPG_GPG_WKS_H
#define GNUPG_GPG_WKS_H

#include "../common/util.h"
#include "../common/strlist.h"

/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;
  unsigned int debug;
  int quiet;
  const char *gpg_program;
  const char *directory;
  const char *default_from;
  strlist_t extra_headers;
} opt;

/* Debug values and macros.  */
#define DBG_CRYPTO_VALUE      4	/* Debug low level crypto.  */
#define DBG_MEMORY_VALUE     32	/* Debug memory allocation stuff.  */
#define DBG_MEMSTAT_VALUE   128	/* Show memory statistics.  */
#define DBG_IPC_VALUE      1024 /* Debug assuan communication.  */
#define DBG_EXTPROG_VALUE 16384 /* debug external program calls */


/*-- wks-receive.c --*/
gpg_error_t wks_receive (estream_t fp,
                         gpg_error_t (*result_cb)(void *opaque,
                                                  const char *mediatype,
                                                  estream_t data),
                         void *cb_data);



#endif /*GNUPG_GPG_WKS_H*/
