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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_GPG_WKS_H
#define GNUPG_GPG_WKS_H

#include "../common/util.h"
#include "../common/strlist.h"
#include "mime-maker.h"

/* The draft version we implement.  */
#define WKS_DRAFT_VERSION 3


/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;
  unsigned int debug;
  int quiet;
  int use_sendmail;
  const char *output;
  const char *gpg_program;
  const char *directory;
  const char *default_from;
  strlist_t extra_headers;
} opt;

/* Debug values and macros.  */
#define DBG_MIME_VALUE        1 /* Debug the MIME structure.  */
#define DBG_PARSER_VALUE      2 /* Debug the Mail parser.  */
#define DBG_CRYPTO_VALUE      4	/* Debug low level crypto.  */
#define DBG_MEMORY_VALUE     32	/* Debug memory allocation stuff.  */
#define DBG_MEMSTAT_VALUE   128	/* Show memory statistics.  */
#define DBG_IPC_VALUE      1024 /* Debug assuan communication.  */
#define DBG_EXTPROG_VALUE 16384 /* debug external program calls */

#define DBG_MIME     (opt.debug & DBG_MIME_VALUE)
#define DBG_PARSER   (opt.debug & DBG_PARSER_VALUE)
#define DBG_CRYPTO   (opt.debug & DBG_CRYPTO_VALUE)


/* The parsed policy flags. */
struct policy_flags_s
{
  unsigned int mailbox_only : 1;
  unsigned int dane_only : 1;
  unsigned int auth_submit : 1;
  unsigned int max_pending;      /* Seconds to wait for a confirmation.  */
};
typedef struct policy_flags_s *policy_flags_t;



/*-- wks-util.c --*/
void wks_set_status_fd (int fd);
void wks_write_status (int no, const char *format, ...) GPGRT_ATTR_PRINTF(2,3);
gpg_error_t wks_list_key (estream_t key, char **r_fpr, strlist_t *r_mboxes);
gpg_error_t wks_send_mime (mime_maker_t mime);
gpg_error_t wks_parse_policy (policy_flags_t flags, estream_t stream,
                              int ignore_unknown);

/*-- wks-receive.c --*/

/* Flag values for the receive callback.  */
#define WKS_RECEIVE_DRAFT2 1

gpg_error_t wks_receive (estream_t fp,
                         gpg_error_t (*result_cb)(void *opaque,
                                                  const char *mediatype,
                                                  estream_t data,
                                                  unsigned int flags),
                         void *cb_data);



#endif /*GNUPG_GPG_WKS_H*/
