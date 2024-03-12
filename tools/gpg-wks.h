/* gpg-wks.h - Common definitions for wks server and client.
 * Copyright (C) 2016 g10 Code GmbH
 * Copyright (C) 2016 Bundesamt für Sicherheit in der Informationstechnik
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
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
EXTERN_UNLESS_MAIN_MODULE
struct
{
  int verbose;
  unsigned int debug;
  int quiet;
  int use_sendmail;
  int with_colons;
  int no_autostart;
  int add_revocs;
  int realclean;
  char *output;
  char *gpg_program;
  char *directory;
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
  char *submission_address;
  unsigned int mailbox_only : 1;
  unsigned int dane_only : 1;
  unsigned int auth_submit : 1;
  unsigned int protocol_version; /* The supported WKS_DRAFT_VERION or 0  */
  unsigned int max_pending;      /* Seconds to wait for a confirmation.  */
};
typedef struct policy_flags_s *policy_flags_t;


/* An object to convey user ids of a key.  */
struct uidinfo_list_s
{
  struct uidinfo_list_s *next;
  time_t created; /* Time the userid was created.  */
  char *mbox;  /* NULL or the malloced mailbox from UID.  */
  unsigned int flags;  /* These flags are cleared on creation.  */
  unsigned int expired:1;
  unsigned int revoked:1;
  char uid[1];
};
typedef struct uidinfo_list_s *uidinfo_list_t;



/*-- wks-util.c --*/
void wks_set_status_fd (int fd);
void wks_write_status (int no, const char *format, ...) GPGRT_ATTR_PRINTF(2,3);
void free_uidinfo_list (uidinfo_list_t list);
gpg_error_t wks_get_key (estream_t *r_key, const char *fingerprint,
                         const char *addrspec, int exact, int binary);
gpg_error_t wks_list_key (estream_t key, char **r_fpr,
                          uidinfo_list_t *r_mboxes);
gpg_error_t wks_filter_uid (estream_t *r_newkey, estream_t key,
                            const char *uid, int binary);
gpg_error_t wks_armor_key (estream_t *r_newkey, estream_t key,
                           const char *prefix);
gpg_error_t wks_find_add_revocs (estream_t key, const char *addrspec);
gpg_error_t wks_send_mime (mime_maker_t mime);
gpg_error_t wks_parse_policy (policy_flags_t flags, estream_t stream,
                              int ignore_unknown);
void wks_free_policy (policy_flags_t policy);
gpg_error_t wks_write_to_file (estream_t src, const char *fname);

gpg_error_t wks_fname_from_userid (const char *userid, int hash_only,
                                   char **r_fname, char **r_addrspec);
gpg_error_t wks_compute_hu_fname (char **r_fname, const char *addrspec);
gpg_error_t wks_install_key_core (estream_t key, const char *addrspec);
gpg_error_t wks_cmd_install_key (const char *fname, const char *userid);
gpg_error_t wks_cmd_remove_key (const char *userid);
gpg_error_t wks_cmd_print_wkd_hash (const char *userid);
gpg_error_t wks_cmd_print_wkd_url (const char *userid);


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
