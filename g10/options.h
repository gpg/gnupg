/* options.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007, 2010, 2011 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH
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
#ifndef G10_OPTIONS_H
#define G10_OPTIONS_H

#include <sys/types.h>
#include "../common/types.h"
#include <stdint.h>
#include "main.h"
#include "packet.h"
#include "tofu.h"
#include "../common/session-env.h"
#include "../common/compliance.h"


/* Object to hold information pertaining to a keyserver; it also
   allows building a list of keyservers.  For historic reasons this is
   not a strlist_t.  */
struct keyserver_spec
{
  struct keyserver_spec *next;
  char *uri;
};
typedef struct keyserver_spec *keyserver_spec_t;


/* Global options for GPG.  */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  int verbose;
  int quiet;
  unsigned debug;
  int armor;
  char *outfile;
  estream_t outfp;  /* Hack, sometimes used in place of outfile.  */
  off_t max_output;

  /* If > 0 a hint with the expected number of input data bytes.  This
   * is not necessary an exact number but intended to be used for
   * progress info and to decide on how to allocate buffers.  */
  uint64_t input_size_hint;

  int dry_run;
  int autostart;
  int list_only;
  int mimemode;
  int textmode;
  int expert;
  const char *def_sig_expire;
  int ask_sig_expire;
  const char *def_cert_expire;
  int ask_cert_expire;
  int batch;	    /* run in batch mode */
  int answer_yes; /* answer yes on most questions */
  int answer_no;  /* answer no on most questions */
  int check_sigs; /* check key signatures */
  int with_colons;
  int with_key_data;
  int with_icao_spelling; /* Print ICAO spelling with fingerprints.  */
  int with_fingerprint; /* Option --with-fingerprint active.  */
  int with_subkey_fingerprint; /* Option --with-subkey-fingerprint active.  */
  int with_keygrip;     /* Option --with-keygrip active.  */
  int with_tofu_info;   /* Option --with-tofu_info active.  */
  int with_secret;      /* Option --with-secret active.  */
  int with_wkd_hash;    /* Option --with-wkd-hash.  */
  int with_key_origin;  /* Option --with-key-origin.  */
  int fingerprint; /* list fingerprints */
  int list_sigs;   /* list signatures */
  int no_armor;
  int list_packets; /* Option --list-packets active.  */
  int def_cipher_algo;
  int def_digest_algo;
  int force_ocb;
  int cert_digest_algo;
  int compress_algo;
  int explicit_compress_option; /* A compress option was explicitly given. */
  int compress_level;
  int bz2_compress_level;
  int bz2_decompress_lowmem;
  strlist_t def_secret_key;
  char *def_recipient;
  int def_recipient_self;
  strlist_t secret_keys_to_try;

  /* A list of mail addresses (addr-spec) provided by the user with
   * the option --sender.  */
  strlist_t sender_list;

  /* A list of fingerprints added as designated revokers to new keys.  */
  strlist_t desig_revokers;

  int def_cert_level;
  int min_cert_level;
  int ask_cert_level;
  int emit_version;       /* 0 = none,
                             1 = major only,
                             2 = major and minor,
                             3 = full version,
                             4 = full version plus OS string. */
  int marginals_needed;
  int completes_needed;
  int max_cert_depth;
  const char *agent_program;
  const char *dirmngr_program;
  int disable_dirmngr;

  const char *def_new_key_algo;

  strlist_t def_new_key_adsks;  /* Option --default-new-key-adsk.  */

  /* Options to be passed to the gpg-agent */
  session_env_t session_env;
  char *lc_ctype;
  char *lc_messages;

  int skip_verify;
  int skip_hidden_recipients;

  /* TM_CLASSIC must be zero to accommodate trustdbsg generated before
     we started storing the trust model inside the trustdb. */
  enum
    {
      TM_CLASSIC=0, TM_PGP=1, TM_EXTERNAL=2,
      TM_ALWAYS, TM_DIRECT, TM_AUTO, TM_TOFU, TM_TOFU_PGP
    } trust_model;
  enum tofu_policy tofu_default_policy;
  int force_ownertrust;
  enum gnupg_compliance_mode compliance;
  enum
    {
      KF_DEFAULT, KF_NONE, KF_SHORT, KF_LONG, KF_0xSHORT, KF_0xLONG
    } keyid_format;
  const char *set_filename;
  strlist_t comments;
  int throw_keyids;
  const char *photo_viewer;
  int s2k_mode;
  int s2k_digest_algo;
  int s2k_cipher_algo;
  unsigned char s2k_count; /* This is the encoded form, not the raw
			      count */
  int not_dash_escaped;
  int escape_from;
  int lock_once;
  keyserver_spec_t keyserver;  /* The list of configured keyservers.  */
  struct
  {
    unsigned int options;
    unsigned int import_options;
    unsigned int export_options;
    char *http_proxy;
  } keyserver_options;
  int exec_disable;
  int exec_path_set;
  unsigned int import_options;
  unsigned int export_options;
  unsigned int list_options;
  unsigned int verify_options;
  const char *def_preference_list;
  const char *def_keyserver_url;
  prefitem_t *personal_cipher_prefs;
  prefitem_t *personal_digest_prefs;
  prefitem_t *personal_compress_prefs;
  struct weakhash *weak_digests;
  int no_perm_warn;
  char *temp_dir;
  int no_encrypt_to;
  int encrypt_to_default_key;
  int interactive;
  struct notation *sig_notations;
  struct notation *cert_notations;
  strlist_t sig_policy_url;
  strlist_t cert_policy_url;
  strlist_t sig_keyserver_url;
  strlist_t cert_subpackets;
  strlist_t sig_subpackets;
  int allow_non_selfsigned_uid;
  int allow_freeform_uid;
  int no_literal;
  ulong set_filesize;
  int fast_list_mode;
  int legacy_list_mode;
  int ignore_time_conflict;
  int ignore_valid_from;
  int ignore_crc_error;
  int ignore_mdc_error;
  int command_fd;
  const char *override_session_key;
  int show_session_key;

  const char *gpg_agent_info;
  int try_all_secrets;
  int no_expensive_trust_checks;
  int no_sig_cache;
  int no_auto_check_trustdb;
  int preserve_permissions;
  int no_homedir_creation;
  struct groupitem *grouplist;
  int mangle_dos_filenames;
  int enable_progress_filter;
  unsigned int screen_columns;
  unsigned int screen_lines;
  byte *show_subpackets;
  int rfc2440_text;
  unsigned int min_rsa_length;   /* Used for compliance checks.  */

  /* If true, let write failures on the status-fd exit the process. */
  int exit_on_status_write_error;

  /* If > 0, limit the number of card insertion prompts to this
     value. */
  int limit_card_insert_tries;

  struct
  {
    /* If set, require an 0x19 backsig to be present on signatures
       made by signing subkeys.  If not set, a missing backsig is not
       an error (but an invalid backsig still is). */
    unsigned int require_cross_cert:1;

    unsigned int use_embedded_filename:1;
    unsigned int utf8_filename:1;
    unsigned int dsa2:1;
    unsigned int allow_multiple_messages:1;
    unsigned int allow_weak_digest_algos:1;
    unsigned int allow_weak_key_signatures:1;
    unsigned int large_rsa:1;
    unsigned int disable_signer_uid:1;
    unsigned int include_key_block:1;
    unsigned int auto_key_import:1;
    /* Flag to enable experimental features from RFC4880bis.  */
    unsigned int rfc4880bis:1;
    /* Hack: --output is not given but OUTFILE was temporary set to "-".  */
    unsigned int dummy_outfile:1;
    /* Force the use of the OpenPGP card and do not allow the use of
     * another card.  */
    unsigned int use_only_openpgp_card:1;
    /* Force signing keys even if a key signature already exists.  */
    unsigned int force_sign_key:1;
    /* The next flag is set internally iff IMPORT_SELF_SIGS_ONLY has
     * been set by the user and is not the default value.  */
    unsigned int expl_import_self_sigs_only:1;
    /* Fail if an operation can't be done in the requested compliance
     * mode.  */
    unsigned int require_compliance:1;
    /* Process all signatures even in batch mode.  */
    unsigned int proc_all_sigs:1;
  } flags;

  /* Linked list of ways to find a key if the key isn't on the local
     keyring. */
  struct akl
  {
    enum {
      AKL_NODEFAULT,
      AKL_LOCAL,
      AKL_CERT,
      AKL_PKA,
      AKL_DANE,
      AKL_WKD,
      AKL_LDAP,
      AKL_NTDS,
      AKL_KEYSERVER,
      AKL_SPEC
    } type;
    keyserver_spec_t spec;
    struct akl *next;
  } *auto_key_locate;

  /* The value of --key-origin.  See parse_key_origin().  */
  int key_origin;
  char *key_origin_url;

  int passphrase_repeat;
  int pinentry_mode;
  int request_origin;

  int unwrap_encryption;
  int only_sign_text_ids;

  int no_symkey_cache;   /* Disable the cache used for --symmetric.  */

  /* Compatibility flags (COMPAT_FLAG_xxxx).  */
  unsigned int compat_flags;
} opt;

/* CTRL is used to keep some global variables we currently can't
   avoid.  Future concurrent versions of gpg will put it into a per
   request structure CTRL. */
EXTERN_UNLESS_MAIN_MODULE
struct {
  int in_auto_key_retrieve; /* True if we are doing an
                               auto_key_retrieve. */
  /* Hack to store the last error.  We currently need it because the
     proc_packet machinery is not able to reliabale return error
     codes.  Thus for the --server purposes we store some of the error
     codes here.  FIXME! */
  gpg_error_t lasterr;

  /* Kludge to silence some warnings using --secret-key-list. */
  int silence_parse_warnings;
} glo_ctrl;

#define DBG_PACKET_VALUE  1	/* debug packet reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug crypto handling */
				/* (may reveal sensitive data) */
#define DBG_FILTER_VALUE  8	/* debug internal filter handling */
#define DBG_IOBUF_VALUE   16	/* debug iobuf stuff */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_TRUST_VALUE   256	/* debug the trustdb */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_IPC_VALUE     1024  /* debug assuan communication */
#define DBG_CLOCK_VALUE   4096
#define DBG_LOOKUP_VALUE  8192	/* debug the key lookup */
#define DBG_EXTPROG_VALUE 16384 /* debug external program calls */

/* Tests for the debugging flags.  */
#define DBG_PACKET (opt.debug & DBG_PACKET_VALUE)
#define DBG_MPI    (opt.debug & DBG_MPI_VALUE)
#define DBG_CRYPTO (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_FILTER (opt.debug & DBG_FILTER_VALUE)
#define DBG_CACHE  (opt.debug & DBG_CACHE_VALUE)
#define DBG_TRUST  (opt.debug & DBG_TRUST_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)
#define DBG_CLOCK   (opt.debug & DBG_CLOCK_VALUE)
#define DBG_LOOKUP  (opt.debug & DBG_LOOKUP_VALUE)
#define DBG_EXTPROG (opt.debug & DBG_EXTPROG_VALUE)

/* FIXME: We need to check why we did not put this into opt. */
#define DBG_MEMORY    memory_debug_mode
#define DBG_MEMSTAT   memory_stat_debug_mode

EXTERN_UNLESS_MAIN_MODULE int memory_debug_mode;
EXTERN_UNLESS_MAIN_MODULE int memory_stat_debug_mode;

/* Compatibility flags */


/* Compliance test macors.  */
#define GNUPG   (opt.compliance==CO_GNUPG || opt.compliance==CO_DE_VS)
#define RFC2440 (opt.compliance==CO_RFC2440)
#define RFC4880 (opt.compliance==CO_RFC4880)
#define PGP6    (opt.compliance==CO_PGP6)
#define PGP7    (opt.compliance==CO_PGP7)
#define PGP8    (opt.compliance==CO_PGP8)
#define PGPX    (PGP6 || PGP7 || PGP8)

/* Various option flags.  Note that there should be no common string
   names between the IMPORT_ and EXPORT_ flags as they can be mixed in
   the keyserver-options option. */

#define IMPORT_LOCAL_SIGS                (1<<0)
#define IMPORT_REPAIR_PKS_SUBKEY_BUG     (1<<1)
#define IMPORT_FAST                      (1<<2)
#define IMPORT_SHOW                      (1<<3)
#define IMPORT_MERGE_ONLY                (1<<4)
#define IMPORT_MINIMAL                   (1<<5)
#define IMPORT_CLEAN                     (1<<6)
#define IMPORT_ONLY_PUBKEYS              (1<<7)
#define IMPORT_KEEP_OWNERTTRUST          (1<<8)
#define IMPORT_EXPORT                    (1<<9)
#define IMPORT_RESTORE                   (1<<10)
#define IMPORT_REPAIR_KEYS               (1<<11)
#define IMPORT_DRY_RUN                   (1<<12)
#define IMPORT_SELF_SIGS_ONLY            (1<<14)

#define EXPORT_LOCAL_SIGS                (1<<0)
#define EXPORT_ATTRIBUTES                (1<<1)
#define EXPORT_SENSITIVE_REVKEYS         (1<<2)
#define EXPORT_RESET_SUBKEY_PASSWD       (1<<3)
#define EXPORT_MINIMAL                   (1<<4)
#define EXPORT_CLEAN                     (1<<5)
#define EXPORT_PKA_FORMAT                (1<<6)
#define EXPORT_DANE_FORMAT               (1<<7)
#define EXPORT_BACKUP                    (1<<10)
#define EXPORT_REVOCS                    (1<<11)

#define LIST_SHOW_PHOTOS                 (1<<0)
#define LIST_SHOW_POLICY_URLS            (1<<1)
#define LIST_SHOW_STD_NOTATIONS          (1<<2)
#define LIST_SHOW_USER_NOTATIONS         (1<<3)
#define LIST_SHOW_NOTATIONS (LIST_SHOW_STD_NOTATIONS|LIST_SHOW_USER_NOTATIONS)
#define LIST_SHOW_KEYSERVER_URLS         (1<<4)
#define LIST_SHOW_UID_VALIDITY           (1<<5)
#define LIST_SHOW_UNUSABLE_UIDS          (1<<6)
#define LIST_SHOW_UNUSABLE_SUBKEYS       (1<<7)
#define LIST_SHOW_KEYRING                (1<<8)
#define LIST_SHOW_SIG_EXPIRE             (1<<9)
#define LIST_SHOW_SIG_SUBPACKETS         (1<<10)
#define LIST_SHOW_USAGE                  (1<<11)
#define LIST_SHOW_ONLY_FPR_MBOX          (1<<12)
#define LIST_SHOW_PREF                   (1<<14)
#define LIST_SHOW_PREF_VERBOSE           (1<<15)

#define VERIFY_SHOW_PHOTOS               (1<<0)
#define VERIFY_SHOW_POLICY_URLS          (1<<1)
#define VERIFY_SHOW_STD_NOTATIONS        (1<<2)
#define VERIFY_SHOW_USER_NOTATIONS       (1<<3)
#define VERIFY_SHOW_NOTATIONS (VERIFY_SHOW_STD_NOTATIONS|VERIFY_SHOW_USER_NOTATIONS)
#define VERIFY_SHOW_KEYSERVER_URLS       (1<<4)
#define VERIFY_SHOW_UID_VALIDITY         (1<<5)
#define VERIFY_SHOW_UNUSABLE_UIDS        (1<<6)
#define VERIFY_PKA_LOOKUPS               (1<<7)
#define VERIFY_PKA_TRUST_INCREASE        (1<<8)
#define VERIFY_SHOW_PRIMARY_UID_ONLY     (1<<9)

#define KEYSERVER_HTTP_PROXY             (1<<0)
#define KEYSERVER_TIMEOUT                (1<<1)
#define KEYSERVER_ADD_FAKE_V3            (1<<2)
#define KEYSERVER_AUTO_KEY_RETRIEVE      (1<<3)
#define KEYSERVER_HONOR_KEYSERVER_URL    (1<<4)
#define KEYSERVER_HONOR_PKA_RECORD       (1<<5)


#endif /*G10_OPTIONS_H*/
