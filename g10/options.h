/* options.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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
#ifndef G10_OPTIONS_H
#define G10_OPTIONS_H

#include <sys/types.h>
#include <types.h>
#include "main.h"
#include "packet.h"

#ifndef EXTERN_UNLESS_MAIN_MODULE
/* Norcraft can't cope with common symbols */
#if defined (__riscos__) && !defined (INCLUDED_BY_MAIN_MODULE)
#define EXTERN_UNLESS_MAIN_MODULE extern
#else
#define EXTERN_UNLESS_MAIN_MODULE 
#endif
#endif

EXTERN_UNLESS_MAIN_MODULE
struct
{
  int verbose;
  int quiet;
  unsigned debug;
  int armor;
  char *outfile;
  off_t max_output;
  int dry_run;
  int list_only;
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
  int with_fingerprint; /* opt --with-fingerprint active */
  int fingerprint; /* list fingerprints */
  int list_sigs;   /* list signatures */
  int no_armor;
  int list_packets; /* list-packets mode: 1=normal, 2=invoked by command*/
  int def_cipher_algo;
  int force_v3_sigs;
  int force_v4_certs;
  int force_mdc;
  int disable_mdc;
  int def_digest_algo;
  int cert_digest_algo;
  int compress_algo;
  int compress_level;
  int bz2_compress_level;
  int bz2_decompress_lowmem;
  const char *def_secret_key;
  char *def_recipient;
  int def_recipient_self;
  int def_cert_level;
  int min_cert_level;
  int ask_cert_level;
  int no_version;
  int marginals_needed;
  int completes_needed;
  int max_cert_depth;
  const char *homedir;

  char *display;      /* 5 options to be passed to the gpg-agent */
  char *ttyname;     
  char *ttytype;
  char *lc_ctype;
  char *lc_messages;

  int skip_verify;
  int compress_keys;
  int compress_sigs;
  /* TM_CLASSIC must be zero to accomodate trustdbs generated before
     we started storing the trust model inside the trustdb. */
  enum
    {
      TM_CLASSIC=0, TM_PGP=1, TM_EXTERNAL=2, TM_ALWAYS, TM_DIRECT, TM_AUTO
    } trust_model;
  int force_ownertrust;
  enum
    {
      CO_GNUPG, CO_RFC4880, CO_RFC2440, CO_RFC1991, CO_PGP2,
      CO_PGP6, CO_PGP7, CO_PGP8
    } compliance;
  enum
    {
      KF_SHORT, KF_LONG, KF_0xSHORT, KF_0xLONG
    } keyid_format;
  int pgp2_workarounds;
  int shm_coprocess;
  const char *set_filename;
  STRLIST comments;
  int throw_keyid;
  const char *photo_viewer;
  int s2k_mode;
  int s2k_digest_algo;
  int s2k_cipher_algo;
  unsigned char s2k_count; /* This is the encoded form, not the raw
			      count */
  int simple_sk_checksum; /* create the deprecated rfc2440 secret key
			     protection */
  int not_dash_escaped;
  int escape_from;
  int lock_once;
  struct keyserver_spec
  {
    char *uri;
    char *scheme;
    char *auth;
    char *host;
    char *port;
    char *path;
    char *opaque;
    STRLIST options;
    struct
    {
      unsigned int direct_uri:1;
    } flags;
    struct keyserver_spec *next;
  } *keyserver;
  struct
  {
    unsigned int options;
    unsigned int import_options;
    unsigned int export_options;
    STRLIST other;
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
  int no_perm_warn;
  int no_mdc_warn;
  char *temp_dir;
  int no_encrypt_to;
  int interactive;
  struct notation *sig_notations;
  struct notation *cert_notations;
  STRLIST sig_policy_url;
  STRLIST cert_policy_url;
  STRLIST sig_keyserver_url;
  STRLIST cert_subpackets;
  STRLIST sig_subpackets;
  int allow_non_selfsigned_uid;
  int allow_freeform_uid;
  int no_literal;
  ulong set_filesize;
  int fast_list_mode;
  int fixed_list_mode;
  int ignore_time_conflict;
  int ignore_valid_from;
  int ignore_crc_error;
  int ignore_mdc_error;
  int command_fd;
  const char *override_session_key;
  int show_session_key;
  int use_agent;
  const char *gpg_agent_info;
  int try_all_secrets;
  int no_expensive_trust_checks;
  int no_sig_cache;
  int no_sig_create_check;
  int no_auto_check_trustdb;
  int preserve_permissions;
  int no_homedir_creation;
  struct groupitem *grouplist;
  int strict;
  int mangle_dos_filenames;
  int enable_progress_filter;
  unsigned int screen_columns;
  unsigned int screen_lines;
  byte *show_subpackets;
  int rfc2440_text;

  /* If true, let write failures on the status-fd exit the process. */
  int exit_on_status_write_error;

  /* If > 0, limit the number of card insertion prompts to this
     value. */
  int limit_card_insert_tries; 

#ifdef ENABLE_CARD_SUPPORT
  const char *ctapi_driver; /* Library to access the ctAPI. */
  const char *pcsc_driver;  /* Library to access the PC/SC system. */
  int disable_ccid;    /* Disable the use of the internal CCID driver. */
#endif /*ENABLE_CARD_SUPPORT*/

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
  } flags;

  /* Linked list of ways to find a key if the key isn't on the local
     keyring. */
  struct akl
  {
    enum {AKL_CERT, AKL_PKA, AKL_LDAP, AKL_KEYSERVER, AKL_SPEC} type;
    struct keyserver_spec *spec;
    struct akl *next;
  } *auto_key_locate;

  int passwd_repeat;
} opt;

/* CTRL is used to keep some global variables we currently can't
   avoid.  Future concurrent versions of gpg will put it into a per
   request structure CTRL. */
EXTERN_UNLESS_MAIN_MODULE
struct {
  int in_auto_key_retrieve; /* True if we are doing an
                               auto_key_retrieve. */
} glo_ctrl;

#define DBG_PACKET_VALUE  1	/* debug packet reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CIPHER_VALUE  4	/* debug cipher handling */
				/* (may reveal sensitive data) */
#define DBG_FILTER_VALUE  8	/* debug internal filter handling */
#define DBG_IOBUF_VALUE   16	/* debug iobuf stuff */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the cacheing */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_TRUST_VALUE   256	/* debug the trustdb */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_EXTPROG_VALUE 1024  /* debug external program calls */
#define DBG_CARD_IO_VALUE 2048  /* debug smart card I/O.  */

#define DBG_PACKET (opt.debug & DBG_PACKET_VALUE)
#define DBG_FILTER (opt.debug & DBG_FILTER_VALUE)
#define DBG_CACHE  (opt.debug & DBG_CACHE_VALUE)
#define DBG_TRUST  (opt.debug & DBG_TRUST_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_EXTPROG (opt.debug & DBG_EXTPROG_VALUE)
#define DBG_CARD_IO (opt.debug & DBG_CARD_IO_VALUE)

#define GNUPG   (opt.compliance==CO_GNUPG)
#define RFC1991 (opt.compliance==CO_RFC1991 || opt.compliance==CO_PGP2)
#define RFC2440 (opt.compliance==CO_RFC2440)
#define RFC4880 (opt.compliance==CO_RFC4880)
#define PGP2    (opt.compliance==CO_PGP2)
#define PGP6    (opt.compliance==CO_PGP6)
#define PGP7    (opt.compliance==CO_PGP7)
#define PGP8    (opt.compliance==CO_PGP8)
#define PGPX    (PGP2 || PGP6 || PGP7 || PGP8)

/* Various option flags.  Note that there should be no common string
   names between the IMPORT_ and EXPORT_ flags as they can be mixed in
   the keyserver-options option. */

#define IMPORT_LOCAL_SIGS                (1<<0)
#define IMPORT_REPAIR_PKS_SUBKEY_BUG     (1<<1)
#define IMPORT_FAST                      (1<<2)
#define IMPORT_SK2PK                     (1<<3)
#define IMPORT_MERGE_ONLY                (1<<4)
#define IMPORT_MINIMAL                   (1<<5)
#define IMPORT_CLEAN                     (1<<6)

#define EXPORT_LOCAL_SIGS                (1<<0)
#define EXPORT_ATTRIBUTES                (1<<1)
#define EXPORT_SENSITIVE_REVKEYS         (1<<2)
#define EXPORT_RESET_SUBKEY_PASSWD       (1<<3)
#define EXPORT_MINIMAL                   (1<<4)
#define EXPORT_CLEAN                     (1<<5)

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

#define KEYSERVER_USE_TEMP_FILES         (1<<0)
#define KEYSERVER_KEEP_TEMP_FILES        (1<<1)
#define KEYSERVER_ADD_FAKE_V3            (1<<2)
#define KEYSERVER_AUTO_KEY_RETRIEVE      (1<<3)
#define KEYSERVER_HONOR_KEYSERVER_URL    (1<<4)
#define KEYSERVER_HONOR_PKA_RECORD       (1<<5)

#endif /*G10_OPTIONS_H*/
