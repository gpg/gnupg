/* options.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
#ifndef G10_OPTIONS_H
#define G10_OPTIONS_H

#include <types.h>
#include "main.h"
#include "packet.h"

#undef ENABLE_COMMENT_PACKETS  /* don't create comment packets */

#ifndef EXTERN_UNLESS_MAIN_MODULE
/* Norcraft can't cope with common symbols */
 #if defined (__riscos__) && !defined (INCLUDED_BY_MAIN_MODULE)
  #define EXTERN_UNLESS_MAIN_MODULE extern
 #else
  #define EXTERN_UNLESS_MAIN_MODULE 
 #endif
#endif

EXTERN_UNLESS_MAIN_MODULE
struct {
    int verbose;
    int quiet;
    unsigned debug;
    int armor;
    int compress;
    char *outfile;
    int dry_run;
    int list_only;
    int textmode;
    int expert;
    int ask_sig_expire;
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
    int def_compress_algo;
    const char *def_secret_key;
    char *def_recipient;
    int def_recipient_self;
    int def_cert_check_level;
    int sk_comments;
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
    int always_trust;
    int pgp2;
    int pgp6;
    int pgp7; /* if we get any more of these, it's time to look at a
		 special emulate_pgp variable... */
    int rfc1991;
    int rfc2440;
    int pgp2_workarounds;
    unsigned int emulate_bugs; /* bug emulation flags EMUBUG_xxxx */
    int shm_coprocess;
    const char *set_filename;
    const char *comment_string;
    int throw_keyid;
    int show_photos;
    const char *photo_viewer;
    int s2k_mode;
    int s2k_digest_algo;
    int s2k_cipher_algo;
    int simple_sk_checksum; /* create the deprecated rfc2440 secret
                               key protection*/
    int not_dash_escaped;
    int escape_from;
    int lock_once;
    char *keyserver_uri;
    char *keyserver_scheme;
    char *keyserver_host;
    char *keyserver_port;
    char *keyserver_opaque;
    struct
    {
      int verbose;
      int include_revoked;
      int include_disabled;
      int include_subkeys;
      int honor_http_proxy;
      int broken_http_proxy;
      int use_temp_files;
      int keep_temp_files;
      int fake_v3_keyids;
      int auto_key_retrieve;
      unsigned int import_options;
      unsigned int export_options;
      STRLIST other;
    } keyserver_options;
    int exec_disable;
    int exec_path_set;
    unsigned int import_options;
    unsigned int export_options;
    char *def_preference_list;
    prefitem_t *personal_cipher_prefs;
    prefitem_t *personal_digest_prefs;
    prefitem_t *personal_compress_prefs;
    int no_perm_warn;
    int no_mdc_warn;
    char *temp_dir;
    int no_encrypt_to;
    int interactive;
    STRLIST sig_notation_data;
    STRLIST cert_notation_data;
    int show_notation;
    STRLIST sig_policy_url;
    STRLIST cert_policy_url;
    int show_policy_url;
    int use_embedded_filename;
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
    int merge_only;
    int try_all_secrets;
    int no_expensive_trust_checks;
    int no_sig_cache;
    int no_sig_create_check;
    int no_auto_check_trustdb;
    int preserve_permissions;
    int no_homedir_creation;
    int show_keyring;
    struct groupitem *grouplist;
} opt;


#define EMUBUG_MDENCODE   4

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


#define DBG_PACKET (opt.debug & DBG_PACKET_VALUE)
#define DBG_FILTER (opt.debug & DBG_FILTER_VALUE)
#define DBG_CACHE  (opt.debug & DBG_CACHE_VALUE)
#define DBG_TRUST  (opt.debug & DBG_TRUST_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_EXTPROG (opt.debug & DBG_EXTPROG_VALUE)


#endif /*G10_OPTIONS_H*/
