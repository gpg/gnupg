/* options.h
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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

#undef ENABLE_COMMENT_PACKETS  /* don't create comment packets */


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
    int batch;	    /* run in batch mode */
    int answer_yes; /* answer yes on most questions */
    int answer_no;  /* answer no on most questions */
    int check_sigs; /* check key signatures */
    int with_colons;
    int with_key_data;
    int fingerprint; /* list fingerprints */
    int list_sigs;   /* list signatures */
    int no_armor;
    int list_packets; /* list-packets mode: 1=normal, 2=invoked by command*/
    int def_cipher_algo;
    int force_v3_sigs;
    int force_mdc;
    int def_digest_algo;
    int def_compress_algo;
    const char *def_secret_key;
    char *def_recipient;
    int def_recipient_self;
    int no_comment;
    int no_version;
    int marginals_needed;
    int completes_needed;
    int max_cert_depth;
    const char *homedir;
    int skip_verify;
    int compress_keys;
    int compress_sigs;
    int always_trust;
    int rfc1991;
    int rfc2440;
    int pgp2_workarounds;
    unsigned int emulate_bugs; /* bug emulation flags EMUBUG_xxxx */
    int shm_coprocess;
    const char *set_filename;
    const char *comment_string;
    int throw_keyid;
    int s2k_mode;
    int s2k_digest_algo;
    int s2k_cipher_algo;
    int not_dash_escaped;
    int escape_from;
    int lock_once;
    const char *keyserver_name;
    int no_encrypt_to;
    int interactive;
    STRLIST notation_data;
    const char *set_policy_url;
    int use_embedded_filename;
    int allow_non_selfsigned_uid;
    int allow_freeform_uid;
    int no_literal;
    ulong set_filesize;
    int honor_http_proxy;
    int fast_list_mode;
    int fixed_list_mode;
    int ignore_time_conflict;
    int ignore_crc_error;
    int command_fd;
    int auto_key_retrieve;
    const char *override_session_key;
    int show_session_key;
    int use_agent;
    int merge_only;
    int allow_secret_key_import;
    int try_all_secrets;
    int no_expensive_trust_checks;
    int no_sig_cache;
    int no_sig_create_check;
} opt;


#define EMUBUG_GPGCHKSUM  1
#define EMUBUG_3DESS2K	  2
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


#define DBG_PACKET (opt.debug & DBG_PACKET_VALUE)
#define DBG_FILTER (opt.debug & DBG_FILTER_VALUE)
#define DBG_CACHE  (opt.debug & DBG_CACHE_VALUE)
#define DBG_TRUST  (opt.debug & DBG_TRUST_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)


#endif /*G10_OPTIONS_H*/
