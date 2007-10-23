/* trustdb.h - Trust database
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004,
 *               2005 Free Software Foundation, Inc.
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

#ifndef G10_TRUSTDB_H
#define G10_TRUSTDB_H

/* Trust values must be sorted in ascending order */
#define TRUST_MASK	 15
#define TRUST_UNKNOWN	  0  /* o: not yet calculated/assigned */
#define TRUST_EXPIRED	  1  /* e: calculation may be invalid */
#define TRUST_UNDEFINED   2  /* q: not enough information for calculation */
#define TRUST_NEVER	  3  /* n: never trust this pubkey */
#define TRUST_MARGINAL	  4  /* m: marginally trusted */
#define TRUST_FULLY	  5  /* f: fully trusted      */
#define TRUST_ULTIMATE	  6  /* u: ultimately trusted */
/* trust values not covered by the mask */
#define TRUST_FLAG_REVOKED 32 /* r: revoked */
#define TRUST_FLAG_SUB_REVOKED 64 /* r: revoked but for subkeys */
#define TRUST_FLAG_DISABLED 128 /* d: key/uid disabled */
#define TRUST_FLAG_PENDING_CHECK 256 /* a check-trustdb is pending */

#define NAMEHASH_HASH DIGEST_ALGO_RMD160
#define NAMEHASH_LEN  20

/*-- trustdb.c --*/
void register_trusted_keyid(u32 *keyid);
void register_trusted_key( const char *string );
void check_trustdb (void);
void update_trustdb (void);
int setup_trustdb( int level, const char *dbname );
void init_trustdb( void );
void check_trustdb_stale(void);
void sync_trustdb( void );

const char *uid_trust_string_fixed(PKT_public_key *key,PKT_user_id *uid);
const char *trust_value_to_string (unsigned int value);
int string_to_trust_value (const char *str);

void revalidation_mark (void);
int trustdb_pending_check(void);
void trustdb_check_or_update(void);

int cache_disabled_value(PKT_public_key *pk);

unsigned int get_validity (PKT_public_key *pk, PKT_user_id *uid);
int get_validity_info (PKT_public_key *pk, PKT_user_id *uid);
const char *get_validity_string (PKT_public_key *pk, PKT_user_id *uid);

void list_trust_path( const char *username );
int enum_cert_paths( void **context, ulong *lid,
		     unsigned *ownertrust, unsigned *validity );
void enum_cert_paths_print( void **context, FILE *fp,
					   int refresh, ulong selected_lid );

void read_trust_options(byte *trust_model,ulong *created,ulong *nextcheck,
			byte *marginals,byte *completes,byte *cert_depth);

unsigned int get_ownertrust (PKT_public_key *pk);
unsigned int get_min_ownertrust (PKT_public_key *pk);
int get_ownertrust_info (PKT_public_key *pk);
const char *get_ownertrust_string (PKT_public_key *pk);

void update_ownertrust (PKT_public_key *pk, unsigned int new_trust );
int clear_ownertrusts (PKT_public_key *pk);

void clean_one_uid(KBNODE keyblock,KBNODE uidnode,int noisy,int self_only,
		   int *uids_cleaned,int *sigs_cleaned);
void clean_key(KBNODE keyblock,int noisy,int self_only,
	       int *uids_cleaned,int *sigs_cleaned);

/*-- tdbdump.c --*/
void list_trustdb(const char *username);
void export_ownertrust(void);
void import_ownertrust(const char *fname);

/*-- pkclist.c --*/
int edit_ownertrust (PKT_public_key *pk, int mode );

#endif /*G10_TRUSTDB_H*/
