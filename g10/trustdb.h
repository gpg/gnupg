/* trustdb.h - Trust database
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

#ifndef G10_TRUSTDB_H
#define G10_TRUSTDB_H


/* Trust values must be sorted in ascending order */
#define TRUST_MASK	 15
#define TRUST_UNKNOWN	  0  /* o: not yet calculated */
#define TRUST_EXPIRED	  1  /* e: calculation may be invalid */
#define TRUST_UNDEFINED   2  /* q: not enough information for calculation */
#define TRUST_NEVER	  3  /* n: never trust this pubkey */
#define TRUST_MARGINAL	  4  /* m: marginally trusted */
#define TRUST_FULLY	  5  /* f: fully trusted      */
#define TRUST_ULTIMATE	  6  /* u: ultimately trusted */
/* trust values not covered by the mask */
#define TRUST_FLAG_REVOKED 32 /* r: revoked */
#define TRUST_FLAG_SUB_REVOKED 64
#define TRUST_FLAG_DISABLED 128 /* d: key/uid disabled */


#define PREFTYPE_SYM	  1
#define PREFTYPE_HASH	  2
#define PREFTYPE_COMPR	  3


/*-- trustdb.c --*/
void list_trust_path( const char *username );
void register_trusted_key( const char *string );
void check_trustdb( const char *username );
void update_trustdb( void );
int setup_trustdb( int level, const char *dbname );
void init_trustdb( void );
void sync_trustdb( void );
int check_trust( PKT_public_key *pk, unsigned *r_trustlevel,
		 const byte* nh, int (*add_fnc)(ulong), unsigned *retflgs );
int query_trust_info( PKT_public_key *pk, const byte *nh );
int enum_cert_paths( void **context, ulong *lid,
		     unsigned *ownertrust, unsigned *validity );
void enum_cert_paths_print( void **context, FILE *fp,
					   int refresh, ulong selected_lid );
unsigned get_ownertrust( ulong lid );
int get_ownertrust_info( ulong lid );
byte *get_pref_data( ulong lid, const byte *namehash, size_t *ret_n );
int is_algo_in_prefs( ulong lid, int preftype, int algo );
int keyid_from_lid( ulong lid, u32 *keyid );
ulong lid_from_keyblock( KBNODE keyblock );
int query_trust_record( PKT_public_key *pk );
int clear_trust_checked_flag( PKT_public_key *pk );
int update_trust_record( KBNODE keyblock, int fast, int *modified );
int insert_trust_record( KBNODE keyblock );
int insert_trust_record_by_pk( PKT_public_key *pk );
int update_ownertrust( ulong lid, unsigned new_trust );
int trust_letter( unsigned value );

/*-- tdbdump.c --*/
void list_trustdb(const char *username);
void export_ownertrust(void);
void import_ownertrust(const char *fname);

/*-- pkclist.c --*/
int edit_ownertrust( ulong lid, int mode );

#endif /*G10_TRUSTDB_H*/
