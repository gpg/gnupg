/* trustdb.h - Trust database
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

/*-- trustdb.c --*/
void register_trusted_key( const char *string );
void check_trustdb (void);
void update_trustdb (void);
int setup_trustdb( int level, const char *dbname );
void init_trustdb( void );
void sync_trustdb( void );

int trust_letter( unsigned value );

void revalidation_mark (void);

unsigned int get_validity (PKT_public_key *pk, const byte *namehash);
int get_validity_info (PKT_public_key *pk, const byte *namehash);

void list_trust_path( const char *username );

int enum_cert_paths( void **context, ulong *lid,
		     unsigned *ownertrust, unsigned *validity );
void enum_cert_paths_print( void **context, FILE *fp,
					   int refresh, ulong selected_lid );

unsigned int get_ownertrust (PKT_public_key *pk);
int get_ownertrust_info (PKT_public_key *pk);
void update_ownertrust (PKT_public_key *pk, unsigned int new_trust );
int clear_ownertrust (PKT_public_key *pk);


/*-- tdbdump.c --*/
void list_trustdb(const char *username);
void export_ownertrust(void);
void import_ownertrust(const char *fname);

/*-- pkclist.c --*/
int edit_ownertrust (PKT_public_key *pk, int mode );

#endif /*G10_TRUSTDB_H*/
