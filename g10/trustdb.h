/* trustdb.h - Trust database
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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


/* Trust values mus be sorted in ascending order */
#define TRUST_UNKNOWN	  0  /* not yet calculated */
#define TRUST_EXPIRED	  1  /* calculation may be invalid */
#define TRUST_UNDEFINED   2  /* not enough informations for calculation */
#define TRUST_NEVER	  3  /* never trusted this pubkey */
#define TRUST_MARGINAL	  4  /* marginally trusted */
#define TRUST_FULLY	  5  /* fully trusted	   */
#define TRUST_ULTIMATE	  6  /* ultimately trusted */


/*-- trustdb.c --*/
void list_trustdb(const char *username);
void list_trust_path( int max_depth, const char *username );
int init_trustdb( int level, const char *dbname );
int check_trust( PKT_public_cert *pkc, unsigned *r_trustlevel );
int enum_trust_web( void **context, ulong *lid );
int get_ownertrust( ulong lid, unsigned *r_otrust );
int keyid_from_trustdb( ulong lid, u32 *keyid );
int query_trust_record( PKT_public_cert *pkc );
int insert_trust_record( PKT_public_cert *pkc );
int update_ownertrust( ulong lid, unsigned new_trust );
int verify_private_data(void);
int sign_private_data(void);

#endif /*G10_TRUSTDB_H*/
