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



#define TRUST_MASK	0x07 /* for the trust leveles */
#define TRUST_UNKNOWN	  1  /* unknown 	   */
#define TRUST_NO_TRUST	  2  /* not trusted	   */
#define TRUST_MARG_TRUST  4  /* marginally trusted */
#define TRUST_FULL_TRUST  5  /* fully trusted	   */
#define TRUST_ULT_TRUST   7  /* ultimately trusted */
 /* other bits used with the trustlevel */
#define TRUST_NO_PUBKEY 0x10 /* we do not have the pubkey in out trustDB */


/*-- trustdb.c --*/
void list_trustdb(const char *username);
void list_trust_path( int max_depth, const char *username );
int init_trustdb( int level );
int check_pkc_trust( PKT_public_cert *pkc, int *r_trustlevel );
int get_ownertrust( PKT_public_cert *pkc, int *r_otrust );
int insert_trust_record( PKT_public_cert *pkc );
int verify_private_data(void);
int sign_private_data(void);

#endif /*G10_TRUSTDB_H*/
