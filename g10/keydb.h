/* keydb.h - Key database
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

#ifndef G10_KEYDB_H
#define G10_KEYDB_H

#include "types.h"
#include "cipher.h"


/*-- passphrase.h --*/
DEK *get_passphrase_hash( u32 *keyid, char *text );
int make_dek_from_passphrase( DEK *dek, int mode );

/*-- getkey.c --*/
void add_keyring( const char *name );
void cache_pubkey_cert( PKT_pubkey_cert *pkc );
void cache_user_id( PKT_user_id *uid, u32 *keyid );
int get_pubkey( PKT_pubkey_cert *pkc, u32 *keyid );
int get_pubkey_by_name( PKT_pubkey_cert *pkc, const char *name );
int get_seckey( RSA_secret_key *skey, u32 *keyid );
char*get_user_id_string( u32 *keyid );





#endif /*G10_KEYDB_H*/
