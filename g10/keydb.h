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
#include "packet.h"
#include "cipher.h"



/****************
 * A Keyblock are all packets which form an entire certificate;
 * i.e. the public key, certificate, trust packets, user ids,
 * signatures, and subkey.
 *
 * This structure is also used to bind arbitrary packets together.
 */

typedef struct kbnode_struct *KBNODE;
struct kbnode_struct {
    PACKET *pkt;
    KBNODE next;   /* used to form a link list */
    KBNODE child;
    int flag;
};

/****************
 * A data structre to hold informations about the external position
 * of a keyblock.
 */
struct keyblock_pos_struct {
    int   resno;  /* resource number */
    ulong offset; /* position information */
    ulong length; /* length of thge keyblock */
    int last_block;
};
typedef struct keyblock_pos_struct KBPOS;



/*-- passphrase.h --*/
DEK *get_passphrase_hash( u32 *keyid, char *text );
int make_dek_from_passphrase( DEK *dek, int mode );

/*-- getkey.c --*/
void add_keyring( const char *name );
void add_secret_keyring( const char *name );
void cache_public_cert( PKT_public_cert *pkc );
void cache_user_id( PKT_user_id *uid, u32 *keyid );
int get_pubkey( PKT_public_cert *pkc, u32 *keyid );
int get_pubkey_byname( PKT_public_cert *pkc, const char *name );
int get_seckey( PKT_secret_cert *skc, u32 *keyid );
int get_seckey_byname( PKT_secret_cert *skc, const char *name, int unlock );
char*get_user_id_string( u32 *keyid );
char*get_user_id( u32 *keyid, size_t *rn );

/*-- keyid.c --*/
int pubkey_letter( int algo );
u32 keyid_from_skc( PKT_secret_cert *skc, u32 *keyid );
u32 keyid_from_pkc( PKT_public_cert *pkc, u32 *keyid );
u32 keyid_from_sig( PKT_signature *sig, u32 *keyid );
unsigned nbits_from_pkc( PKT_public_cert *pkc );
unsigned nbits_from_skc( PKT_secret_cert *skc );
const char *datestr_from_pkc( PKT_public_cert *pkc );
const char *datestr_from_skc( PKT_secret_cert *skc );
const char *datestr_from_sig( PKT_signature *sig );
byte *fingerprint_from_skc( PKT_secret_cert *skc, size_t *ret_len );
byte *fingerprint_from_pkc( PKT_public_cert *pkc, size_t *ret_len );

/*-- kbnode.c --*/
KBNODE new_kbnode( PACKET *pkt );
void release_kbnode( KBNODE n );
void add_kbnode( KBNODE root, KBNODE node );
void add_kbnode_as_child( KBNODE root, KBNODE node );
KBNODE find_kbparent( KBNODE root, KBNODE node );
KBNODE walk_kbtree( KBNODE root, KBNODE *context );
void clear_kbnode_flags( KBNODE n );

/*-- ringedit.c --*/
int add_keyblock_resource( const char *filename, int force );
int get_keyblock_handle( const char *filename, KBPOS *kbpos );
int search_keyblock( PACKET *pkt, KBPOS *kbpos );
int search_keyblock_byname( KBPOS *kbpos, const char *username );
int lock_keyblock( KBPOS *kbpos );
void unlock_keyblock( KBPOS *kbpos );
int read_keyblock( KBPOS *kbpos, KBNODE *ret_root );
int insert_keyblock( KBPOS *kbpos, KBNODE root );
int delete_keyblock( KBPOS *kbpos );
int update_keyblock( KBPOS *kbpos, KBNODE root );


#endif /*G10_KEYDB_H*/
