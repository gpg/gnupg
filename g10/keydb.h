/* keydb.h - Key database
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

#ifndef G10_KEYDB_H
#define G10_KEYDB_H

#ifdef HAVE_LIBGDBM
  #include <gdbm.h>
#endif

#include "types.h"
#include "packet.h"
#include "cipher.h"

#define MAX_FINGERPRINT_LEN 20

#define IS_KEY_SIG(s)    ((s)->sig_class == 0x1f)
#define IS_UID_SIG(s)    (((s)->sig_class & ~3) == 0x10)
#define IS_SUBKEY_SIG(s) ((s)->sig_class == 0x18)
#define IS_KEY_REV(s)    ((s)->sig_class == 0x20)
#define IS_UID_REV(s)    ((s)->sig_class == 0x30)
#define IS_SUBKEY_REV(s) ((s)->sig_class == 0x28)


struct getkey_ctx_s;
typedef struct getkey_ctx_s *GETKEY_CTX;

/****************
 * A Keyblock is all packets which form an entire certificate;
 * i.e. the public key, certificate, trust packets, user ids,
 * signatures, and subkey.
 *
 * This structure is also used to bind arbitrary packets together.
 */

typedef struct kbnode_struct *KBNODE;
struct kbnode_struct {
    KBNODE next;
    PACKET *pkt;
    int flag;
    int private_flag;
    ulong recno;  /* used while updating the trustdb */
};

#define is_deleted_kbnode(a)  ((a)->private_flag & 1)
#define is_cloned_kbnode(a)   ((a)->private_flag & 2)


enum resource_type {
    rt_UNKNOWN = 0,
    rt_RING = 1,
    rt_GDBM = 2
};


/****************
 * A data structre to hold information about the external position
 * of a keyblock.
 */
struct keyblock_pos_struct {
    int   resno;     /* resource number */
    enum resource_type rt;
    off_t offset;    /* position information */
    unsigned count;  /* length of the keyblock in packets */
    IOBUF  fp;	     /* used by enum_keyblocks */
    int secret;      /* working on a secret keyring */
  #ifdef HAVE_LIBGDBM
    GDBM_FILE dbf;
    byte keybuf[21];
  #endif
    PACKET *pkt;     /* ditto */
    int valid;
};
typedef struct keyblock_pos_struct KBPOS;

/* structure to hold a couple of public key certificates */
typedef struct pk_list *PK_LIST;
struct pk_list {
    PK_LIST next;
    PKT_public_key *pk;
    int mark;
};

/* structure to hold a couple of secret key certificates */
typedef struct sk_list *SK_LIST;
struct sk_list {
    SK_LIST next;
    PKT_secret_key *sk;
    int mark;
};

/* structure to collect all information which can be used to
 * identify a public key */
typedef struct pubkey_find_info *PUBKEY_FIND_INFO;
struct pubkey_find_info {
    u32  keyid[2];
    unsigned nbits;
    byte pubkey_algo;
    byte fingerprint[MAX_FINGERPRINT_LEN];
    char userid[1];
};



/*-- pkclist.c --*/
int  check_signatures_trust( PKT_signature *sig );
void release_pk_list( PK_LIST pk_list );
int  build_pk_list( STRLIST remusr, PK_LIST *ret_pk_list, unsigned use );
int  select_algo_from_prefs( PK_LIST pk_list, int preftype );

/*-- skclist.c --*/
void release_sk_list( SK_LIST sk_list );
int  build_sk_list( STRLIST locusr, SK_LIST *ret_sk_list,
					    int unlock, unsigned use );

/*-- passphrase.h --*/
int  have_static_passphrase(void);
void read_passphrase_from_fd( int fd );
void passphrase_clear_cache ( u32 *keyid, int algo );
DEK *passphrase_to_dek( u32 *keyid, int pubkey_algo,
			int cipher_algo, STRING2KEY *s2k, int mode);
void set_next_passphrase( const char *s );
char *get_last_passphrase(void);

/*-- getkey.c --*/
int classify_user_id( const char *name, u32 *keyid, byte *fprint,
		      const char **retstr, size_t *retlen );
void cache_public_key( PKT_public_key *pk );
void getkey_disable_caches(void);
int get_pubkey( PKT_public_key *pk, u32 *keyid );
KBNODE get_pubkeyblock( u32 *keyid );
int get_pubkey_byname( GETKEY_CTX *rx, PKT_public_key *pk,
		       const char *name, KBNODE *ret_keyblock );
int get_pubkey_bynames( GETKEY_CTX *rx, PKT_public_key *pk,
			STRLIST names, KBNODE *ret_keyblock );
int get_pubkey_next( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock );
void get_pubkey_end( GETKEY_CTX ctx );
int get_seckey( PKT_secret_key *sk, u32 *keyid );
int get_primary_seckey( PKT_secret_key *sk, u32 *keyid );
int get_pubkey_byfprint( PKT_public_key *pk, const byte *fprint,
						 size_t fprint_len );
int get_keyblock_byfprint( KBNODE *ret_keyblock, const byte *fprint,
						 size_t fprint_len );
int get_keyblock_bylid( KBNODE *ret_keyblock, ulong lid );
int seckey_available( u32 *keyid );
int get_seckey_byname( PKT_secret_key *sk, const char *name, int unlock );
int get_seckey_bynames( GETKEY_CTX *rx, PKT_secret_key *sk,
			STRLIST names, KBNODE *ret_keyblock );
int get_seckey_next( GETKEY_CTX ctx, PKT_secret_key *sk, KBNODE *ret_keyblock );
void get_seckey_end( GETKEY_CTX ctx );
int enum_secret_keys( void **context, PKT_secret_key *sk, int with_subkeys );
void merge_keys_and_selfsig( KBNODE keyblock );
char*get_user_id_string( u32 *keyid );
char*get_user_id_string_native( u32 *keyid );
char*get_long_user_id_string( u32 *keyid );
char*get_user_id( u32 *keyid, size_t *rn );

/*-- keyid.c --*/
int pubkey_letter( int algo );
int get_lsign_letter ( PKT_signature *sig );
u32 keyid_from_sk( PKT_secret_key *sk, u32 *keyid );
u32 keyid_from_pk( PKT_public_key *pk, u32 *keyid );
u32 keyid_from_sig( PKT_signature *sig, u32 *keyid );
u32 keyid_from_fingerprint( const byte *fprint, size_t fprint_len, u32 *keyid );
unsigned nbits_from_pk( PKT_public_key *pk );
unsigned nbits_from_sk( PKT_secret_key *sk );
const char *datestr_from_pk( PKT_public_key *pk );
const char *datestr_from_sk( PKT_secret_key *sk );
const char *datestr_from_sig( PKT_signature *sig );
const char *expirestr_from_pk( PKT_public_key *pk );
const char *expirestr_from_sk( PKT_secret_key *sk );

const char *colon_strtime (u32 t);
const char *colon_datestr_from_pk (PKT_public_key *pk);
const char *colon_datestr_from_sk (PKT_secret_key *sk);
const char *colon_datestr_from_sig (PKT_signature *sig);

byte *fingerprint_from_sk( PKT_secret_key *sk, byte *buf, size_t *ret_len );
byte *fingerprint_from_pk( PKT_public_key *pk, byte *buf, size_t *ret_len );

/*-- kbnode.c --*/
KBNODE new_kbnode( PACKET *pkt );
KBNODE clone_kbnode( KBNODE node );
void release_kbnode( KBNODE n );
void delete_kbnode( KBNODE node );
void add_kbnode( KBNODE root, KBNODE node );
void insert_kbnode( KBNODE root, KBNODE node, int pkttype );
void move_kbnode( KBNODE *root, KBNODE node, KBNODE where );
void remove_kbnode( KBNODE *root, KBNODE node );
KBNODE find_prev_kbnode( KBNODE root, KBNODE node, int pkttype );
KBNODE find_next_kbnode( KBNODE node, int pkttype );
KBNODE find_kbnode( KBNODE node, int pkttype );
KBNODE walk_kbnode( KBNODE root, KBNODE *context, int all );
void clear_kbnode_flags( KBNODE n );
int  commit_kbnode( KBNODE *root );
void dump_kbnode( KBNODE node );

/*-- ringedit.c --*/
const char *enum_keyblock_resources( int *sequence, int secret );
int add_keyblock_resource( const char *resname, int force, int secret );
const char *keyblock_resource_name( KBPOS *kbpos );
int get_keyblock_handle( const char *filename, int secret, KBPOS *kbpos );
char *get_writable_keyblock_file( int secret );
int locate_keyblock_by_fpr( KBPOS *kbpos, const byte *fpr,
					    int fprlen, int secret );
int locate_keyblock_by_keyid( KBPOS *kbpos, u32 *keyid,
					    int shortkid, int secret );
int find_keyblock( PUBKEY_FIND_INFO info, KBPOS *kbpos );
int find_keyblock_byname( KBPOS *kbpos, const char *username );
int find_keyblock_bypk( KBPOS *kbpos, PKT_public_key *pk );
int find_keyblock_bysk( KBPOS *kbpos, PKT_secret_key *sk );
int find_secret_keyblock_byname( KBPOS *kbpos, const char *username );
int lock_keyblock( KBPOS *kbpos );
void unlock_keyblock( KBPOS *kbpos );
int read_keyblock( KBPOS *kbpos, KBNODE *ret_root );
int enum_keyblocks( int mode, KBPOS *kbpos, KBNODE *ret_root );
int insert_keyblock( KBPOS *kbpos, KBNODE root );
int delete_keyblock( KBPOS *kbpos );
int update_keyblock( KBPOS *kbpos, KBNODE root );


#endif /*G10_KEYDB_H*/
