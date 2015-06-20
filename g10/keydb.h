/* keydb.h - Key database
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006, 2010 Free Software Foundation, Inc.
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

#ifndef G10_KEYDB_H
#define G10_KEYDB_H

#include <assuan.h>

#include "types.h"
#include "util.h"
#include "packet.h"

/* What qualifies as a certification (rather than a signature?) */
#define IS_CERT(s)       (IS_KEY_SIG(s) || IS_UID_SIG(s) || IS_SUBKEY_SIG(s) \
                         || IS_KEY_REV(s) || IS_UID_REV(s) || IS_SUBKEY_REV(s))
#define IS_SIG(s)        (!IS_CERT(s))
#define IS_KEY_SIG(s)    ((s)->sig_class == 0x1f)
#define IS_UID_SIG(s)    (((s)->sig_class & ~3) == 0x10)
#define IS_SUBKEY_SIG(s) ((s)->sig_class == 0x18)
#define IS_KEY_REV(s)    ((s)->sig_class == 0x20)
#define IS_UID_REV(s)    ((s)->sig_class == 0x30)
#define IS_SUBKEY_REV(s) ((s)->sig_class == 0x28)

struct getkey_ctx_s;
typedef struct getkey_ctx_s *GETKEY_CTX;
typedef struct getkey_ctx_s *getkey_ctx_t;

/****************
 * A Keyblock is all packets which form an entire certificate;
 * i.e. the public key, certificate, trust packets, user ids,
 * signatures, and subkey.
 *
 * This structure is also used to bind arbitrary packets together.
 */

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
    rt_RING = 1
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
    iobuf_t  fp;     /* Used by enum_keyblocks. */
    int secret;      /* working on a secret keyring */
    PACKET *pkt;     /* ditto */
    int valid;
};
typedef struct keyblock_pos_struct KBPOS;

/* Structure to hold a couple of public key certificates. */
typedef struct pk_list *PK_LIST;  /* Deprecated. */
typedef struct pk_list *pk_list_t;
struct pk_list
{
  PK_LIST next;
  PKT_public_key *pk;
  int flags; /* flag bit 1==throw_keyid */
};

/* Structure to hold a list of secret key certificates.  */
typedef struct sk_list *SK_LIST;
struct sk_list
{
  SK_LIST next;
  PKT_public_key *pk;
  int mark; /* not used */
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


typedef struct keydb_handle *KEYDB_HANDLE;


/* Helper type for preference fucntions. */
union pref_hint
{
  int digest_length;
};


/*-- keydb.c --*/

#define KEYDB_RESOURCE_FLAG_PRIMARY  2  /* The primary resource.  */
#define KEYDB_RESOURCE_FLAG_DEFAULT  4  /* The default one.  */
#define KEYDB_RESOURCE_FLAG_READONLY 8  /* Open in read only mode.  */

gpg_error_t keydb_add_resource (const char *url, unsigned int flags);
void        keydb_dump_stats (void);

KEYDB_HANDLE keydb_new (void);
void keydb_release (KEYDB_HANDLE hd);
void keydb_disable_caching (KEYDB_HANDLE hd);
void keydb_push_found_state (KEYDB_HANDLE hd);
void keydb_pop_found_state (KEYDB_HANDLE hd);
const char *keydb_get_resource_name (KEYDB_HANDLE hd);
gpg_error_t keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb);
gpg_error_t keydb_update_keyblock (KEYDB_HANDLE hd, kbnode_t kb);
gpg_error_t keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb);
gpg_error_t keydb_delete_keyblock (KEYDB_HANDLE hd);
gpg_error_t keydb_locate_writable (KEYDB_HANDLE hd, const char *reserved);
void keydb_rebuild_caches (int noisy);
unsigned long keydb_get_skipped_counter (KEYDB_HANDLE hd);
gpg_error_t keydb_search_reset (KEYDB_HANDLE hd);
gpg_error_t keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
                          size_t ndesc, size_t *descindex);
gpg_error_t keydb_search_first (KEYDB_HANDLE hd);
gpg_error_t keydb_search_next (KEYDB_HANDLE hd);
gpg_error_t keydb_search_kid (KEYDB_HANDLE hd, u32 *kid);
gpg_error_t keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr);


/*-- pkclist.c --*/
void show_revocation_reason( PKT_public_key *pk, int mode );
int  check_signatures_trust( PKT_signature *sig );

void release_pk_list (PK_LIST pk_list);
int  build_pk_list (ctrl_t ctrl,
                    strlist_t rcpts, PK_LIST *ret_pk_list, unsigned use);
gpg_error_t find_and_check_key (ctrl_t ctrl,
                                const char *name, unsigned int use,
                                int mark_hidden, pk_list_t *pk_list_addr);

int  algo_available( preftype_t preftype, int algo,
		     const union pref_hint *hint );
int  select_algo_from_prefs( PK_LIST pk_list, int preftype,
			     int request, const union pref_hint *hint);
int  select_mdc_from_pklist (PK_LIST pk_list);
void warn_missing_mdc_from_pklist (PK_LIST pk_list);
void warn_missing_aes_from_pklist (PK_LIST pk_list);

/*-- skclist.c --*/
int  random_is_faked (void);
void release_sk_list( SK_LIST sk_list );
gpg_error_t  build_sk_list (strlist_t locusr, SK_LIST *ret_sk_list,
                            unsigned use);

/*-- passphrase.h --*/
unsigned char encode_s2k_iterations (int iterations);
assuan_context_t agent_open (int try, const char *orig_codeset);
void agent_close (assuan_context_t ctx);
int  have_static_passphrase(void);
const char *get_static_passphrase (void);
void set_passphrase_from_string(const char *pass);
void read_passphrase_from_fd( int fd );
void passphrase_clear_cache ( u32 *keyid, const char *cacheid, int algo );
DEK *passphrase_to_dek_ext(u32 *keyid, int pubkey_algo,
                           int cipher_algo, STRING2KEY *s2k, int mode,
                           const char *tryagain_text,
                           const char *custdesc, const char *custprompt,
                           int *canceled);
DEK *passphrase_to_dek( u32 *keyid, int pubkey_algo,
			int cipher_algo, STRING2KEY *s2k, int mode,
                        const char *tryagain_text, int *canceled);
void set_next_passphrase( const char *s );
char *get_last_passphrase(void);
void next_to_last_passphrase(void);

void emit_status_need_passphrase (u32 *keyid, u32 *mainkeyid, int pubkey_algo);

#define FORMAT_KEYDESC_NORMAL  0
#define FORMAT_KEYDESC_IMPORT  1
#define FORMAT_KEYDESC_EXPORT  2
#define FORMAT_KEYDESC_DELKEY  3
char *gpg_format_keydesc (PKT_public_key *pk, int mode, int escaped);


/*-- getkey.c --*/
void cache_public_key( PKT_public_key *pk );
void getkey_disable_caches(void);
int get_pubkey( PKT_public_key *pk, u32 *keyid );
int get_pubkey_fast ( PKT_public_key *pk, u32 *keyid );
KBNODE get_pubkeyblock( u32 *keyid );
int get_pubkey_byname (ctrl_t ctrl,
                       GETKEY_CTX *rx, PKT_public_key *pk,  const char *name,
                       KBNODE *ret_keyblock, KEYDB_HANDLE *ret_kdbhd,
		       int include_unusable, int no_akl );
int get_pubkey_bynames( GETKEY_CTX *rx, PKT_public_key *pk,
			strlist_t names, KBNODE *ret_keyblock );
int get_pubkey_next( GETKEY_CTX ctx, PKT_public_key *pk, KBNODE *ret_keyblock );
void get_pubkey_end( GETKEY_CTX ctx );
gpg_error_t get_seckey (PKT_public_key *pk, u32 *keyid);
gpg_error_t get_pubkey_byfpr (PKT_public_key *pk, const byte *fpr);
int get_pubkey_byfprint (PKT_public_key *pk,  kbnode_t *r_keyblock,
                         const byte *fprint, size_t fprint_len);
int get_pubkey_byfprint_fast (PKT_public_key *pk,
                              const byte *fprint, size_t fprint_len);
int get_keyblock_byfprint( KBNODE *ret_keyblock, const byte *fprint,
						 size_t fprint_len );

int have_secret_key_with_kid (u32 *keyid);

gpg_error_t get_seckey_byname (PKT_public_key *pk, const char *name);

gpg_error_t get_seckey_byfprint (PKT_public_key *pk,
                                 const byte *fprint, size_t fprint_len);
gpg_error_t get_seckeyblock_byfprint (kbnode_t *ret_keyblock,
                                      const byte *fprint, size_t fprint_len);

gpg_error_t getkey_bynames (getkey_ctx_t *retctx, PKT_public_key *pk,
                            strlist_t names, int want_secret,
                            kbnode_t *ret_keyblock);
gpg_error_t getkey_byname (getkey_ctx_t *retctx, PKT_public_key *pk,
                           const char *name, int want_secret,
                           kbnode_t *ret_keyblock);
gpg_error_t getkey_next (getkey_ctx_t ctx, PKT_public_key *pk,
                         kbnode_t *ret_keyblock);
void getkey_end (getkey_ctx_t ctx);

gpg_error_t enum_secret_keys (void **context, PKT_public_key *pk);

void setup_main_keyids (kbnode_t keyblock);
void merge_keys_and_selfsig( KBNODE keyblock );
char*get_user_id_string_native( u32 *keyid );
char*get_long_user_id_string( u32 *keyid );
char*get_user_id( u32 *keyid, size_t *rn );
char*get_user_id_native( u32 *keyid );
char *get_user_id_byfpr (const byte *fpr, size_t *rn);
char *get_user_id_byfpr_native (const byte *fpr);
KEYDB_HANDLE get_ctx_handle(GETKEY_CTX ctx);
void release_akl(void);
int parse_auto_key_locate(char *options);

/*-- keyid.c --*/
int pubkey_letter( int algo );
char *pubkey_string (PKT_public_key *pk, char *buffer, size_t bufsize);
#define PUBKEY_STRING_SIZE 32
u32 v3_keyid (gcry_mpi_t a, u32 *ki);
void hash_public_key( gcry_md_hd_t md, PKT_public_key *pk );
size_t keystrlen(void);
const char *keystr(u32 *keyid);
const char *keystr_with_sub (u32 *main_kid, u32 *sub_kid);
const char *keystr_from_pk(PKT_public_key *pk);
const char *keystr_from_pk_with_sub (PKT_public_key *main_pk,
                                     PKT_public_key *sub_pk);
const char *keystr_from_desc(KEYDB_SEARCH_DESC *desc);
u32 keyid_from_pk( PKT_public_key *pk, u32 *keyid );
u32 keyid_from_sig( PKT_signature *sig, u32 *keyid );
u32 keyid_from_fingerprint(const byte *fprint, size_t fprint_len, u32 *keyid);
byte *namehash_from_uid(PKT_user_id *uid);
unsigned nbits_from_pk( PKT_public_key *pk );
const char *datestr_from_pk( PKT_public_key *pk );
const char *datestr_from_sig( PKT_signature *sig );
const char *expirestr_from_pk( PKT_public_key *pk );
const char *expirestr_from_sig( PKT_signature *sig );
const char *revokestr_from_pk( PKT_public_key *pk );
const char *usagestr_from_pk (PKT_public_key *pk, int fill);
const char *colon_strtime (u32 t);
const char *colon_datestr_from_pk (PKT_public_key *pk);
const char *colon_datestr_from_sig (PKT_signature *sig);
const char *colon_expirestr_from_sig (PKT_signature *sig);
byte *fingerprint_from_pk( PKT_public_key *pk, byte *buf, size_t *ret_len );
char *hexfingerprint (PKT_public_key *pk);
gpg_error_t keygrip_from_pk (PKT_public_key *pk, unsigned char *array);
gpg_error_t hexkeygrip_from_pk (PKT_public_key *pk, char **r_grip);


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

#endif /*G10_KEYDB_H*/
