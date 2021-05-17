/* keydb.h - Key database
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2015, 2016 g10 Code GmbH
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef G10_KEYDB_H
#define G10_KEYDB_H

#include "../common/types.h"
#include "../common/util.h"
#include "packet.h"

/* What qualifies as a certification (key-signature in contrast to a
 * data signature)?  Note that a back signature is special and can be
 * made by key and data signatures capable subkeys.) */
#define IS_CERT(s)       (IS_KEY_SIG(s) || IS_UID_SIG(s) || IS_SUBKEY_SIG(s) \
                         || IS_KEY_REV(s) || IS_UID_REV(s) || IS_SUBKEY_REV(s))
#define IS_SIG(s)        (!IS_CERT(s))
#define IS_KEY_SIG(s)    ((s)->sig_class == 0x1f)
#define IS_UID_SIG(s)    (((s)->sig_class & ~3) == 0x10)
#define IS_SUBKEY_SIG(s) ((s)->sig_class == 0x18)
#define IS_BACK_SIG(s)   ((s)->sig_class == 0x19)
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

struct kbnode_struct
{
  kbnode_t next;
  PACKET *pkt;
  int flag;          /* Local use during keyblock processing (not cloned).*/
  unsigned int tag;  /* Ditto. */
  int private_flag;
};

#define is_deleted_kbnode(a)  ((a)->private_flag & 1)
#define is_cloned_kbnode(a)   ((a)->private_flag & 2)


/*
 * A structure to store key identification as well as some stuff
 * needed for key validation.
 */
struct key_item {
  struct key_item *next;
  unsigned int ownertrust,min_ownertrust;
  byte trust_depth;
  byte trust_value;
  char *trust_regexp;
  u32 kid[2];
};


/* Bit flags used with build_pk_list.  */
enum
  {
    PK_LIST_ENCRYPT_TO = 1, /* This is an encrypt-to recipient.    */
    PK_LIST_HIDDEN     = 2, /* This is a hidden recipient.         */
    PK_LIST_CONFIG     = 4, /* Specified via config file.          */
    PK_LIST_FROM_FILE  = 8  /* Take key from file with that name.  */
  };

/* To store private data in the flags the private data must be left
 * shifted by this value.  */
enum
  {
    PK_LIST_SHIFT = 4
  };


/* Structure to hold a couple of public key certificates. */
typedef struct pk_list *PK_LIST;  /* Deprecated. */
typedef struct pk_list *pk_list_t;
struct pk_list
{
  PK_LIST next;
  PKT_public_key *pk;
  int flags;           /* See PK_LIST_ constants. */
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


/* Helper type for preference functions. */
struct pref_hint
{
  int digest_length;  /* We want at least this digest length.  */
  int exact;          /* We need to use exactly this length.   */
};


/* Constants to describe from where a key was fetched or updated.  */
enum
  {
    KEYORG_UNKNOWN = 0,
    KEYORG_KS      = 1, /* Public keyserver.    */
    KEYORG_KS_PREF = 2, /* Preferred keysrver.  */
    KEYORG_DANE    = 3, /* OpenPGP DANE.        */
    KEYORG_WKD     = 4, /* Web Key Directory.   */
    KEYORG_URL     = 5, /* Trusted URL.         */
    KEYORG_FILE    = 6, /* Trusted file.        */
    KEYORG_SELF    = 7  /* We generated it.     */
  };


/*
 * Check whether the signature SIG is in the klist K.
 */
static inline struct key_item *
is_in_klist (struct key_item *k, PKT_signature *sig)
{
  for (; k; k = k->next)
    {
      if (k->kid[0] == sig->keyid[0] && k->kid[1] == sig->keyid[1])
        return k;
    }
  return NULL;
}



/*-- keydb.c --*/

#define KEYDB_RESOURCE_FLAG_PRIMARY  2  /* The primary resource.  */
#define KEYDB_RESOURCE_FLAG_DEFAULT  4  /* The default one.  */
#define KEYDB_RESOURCE_FLAG_READONLY 8  /* Open in read only mode.  */
#define KEYDB_RESOURCE_FLAG_GPGVDEF 16  /* Default file for gpgv.  */

/* Format a search term for debugging output.  The caller must free
   the result.  */
char *keydb_search_desc_dump (struct keydb_search_desc *desc);

/* Register a resource (keyring or keybox).  */
gpg_error_t keydb_add_resource (const char *url, unsigned int flags);

/* Dump some statistics to the log.  */
void keydb_dump_stats (void);

/* Create a new database handle.  Returns NULL on error, sets ERRNO,
   and prints an error diagnostic. */
KEYDB_HANDLE keydb_new (void);

/* Free all resources owned by the database handle.  */
void keydb_release (KEYDB_HANDLE hd);

/* Take a lock on the files immediately and not only during insert or
 * update.  This lock is released with keydb_release.  */
gpg_error_t keydb_lock (KEYDB_HANDLE hd);

/* Set a flag on the handle to suppress use of cached results.  This
   is required for updating a keyring and for key listings.  Fixme:
   Using a new parameter for keydb_new might be a better solution.  */
void keydb_disable_caching (KEYDB_HANDLE hd);

/* Save the last found state and invalidate the current selection.  */
void keydb_push_found_state (KEYDB_HANDLE hd);

/* Restore the previous save state.  */
void keydb_pop_found_state (KEYDB_HANDLE hd);

/* Return the file name of the resource.  */
const char *keydb_get_resource_name (KEYDB_HANDLE hd);

/* Return the keyblock last found by keydb_search.  */
gpg_error_t keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb);

/* Update the keyblock KB.  */
gpg_error_t keydb_update_keyblock (ctrl_t ctrl, KEYDB_HANDLE hd, kbnode_t kb);

/* Insert a keyblock into one of the underlying keyrings or keyboxes.  */
gpg_error_t keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb);

/* Delete the currently selected keyblock.  */
gpg_error_t keydb_delete_keyblock (KEYDB_HANDLE hd);

/* Find the first writable resource.  */
gpg_error_t keydb_locate_writable (KEYDB_HANDLE hd);

/* Rebuild the on-disk caches of all key resources.  */
void keydb_rebuild_caches (ctrl_t ctrl, int noisy);

/* Return the number of skipped blocks (because they were to large to
   read from a keybox) since the last search reset.  */
unsigned long keydb_get_skipped_counter (KEYDB_HANDLE hd);

/* Clears the current search result and resets the handle's position.  */
gpg_error_t keydb_search_reset (KEYDB_HANDLE hd);

/* Search the database for keys matching the search description.  */
gpg_error_t keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
                          size_t ndesc, size_t *descindex);

/* Return the first non-legacy key in the database.  */
gpg_error_t keydb_search_first (KEYDB_HANDLE hd);

/* Return the next key (not the next matching key!).  */
gpg_error_t keydb_search_next (KEYDB_HANDLE hd);

/* This is a convenience function for searching for keys with a long
   key id.  */
gpg_error_t keydb_search_kid (KEYDB_HANDLE hd, u32 *kid);

/* This is a convenience function for searching for keys with a long
   (20 byte) fingerprint.  */
gpg_error_t keydb_search_fpr (KEYDB_HANDLE hd, const byte *fpr);


/*-- pkclist.c --*/
void show_revocation_reason (ctrl_t ctrl, PKT_public_key *pk, int mode );
int  check_signatures_trust (ctrl_t ctrl, PKT_signature *sig);

void release_pk_list (PK_LIST pk_list);
int  build_pk_list (ctrl_t ctrl, strlist_t rcpts, PK_LIST *ret_pk_list);
gpg_error_t find_and_check_key (ctrl_t ctrl,
                                const char *name, unsigned int use,
                                int mark_hidden, int from_file,
                                pk_list_t *pk_list_addr);

int  algo_available( preftype_t preftype, int algo,
		     const struct pref_hint *hint );
int  select_algo_from_prefs( PK_LIST pk_list, int preftype,
			     int request, const struct pref_hint *hint);
int  select_mdc_from_pklist (PK_LIST pk_list);
void warn_missing_mdc_from_pklist (PK_LIST pk_list);
void warn_missing_aes_from_pklist (PK_LIST pk_list);

/*-- skclist.c --*/
int  random_is_faked (void);
void release_sk_list( SK_LIST sk_list );
gpg_error_t build_sk_list (ctrl_t ctrl, strlist_t locusr,
                           SK_LIST *ret_sk_list, unsigned use);

/*-- passphrase.h --*/

/* Flags for passphrase_to_dek */
#define GETPASSWORD_FLAG_SYMDECRYPT  1


unsigned char encode_s2k_iterations (int iterations);
int  have_static_passphrase(void);
const char *get_static_passphrase (void);
void set_passphrase_from_string(const char *pass);
void read_passphrase_from_fd( int fd );
void passphrase_clear_cache (const char *cacheid);
DEK *passphrase_to_dek (int cipher_algo, STRING2KEY *s2k,
                        int create, int nocache,
                        const char *tryagain_text, unsigned int flags,
                        int *canceled);
void set_next_passphrase( const char *s );
char *get_last_passphrase(void);
void next_to_last_passphrase(void);

void emit_status_need_passphrase (ctrl_t ctrl, u32 *keyid,
                                  u32 *mainkeyid, int pubkey_algo);

#define FORMAT_KEYDESC_NORMAL  0
#define FORMAT_KEYDESC_IMPORT  1
#define FORMAT_KEYDESC_EXPORT  2
#define FORMAT_KEYDESC_DELKEY  3
char *gpg_format_keydesc (ctrl_t ctrl,
                          PKT_public_key *pk, int mode, int escaped);


/*-- getkey.c --*/

/* Cache a copy of a public key in the public key cache.  */
void cache_public_key( PKT_public_key *pk );

/* Disable and drop the public key cache.  */
void getkey_disable_caches(void);

/* Return the public key used for signature SIG and store it at PK.  */
gpg_error_t get_pubkey_for_sig (ctrl_t ctrl,
                                PKT_public_key *pk, PKT_signature *sig,
                                PKT_public_key *forced_pk);

/* Return the public key with the key id KEYID and store it at PK.  */
int get_pubkey (ctrl_t ctrl, PKT_public_key *pk, u32 *keyid);

/* Same as get_pubkey but with auto LDAP fetch.  */
gpg_error_t get_pubkey_with_ldap_fallback (ctrl_t ctrl,
                                           PKT_public_key *pk, u32 * keyid);

/* Similar to get_pubkey, but it does not take PK->REQ_USAGE into
   account nor does it merge in the self-signed data.  This function
   also only considers primary keys.  */
int get_pubkey_fast (PKT_public_key *pk, u32 *keyid);

/* Return the entire keyblock used to create SIG.  This is a
 * specialized version of get_pubkeyblock.  */
kbnode_t get_pubkeyblock_for_sig (ctrl_t ctrl, PKT_signature *sig);

/* Return the key block for the key with KEYID.  */
kbnode_t get_pubkeyblock (ctrl_t ctrl, u32 *keyid);

/* A list used by get_pubkeys to gather all of the matches.  */
struct pubkey_s
{
  struct pubkey_s *next;
  /* The key to use (either the public key or the subkey).  */
  PKT_public_key *pk;
  kbnode_t keyblock;
};
typedef struct pubkey_s *pubkey_t;

/* Free a list of public keys.  */
void pubkeys_free (pubkey_t keys);


/* Mode flags for get_pubkey_byname.  */
enum get_pubkey_modes
  {
   GET_PUBKEY_NORMAL = 0,
   GET_PUBKEY_NO_AKL = 1,
   GET_PUBKEY_NO_LOCAL = 2
  };

/* Find a public key identified by NAME.  */
int get_pubkey_byname (ctrl_t ctrl, enum get_pubkey_modes mode,
                       GETKEY_CTX *retctx, PKT_public_key *pk,
		       const char *name,
                       KBNODE *ret_keyblock, KEYDB_HANDLE *ret_kdbhd,
		       int include_unusable);

/* Likewise, but only return the best match if NAME resembles a mail
 * address.  */
gpg_error_t get_best_pubkey_byname (ctrl_t ctrl, enum get_pubkey_modes mode,
                                    GETKEY_CTX *retctx, PKT_public_key *pk,
                                    const char *name, KBNODE *ret_keyblock,
                                    int include_unusable);

/* Get a public key directly from file FNAME.  */
gpg_error_t get_pubkey_fromfile (ctrl_t ctrl,
                                 PKT_public_key *pk, const char *fname);

/* Get a public key from a buffer.  */
gpg_error_t get_pubkey_from_buffer (ctrl_t ctrl, PKT_public_key *pkbuf,
                                    const void *buffer, size_t buflen,
                                    u32 *want_keyid, kbnode_t *r_keyblock);

/* Return the public key with the key id KEYID iff the secret key is
 * available and store it at PK.  */
gpg_error_t get_seckey (ctrl_t ctrl, PKT_public_key *pk, u32 *keyid);

/* Lookup a key with the specified fingerprint.  */
int get_pubkey_byfprint (ctrl_t ctrl, PKT_public_key *pk, kbnode_t *r_keyblock,
                         const byte *fprint, size_t fprint_len);

/* This function is similar to get_pubkey_byfprint, but it doesn't
   merge the self-signed data into the public key and subkeys or into
   the user ids.  */
gpg_error_t get_pubkey_byfprint_fast (PKT_public_key *pk,
                                      const byte *fprint, size_t fprint_len);

/* This function is similar to get_pubkey_byfprint, but it doesn't
   merge the self-signed data into the public key and subkeys or into
   the user ids.  */
gpg_error_t get_keyblock_byfprint_fast (kbnode_t *r_keyblock,
                                        KEYDB_HANDLE *r_hd,
                                        const byte *fprint, size_t fprint_len,
                                        int lock);


/* Returns true if a secret key is available for the public key with
   key id KEYID.  */
int have_secret_key_with_kid (u32 *keyid);

/* Parse the --default-key parameter.  Returns the last key (in terms
   of when the option is given) that is available.  */
const char *parse_def_secret_key (ctrl_t ctrl);

/* Look up a secret key.  */
gpg_error_t get_seckey_default (ctrl_t ctrl, PKT_public_key *pk);
gpg_error_t get_seckey_default_or_card (ctrl_t ctrl, PKT_public_key *pk,
                                        const byte *fpr, size_t fpr_len);

/* Search for keys matching some criteria.  */
gpg_error_t getkey_bynames (ctrl_t ctrl,
                            getkey_ctx_t *retctx, PKT_public_key *pk,
                            strlist_t names, int want_secret,
                            kbnode_t *ret_keyblock);

/* Search for one key matching some criteria.  */
gpg_error_t getkey_byname (ctrl_t ctrl,
                           getkey_ctx_t *retctx, PKT_public_key *pk,
                           const char *name, int want_secret,
                           kbnode_t *ret_keyblock);

/* Return the next search result.  */
gpg_error_t getkey_next (ctrl_t ctrl, getkey_ctx_t ctx,
                         PKT_public_key *pk, kbnode_t *ret_keyblock);

/* Release any resources used by a key listing context.  */
void getkey_end (ctrl_t ctrl, getkey_ctx_t ctx);

/* Return the database handle used by this context.  The context still
   owns the handle.  */
KEYDB_HANDLE get_ctx_handle(GETKEY_CTX ctx);

/* Enumerate some secret keys.  */
gpg_error_t enum_secret_keys (ctrl_t ctrl, void **context, PKT_public_key *pk);

/* Set the mainkey_id fields for all keys in KEYBLOCK.  */
void setup_main_keyids (kbnode_t keyblock);

/* This function merges information from the self-signed data into the
   data structures.  */
void merge_keys_and_selfsig (ctrl_t ctrl, kbnode_t keyblock);

char *get_user_id_string_native (ctrl_t ctrl, u32 *keyid);
char *get_long_user_id_string (ctrl_t ctrl, u32 *keyid);
char *get_user_id (ctrl_t ctrl, u32 *keyid, size_t *rn, int *r_nouid);
char *get_user_id_native (ctrl_t ctrl, u32 *keyid);
char *get_user_id_byfpr (ctrl_t ctrl, const byte *fpr, size_t *rn);
char *get_user_id_byfpr_native (ctrl_t ctrl, const byte *fpr);

void release_akl(void);
int akl_empty_or_only_local (void);
int parse_auto_key_locate(const char *options);
int parse_key_origin (char *string);
const char *key_origin_string (int origin);

/*-- keyid.c --*/
int pubkey_letter( int algo );
char *pubkey_string (PKT_public_key *pk, char *buffer, size_t bufsize);
#define PUBKEY_STRING_SIZE 32
u32 v3_keyid (gcry_mpi_t a, u32 *ki);
void hash_public_key( gcry_md_hd_t md, PKT_public_key *pk );
char *format_keyid (u32 *keyid, int format, char *buffer, int len);

/* Return PK's keyid.  The memory is owned by PK.  */
u32 *pk_keyid (PKT_public_key *pk);

/* Return the keyid of the primary key associated with PK.  The memory
   is owned by PK.  */
u32 *pk_main_keyid (PKT_public_key *pk);

/* Order A and B.  If A < B then return -1, if A == B then return 0,
   and if A > B then return 1.  */
static int GPGRT_ATTR_UNUSED
keyid_cmp (const u32 *a, const u32 *b)
{
  if (a[0] < b[0])
    return -1;
  if (a[0] > b[0])
    return 1;
  if (a[1] < b[1])
    return -1;
  if (a[1] > b[1])
    return 1;
  return 0;
}

/* Return whether PK is a primary key.  */
static int GPGRT_ATTR_UNUSED
pk_is_primary (PKT_public_key *pk)
{
  return keyid_cmp (pk_keyid (pk), pk_main_keyid (pk)) == 0;
}

/* Copy the keyid in SRC to DEST and return DEST.  */
u32 *keyid_copy (u32 *dest, const u32 *src);

size_t keystrlen(void);
const char *keystr(u32 *keyid);
const char *keystr_with_sub (u32 *main_kid, u32 *sub_kid);
const char *keystr_from_pk(PKT_public_key *pk);
const char *keystr_from_pk_with_sub (PKT_public_key *main_pk,
                                     PKT_public_key *sub_pk);

/* Return PK's key id as a string using the default format.  PK owns
   the storage.  */
const char *pk_keyid_str (PKT_public_key *pk);

const char *keystr_from_desc(KEYDB_SEARCH_DESC *desc);
u32 keyid_from_pk( PKT_public_key *pk, u32 *keyid );
u32 keyid_from_sig (PKT_signature *sig, u32 *keyid );
u32 keyid_from_fingerprint (ctrl_t ctrl, const byte *fprint, size_t fprint_len,
                            u32 *keyid);
byte *namehash_from_uid(PKT_user_id *uid);
unsigned nbits_from_pk( PKT_public_key *pk );

/* Convert an UTC TIMESTAMP into an UTC yyyy-mm-dd string.  Return
 * that string.  The caller should pass a buffer with at least a size
 * of MK_DATESTR_SIZE.  */
char *mk_datestr (char *buffer, size_t bufsize, u32 timestamp);
#define MK_DATESTR_SIZE 11

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
char *hexfingerprint (PKT_public_key *pk, char *buffer, size_t buflen);
char *format_hexfingerprint (const char *fingerprint,
                             char *buffer, size_t buflen);
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
