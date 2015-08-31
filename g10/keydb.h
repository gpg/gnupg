/* keydb.h - Key database
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2015 g10 Code GmbH
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
#define KEYDB_RESOURCE_FLAG_GPGVDEF 16  /* Default file for gpgv.  */

/* Register a resource (keyring or keybox).  The first keyring or
   keybox that is added using this function is created if it does not
   already exist and the KEYDB_RESOURCE_FLAG_READONLY is not set.

   FLAGS are a combination of the KEYDB_RESOURCE_FLAG_* constants.

   URL must have the following form:

     gnupg-ring:filename  = plain keyring
     gnupg-kbx:filename   = keybox file
     filename             = check file's type (create as a plain keyring)

   Note: on systems with drive letters (Windows) invalid URLs (i.e.,
   those with an unrecognized part before the ':' such as "c:\...")
   will silently be treated as bare filenames.  On other systems, such
   URLs will cause this function to return GPG_ERR_GENERAL.

   If KEYDB_RESOURCE_FLAG_DEFAULT is set, the resource is a keyring
   and the file ends in ".gpg", then this function also checks if a
   file with the same name, but the extension ".kbx" exists, is a
   keybox and the OpenPGP flag is set.  If so, this function opens
   that resource instead.

   If the file is not found, KEYDB_RESOURCE_FLAG_GPGVDEF is set and
   the URL ends in ".kbx", then this function will try opening the
   same URL, but with the extension ".gpg".  If that file is a keybox
   with the OpenPGP flag set or it is a keyring, then we use that
   instead.

   If the file is not found, KEYDB_RESOURCE_FLAG_DEFAULT is set, the
   file should be created and the file's extension is ".gpg" then we
   replace the extension with ".kbx".


   If the KEYDB_RESOURCE_FLAG_PRIMARY is set and the resource is a
   keyring (not a keybox), then this resource is considered the
   primary resource.  This is used by keydb_locate_writable().  If
   another primary keyring is set, then that keyring is considered the
   primary.

   If KEYDB_RESOURCE_FLAG_READONLY is set and the resource is a
   keyring (not a keybox), then the keyring is marked as read only and
   operations just as keyring_insert_keyblock will return
   GPG_ERR_ACCESS.  */
gpg_error_t keydb_add_resource (const char *url, unsigned int flags);

/* Dump some statistics to the log.  */
void keydb_dump_stats (void);

/* Create a new database handle.  A database handle is similar to a
   file handle: it contains a local file position.  This is used when
   searching: subsequent searches resume where the previous search
   left off.  To rewind the position, use keydb_search_reset().  */
KEYDB_HANDLE keydb_new (void);

/* Free all resources owned by the database handle.  */
void keydb_release (KEYDB_HANDLE hd);

/* Set a flag on the handle to suppress use of cached results.  This
   is required for updating a keyring and for key listings.  Fixme:
   Using a new parameter for keydb_new might be a better solution.  */
void keydb_disable_caching (KEYDB_HANDLE hd);

/* Save the last found state and invalidate the current selection
   (i.e., the entry selected by keydb_search() is invalidated and
   something like keydb_get_keyblock() will return an error).  This
   does not change the file position.  This makes it possible to do
   something like:

     keydb_search (hd, ...);  // Result 1.
     keydb_push_found_state (hd);
       keydb_search_reset (hd);
       keydb_search (hd, ...);  // Result 2.
     keydb_pop_found_state (hd);
     keydb_get_keyblock (hd, ...);  // -> Result 1.

   Note: it is only possible to save a single save state at a time.
   In other words, the the save stack only has room for a single
   instance of the state.  */
void keydb_push_found_state (KEYDB_HANDLE hd);

/* Restore the previous save state.  If the saved state is invalid,
   this is equivalent to */
void keydb_pop_found_state (KEYDB_HANDLE hd);

/* Return the file name of the resource in which the current search
   result was found or, if there is no search result, the filename of
   the current resource (i.e., the resource that the file position
   points to).  Note: the filename is not necessarily the URL used to
   open it!

   This function only returns NULL if no handle is specified, in all
   other error cases an empty string is returned.  */
const char *keydb_get_resource_name (KEYDB_HANDLE hd);

/* Return the keyblock last found by keydb_search() in *RET_KB.

   On success, the function returns 0 and the caller must free *RET_KB
   using release_kbnode().  Otherwise, the function returns an error
   code.

   The returned keyblock has the kbnode flag bit 0 set for the node
   with the public key used to locate the keyblock or flag bit 1 set
   for the user ID node.  */
gpg_error_t keydb_get_keyblock (KEYDB_HANDLE hd, KBNODE *ret_kb);

/* Replace the currently selected keyblock (i.e., the last result
   returned by keydb_search) with the key block in KB.

   This doesn't do anything if --dry-run was specified.

   Returns 0 on success.  Otherwise, it returns an error code.  */
gpg_error_t keydb_update_keyblock (KEYDB_HANDLE hd, kbnode_t kb);

/* Insert a keyblock into one of the underlying keyrings or keyboxes.

   Be default, the keyring / keybox from which the last search result
   came is used.  If there was no previous search result (or
   keydb_search_reset was called), then the keyring / keybox where the
   next search would start is used (i.e., the current file position).

   Note: this doesn't do anything if --dry-run was specified.

   Returns 0 on success.  Otherwise, it returns an error code.  */
gpg_error_t keydb_insert_keyblock (KEYDB_HANDLE hd, kbnode_t kb);

/* Delete the currently selected keyblock.  If you haven't done a
   search yet on this database handle (or called keydb_search_reset),
   then this will return an error.

   Returns 0 on success or an error code, if an error occurs.  */
gpg_error_t keydb_delete_keyblock (KEYDB_HANDLE hd);

/* A database may consists of multiple keyrings / key boxes.  This
   sets the "file position" to the start of the first keyring / key
   box that is writable (i.e., doesn't have the read-only flag set).

   This first tries the primary keyring (the last keyring (not
   keybox!) added using keydb_add_resource() and with
   KEYDB_RESOURCE_FLAG_PRIMARY set).  If that is not writable, then it
   tries the keyrings / keyboxes in the order in which they were
   added.  */
gpg_error_t keydb_locate_writable (KEYDB_HANDLE hd);

/* Rebuild the on-disk caches of all key resources.  */
void keydb_rebuild_caches (int noisy);

/* Return the number of skipped blocks (because they were to large to
   read from a keybox) since the last search reset.  */
unsigned long keydb_get_skipped_counter (KEYDB_HANDLE hd);

/* Clears the current search result and resets the handle's position
   so that the next search starts at the beginning of the database
   (the start of the first resource).

   Returns 0 on success and an error code if an error occured.
   (Currently, this function always returns 0 if HD is valid.)  */
gpg_error_t keydb_search_reset (KEYDB_HANDLE hd);

/* Search the database for keys matching the search description.

   DESC is an array of search terms with NDESC entries.  The search
   terms are or'd together.  That is, the next entry in the DB that
   matches any of the descriptions will be returned.

   Note: this function resumes searching where the last search left
   off (i.e., at the current file position).  If you want to search
   from the start of the database, then you need to first call
   keydb_search_reset().

   If no key matches the search description, returns
   GPG_ERR_NOT_FOUND.  If there was a match, returns 0.  If an error
   occured, returns an error code.

   The returned key is considered to be selected and the raw data can,
   for instance, be returned by calling keydb_get_keyblock().  */
gpg_error_t keydb_search (KEYDB_HANDLE hd, KEYDB_SEARCH_DESC *desc,
                          size_t ndesc, size_t *descindex);

/* Return the first non-legacy key in the database.

   If you want the very first key in the database, you can directly
   call keydb_search with the search description
   KEYDB_SEARCH_MODE_FIRST.  */
gpg_error_t keydb_search_first (KEYDB_HANDLE hd);

/* Return the next key (not the next matching key!).

   Unlike calling keydb_search with KEYDB_SEARCH_MODE_NEXT, this
   function silently skips legacy keys.  */
gpg_error_t keydb_search_next (KEYDB_HANDLE hd);

/* This is a convenience function for searching for keys with a long
   key id.

   Note: this function resumes searching where the last search left
   off.  If you want to search the whole database, then you need to
   first call keydb_search_reset().  */
gpg_error_t keydb_search_kid (KEYDB_HANDLE hd, u32 *kid);

/* This is a convenience function for searching for keys with a long
   (20 byte) fingerprint.  This function ignores legacy keys.

   Note: this function resumes searching where the last search left
   off.  If you want to search the whole database, then you need to
   first call keydb_search_reset().  */
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

/* Return whether a secret key is available for the public key with
   key id KEYID.  Note: this is just a fast check and does not tell us
   whether the secret key is valid; this check merely indicates
   whether there is some secret key with the specified key id.  */
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
