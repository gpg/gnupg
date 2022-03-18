/* main.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2009, 2010 Free Software Foundation, Inc.
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
#ifndef G10_MAIN_H
#define G10_MAIN_H

#include "../common/types.h"
#include "../common/iobuf.h"
#include "../common/util.h"
#include "keydb.h"
#include "keyedit.h"

/* It could be argued that the default cipher should be 3DES rather
   than AES128, and the default compression should be 0
   (i.e. uncompressed) rather than 1 (zip).  However, the real world
   issues of speed and size come into play here. */

#if GPG_USE_AES128
# define DEFAULT_CIPHER_ALGO     CIPHER_ALGO_AES
#elif GPG_USE_CAST5
# define DEFAULT_CIPHER_ALGO     CIPHER_ALGO_CAST5
#else
# define DEFAULT_CIPHER_ALGO     CIPHER_ALGO_3DES
#endif

#define DEFAULT_DIGEST_ALGO     ((GNUPG)? DIGEST_ALGO_SHA256:DIGEST_ALGO_SHA1)
#define DEFAULT_S2K_DIGEST_ALGO DIGEST_ALGO_SHA1
#ifdef HAVE_ZIP
# define DEFAULT_COMPRESS_ALGO   COMPRESS_ALGO_ZIP
#else
# define DEFAULT_COMPRESS_ALGO   COMPRESS_ALGO_NONE
#endif


#define S2K_DIGEST_ALGO (opt.s2k_digest_algo?opt.s2k_digest_algo:DEFAULT_S2K_DIGEST_ALGO)


/* Various data objects.  */

typedef struct
{
  ctrl_t ctrl;
  int header_okay;
  PK_LIST pk_list;
  DEK *symkey_dek;
  STRING2KEY *symkey_s2k;
  cipher_filter_context_t cfx;
} encrypt_filter_context_t;


struct groupitem
{
  char *name;
  strlist_t values;
  struct groupitem *next;
};

struct weakhash
{
  enum gcry_md_algos algo;
  int rejection_shown;
  struct weakhash *next;
};


/*-- gpg.c --*/
extern int g10_errors_seen;

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
  void g10_exit(int rc) __attribute__ ((noreturn));
#else
  void g10_exit(int rc);
#endif
void print_pubkey_algo_note (pubkey_algo_t algo);
void print_cipher_algo_note (cipher_algo_t algo);
void print_digest_algo_note (digest_algo_t algo);
void print_digest_rejected_note (enum gcry_md_algos algo);
void print_sha1_keysig_rejected_note (void);
void print_reported_error (gpg_error_t err, gpg_err_code_t skip_if_ec);
void print_further_info (const char *format, ...) GPGRT_ATTR_PRINTF(1,2);
void additional_weak_digest (const char* digestname);
int  is_weak_digest (digest_algo_t algo);

/*-- armor.c --*/
char *make_radix64_string( const byte *data, size_t len );

/*-- misc.c --*/
void trap_unaligned(void);
void register_secured_file (const char *fname);
void unregister_secured_file (const char *fname);
int  is_secured_file (int fd);
int  is_secured_filename (const char *fname);
u16 checksum_u16( unsigned n );
u16 checksum( byte *p, unsigned n );
u16 checksum_mpi( gcry_mpi_t a );
u32 buffer_to_u32( const byte *buffer );
const byte *get_session_marker( size_t *rlen );

enum gcry_cipher_algos map_cipher_openpgp_to_gcry (cipher_algo_t algo);
#define openpgp_cipher_open(_a,_b,_c,_d) \
  gcry_cipher_open((_a),map_cipher_openpgp_to_gcry((_b)),(_c),(_d))
#define openpgp_cipher_get_algo_keylen(_a) \
  gcry_cipher_get_algo_keylen(map_cipher_openpgp_to_gcry((_a)))
#define openpgp_cipher_get_algo_blklen(_a) \
  gcry_cipher_get_algo_blklen(map_cipher_openpgp_to_gcry((_a)))
int openpgp_cipher_blocklen (cipher_algo_t algo);
int openpgp_cipher_test_algo(cipher_algo_t algo);
const char *openpgp_cipher_algo_name (cipher_algo_t algo);
const char *openpgp_cipher_algo_mode_name (cipher_algo_t algo,
                                           aead_algo_t aead);

gpg_error_t openpgp_aead_test_algo (aead_algo_t algo);
const char *openpgp_aead_algo_name (aead_algo_t algo);
gpg_error_t openpgp_aead_algo_info (aead_algo_t algo,
                                    enum gcry_cipher_modes *r_mode,
                                    unsigned int *r_noncelen);

pubkey_algo_t map_pk_gcry_to_openpgp (enum gcry_pk_algos algo);
int openpgp_pk_test_algo (pubkey_algo_t algo);
int openpgp_pk_test_algo2 (pubkey_algo_t algo, unsigned int use);
int openpgp_pk_algo_usage ( int algo );
const char *openpgp_pk_algo_name (pubkey_algo_t algo);

enum gcry_md_algos map_md_openpgp_to_gcry (digest_algo_t algo);
int openpgp_md_test_algo (digest_algo_t algo);
const char *openpgp_md_algo_name (int algo);

struct expando_args
{
  PKT_public_key *pk;
  PKT_public_key *pksk;
  byte imagetype;
  int validity_info;
  const char *validity_string;
  const byte *namehash;
};

char *pct_expando(const char *string,struct expando_args *args);
void deprecated_warning(const char *configname,unsigned int configlineno,
			const char *option,const char *repl1,const char *repl2);
void deprecated_command (const char *name);
void obsolete_scdaemon_option (const char *configname,
                               unsigned int configlineno, const char *name);

int string_to_cipher_algo (const char *string);
int string_to_digest_algo (const char *string);

const char *compress_algo_to_string(int algo);
int string_to_compress_algo(const char *string);
int check_compress_algo(int algo);
int default_cipher_algo(void);
int default_compress_algo(void);
void compliance_failure(void);

struct parse_options
{
  char *name;
  unsigned int bit;
  char **value;
  char *help;
};

char *optsep(char **stringp);
char *argsplit(char *string);
int parse_options(char *str,unsigned int *options,
		  struct parse_options *opts,int noisy);
const char *get_libexecdir (void);
int path_access(const char *file,int mode);

int pubkey_get_npkey (pubkey_algo_t algo);
int pubkey_get_nskey (pubkey_algo_t algo);
int pubkey_get_nsig (pubkey_algo_t algo);
int pubkey_get_nenc (pubkey_algo_t algo);

/* Temporary helpers. */
unsigned int pubkey_nbits( int algo, gcry_mpi_t *pkey );
int mpi_print (estream_t stream, gcry_mpi_t a, int mode);
unsigned int ecdsa_qbits_from_Q (unsigned int qbits);


/*-- cpr.c --*/
void set_status_fd ( int fd );
int  is_status_enabled ( void );
void write_status ( int no );
void write_status_error (const char *where, gpg_error_t err);
void write_status_errcode (const char *where, int errcode);
void write_status_failure (const char *where, gpg_error_t err);
void write_status_text ( int no, const char *text );
void write_status_printf (int no, const char *format,
                          ...) GPGRT_ATTR_PRINTF(2,3);
void write_status_strings (int no, const char *text,
                           ...) GPGRT_ATTR_SENTINEL(0);
void write_status_buffer ( int no,
                           const char *buffer, size_t len, int wrap );
void write_status_text_and_buffer ( int no, const char *text,
                                    const char *buffer, size_t len, int wrap );

void write_status_begin_signing (gcry_md_hd_t md);


int cpr_enabled(void);
char *cpr_get( const char *keyword, const char *prompt );
char *cpr_get_no_help( const char *keyword, const char *prompt );
char *cpr_get_utf8( const char *keyword, const char *prompt );
char *cpr_get_hidden( const char *keyword, const char *prompt );
void cpr_kill_prompt(void);
int  cpr_get_answer_is_yes_def (const char *keyword, const char *prompt,
                                int def_yes);
int  cpr_get_answer_is_yes( const char *keyword, const char *prompt );
int  cpr_get_answer_yes_no_quit( const char *keyword, const char *prompt );
int  cpr_get_answer_okay_cancel (const char *keyword,
                                 const char *prompt,
                                 int def_answer);

/*-- helptext.c --*/
void display_online_help( const char *keyword );

/*-- encode.c --*/
gpg_error_t setup_symkey (STRING2KEY **symkey_s2k,DEK **symkey_dek);
void encrypt_seskey (DEK *dek, DEK **seskey, byte *enckey);
int use_mdc (pk_list_t pk_list,int algo);
int encrypt_symmetric (const char *filename );
int encrypt_store (const char *filename );
int encrypt_crypt (ctrl_t ctrl, int filefd, const char *filename,
                   strlist_t remusr, int use_symkey, pk_list_t provided_keys,
                   int outputfd);
void encrypt_crypt_files (ctrl_t ctrl,
                          int nfiles, char **files, strlist_t remusr);
int encrypt_filter (void *opaque, int control,
		    iobuf_t a, byte *buf, size_t *ret_len);

int write_pubkey_enc (ctrl_t ctrl, PKT_public_key *pk, int throw_keyid,
                      DEK *dek, iobuf_t out);

/*-- sign.c --*/
int sign_file (ctrl_t ctrl, strlist_t filenames, int detached, strlist_t locusr,
	       int do_encrypt, strlist_t remusr, const char *outfile );
int clearsign_file (ctrl_t ctrl,
                    const char *fname, strlist_t locusr, const char *outfile);
int sign_symencrypt_file (ctrl_t ctrl, const char *fname, strlist_t locusr);

/*-- sig-check.c --*/
void sig_check_dump_stats (void);

/* SIG is a revocation signature.  Check if any of PK's designated
   revokers generated it.  If so, return 0.  Note: this function
   (correctly) doesn't care if the designated revoker is revoked.  */
int check_revocation_keys (ctrl_t ctrl, PKT_public_key *pk, PKT_signature *sig);
/* Check that the backsig BACKSIG from the subkey SUB_PK to its
   primary key MAIN_PK is valid.  */
int check_backsig(PKT_public_key *main_pk,PKT_public_key *sub_pk,
		  PKT_signature *backsig);
/* Check that the signature SIG over a key (e.g., a key binding or a
   key revocation) is valid.  (To check signatures over data, use
   check_signature.)  */
int check_key_signature (ctrl_t ctrl, kbnode_t root, kbnode_t sig,
                         int *is_selfsig );
/* Like check_key_signature, but with the ability to specify some
   additional parameters and get back additional information.  See the
   documentation for the implementation for details.  */
int check_key_signature2 (ctrl_t ctrl, kbnode_t root, kbnode_t node,
                          PKT_public_key *check_pk, PKT_public_key *ret_pk,
                          int *is_selfsig, u32 *r_expiredate, int *r_expired);

/* Returns whether SIGNER generated the signature SIG over the packet
   PACKET, which is a key, subkey or uid, and comes from the key block
   KB.  If SIGNER is NULL, it is looked up based on the information in
   SIG.  If not NULL, sets *IS_SELFSIG to indicate whether the
   signature is a self-signature and *RET_PK to a copy of the signer's
   key.  */
gpg_error_t check_signature_over_key_or_uid (ctrl_t ctrl,
                                             PKT_public_key *signer,
                                             PKT_signature *sig,
                                             KBNODE kb, PACKET *packet,
                                             int *is_selfsig,
                                             PKT_public_key *ret_pk);


/*-- delkey.c --*/
gpg_error_t delete_keys (ctrl_t ctrl,
                         strlist_t names, int secret, int allow_both);

/*-- keygen.c --*/
const char *get_default_pubkey_algo (void);
u32 parse_expire_string(const char *string);
u32 ask_expire_interval(int object,const char *def_expire);
u32 ask_expiredate(void);
unsigned int ask_key_flags (int algo, int subkey, unsigned int current);
const char *ask_curve (int *algo, int *subkey_algo, const char *current);
void quick_generate_keypair (ctrl_t ctrl, const char *uid, const char *algostr,
                             const char *usagestr, const char *expirestr);
void generate_keypair (ctrl_t ctrl, int full, const char *fname,
                       const char *card_serialno, int card_backup_key);
int keygen_set_std_prefs (const char *string,int personal);
PKT_user_id *keygen_get_std_prefs (void);
int keygen_add_key_expire( PKT_signature *sig, void *opaque );
int keygen_add_key_flags (PKT_signature *sig, void *opaque);
int keygen_add_std_prefs( PKT_signature *sig, void *opaque );
int keygen_upd_std_prefs( PKT_signature *sig, void *opaque );
int keygen_add_keyserver_url(PKT_signature *sig, void *opaque);
int keygen_add_notations(PKT_signature *sig,void *opaque);
int keygen_add_revkey(PKT_signature *sig, void *opaque);
gpg_error_t make_backsig (ctrl_t ctrl,
                          PKT_signature *sig, PKT_public_key *pk,
                          PKT_public_key *sub_pk, PKT_public_key *sub_psk,
                          u32 timestamp, const char *cache_nonce);
gpg_error_t generate_subkeypair (ctrl_t ctrl, kbnode_t keyblock,
                                 const char *algostr,
                                 const char *usagestr,
                                 const char *expirestr);
#ifdef ENABLE_CARD_SUPPORT
gpg_error_t generate_card_subkeypair (ctrl_t ctrl, kbnode_t pub_keyblock,
                                      int keyno, const char *serialno);
#endif


/*-- openfile.c --*/
int overwrite_filep( const char *fname );
char *make_outfile_name( const char *iname );
char *ask_outfile_name( const char *name, size_t namelen );
int open_outfile (int inp_fd, const char *iname, int mode,
                  int restrictedperm, iobuf_t *a);
char *get_matching_datafile (const char *sigfilename);
iobuf_t open_sigfile (const char *sigfilename, progress_filter_context_t *pfx);
void try_make_homedir( const char *fname );
char *get_openpgp_revocdir (const char *home);

/*-- seskey.c --*/
void make_session_key( DEK *dek );
gcry_mpi_t encode_session_key( int openpgp_pk_algo, DEK *dek, unsigned nbits );
gcry_mpi_t encode_md_value (PKT_public_key *pk,
                            gcry_md_hd_t md, int hash_algo );

/*-- import.c --*/
struct import_stats_s;
typedef struct import_stats_s *import_stats_t;
struct import_filter_s;
typedef struct import_filter_s *import_filter_t;
typedef gpg_error_t (*import_screener_t)(kbnode_t keyblock, void *arg);

int parse_import_options(char *str,unsigned int *options,int noisy);

gpg_error_t parse_and_set_import_filter (const char *string);
import_filter_t save_and_clear_import_filter (void);
void            restore_import_filter (import_filter_t filt);

gpg_error_t read_key_from_file_or_buffer (ctrl_t ctrl, const char *fname,
                                          const void *buffer, size_t buflen,
                                          kbnode_t *r_keyblock);
gpg_error_t import_included_key_block (ctrl_t ctrl, kbnode_t keyblock);
void import_keys (ctrl_t ctrl, char **fnames, int nnames,
		  import_stats_t stats_hd, unsigned int options,
                  int origin, const char *url);
gpg_error_t import_keys_es_stream (ctrl_t ctrl, estream_t fp,
                           import_stats_t stats_handle,
                           unsigned char **fpr, size_t *fpr_len,
                           unsigned int options,
                           import_screener_t screener, void *screener_arg,
                           int origin, const char *url);
gpg_error_t import_old_secring (ctrl_t ctrl, const char *fname);
import_stats_t import_new_stats_handle (void);
void import_release_stats_handle (import_stats_t hd);
void import_print_stats (import_stats_t hd);
/* Communication for impex_filter_getval */
struct impex_filter_parm_s
{
  ctrl_t ctrl;
  kbnode_t node;
  char hexfpr[2*MAX_FINGERPRINT_LEN + 1];
};

const char *impex_filter_getval (void *cookie, const char *propname);
gpg_error_t transfer_secret_keys (ctrl_t ctrl, struct import_stats_s *stats,
                                  kbnode_t sec_keyblock, int batch, int force,
                                  int only_marked);

int collapse_uids( KBNODE *keyblock );

int get_revocation_reason (PKT_signature *sig, char **r_reason,
                           char **r_comment, size_t *r_commentlen);


/*-- export.c --*/
struct export_stats_s;
typedef struct export_stats_s *export_stats_t;

export_stats_t export_new_stats (void);
void export_release_stats (export_stats_t stats);
void export_print_stats (export_stats_t stats);

int parse_export_options(char *str,unsigned int *options,int noisy);
gpg_error_t parse_and_set_export_filter (const char *string);
void push_export_filters (void);
void pop_export_filters (void);

int exact_subkey_match_p (KEYDB_SEARCH_DESC *desc, kbnode_t node);

int export_pubkeys (ctrl_t ctrl, strlist_t users, unsigned int options,
                    export_stats_t stats);
int export_seckeys (ctrl_t ctrl, strlist_t users, unsigned int options,
                    export_stats_t stats);
int export_secsubkeys (ctrl_t ctrl, strlist_t users, unsigned int options,
                       export_stats_t stats);

gpg_error_t export_pubkey_buffer (ctrl_t ctrl, const char *keyspec,
                                  unsigned int options,
                                  const void *prefix, size_t prefixlen,
                                  export_stats_t stats,
                                  kbnode_t *r_keyblock,
                                  void **r_data, size_t *r_datalen);

gpg_error_t receive_seckey_from_agent (ctrl_t ctrl, gcry_cipher_hd_t cipherhd,
                                       int cleartext,
                                       char **cache_nonce_addr,
                                       const char *hexgrip,
                                       PKT_public_key *pk);

gpg_error_t write_keyblock_to_output (kbnode_t keyblock,
                                      int with_armor, unsigned int options);

gpg_error_t export_ssh_key (ctrl_t ctrl, const char *userid);

/*-- dearmor.c --*/
int dearmor_file( const char *fname );
int enarmor_file( const char *fname );

/*-- revoke.c --*/
struct revocation_reason_info;

int gen_standard_revoke (ctrl_t ctrl,
                         PKT_public_key *psk, const char *cache_nonce);
int gen_revoke (ctrl_t ctrl, const char *uname);
int gen_desig_revoke (ctrl_t ctrl, const char *uname, strlist_t locusr);
int revocation_reason_build_cb( PKT_signature *sig, void *opaque );
struct revocation_reason_info *
		ask_revocation_reason( int key_rev, int cert_rev, int hint );
struct revocation_reason_info * get_default_uid_revocation_reason (void);
struct revocation_reason_info * get_default_sig_revocation_reason (void);
void release_revocation_reason_info (struct revocation_reason_info *reason);

/*-- keylist.c --*/
void public_key_list (ctrl_t ctrl, strlist_t list,
                      int locate_mode, int no_local);
void secret_key_list (ctrl_t ctrl, strlist_t list );
void print_subpackets_colon(PKT_signature *sig);
void reorder_keyblock (KBNODE keyblock);
void list_keyblock_direct (ctrl_t ctrl, kbnode_t keyblock, int secret,
                           int has_secret, int fpr, int no_validity);
int  cmp_signodes (const void *av, const void *bv);
void print_fingerprint (ctrl_t ctrl, estream_t fp,
                        PKT_public_key *pk, int mode);
void print_revokers (estream_t fp, PKT_public_key *pk);
void show_policy_url(PKT_signature *sig,int indent,int mode);
void show_keyserver_url(PKT_signature *sig,int indent,int mode);
void show_notation(PKT_signature *sig,int indent,int mode,int which);
void dump_attribs (const PKT_user_id *uid, PKT_public_key *pk);
void set_attrib_fd(int fd);
char *format_seckey_info (ctrl_t ctrl, PKT_public_key *pk);
void print_seckey_info (ctrl_t ctrl, PKT_public_key *pk);
void print_pubkey_info (ctrl_t ctrl, estream_t fp, PKT_public_key *pk);
void print_card_key_info (estream_t fp, KBNODE keyblock);
void print_key_line (ctrl_t ctrl, estream_t fp, PKT_public_key *pk, int secret);

/*-- verify.c --*/
void print_file_status( int status, const char *name, int what );
int verify_signatures (ctrl_t ctrl, int nfiles, char **files );
int verify_files (ctrl_t ctrl, int nfiles, char **files );
int gpg_verify (ctrl_t ctrl, int sig_fd, int data_fd, estream_t out_fp);

/*-- decrypt.c --*/
int decrypt_message (ctrl_t ctrl, const char *filename );
gpg_error_t decrypt_message_fd (ctrl_t ctrl, int input_fd, int output_fd);
void decrypt_messages (ctrl_t ctrl, int nfiles, char *files[]);

/*-- plaintext.c --*/
int hash_datafiles( gcry_md_hd_t md, gcry_md_hd_t md2,
		    strlist_t files, const char *sigfilename, int textmode);
int hash_datafile_by_fd ( gcry_md_hd_t md, gcry_md_hd_t md2, int data_fd,
                          int textmode );
PKT_plaintext *setup_plaintext_name(const char *filename,IOBUF iobuf);

/*-- server.c --*/
int gpg_server (ctrl_t);
gpg_error_t gpg_proxy_pinentry_notify (ctrl_t ctrl,
                                       const unsigned char *line);

#ifdef ENABLE_CARD_SUPPORT
/*-- card-util.c --*/
void change_pin (int no, int allow_admin);
void card_status (ctrl_t ctrl, estream_t fp, const char *serialno);
void card_edit (ctrl_t ctrl, strlist_t commands);
gpg_error_t  card_generate_subkey (ctrl_t ctrl, kbnode_t pub_keyblock);
int  card_store_subkey (KBNODE node, int use);
#endif

#define S2K_DECODE_COUNT(_val) ((16ul + ((_val) & 15)) << (((_val) >> 4) + 6))

/*-- migrate.c --*/
void migrate_secring (ctrl_t ctrl);


#endif /*G10_MAIN_H*/
