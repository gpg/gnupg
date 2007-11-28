/* main.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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
#ifndef G10_MAIN_H
#define G10_MAIN_H
#include "types.h"
#include "iobuf.h"
#include "mpi.h"
#include "cipher.h"
#include "keydb.h"

/* It could be argued that the default cipher should be 3DES rather
   than CAST5, and the default compression should be 0
   (i.e. uncompressed) rather than 1 (zip).  However, the real world
   issues of speed and size come into play here. */

#define DEFAULT_CIPHER_ALGO     CIPHER_ALGO_CAST5
#define DEFAULT_DIGEST_ALGO     DIGEST_ALGO_SHA1
#define DEFAULT_COMPRESS_ALGO   COMPRESS_ALGO_ZIP
#define DEFAULT_S2K_DIGEST_ALGO DIGEST_ALGO_SHA1

#define S2K_DIGEST_ALGO (opt.s2k_digest_algo?opt.s2k_digest_algo:DEFAULT_S2K_DIGEST_ALGO)

typedef struct
{
  int header_okay;
  PK_LIST pk_list;
  DEK *symkey_dek;
  STRING2KEY *symkey_s2k;
  cipher_filter_context_t cfx;
} encrypt_filter_context_t;

struct groupitem
{
  char *name;
  STRLIST values;
  struct groupitem *next;
};

/*-- gpg.c --*/
extern int g10_errors_seen;

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
  void g10_exit(int rc) __attribute__ ((noreturn));
#else
  void g10_exit(int rc);
#endif
void print_pubkey_algo_note( int algo );
void print_cipher_algo_note( int algo );
void print_digest_algo_note( int algo );

/*-- armor.c --*/
char *make_radix64_string( const byte *data, size_t len );

/*-- misc.c --*/
void trap_unaligned(void);
int disable_core_dumps(void);
void register_secured_file (const char *fname);
void unregister_secured_file (const char *fname);
int  is_secured_file (int fd);
int  is_secured_filename (const char *fname);
u16 checksum_u16( unsigned n );
u16 checksum( byte *p, unsigned n );
u16 checksum_mpi( MPI a );
u32 buffer_to_u32( const byte *buffer );
const byte *get_session_marker( size_t *rlen );
int openpgp_cipher_test_algo( int algo );
int openpgp_pk_test_algo( int algo, unsigned int usage_flags );
int openpgp_pk_algo_usage ( int algo );
int openpgp_md_test_algo( int algo );

#ifdef USE_IDEA
void idea_cipher_warn( int show );
#else
#define idea_cipher_warn(a)
#endif

struct expando_args
{
  PKT_public_key *pk;
  PKT_secret_key *sk;
  byte imagetype;
};

char *pct_expando(const char *string,struct expando_args *args);
void deprecated_warning(const char *configname,unsigned int configlineno,
			const char *option,const char *repl1,const char *repl2);
void deprecated_command (const char *name);

const char *compress_algo_to_string(int algo);
int string_to_compress_algo(const char *string);
int check_compress_algo(int algo);
int default_cipher_algo(void);
int default_compress_algo(void);
const char *compliance_option_string(void);
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
char *unescape_percent_string (const unsigned char *s);
int has_invalid_email_chars (const char *s);
int is_valid_mailbox (const char *name);
char *default_homedir (void);
const char *get_libexecdir (void);
int path_access(const char *file,int mode);

/*-- helptext.c --*/
void display_online_help( const char *keyword );

/*-- encode.c --*/
int setup_symkey(STRING2KEY **symkey_s2k,DEK **symkey_dek);
int encode_symmetric( const char *filename );
int encode_store( const char *filename );
int encode_crypt( const char *filename, STRLIST remusr, int use_symkey );
void encode_crypt_files(int nfiles, char **files, STRLIST remusr);
int encrypt_filter( void *opaque, int control,
		    IOBUF a, byte *buf, size_t *ret_len);


/*-- sign.c --*/
int complete_sig( PKT_signature *sig, PKT_secret_key *sk, MD_HANDLE md );
int sign_file( STRLIST filenames, int detached, STRLIST locusr,
	       int do_encrypt, STRLIST remusr, const char *outfile );
int clearsign_file( const char *fname, STRLIST locusr, const char *outfile );
int sign_symencrypt_file (const char *fname, STRLIST locusr);

/*-- sig-check.c --*/
int check_revocation_keys (PKT_public_key *pk, PKT_signature *sig);
int check_backsig(PKT_public_key *main_pk,PKT_public_key *sub_pk,
		  PKT_signature *backsig);
int check_key_signature( KBNODE root, KBNODE node, int *is_selfsig );
int check_key_signature2( KBNODE root, KBNODE node, PKT_public_key *check_pk,
			  PKT_public_key *ret_pk, int *is_selfsig,
			  u32 *r_expiredate, int *r_expired );

/*-- delkey.c --*/
int delete_keys( STRLIST names, int secret, int allow_both );

/*-- keyedit.c --*/
void keyedit_menu( const char *username, STRLIST locusr,
		   STRLIST commands, int quiet, int seckey_check );
void show_basic_key_info (KBNODE keyblock);

/*-- keygen.c --*/
u32 parse_expire_string(u32 timestamp,const char *string);
u32 ask_expire_interval(u32 timestamp,int object,const char *def_expire);
void generate_keypair( const char *fname, const char *card_serialno,
                       const char *backup_encryption_dir );
int keygen_set_std_prefs (const char *string,int personal);
PKT_user_id *keygen_get_std_prefs (void);
int keygen_add_key_expire( PKT_signature *sig, void *opaque );
int keygen_add_std_prefs( PKT_signature *sig, void *opaque );
int keygen_upd_std_prefs( PKT_signature *sig, void *opaque );
int keygen_add_keyserver_url(PKT_signature *sig, void *opaque);
int keygen_add_notations(PKT_signature *sig,void *opaque);
int keygen_add_revkey(PKT_signature *sig, void *opaque);
int make_backsig(PKT_signature *sig,PKT_public_key *pk,
		 PKT_public_key *sub_pk,PKT_secret_key *sub_sk);
int generate_subkeypair( KBNODE pub_keyblock, KBNODE sec_keyblock );
#ifdef ENABLE_CARD_SUPPORT
int generate_card_subkeypair (KBNODE pub_keyblock, KBNODE sec_keyblock,
                              int keyno, const char *serialno);
int save_unprotected_key_to_card (PKT_secret_key *sk, int keyno);
#endif

/*-- openfile.c --*/
int overwrite_filep( const char *fname );
char *make_outfile_name( const char *iname );
char *ask_outfile_name( const char *name, size_t namelen );
int   open_outfile( const char *iname, int mode, IOBUF *a );
IOBUF open_sigfile( const char *iname, progress_filter_context_t *pfx );
void try_make_homedir( const char *fname );

/*-- seskey.c --*/
void make_session_key( DEK *dek );
MPI encode_session_key( DEK *dek, unsigned nbits );
MPI pkcs1_encode_md( MD_HANDLE md, int algo, size_t len, unsigned nbits,
		     const byte *asn, size_t asnlen );
MPI encode_md_value( PKT_public_key *pk, PKT_secret_key *sk,
		     MD_HANDLE md, int hash_algo );

/*-- import.c --*/
int parse_import_options(char *str,unsigned int *options,int noisy);
void import_keys( char **fnames, int nnames,
		  void *stats_hd, unsigned int options );
int import_keys_stream( IOBUF inp,void *stats_hd,unsigned char **fpr,
			size_t *fpr_len,unsigned int options );
void *import_new_stats_handle (void);
void import_release_stats_handle (void *p);
void import_print_stats (void *hd);

int collapse_uids( KBNODE *keyblock );

int auto_create_card_key_stub ( const char *serialnostr, 
                                const unsigned char *fpr1,
                                const unsigned char *fpr2,
                                const unsigned char *fpr3);

/*-- export.c --*/
int parse_export_options(char *str,unsigned int *options,int noisy);
int export_pubkeys( STRLIST users, unsigned int options );
int export_pubkeys_stream( IOBUF out, STRLIST users,
			   KBNODE *keyblock_out, unsigned int options );
int export_seckeys( STRLIST users );
int export_secsubkeys( STRLIST users );

/* dearmor.c --*/
int dearmor_file( const char *fname );
int enarmor_file( const char *fname );

/*-- revoke.c --*/
struct revocation_reason_info;
int gen_revoke( const char *uname );
int gen_desig_revoke( const char *uname, STRLIST locusr);
int revocation_reason_build_cb( PKT_signature *sig, void *opaque );
struct revocation_reason_info *
		ask_revocation_reason( int key_rev, int cert_rev, int hint );
void release_revocation_reason_info( struct revocation_reason_info *reason );

/*-- keylist.c --*/
void public_key_list( STRLIST list );
void secret_key_list( STRLIST list );
void print_subpackets_colon(PKT_signature *sig);
void reorder_keyblock (KBNODE keyblock);
void list_keyblock( KBNODE keyblock, int secret, int fpr, void *opaque );
void print_fingerprint (PKT_public_key *pk, PKT_secret_key *sk, int mode);
void print_revokers(PKT_public_key *pk);
void show_policy_url(PKT_signature *sig,int indent,int mode);
void show_keyserver_url(PKT_signature *sig,int indent,int mode);
void show_notation(PKT_signature *sig,int indent,int mode,int which);
void dump_attribs(const PKT_user_id *uid,
		  PKT_public_key *pk,PKT_secret_key *sk);
void set_attrib_fd(int fd);
void print_seckey_info (PKT_secret_key *sk);
void print_pubkey_info (FILE *fp, PKT_public_key *pk);
void print_card_key_info (FILE *fp, KBNODE keyblock);

/*-- verify.c --*/
void print_file_status( int status, const char *name, int what );
int verify_signatures( int nfiles, char **files );
int verify_files( int nfiles, char **files );

/*-- decrypt.c --*/
int decrypt_message( const char *filename );
void decrypt_messages(int nfiles, char *files[]);

/*-- plaintext.c --*/
int hash_datafiles( MD_HANDLE md, MD_HANDLE md2,
		    STRLIST files, const char *sigfilename, int textmode );
PKT_plaintext *setup_plaintext_name(const char *filename,IOBUF iobuf);

/*-- pipemode.c --*/
void run_in_pipemode (void);

/*-- signal.c --*/
void init_signals(void);
void pause_on_sigusr( int which );
void block_all_signals(void);
void unblock_all_signals(void);


#ifdef ENABLE_CARD_SUPPORT
/*-- card-util.c --*/
void change_pin (int no, int allow_admin);
void card_status (FILE *fp, char *serialno, size_t serialnobuflen);
void card_edit (STRLIST commands);
int  card_generate_subkey (KBNODE pub_keyblock, KBNODE sec_keyblock);
int  card_store_subkey (KBNODE node, int use);
#endif

#define S2K_DECODE_COUNT(_val) ((16ul + ((_val) & 15)) << (((_val) >> 4) + 6))

#endif /*G10_MAIN_H*/
