/* gpgsm.h - Global definitions for GpgSM
 *	Copyright (C) 2001, 2003, 2004 Free Software Foundation, Inc.
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

#ifndef GPGSM_H
#define GPGSM_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_GPGSM
#include <gpg-error.h>

#include <ksba.h>
#include "../common/util.h"
#include "../common/errors.h"

#define OUT_OF_CORE(a) (gpg_error (gpg_err_code_from_errno ((a))))

#define MAX_DIGEST_LEN 24 

/* A large struct named "opt" to keep global flags */
struct {
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int verbose;      /* verbosity level */
  int quiet;        /* be as quiet as possible */
  int batch;        /* run in batch mode, i.e w/o any user interaction */
  int answer_yes;   /* assume yes on most questions */
  int answer_no;    /* assume no on most questions */
  int dry_run;      /* don't change any persistent data */

  const char *homedir; /* configuration directory name */
  const char *agent_program; 
  char *display;
  char *ttyname;
  char *ttytype;
  char *lc_ctype;
  char *lc_messages;

  const char *dirmngr_program;
  const char *protect_tool_program;
  char *outfile;    /* name of output file */

  int with_key_data;/* include raw key in the column delimted output */
  
  int fingerprint;  /* list fingerprints in all key listings */

  int with_md5_fingerprint; /* Also print an MD5 fingerprint for
                               standard key listings. */

  int armor;        /* force base64 armoring (see also ctrl.with_base64) */
  int no_armor;     /* don't try to figure out whether data is base64 armored*/

  const char *def_cipher_algoid;  /* cipher algorithm to use if
                                     nothing else is specified */

  int def_digest_algo;    /* Ditto for hash algorithm */
  int def_compress_algo;  /* Ditto for compress algorithm */

  char *def_recipient;    /* userID of the default recipient */
  int def_recipient_self; /* The default recipient is the default key */

  int no_encrypt_to;      /* Ignore all as encrypt to marked recipients. */

  char *local_user;       /* NULL or argument to -u */

  int always_trust;       /* Trust the given keys even if there is no
                             valid certification chain */
  int skip_verify;        /* do not check signatures on data */

  int lock_once;          /* Keep lock once they are set */

  int ignore_time_conflict; /* Ignore certain time conflicts */

  int no_crl_check;         /* Don't do a CRL check */
  int enable_ocsp;          /* Default to use OCSP checks. */

  char *policy_file;        /* full pathname of policy file */
  int no_policy_check;      /* ignore certificate policies */
  int no_chain_validation;  /* Bypass all cert chain validity tests */
  int ignore_expiration;    /* Ignore the notAfter validity checks. */

  int auto_issuer_key_retrieve; /* try to retrieve a missing issuer key. */
} opt;


#define DBG_X509_VALUE    1	/* debug x.509 data reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_ASSUAN_VALUE  1024  /* debug assuan communication */

#define DBG_X509    (opt.debug & DBG_X509_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_ASSUAN   (opt.debug & DBG_ASSUAN_VALUE)

struct server_local_s;

/* Note that the default values for this are set by
   gpgsm_init_default_ctrl() */
struct server_control_s {
  int no_server;      /* We are not running under server control */
  int  status_fd;     /* Only for non-server mode */
  struct server_local_s *server_local;
  int with_colons;    /* Use column delimited output format */
  int with_chain;     /* Include the certifying certs in a listing */
  int with_validation;/* Validate each key while listing. */

  int autodetect_encoding; /* Try to detect the input encoding */
  int is_pem;         /* Is in PEM format */
  int is_base64;      /* is in plain base-64 format */

  int create_base64;  /* Create base64 encoded output */
  int create_pem;     /* create PEM output */
  const char *pem_name; /* PEM name to use */

  int include_certs;  /* -1 to send all certificates in the chain
                         along with a signature or the number of
                         certificates up the chain (0 = none, 1 = only
                         signer) */
  int use_ocsp;       /* Set to true if OCSP should be used. */
};
typedef struct server_control_s *CTRL;
typedef struct server_control_s *ctrl_t;

/* data structure used in base64.c */
typedef struct base64_context_s *Base64Context;


struct certlist_s {
  struct certlist_s *next;
  ksba_cert_t cert;
  int is_encrypt_to; /* True if the certificate has been set through
                        the --encrypto-to option. */
};
typedef struct certlist_s *CERTLIST;
typedef struct certlist_s *certlist_t;

/*-- gpgsm.c --*/
void gpgsm_exit (int rc);
void gpgsm_init_default_ctrl (struct server_control_s *ctrl);

/*-- server.c --*/
void gpgsm_server (certlist_t default_recplist);
void gpgsm_status (ctrl_t ctrl, int no, const char *text);
void gpgsm_status2 (ctrl_t ctrl, int no, ...);
void gpgsm_status_with_err_code (ctrl_t ctrl, int no, const char *text,
                                 gpg_err_code_t ec);

/*-- fingerprint --*/
char *gpgsm_get_fingerprint (ksba_cert_t cert, int algo,
                             char *array, int *r_len);
char *gpgsm_get_fingerprint_string (ksba_cert_t cert, int algo);
char *gpgsm_get_fingerprint_hexstring (ksba_cert_t cert, int algo);
unsigned long gpgsm_get_short_fingerprint (ksba_cert_t cert);
char *gpgsm_get_keygrip (ksba_cert_t cert, char *array);
char *gpgsm_get_keygrip_hexstring (ksba_cert_t cert);
char *gpgsm_get_certid (ksba_cert_t cert);


/*-- base64.c --*/
int  gpgsm_create_reader (Base64Context *ctx,
                          ctrl_t ctrl, FILE *fp, int allow_multi_pem,
                          ksba_reader_t *r_reader);
int gpgsm_reader_eof_seen (Base64Context ctx);
void gpgsm_destroy_reader (Base64Context ctx);
int  gpgsm_create_writer (Base64Context *ctx,
                          ctrl_t ctrl, FILE *fp, ksba_writer_t *r_writer);
int  gpgsm_finish_writer (Base64Context ctx);
void gpgsm_destroy_writer (Base64Context ctx);


/*-- certdump.c --*/
void gpgsm_print_serial (FILE *fp, ksba_const_sexp_t p);
void gpgsm_print_time (FILE *fp, ksba_isotime_t t);
void gpgsm_print_name (FILE *fp, const char *string);

void gpgsm_dump_cert (const char *text, ksba_cert_t cert);
void gpgsm_dump_serial (ksba_const_sexp_t p);
void gpgsm_dump_time (ksba_isotime_t t);
void gpgsm_dump_string (const char *string);

char *gpgsm_format_serial (ksba_const_sexp_t p);
char *gpgsm_format_name (const char *name);

char *gpgsm_format_keydesc (ksba_cert_t cert);


/*-- certcheck.c --*/
int gpgsm_check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert);
int gpgsm_check_cms_signature (ksba_cert_t cert, ksba_const_sexp_t sigval,
                               gcry_md_hd_t md, int hash_algo);
/* fixme: move create functions to another file */
int gpgsm_create_cms_signature (ksba_cert_t cert, gcry_md_hd_t md, int mdalgo,
                                char **r_sigval);


/*-- certchain.c --*/
int gpgsm_walk_cert_chain (ksba_cert_t start, ksba_cert_t *r_next);
int gpgsm_is_root_cert (ksba_cert_t cert);
int gpgsm_validate_chain (ctrl_t ctrl, ksba_cert_t cert,
                          ksba_isotime_t r_exptime,
                          int listmode, FILE *listfp);
int gpgsm_basic_cert_check (ksba_cert_t cert);

/*-- certlist.c --*/
int gpgsm_cert_use_sign_p (ksba_cert_t cert);
int gpgsm_cert_use_encrypt_p (ksba_cert_t cert);
int gpgsm_cert_use_verify_p (ksba_cert_t cert);
int gpgsm_cert_use_decrypt_p (ksba_cert_t cert);
int gpgsm_cert_use_cert_p (ksba_cert_t cert);
int gpgsm_add_cert_to_certlist (ctrl_t ctrl, ksba_cert_t cert,
                                certlist_t *listaddr, int is_encrypt_to);
int gpgsm_add_to_certlist (ctrl_t ctrl, const char *name, int secret,
                           certlist_t *listaddr, int is_encrypt_to);
void gpgsm_release_certlist (certlist_t list);
int gpgsm_find_cert (const char *name, ksba_cert_t *r_cert);

/*-- keylist.c --*/
gpg_error_t gpgsm_list_keys (ctrl_t ctrl, STRLIST names,
                             FILE *fp, unsigned int mode);

/*-- import.c --*/
int gpgsm_import (ctrl_t ctrl, int in_fd);
int gpgsm_import_files (ctrl_t ctrl, int nfiles, char **files,
                        int (*of)(const char *fname));

/*-- export.c --*/
void gpgsm_export (ctrl_t ctrl, STRLIST names, FILE *fp);
void gpgsm_p12_export (ctrl_t ctrl, const char *name, FILE *fp);

/*-- delete.c --*/
int gpgsm_delete (ctrl_t ctrl, STRLIST names);

/*-- verify.c --*/
int gpgsm_verify (ctrl_t ctrl, int in_fd, int data_fd, FILE *out_fp);

/*-- sign.c --*/
int gpgsm_get_default_cert (ksba_cert_t *r_cert);
int gpgsm_sign (ctrl_t ctrl, CERTLIST signerlist,
                int data_fd, int detached, FILE *out_fp);

/*-- encrypt.c --*/
int gpgsm_encrypt (ctrl_t ctrl, CERTLIST recplist, int in_fd, FILE *out_fp);

/*-- decrypt.c --*/
int gpgsm_decrypt (ctrl_t ctrl, int in_fd, FILE *out_fp);

/*-- certreqgen.c --*/
int gpgsm_genkey (ctrl_t ctrl, int in_fd, FILE *out_fp);

/*-- call-agent.c --*/
int gpgsm_agent_pksign (const char *keygrip, const char *desc,
                        unsigned char *digest,
                        size_t digestlen,
                        int digestalgo,
                        char **r_buf, size_t *r_buflen);
int gpgsm_agent_pkdecrypt (const char *keygrip, const char *desc,
                           ksba_const_sexp_t ciphertext, 
                           char **r_buf, size_t *r_buflen);
int gpgsm_agent_genkey (ksba_const_sexp_t keyparms, ksba_sexp_t *r_pubkey);
int gpgsm_agent_istrusted (ksba_cert_t cert);
int gpgsm_agent_havekey (const char *hexkeygrip);
int gpgsm_agent_marktrusted (ksba_cert_t cert);
int gpgsm_agent_learn (void);
int gpgsm_agent_passwd (const char *hexkeygrip, const char *desc);

/*-- call-dirmngr.c --*/
int gpgsm_dirmngr_isvalid (ksba_cert_t cert, ksba_cert_t issuer_cert,
                           int use_ocsp);
int gpgsm_dirmngr_lookup (ctrl_t ctrl, STRLIST names,
                          void (*cb)(void*, ksba_cert_t), void *cb_value);
int gpgsm_dirmngr_run_command (ctrl_t ctrl, const char *command,
                               int argc, char **argv);





#endif /*GPGSM_H*/
