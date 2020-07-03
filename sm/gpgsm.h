/* gpgsm.h - Global definitions for GpgSM
 * Copyright (C) 2001, 2003, 2004, 2007, 2009,
 *               2010 Free Software Foundation, Inc.
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

#ifndef GPGSM_H
#define GPGSM_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_GPGSM
#include <gpg-error.h>


#include <ksba.h>
#include "../common/util.h"
#include "../common/status.h"
#include "../common/audit.h"
#include "../common/session-env.h"
#include "../common/ksba-io-support.h"
#include "../common/compliance.h"


#define MAX_DIGEST_LEN 64

struct keyserver_spec
{
  struct keyserver_spec *next;

  char *host;
  int port;
  char *user;
  char *pass;
  char *base;
};


/* A large struct named "opt" to keep global flags. */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int verbose;      /* verbosity level */
  int quiet;        /* be as quiet as possible */
  int batch;        /* run in batch mode, i.e w/o any user interaction */
  int answer_yes;   /* assume yes on most questions */
  int answer_no;    /* assume no on most questions */
  int dry_run;      /* don't change any persistent data */
  int no_homedir_creation;

  const char *config_filename; /* Name of the used config file. */
  const char *agent_program;

  session_env_t session_env;
  char *lc_ctype;
  char *lc_messages;

  int autostart;
  const char *dirmngr_program;
  int disable_dirmngr;        /* Do not do any dirmngr calls.  */
  const char *protect_tool_program;
  char *outfile;    /* name of output file */

  int with_key_data;/* include raw key in the column delimted output */

  int fingerprint;  /* list fingerprints in all key listings */

  int with_md5_fingerprint; /* Also print an MD5 fingerprint for
                               standard key listings. */

  int with_keygrip; /* Option --with-keygrip active.  */

  int pinentry_mode;
  int request_origin;

  int armor;        /* force base64 armoring (see also ctrl.with_base64) */
  int no_armor;     /* don't try to figure out whether data is base64 armored*/

  const char *p12_charset; /* Use this charset for encoding the
                              pkcs#12 passphrase.  */


  const char *def_cipher_algoid;  /* cipher algorithm to use if
                                     nothing else is specified */

  int def_compress_algo;  /* Ditto for compress algorithm */

  int forced_digest_algo; /* User forced hash algorithm. */

  char *def_recipient;    /* userID of the default recipient */
  int def_recipient_self; /* The default recipient is the default key */

  int no_encrypt_to;      /* Ignore all as encrypt to marked recipients. */

  char *local_user;       /* NULL or argument to -u */

  int extra_digest_algo;  /* A digest algorithm also used for
                             verification of signatures.  */

  int always_trust;       /* Trust the given keys even if there is no
                             valid certification chain */
  int skip_verify;        /* do not check signatures on data */

  int lock_once;          /* Keep lock once they are set */

  int ignore_time_conflict; /* Ignore certain time conflicts */

  int no_crl_check;         /* Don't do a CRL check */
  int no_trusted_cert_crl_check; /* Don't run a CRL check for trusted certs. */
  int force_crl_refresh;    /* Force refreshing the CRL. */
  int enable_issuer_based_crl_check; /* Backward compatibility hack.  */
  int enable_ocsp;          /* Default to use OCSP checks. */

  char *policy_file;        /* full pathname of policy file */
  int no_policy_check;      /* ignore certificate policies */
  int no_chain_validation;  /* Bypass all cert chain validity tests */
  int ignore_expiration;    /* Ignore the notAfter validity checks. */

  int auto_issuer_key_retrieve; /* try to retrieve a missing issuer key. */

  int qualsig_approval;     /* Set to true if this software has
                               officially been approved to create an
                               verify qualified signatures.  This is a
                               runtime option in case we want to check
                               the integrity of the software at
                               runtime. */

  struct keyserver_spec *keyserver;

  /* A list of certificate extension OIDs which are ignored so that
     one can claim that a critical extension has been handled.  One
     OID per string.  */
  strlist_t ignored_cert_extensions;

  enum gnupg_compliance_mode compliance;
} opt;

/* Debug values and macros.  */
#define DBG_X509_VALUE    1	/* debug x.509 data reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_IPC_VALUE     1024  /* debug assuan communication */

#define DBG_X509    (opt.debug & DBG_X509_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)

/* Forward declaration for an object defined in server.c */
struct server_local_s;

/* Session control object.  This object is passed down to most
   functions.  Note that the default values for it are set by
   gpgsm_init_default_ctrl(). */
struct server_control_s
{
  int no_server;      /* We are not running under server control */
  int  status_fd;     /* Only for non-server mode */
  struct server_local_s *server_local;

  audit_ctx_t audit;  /* NULL or a context for the audit subsystem.  */
  int agent_seen;     /* Flag indicating that the gpg-agent has been
                         accessed.  */

  int with_colons;    /* Use column delimited output format */
  int with_secret;    /* Mark secret keys in a public key listing.  */
  int with_chain;     /* Include the certifying certs in a listing */
  int with_validation;/* Validate each key while listing. */
  int with_ephemeral_keys;  /* Include ephemeral flagged keys in the
                               keylisting. */

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
  int validation_model; /* 0 := standard model (shell),
                           1 := chain model,
                           2 := STEED model. */
  int offline;        /* If true gpgsm won't do any network access.  */

  /* The current time.  Used as a helper in certchain.c.  */
  ksba_isotime_t current_time;
};


/* An object to keep a list of certificates. */
struct certlist_s
{
  struct certlist_s *next;
  ksba_cert_t cert;
  int is_encrypt_to; /* True if the certificate has been set through
                        the --encrypto-to option. */
  int hash_algo;     /* Used to track the hash algorithm to use.  */
  const char *hash_algo_oid;  /* And the corresponding OID.  */
};
typedef struct certlist_s *certlist_t;


/* A structure carrying information about trusted root certificates. */
struct rootca_flags_s
{
  unsigned int valid:1;  /* The rest of the structure has valid
                            information.  */
  unsigned int relax:1;  /* Relax checking of root certificates.  */
  unsigned int chain_model:1; /* Root requires the use of the chain model.  */
};



/*-- gpgsm.c --*/
void gpgsm_exit (int rc);
void gpgsm_init_default_ctrl (struct server_control_s *ctrl);
int  gpgsm_parse_validation_model (const char *model);

/*-- server.c --*/
void gpgsm_server (certlist_t default_recplist);
gpg_error_t gpgsm_status (ctrl_t ctrl, int no, const char *text);
gpg_error_t gpgsm_status2 (ctrl_t ctrl, int no, ...) GPGRT_ATTR_SENTINEL(0);
gpg_error_t gpgsm_status_with_err_code (ctrl_t ctrl, int no, const char *text,
                                        gpg_err_code_t ec);
gpg_error_t gpgsm_status_with_error (ctrl_t ctrl, int no, const char *text,
                                     gpg_error_t err);
gpg_error_t gpgsm_proxy_pinentry_notify (ctrl_t ctrl,
                                         const unsigned char *line);

/*-- fingerprint --*/
unsigned char *gpgsm_get_fingerprint (ksba_cert_t cert, int algo,
                                      unsigned char *array, int *r_len);
char *gpgsm_get_fingerprint_string (ksba_cert_t cert, int algo);
char *gpgsm_get_fingerprint_hexstring (ksba_cert_t cert, int algo);
unsigned long gpgsm_get_short_fingerprint (ksba_cert_t cert,
                                           unsigned long *r_high);
unsigned char *gpgsm_get_keygrip (ksba_cert_t cert, unsigned char *array);
char *gpgsm_get_keygrip_hexstring (ksba_cert_t cert);
int  gpgsm_get_key_algo_info (ksba_cert_t cert, unsigned int *nbits);
char *gpgsm_pubkey_algo_string (ksba_cert_t cert, int *r_algoid);
char *gpgsm_get_certid (ksba_cert_t cert);


/*-- certdump.c --*/
void gpgsm_print_serial (estream_t fp, ksba_const_sexp_t p);
void gpgsm_print_serial_decimal (estream_t fp, ksba_const_sexp_t sn);
void gpgsm_print_time (estream_t fp, ksba_isotime_t t);
void gpgsm_print_name2 (FILE *fp, const char *string, int translate);
void gpgsm_print_name (FILE *fp, const char *string);
void gpgsm_es_print_name (estream_t fp, const char *string);
void gpgsm_es_print_name2 (estream_t fp, const char *string, int translate);

void gpgsm_cert_log_name (const char *text, ksba_cert_t cert);

void gpgsm_dump_cert (const char *text, ksba_cert_t cert);
void gpgsm_dump_serial (ksba_const_sexp_t p);
void gpgsm_dump_time (ksba_isotime_t t);
void gpgsm_dump_string (const char *string);

char *gpgsm_format_serial (ksba_const_sexp_t p);
char *gpgsm_format_name2 (const char *name, int translate);
char *gpgsm_format_name (const char *name);
char *gpgsm_format_sn_issuer (ksba_sexp_t sn, const char *issuer);

char *gpgsm_fpr_and_name_for_status (ksba_cert_t cert);

char *gpgsm_format_keydesc (ksba_cert_t cert);


/*-- certcheck.c --*/
int gpgsm_check_cert_sig (ksba_cert_t issuer_cert, ksba_cert_t cert);
int gpgsm_check_cms_signature (ksba_cert_t cert, gcry_sexp_t sigval,
                               gcry_md_hd_t md,
                               int hash_algo, unsigned int pkalgoflags,
                               int *r_pkalgo);
/* fixme: move create functions to another file */
int gpgsm_create_cms_signature (ctrl_t ctrl,
                                ksba_cert_t cert, gcry_md_hd_t md, int mdalgo,
                                unsigned char **r_sigval);


/*-- certchain.c --*/

/* Flags used with  gpgsm_validate_chain.  */
#define VALIDATE_FLAG_NO_DIRMNGR  1
#define VALIDATE_FLAG_CHAIN_MODEL 2
#define VALIDATE_FLAG_STEED       4

int gpgsm_walk_cert_chain (ctrl_t ctrl,
                           ksba_cert_t start, ksba_cert_t *r_next);
int gpgsm_is_root_cert (ksba_cert_t cert);
int gpgsm_validate_chain (ctrl_t ctrl, ksba_cert_t cert,
                          ksba_isotime_t checktime,
                          ksba_isotime_t r_exptime,
                          int listmode, estream_t listfp,
                          unsigned int flags, unsigned int *retflags);
int gpgsm_basic_cert_check (ctrl_t ctrl, ksba_cert_t cert);

/*-- certlist.c --*/
int gpgsm_cert_use_sign_p (ksba_cert_t cert, int silent);
int gpgsm_cert_use_encrypt_p (ksba_cert_t cert);
int gpgsm_cert_use_verify_p (ksba_cert_t cert);
int gpgsm_cert_use_decrypt_p (ksba_cert_t cert);
int gpgsm_cert_use_cert_p (ksba_cert_t cert);
int gpgsm_cert_use_ocsp_p (ksba_cert_t cert);
int gpgsm_cert_has_well_known_private_key (ksba_cert_t cert);
int gpgsm_certs_identical_p (ksba_cert_t cert_a, ksba_cert_t cert_b);
int gpgsm_add_cert_to_certlist (ctrl_t ctrl, ksba_cert_t cert,
                                certlist_t *listaddr, int is_encrypt_to);
int gpgsm_add_to_certlist (ctrl_t ctrl, const char *name, int secret,
                           certlist_t *listaddr, int is_encrypt_to);
void gpgsm_release_certlist (certlist_t list);
int gpgsm_find_cert (ctrl_t ctrl, const char *name, ksba_sexp_t keyid,
                     ksba_cert_t *r_cert, int allow_ambiguous);

/*-- keylist.c --*/
gpg_error_t gpgsm_list_keys (ctrl_t ctrl, strlist_t names,
                             estream_t fp, unsigned int mode);

/*-- import.c --*/
int gpgsm_import (ctrl_t ctrl, int in_fd, int reimport_mode);
int gpgsm_import_files (ctrl_t ctrl, int nfiles, char **files,
                        int (*of)(const char *fname));

/*-- export.c --*/
void gpgsm_export (ctrl_t ctrl, strlist_t names, estream_t stream);
void gpgsm_p12_export (ctrl_t ctrl, const char *name, estream_t stream,
                       int rawmode);

/*-- delete.c --*/
int gpgsm_delete (ctrl_t ctrl, strlist_t names);

/*-- verify.c --*/
int gpgsm_verify (ctrl_t ctrl, int in_fd, int data_fd, estream_t out_fp);

/*-- sign.c --*/
int gpgsm_get_default_cert (ctrl_t ctrl, ksba_cert_t *r_cert);
int gpgsm_sign (ctrl_t ctrl, certlist_t signerlist,
                int data_fd, int detached, estream_t out_fp);

/*-- encrypt.c --*/
int gpgsm_encrypt (ctrl_t ctrl, certlist_t recplist,
                   int in_fd, estream_t out_fp);

/*-- decrypt.c --*/
int gpgsm_decrypt (ctrl_t ctrl, int in_fd, estream_t out_fp);

/*-- certreqgen.c --*/
int gpgsm_genkey (ctrl_t ctrl, estream_t in_stream, estream_t out_stream);

/*-- certreqgen-ui.c --*/
void gpgsm_gencertreq_tty (ctrl_t ctrl, estream_t out_stream);


/*-- qualified.c --*/
gpg_error_t gpgsm_is_in_qualified_list (ctrl_t ctrl, ksba_cert_t cert,
                                        char *country);
gpg_error_t gpgsm_qualified_consent (ctrl_t ctrl, ksba_cert_t cert);
gpg_error_t gpgsm_not_qualified_warning (ctrl_t ctrl, ksba_cert_t cert);

/*-- call-agent.c --*/
int gpgsm_agent_pksign (ctrl_t ctrl, const char *keygrip, const char *desc,
                        unsigned char *digest,
                        size_t digestlen,
                        int digestalgo,
                        unsigned char **r_buf, size_t *r_buflen);
int gpgsm_scd_pksign (ctrl_t ctrl, const char *keyid, const char *desc,
                      unsigned char *digest, size_t digestlen, int digestalgo,
                      unsigned char **r_buf, size_t *r_buflen);
int gpgsm_agent_pkdecrypt (ctrl_t ctrl, const char *keygrip, const char *desc,
                           ksba_const_sexp_t ciphertext,
                           char **r_buf, size_t *r_buflen);
int gpgsm_agent_genkey (ctrl_t ctrl,
                        ksba_const_sexp_t keyparms, ksba_sexp_t *r_pubkey);
int gpgsm_agent_readkey (ctrl_t ctrl, int fromcard, const char *hexkeygrip,
                         ksba_sexp_t *r_pubkey);
int gpgsm_agent_scd_serialno (ctrl_t ctrl, char **r_serialno);
int gpgsm_agent_scd_keypairinfo (ctrl_t ctrl, strlist_t *r_list);
int gpgsm_agent_istrusted (ctrl_t ctrl, ksba_cert_t cert, const char *hexfpr,
                           struct rootca_flags_s *rootca_flags);
int gpgsm_agent_havekey (ctrl_t ctrl, const char *hexkeygrip);
int gpgsm_agent_marktrusted (ctrl_t ctrl, ksba_cert_t cert);
int gpgsm_agent_learn (ctrl_t ctrl);
int gpgsm_agent_passwd (ctrl_t ctrl, const char *hexkeygrip, const char *desc);
gpg_error_t gpgsm_agent_get_confirmation (ctrl_t ctrl, const char *desc);
gpg_error_t gpgsm_agent_send_nop (ctrl_t ctrl);
gpg_error_t gpgsm_agent_keyinfo (ctrl_t ctrl, const char *hexkeygrip,
                                 char **r_serialno);
gpg_error_t gpgsm_agent_ask_passphrase (ctrl_t ctrl, const char *desc_msg,
                                        int repeat, char **r_passphrase);
gpg_error_t gpgsm_agent_keywrap_key (ctrl_t ctrl, int forexport,
                                     void **r_kek, size_t *r_keklen);
gpg_error_t gpgsm_agent_import_key (ctrl_t ctrl,
                                    const void *key, size_t keylen);
gpg_error_t gpgsm_agent_export_key (ctrl_t ctrl, const char *keygrip,
                                    const char *desc,
                                    unsigned char **r_result,
                                    size_t *r_resultlen);

/*-- call-dirmngr.c --*/
int gpgsm_dirmngr_isvalid (ctrl_t ctrl,
                           ksba_cert_t cert, ksba_cert_t issuer_cert,
                           int use_ocsp);
int gpgsm_dirmngr_lookup (ctrl_t ctrl, strlist_t names, const char *uri,
                          int cache_only,
                          void (*cb)(void*, ksba_cert_t), void *cb_value);
int gpgsm_dirmngr_run_command (ctrl_t ctrl, const char *command,
                               int argc, char **argv);


/*-- misc.c --*/
void setup_pinentry_env (void);
gpg_error_t transform_sigval (const unsigned char *sigval, size_t sigvallen,
                              int mdalgo,
                              unsigned char **r_newsigval,
                              size_t *r_newsigvallen);
gcry_sexp_t gpgsm_ksba_cms_get_sig_val (ksba_cms_t cms, int idx);
int gpgsm_get_hash_algo_from_sigval (gcry_sexp_t sigval,
                                     unsigned int *r_pkalgo_flags);



#endif /*GPGSM_H*/
