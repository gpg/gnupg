/* gpgsm.h - Global definitions for GpgSM
 *	Copyright (C) 2001 Free Software Foundation, Inc.
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

#include <ksba.h>
#include "../common/util.h"
#include "../common/errors.h"

#define MAX_DIGEST_LEN 24 

/* A large struct name "opt" to keep global flags */
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
  const char *dirmngr_program;
  char *outfile;    /* name of output file */

  int with_key_data;/* include raw key in the column delimted output */

  int fingerprint;  /* list fingerprints in all key listings */

  int armor;        /* force base64 armoring (see also ctrl.with_base64) */
  int no_armor;     /* don't try to figure out whether data is base64 armored*/

  const char *def_cipher_algoid;  /* cipher algorithm to use if
                                     nothing else is specified */

  int def_digest_algo;    /* Ditto for hash algorithm */
  int def_compress_algo;  /* Ditto for compress algorithm */

  char *def_recipient;    /* userID of the default recipient */
  int def_recipient_self; /* The default recipient is the default key */

  int always_trust;       /* Trust the given keys even if there is no
                             valid certification path */
  int skip_verify;        /* do not check signatures on data */

  int lock_once;          /* Keep lock once they are set */

  int ignore_time_conflict; /* Ignore certain time conflicts */

  int no_crl_check;       /* Don't do a CRL check */

} opt;


#define DBG_X509_VALUE    1	/* debug x.509 data reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_AGENT_VALUE  1024   /* debug communication with the agent */

#define DBG_X509    (opt.debug & DBG_X509_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_AGENT   (opt.debug & DBG_AGENT_VALUE)

struct server_local_s;

/* Note that the default values for this are set by
   gpgsm_init_default_ctrl() */
struct server_control_s {
  int no_server;     /* we are not running under server control */
  int  status_fd;    /* only for non-server mode */
  struct server_local_s *server_local;
  int with_colons;  /* use column delimited output format */

  int autodetect_encoding; /* try to detect the input encoding */
  int is_pem;         /* Is in PEM format */
  int is_base64;      /* is in plain base-64 format */

  int create_base64;  /* Create base64 encoded output */
  int create_pem;     /* create PEM output */
  const char *pem_name; /* PEM name to use */

  int include_certs;  /* -1 to send all certificates in the chain
                         along with a signature or the number of
                         certificates up the chain (0 = none, 1 = only
                         signer) */
 
};
typedef struct server_control_s *CTRL;

/* data structure used in base64.c */
typedef struct base64_context_s *Base64Context;


struct certlist_s {
  struct certlist_s *next;
  KsbaCert cert;
};
typedef struct certlist_s *CERTLIST;

/*-- gpgsm.c --*/
void gpgsm_exit (int rc);
void gpgsm_init_default_ctrl (struct server_control_s *ctrl);

/*-- server.c --*/
void gpgsm_server (void);
void gpgsm_status (CTRL ctrl, int no, const char *text);

/*-- fingerprint --*/
char *gpgsm_get_fingerprint (KsbaCert cert, int algo, char *array, int *r_len);
char *gpgsm_get_fingerprint_string (KsbaCert cert, int algo);
char *gpgsm_get_fingerprint_hexstring (KsbaCert cert, int algo);
char *gpgsm_get_keygrip (KsbaCert cert, char *array);
char *gpgsm_get_keygrip_hexstring (KsbaCert cert);
char *gpgsm_get_certid (KsbaCert cert);


/*-- base64.c --*/
int  gpgsm_create_reader (Base64Context *ctx,
                          CTRL ctrl, FILE *fp, KsbaReader *r_reader);
void gpgsm_destroy_reader (Base64Context ctx);
int  gpgsm_create_writer (Base64Context *ctx,
                          CTRL ctrl, FILE *fp, KsbaWriter *r_writer);
int  gpgsm_finish_writer (Base64Context ctx);
void gpgsm_destroy_writer (Base64Context ctx);


/*-- certdump.c --*/
void gpgsm_dump_cert (const char *text, KsbaCert cert);
void gpgsm_dump_serial (KsbaConstSexp p);
void gpgsm_dump_time (time_t t);
void gpgsm_dump_string (const char *string);

/*-- certcheck.c --*/
int gpgsm_check_cert_sig (KsbaCert issuer_cert, KsbaCert cert);
int gpgsm_check_cms_signature (KsbaCert cert, KsbaConstSexp sigval,
                               GCRY_MD_HD md, int hash_algo);
/* fixme: move create functions to another file */
int gpgsm_create_cms_signature (KsbaCert cert, GCRY_MD_HD md, int mdalgo,
                                char **r_sigval);


/*-- certpath.c --*/
int gpgsm_walk_cert_chain (KsbaCert start, KsbaCert *r_next);
int gpgsm_validate_path (KsbaCert cert);
int gpgsm_basic_cert_check (KsbaCert cert);

/*-- cetrlist.c --*/
int gpgsm_add_to_certlist (const char *name, CERTLIST *listaddr);
void gpgsm_release_certlist (CERTLIST list);
int gpgsm_find_cert (const char *name, KsbaCert *r_cert);

/*-- keylist.c --*/
void gpgsm_list_keys (CTRL ctrl, STRLIST names, FILE *fp);

/*-- import.c --*/
int gpgsm_import (CTRL ctrl, int in_fd);

/*-- verify.c --*/
int gpgsm_verify (CTRL ctrl, int in_fd, int data_fd, FILE *out_fp);

/*-- sign.c --*/
int gpgsm_sign (CTRL ctrl, int data_fd, int detached, FILE *out_fp);

/*-- encrypt.c --*/
int gpgsm_encrypt (CTRL ctrl, CERTLIST recplist, int in_fd, FILE *out_fp);

/*-- decrypt.c --*/
int gpgsm_decrypt (CTRL ctrl, int in_fd, FILE *out_fp);

/*-- certreqgen.c --*/
int gpgsm_genkey (CTRL ctrl, int in_fd, FILE *out_fp);

/*-- call-agent.c --*/
int gpgsm_agent_pksign (const char *keygrip,
                        unsigned char *digest,
                        size_t digestlen,
                        int digestalgo,
                        char **r_buf, size_t *r_buflen);
int gpgsm_agent_pkdecrypt (const char *keygrip,
                           KsbaConstSexp  ciphertext, 
                           char **r_buf, size_t *r_buflen);
int gpgsm_agent_genkey (KsbaConstSexp keyparms, KsbaSexp *r_pubkey);
int gpgsm_agent_istrusted (KsbaCert cert);

/*-- call-dirmngr.c --*/
int gpgsm_dirmngr_isvalid (KsbaCert cert);





#endif /*GPGSM_H*/



