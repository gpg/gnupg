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
#include "util.h"

/* Error numbers */
enum {
  GPGSM_EOF = -1,
  GPGSM_No_Error = 0,
  GPGSM_General_Error = 1, 
  GPGSM_Out_Of_Core = 2,
  GPGSM_Invalid_Value = 3,
  GPGSM_IO_Error = 4,
  GPGSM_Resource_Limit = 5,
  GPGSM_Internal_Error = 6,
  GPGSM_Bad_Certificate = 7,
  GPGSM_Bad_Certificate_Path = 8,
  GPGSM_Missing_Certificate = 9,
  GPGSM_No_Data = 10,
  GPGSM_Bad_Signature = 11,
  GPGSM_Not_Implemented = 12,
  GPGSM_Conflict = 13,
};

/* Status codes (shared with gpg) */
enum {
  STATUS_ENTER,
  STATUS_LEAVE,
  STATUS_ABORT,
  STATUS_GOODSIG,
  STATUS_BADSIG,
  STATUS_ERRSIG,
  STATUS_BADARMOR,
  STATUS_RSA_OR_IDEA,
  STATUS_SIGEXPIRED,
  STATUS_KEYREVOKED,
  STATUS_TRUST_UNDEFINED,
  STATUS_TRUST_NEVER,
  STATUS_TRUST_MARGINAL,
  STATUS_TRUST_FULLY,
  STATUS_TRUST_ULTIMATE,
  
  STATUS_SHM_INFO,
  STATUS_SHM_GET,
  STATUS_SHM_GET_BOOL,
  STATUS_SHM_GET_HIDDEN,
  
  STATUS_NEED_PASSPHRASE,
  STATUS_VALIDSIG,
  STATUS_SIG_ID,
  STATUS_ENC_TO,
  STATUS_NODATA,
  STATUS_BAD_PASSPHRASE,
  STATUS_NO_PUBKEY,
  STATUS_NO_SECKEY,
  STATUS_NEED_PASSPHRASE_SYM,
  STATUS_DECRYPTION_FAILED,
  STATUS_DECRYPTION_OKAY,
  STATUS_MISSING_PASSPHRASE,
  STATUS_GOOD_PASSPHRASE,
  STATUS_GOODMDC,
  STATUS_BADMDC,
  STATUS_ERRMDC,
  STATUS_IMPORTED,
  STATUS_IMPORT_RES,
  STATUS_FILE_START,
  STATUS_FILE_DONE,
  STATUS_FILE_ERROR,
  
  STATUS_BEGIN_DECRYPTION,
  STATUS_END_DECRYPTION,
  STATUS_BEGIN_ENCRYPTION,
  STATUS_END_ENCRYPTION,
  
  STATUS_DELETE_PROBLEM,
  STATUS_GET_BOOL,
  STATUS_GET_LINE,
  STATUS_GET_HIDDEN,
  STATUS_GOT_IT,
  STATUS_PROGRESS,
  STATUS_SIG_CREATED,
  STATUS_SESSION_KEY,
  STATUS_NOTATION_NAME,
  STATUS_NOTATION_DATA,
  STATUS_POLICY_URL,
  STATUS_BEGIN_STREAM,
  STATUS_END_STREAM,
  STATUS_KEY_CREATED,
  STATUS_USERID_HIN,
  STATUS_UNEXPECTED,
  STATUS_INV_RECP,
  STATUS_NO_RECP,
  STATUS_ALREADY_SIGNED,
};


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
  char *outfile;    /* name of output file */

  int with_colons;  /* use column delimited output format */
  int with_key_data;/* include raw key in the column delimted output */

  int fingerprint;  /* list fingerprints in all key listings */

  int armor;        /* force base64 armoring */
  int no_armor;     /* don't try to figure out whether data is base64 armored*/

  int def_cipher_algo;    /* cipher algorithm to use if nothing else is know */
  int def_digest_algo;    /* Ditto for hash algorithm */
  int def_compress_algo;  /* Ditto for compress algorithm */

  char *def_recipient;    /* userID of the default recipient */
  int def_recipient_self; /* The default recipient is the default key */

  int always_trust;       /* Trust the given keys even if there is no
                             valid certification path */
  int skip_verify;        /* do not check signatures on data */

  int lock_once;          /* Keep lock once they are set */

  int ignore_time_conflict; /* Ignore certain time conflicts */

} opt;


#define DBG_X509_VALUE    1	/* debug x.509 data reading/writing */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */

#define DBG_X509    (opt.debug & DBG_X509_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)

struct server_local_s;

struct server_control_s {
  int no_server;     /* we are not running under server control */
  int  status_fd;    /* only for non-server mode */
  struct server_local_s *server_local;
};
typedef struct server_control_s *CTRL;


/*-- gpgsm.c --*/
void gpgsm_exit (int rc);

/*-- server.c --*/
void gpgsm_server (void);
void gpgsm_status (CTRL ctrl, int no, const char *text);

/*-- fingerprint --*/
char *gpgsm_get_fingerprint (KsbaCert cert, int algo, char *array, int *r_len);
char *gpgsm_get_fingerprint_string (KsbaCert cert, int algo);
char *gpgsm_get_fingerprint_hexstring (KsbaCert cert, int algo);

/*-- certdump.c --*/
void gpgsm_dump_cert (const char *text, KsbaCert cert);

/*-- certcheck.c --*/
int gpgsm_check_cert_sig (KsbaCert issuer_cert, KsbaCert cert);
int gpgsm_check_cms_signature (KsbaCert cert, const char *sigval,
                               GCRY_MD_HD md, int hash_algo);


/*-- certpath.c --*/
int gpgsm_validate_path (KsbaCert cert);




/*-- import.c --*/
int gpgsm_import (CTRL ctrl, int in_fd);

/*-- verify.c --*/
int gpgsm_verify (CTRL ctrl, int in_fd, int data_fd);




/*-- errors.c (built) --*/
const char *gpgsm_strerror (int err);


#endif /*GPGSM_H*/
