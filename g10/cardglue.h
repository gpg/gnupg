/* cardglue.h - Divert operations to the agent
 * Copyright (C) 2003, 2004 Free Software Foundation, Inc.
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
#ifndef GNUPG_G10_CARDGLUE_H
#define GNUPG_G10_CARDGLUE_H 

#ifdef ENABLE_CARD_SUPPORT
/* 
   Note, that most card related code has been taken from 1.9.x branch
   and is maintained over there if at all possible.  Thus, if you make
   changes here, please check that a similar change has been commited
   to the 1.9.x branch.
*/


struct agent_card_info_s {
  int error;         /* private. */
  char *serialno;    /* malloced hex string. */
  char *disp_name;   /* malloced. */
  char *disp_lang;   /* malloced. */
  int  disp_sex;     /* 0 = unspecified, 1 = male, 2 = female */
  char *pubkey_url;  /* malloced. */
  char *login_data;  /* malloced. */
  char *private_do[4]; /* malloced. */
  char cafpr1valid;
  char cafpr2valid;
  char cafpr3valid;
  char cafpr1[20];
  char cafpr2[20];
  char cafpr3[20];
  char fpr1valid;
  char fpr2valid;
  char fpr3valid;
  char fpr1[20];
  char fpr2[20];
  char fpr3[20];
  u32  fpr1time;
  u32  fpr2time;
  u32  fpr3time;
  unsigned long sig_counter;
  int chv1_cached;   /* True if a PIN is not required for each
                        signing.  Note that the gpg-agent might cache
                        it anyway. */
  int chvmaxlen[3];  /* Maximum allowed length of a CHV. */
  int chvretry[3];   /* Allowed retries for the CHV; 0 = blocked. */
};

struct agent_card_genkey_s {
  char fprvalid;
  char fpr[20];
  u32  created_at;
  MPI  n;
  MPI  e;
};


struct app_ctx_s;
struct ctrl_ctx_s;

typedef struct app_ctx_s *APP; /* deprecated. */
typedef struct app_ctx_s *app_t;
typedef struct ctrl_ctx_s *CTRL; /* deprecated. */
typedef struct ctrl_ctx_s *ctrl_t;


#define GPG_ERR_GENERAL           G10ERR_GENERAL
#define GPG_ERR_BAD_PIN           G10ERR_BAD_PASS
#define GPG_ERR_BAD_KEY           G10ERR_BAD_KEY
#define GPG_ERR_CARD              G10ERR_GENERAL
#define GPG_ERR_EEXIST            G10ERR_FILE_EXISTS
#define GPG_ERR_ENOMEM            G10ERR_RESOURCE_LIMIT
#define GPG_ERR_GENERAL           G10ERR_GENERAL
#define GPG_ERR_HARDWARE          G10ERR_GENERAL
#define GPG_ERR_INV_CARD          G10ERR_GENERAL
#define GPG_ERR_INV_ID            G10ERR_GENERAL
#define GPG_ERR_INV_NAME          G10ERR_GENERAL
#define GPG_ERR_INV_VALUE         G10ERR_INV_ARG
#define GPG_ERR_INV_SEXP          G10ERR_INV_ARG
#define GPG_ERR_NOT_SUPPORTED     G10ERR_UNSUPPORTED
#define GPG_ERR_NO_OBJ            G10ERR_GENERAL
#define GPG_ERR_PIN_BLOCKED       G10ERR_PASSPHRASE
#define GPG_ERR_UNSUPPORTED_ALGORITHM G10ERR_PUBKEY_ALGO 
#define GPG_ERR_USE_CONDITIONS    G10ERR_GENERAL
#define GPG_ERR_WRONG_CARD        G10ERR_GENERAL
#define GPG_ERR_WRONG_SECKEY      G10ERR_WRONG_SECKEY
#define GPG_ERR_PIN_NOT_SYNCED    G10ERR_GENERAL
#define GPG_ERR_NOT_FOUND         G10ERR_GENERAL
#define GPG_ERR_BUG               G10ERR_GENERAL
#define GPG_ERR_NOT_IMPLEMENTED   G10ERR_GENERAL
#define GPG_ERR_BAD_BER           G10ERR_GENERAL
#define GPG_ERR_EOF               (-1)
#define GPG_ERR_CARD_NOT_PRESENT  G10ERR_NO_CARD
#define GPG_ERR_CARD_RESET        G10ERR_GENERAL
#define GPG_ERR_WRONG_PUBKEY_ALGO G10ERR_PUBKEY_ALGO
#define GPG_ERR_UNKNOWN_SEXP      G10ERR_INV_ARG
#define GPG_ERR_DUP_VALUE         G10ERR_INV_ARG
#define GPG_ERR_BAD_SECKEY        G10ERR_BAD_SECKEY
#define GPG_ERR_TOO_LARGE         G10ERR_GENERAL

#define GPG_ERR_EBUSY             G10ERR_GENERAL
#define GPG_ERR_ENOENT            G10ERR_OPEN_FILE
#define GPG_ERR_EACCES            G10ERR_UNSUPPORTED
#define GPG_ERR_EIO               G10ERR_GENERAL
#define GPG_ERR_ENODEV            G10ERR_GENERAL
#define GPG_ERR_CANCELED          G10ERR_CANCELED

typedef int gpg_error_t;
typedef int gpg_err_code_t;

#define gpg_error(n) (n)
#define gpg_err_code(n) (n)
#define gpg_strerror(n) g10_errstr ((n))
#define gpg_error_from_errno(n) (G10ERR_GENERAL) /*FIXME*/
#define gpg_err_code_from_errno(n) (G10ERR_GENERAL)
#define gpg_error_from_syserror()  (G10ERR_GENERAL) /*FIXME*/

/* We are not using it in a library, so we even let xtrymalloc
   abort. Because we won't never return from these malloc functions,
   we also don't need the out_of_core function, we simply define it to
   return -1 */
#define xtrymalloc(n)    xmalloc((n))
#define xtrycalloc(n,m)  xcalloc((n),(m))
#define xtryrealloc(n,m) xrealloc((n),(m))
#define xtrymalloc_secure(n)  xmalloc_secure((n))
#define out_of_core()    (-1) 

#define gnupg_get_time() make_timestamp ()


void card_set_reader_port (const char *portstr);

char *serialno_and_fpr_from_sk (const unsigned char *sn, size_t snlen,
                                PKT_secret_key *sk);
void send_status_info (ctrl_t ctrl, const char *keyword, ...);
void gcry_md_hash_buffer (int algo, void *digest,
			  const void *buffer, size_t length);
void log_printf (const char *fmt, ...);
void log_printhex (const char *text, const void *buffer, size_t length);


#define GCRY_MD_SHA1 DIGEST_ALGO_SHA1
#define GCRY_MD_RMD160 DIGEST_ALGO_RMD160

void card_close (void);


/* Release the card info structure. */
void agent_release_card_info (struct agent_card_info_s *info);

/* Return card info. */
int agent_learn (struct agent_card_info_s *info);

/* Check whether the secret key for the key identified by HEXKEYGRIP
   is available.  Return 0 for yes or an error code. */
int agent_havekey (const char *hexkeygrip);

/* Return card info. */
int agent_scd_getattr (const char *name, struct agent_card_info_s *info);

/* Send a SETATTR command to the SCdaemon. */
int agent_scd_setattr (const char *name,
                       const unsigned char *value, size_t valuelen,
                       const char *serialno);

/* Send a WRITEKEY command to the SCdaemon. */
int agent_scd_writekey (int keyno, const char *serialno,
                        const unsigned char *keydata, size_t keydatalen);

/* Send a GENKEY command to the SCdaemon. */
int agent_scd_genkey (struct agent_card_genkey_s *info, int keyno, int force,
                      const char *serialno);

/* Send a PKSIGN command to the SCdaemon. */
int agent_scd_pksign (const char *keyid, int hashalgo,
                      const unsigned char *indata, size_t indatalen,
                      unsigned char **r_buf, size_t *r_buflen);

/* Send a PKDECRYPT command to the SCdaemon. */
int agent_scd_pkdecrypt (const char *serialno,
                         const unsigned char *indata, size_t indatalen,
                         unsigned char **r_buf, size_t *r_buflen);

/* Change the PIN of an OpenPGP card or reset the retry counter. */
int agent_scd_change_pin (int chvno, const char *serialno);

/* Send a CHECKPIN command. */
int agent_scd_checkpin (const char *serialnobuf);

/* Clear a cached PIN. */
void agent_clear_pin_cache (const char *sn);


#endif /*ENABLE_CARD_SUPPORT*/
#endif /*GNUPG_G10_CARDGLUE_H*/

