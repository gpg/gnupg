/* call-agent.h - Divert operations to the agent
 * Copyright (C) 2003 Free Software Foundation, Inc.
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
#ifndef GNUPG_G10_CALL_AGENT_H
#define GNUPG_G10_CALL_AGENT_H


struct agent_card_info_s
{
  int error;         /* private. */
  char *reader;      /* Reader information.  */
  char *apptype;     /* Malloced application type string.  */
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
  int is_v2;         /* True if this is a v2 card.  */
  int chvmaxlen[3];  /* Maximum allowed length of a CHV. */
  int chvretry[3];   /* Allowed retries for the CHV; 0 = blocked. */
  struct {           /* Array with key attributes.  */
    int algo;              /* Algorithm identifier.  */
    union {
      unsigned int nbits;  /* Supported keysize.  */
      const char *curve;   /* Name of curve.  */
    };
  } key_attr[3];
  struct {
    unsigned int ki:1;     /* Key import available.  */
    unsigned int aac:1;    /* Algorithm attributes are changeable.  */
  } extcap;
  unsigned int status_indicator;
};



/* Release the card info structure. */
void agent_release_card_info (struct agent_card_info_s *info);

/* Return card info. */
int agent_scd_learn (struct agent_card_info_s *info, int force);

/* Return list of cards.  */
int agent_scd_cardlist (strlist_t *result);

/* Return the serial number, possibly select by DEMAND.  */
int agent_scd_serialno (char **r_serialno, const char *demand);

/* Send an APDU to the card.  */
gpg_error_t agent_scd_apdu (const char *hexapdu, unsigned int *r_sw);

/* Update INFO with the attribute NAME. */
int agent_scd_getattr (const char *name, struct agent_card_info_s *info);

/* Send the KEYTOCARD command. */
int agent_keytocard (const char *hexgrip, int keyno, int force,
                     const char *serialno, const char *timestamp);

/* Send a SETATTR command to the SCdaemon. */
int agent_scd_setattr (const char *name,
                       const unsigned char *value, size_t valuelen,
                       const char *serialno);

/* Send a WRITECERT command to the SCdaemon. */
int agent_scd_writecert (const char *certidstr,
                          const unsigned char *certdata, size_t certdatalen);

/* Send a WRITEKEY command to the SCdaemon. */
int agent_scd_writekey (int keyno, const char *serialno,
                        const unsigned char *keydata, size_t keydatalen);

/* Send a GENKEY command to the SCdaemon. */
int agent_scd_genkey (int keyno, int force, u32 *createtime);

/* Send a READKEY command to the SCdaemon. */
int agent_scd_readcert (const char *certidstr,
                        void **r_buf, size_t *r_buflen);

/* Change the PIN of an OpenPGP card or reset the retry counter. */
int agent_scd_change_pin (int chvno, const char *serialno);

/* Send the CHECKPIN command to the SCdaemon. */
int agent_scd_checkpin  (const char *serialno);

/* Dummy function, only implemented by gpg 1.4. */
void agent_clear_pin_cache (const char *sn);


/* Send the GET_PASSPHRASE command to the agent.  */
gpg_error_t agent_get_passphrase (const char *cache_id,
                                  const char *err_msg,
                                  const char *prompt,
                                  const char *desc_msg,
                                  int repeat,
                                  int check,
                                  char **r_passphrase);

/* Send the CLEAR_PASSPHRASE command to the agent.  */
gpg_error_t agent_clear_passphrase (const char *cache_id);

/* Present the prompt DESC and ask the user to confirm.  */
gpg_error_t gpg_agent_get_confirmation (const char *desc);

/* Return the S2K iteration count as computed by gpg-agent.  */
gpg_error_t agent_get_s2k_count (unsigned long *r_count);

/* Check whether a secret key for public key PK is available.  Returns
   0 if the secret key is available. */
gpg_error_t agent_probe_secret_key (ctrl_t ctrl, PKT_public_key *pk);

/* Ask the agent whether a secret key is availabale for any of the
   keys (primary or sub) in KEYBLOCK.  Returns 0 if available.  */
gpg_error_t agent_probe_any_secret_key (ctrl_t ctrl, kbnode_t keyblock);


/* Return infos about the secret key with HEXKEYGRIP.  */
gpg_error_t agent_get_keyinfo (ctrl_t ctrl, const char *hexkeygrip,
                               char **r_serialno, int *r_cleartext);

/* Generate a new key.  */
gpg_error_t agent_genkey (ctrl_t ctrl,
                          char **cache_nonce_addr, char **passwd_nonce_addr,
                          const char *keyparms, int no_protection,
                          const char *passphrase,
                          gcry_sexp_t *r_pubkey);

/* Read a public key.  */
gpg_error_t agent_readkey (ctrl_t ctrl, int fromcard, const char *hexkeygrip,
                           unsigned char **r_pubkey);

/* Create a signature.  */
gpg_error_t agent_pksign (ctrl_t ctrl, const char *cache_nonce,
                          const char *hexkeygrip, const char *desc,
                          u32 *keyid, u32 *mainkeyid, int pubkey_algo,
                          unsigned char *digest, size_t digestlen,
                          int digestalgo,
                          gcry_sexp_t *r_sigval);

/* Decrypt a ciphertext.  */
gpg_error_t agent_pkdecrypt (ctrl_t ctrl, const char *keygrip, const char *desc,
                             u32 *keyid, u32 *mainkeyid, int pubkey_algo,
                             gcry_sexp_t s_ciphertext,
                             unsigned char **r_buf, size_t *r_buflen,
                             int *r_padding);

/* Retrieve a key encryption key.  */
gpg_error_t agent_keywrap_key (ctrl_t ctrl, int forexport,
                               void **r_kek, size_t *r_keklen);

/* Send a key to the agent.  */
gpg_error_t agent_import_key (ctrl_t ctrl, const char *desc,
                              char **cache_nonce_addr, const void *key,
                              size_t keylen, int unattended, int force);

/* Receive a key from the agent.  */
gpg_error_t agent_export_key (ctrl_t ctrl, const char *keygrip,
                              const char *desc, int openpgp_protected,
                              char **cache_nonce_addr,
                              unsigned char **r_result, size_t *r_resultlen);

/* Delete a key from the agent.  */
gpg_error_t agent_delete_key (ctrl_t ctrl, const char *hexkeygrip,
                              const char *desc, int force);

/* Change the passphrase of a key.  */
gpg_error_t agent_passwd (ctrl_t ctrl, const char *hexkeygrip, const char *desc,
                          int verify,
                          char **cache_nonce_addr, char **passwd_nonce_addr);
/* Get the version reported by gpg-agent.  */
gpg_error_t agent_get_version (ctrl_t ctrl, char **r_version);


#endif /*GNUPG_G10_CALL_AGENT_H*/
