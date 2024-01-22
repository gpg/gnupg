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

struct key_attr {
  int algo;              /* Algorithm identifier.  */
  union {
    unsigned int nbits;  /* Supported keysize.  */
    const char *curve;   /* Name of curve.  */
  };
};

struct agent_card_info_s
{
  int error;         /* private. */
  char *reader;      /* Reader information.  */
  char *apptype;     /* Malloced application type string.  */
  unsigned int appversion; /* Version of the application.  */
  unsigned int manufacturer_id;
  char *manufacturer_name; /* malloced.  */
  char *serialno;    /* malloced hex string. */
  char *disp_name;   /* malloced. */
  char *disp_lang;   /* malloced. */
  int  disp_sex;     /* 0 = unspecified, 1 = male, 2 = female */
  char *pubkey_url;  /* malloced. */
  char *login_data;  /* malloced. */
  char *private_do[4]; /* malloced. */
  char cafpr1len;     /* Length of the CA-fingerprint or 0 if invalid.  */
  char cafpr2len;
  char cafpr3len;
  char cafpr1[20];
  char cafpr2[20];
  char cafpr3[20];
  unsigned char fpr1len; /* Length of the fingerprint or 0 if invalid.  */
  unsigned char fpr2len;
  unsigned char fpr3len;
  char fpr1[20];
  char fpr2[20];
  char fpr3[20];
  u32  fpr1time;
  u32  fpr2time;
  u32  fpr3time;
  char grp1[20];     /* The keygrip for OPENPGP.1 */
  char grp2[20];     /* The keygrip for OPENPGP.2 */
  char grp3[20];     /* The keygrip for OPENPGP.3 */
  unsigned long sig_counter;
  int chv1_cached;   /* True if a PIN is not required for each
                        signing.  Note that the gpg-agent might cache
                        it anyway. */
  int is_v2;         /* True if this is a v2 card.  */
  int chvmaxlen[3];  /* Maximum allowed length of a CHV. */
  int chvretry[3];   /* Allowed retries for the CHV; 0 = blocked. */
  struct key_attr key_attr[3];
  struct {
    unsigned int ki:1;     /* Key import available.  */
    unsigned int aac:1;    /* Algorithm attributes are changeable.  */
    unsigned int kdf:1;    /* KDF object to support PIN hashing available.  */
    unsigned int bt:1;     /* Button for confirmation available.  */
  } extcap;
  unsigned int status_indicator;
  int kdf_do_enabled;      /* Non-zero if card has a KDF object, 0 if not.  */
  int uif[3];              /* True if User Interaction Flag is on.  */
  strlist_t supported_keyalgo[3];
};


/* Object to store information from the KEYPAIRINFO or the KEYINFO
 * status lines.  */
struct keypair_info_s
{
  struct keypair_info_s *next;
  char keygrip[2 * KEYGRIP_LEN + 1];  /* Stored in hex.  */
  char *serialno;      /* NULL or the malloced serialno.  */
  char *idstr;         /* Malloced keyref (e.g. "OPENPGP.1") */
  unsigned int usage;  /* Key usage flags.  */
  u32 keytime;         /* Key creation time from the card's DO.  */
  int algo;            /* Helper to store the pubkey algo.       */
};
typedef struct keypair_info_s *keypair_info_t;

/* Release the card info structure. */
void agent_release_card_info (struct agent_card_info_s *info);

/* Return card info. */
int agent_scd_learn (struct agent_card_info_s *info, int force);

/* Get the keypariinfo directly from scdaemon.  */
gpg_error_t agent_scd_keypairinfo (ctrl_t ctrl, const char *keyref,
                                   keypair_info_t *r_list);

/* Return list of cards.  */
int agent_scd_cardlist (strlist_t *result);

/* Switch/assure a certain application. */
gpg_error_t agent_scd_switchapp (const char *appname);

/* Free a keypair info list.  */
void free_keypair_info (keypair_info_t l);

/* Return card key information.  */
gpg_error_t agent_scd_keyinfo (const char *keygrip, int cap,
                               keypair_info_t *result);

/* Return the serial number, possibly select by DEMAND.  */
int agent_scd_serialno (char **r_serialno, const char *demand);

/* Send an APDU to the card.  */
gpg_error_t agent_scd_apdu (const char *hexapdu, unsigned int *r_sw);

/* Get attribute NAME from the card and store at R_VALUE.  */
gpg_error_t agent_scd_getattr_one (const char *name, char **r_value);

/* Update INFO with the attribute NAME. */
int agent_scd_getattr (const char *name, struct agent_card_info_s *info);

/* send the KEYTOTPM command */
int agent_keytotpm (ctrl_t ctrl, const char *hexgrip);

/* Send the KEYTOCARD command. */
int agent_keytocard (const char *hexgrip, int keyno, int force,
                     const char *serialno, const char *timestamp,
                     const char *ecdh_param_str);

/* Send a SETATTR command to the SCdaemon. */
gpg_error_t agent_scd_setattr (const char *name,
                               const void *value, size_t valuelen);

/* Send a WRITECERT command to the SCdaemon. */
int agent_scd_writecert (const char *certidstr,
                          const unsigned char *certdata, size_t certdatalen);

/* Send a GENKEY command to the SCdaemon. */
int agent_scd_genkey (int keyno, int force, u32 *createtime);

/* Send a READCERT command to the SCdaemon. */
int agent_scd_readcert (const char *certidstr,
                        void **r_buf, size_t *r_buflen);

/* Send a READKEY command to the SCdaemon.  */
gpg_error_t agent_scd_readkey (ctrl_t ctrl, const char *keyrefstr,
                               gcry_sexp_t *r_result, u32 *r_keytime);

/* Change the PIN of an OpenPGP card or reset the retry counter. */
int agent_scd_change_pin (int chvno, const char *serialno);

/* Send the CHECKPIN command to the SCdaemon. */
int agent_scd_checkpin  (const char *serialno);

/* Send the GET_PASSPHRASE command to the agent.  */
gpg_error_t agent_get_passphrase (const char *cache_id,
                                  const char *err_msg,
                                  const char *prompt,
                                  const char *desc_msg,
                                  int newsymkey,
                                  int repeat,
                                  int check,
                                  char **r_passphrase);

/* Send the CLEAR_PASSPHRASE command to the agent.  */
gpg_error_t agent_clear_passphrase (const char *cache_id);

/* Present the prompt DESC and ask the user to confirm.  */
gpg_error_t gpg_agent_get_confirmation (const char *desc);

/* Return the S2K iteration count as computed by gpg-agent.  */
unsigned long agent_get_s2k_count (void);

/* Check whether a secret key for public key PK is available.  Returns
   0 if not available, positive value if the secret key is available. */
int agent_probe_secret_key (ctrl_t ctrl, PKT_public_key *pk);

/* Ask the agent whether a secret key is available for any of the
   keys (primary or sub) in KEYBLOCK.  Returns 0 if available.  */
gpg_error_t agent_probe_any_secret_key (ctrl_t ctrl, kbnode_t keyblock);


/* Return infos about the secret key with HEXKEYGRIP.  */
gpg_error_t agent_get_keyinfo (ctrl_t ctrl, const char *hexkeygrip,
                               char **r_serialno, int *r_cleartext);

/* Generate a new key.  */
gpg_error_t agent_genkey (ctrl_t ctrl,
                          char **cache_nonce_addr, char **passwd_nonce_addr,
                          const char *keyparms, int no_protection,
                          const char *passphrase, time_t timestamp,
                          gcry_sexp_t *r_pubkey);

/* Read a public key.  FROMCARD may be 0, 1, or 2. */
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
                              size_t keylen, int unattended, int force,
                              u32 *keyid, u32 *mainkeyid, int pubkey_algo,
                              u32 timestamp);

/* Receive a key from the agent.  */
gpg_error_t agent_export_key (ctrl_t ctrl, const char *keygrip,
                              const char *desc, int openpgp_protected,
                              int mode1003, char **cache_nonce_addr,
                              unsigned char **r_result, size_t *r_resultlen,
                              u32 *keyid, u32 *mainkeyid, int pubkey_algo);

/* Delete a key from the agent.  */
gpg_error_t agent_delete_key (ctrl_t ctrl, const char *hexkeygrip,
                              const char *desc, int force);

/* Change the passphrase of a key.  */
gpg_error_t agent_passwd (ctrl_t ctrl, const char *hexkeygrip, const char *desc,
                          int verify,
                          char **cache_nonce_addr, char **passwd_nonce_addr);

/* Set or get the ephemeral mode.  */
gpg_error_t agent_set_ephemeral_mode (ctrl_t ctrl, int enable, int *r_previous);

/* Get the version reported by gpg-agent.  */
gpg_error_t agent_get_version (ctrl_t ctrl, char **r_version);


#endif /*GNUPG_G10_CALL_AGENT_H*/
