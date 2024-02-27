/* gpg-card.h - Common definitions for the gpg-card-tool
 * Copyright (C) 2019, 2020 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef GNUPG_GPG_CARD_H
#define GNUPG_GPG_CARD_H

#include "../common/session-env.h"
#include "../common/strlist.h"


/* We keep all global options in the structure OPT.  */
EXTERN_UNLESS_MAIN_MODULE
struct
{
  int interactive;
  int verbose;
  unsigned int debug;
  int quiet;
  int with_colons;
  char *gpg_program;
  char *gpgsm_program;
  char *agent_program;
  int autostart;

  int no_key_lookup;  /* Assume --no-key-lookup for "list".  */

  int no_history;     /* Do not use the command line history.  */

  /* Options passed to the gpg-agent: */
  session_env_t session_env;
  char *lc_ctype;
  char *lc_messages;

} opt;

/* Debug values and macros.  */
#define DBG_IPC_VALUE      1024 /* Debug assuan communication.  */
#define DBG_EXTPROG_VALUE 16384 /* Debug external program calls */

#define DBG_IPC       (opt.debug & DBG_IPC_VALUE)
#define DBG_EXTPROG   (opt.debug & DBG_EXTPROG_VALUE)

/* The maximum length of a binary fingerprint.  */
#define MAX_FINGERPRINT_LEN  32


/*
 * Data structures to store keyblocks (aka certificates).
 */
struct pubkey_s
{
  struct pubkey_s *next;   /* The next key.  */
  unsigned char grip[KEYGRIP_LEN];
  unsigned char fpr[MAX_FINGERPRINT_LEN];
  unsigned char fprlen;     /* The used length of a FPR.  */
  time_t created;           /* The creation date of the key.  */
  unsigned int grip_valid:1;/* The grip is valid.  */
  unsigned int requested: 1;/* This is the requested grip.  */
};
typedef struct pubkey_s *pubkey_t;

struct userid_s
{
  struct userid_s *next;
  char *value;   /* Malloced.  */
};
typedef struct userid_s *userid_t;

struct keyblock_s
{
  struct keyblock_s *next;  /* Allow to link several keyblocks.  */
  int protocol;      /* GPGME_PROTOCOL_OPENPGP or _CMS. */
  pubkey_t keys;     /* The key.  For OpenPGP primary + list of subkeys.  */
  userid_t uids;     /* The list of user ids.  */
};
typedef struct keyblock_s *keyblock_t;



/* Enumeration of the known card application types. */
typedef enum
  {
   APP_TYPE_NONE,        /* Not yet known or for direct APDU sending.  */
   APP_TYPE_OPENPGP,
   APP_TYPE_NKS,
   APP_TYPE_DINSIG,
   APP_TYPE_P15,
   APP_TYPE_GELDKARTE,
   APP_TYPE_SC_HSM,
   APP_TYPE_PIV,
   APP_TYPE_UNKNOWN      /* Unknown by this tool.  */
  } app_type_t;


/* An object to store information pertaining to a key pair as stored
 * on a card.  This is commonly used as a linked list with all keys
 * known for the current card.  */
struct key_info_s
{
  struct key_info_s *next;

  unsigned char grip[20];/* The keygrip.  */

  unsigned char xflag;   /* Temporary flag to help processing a list. */

  /* OpenPGP card and possible other cards keyalgo string (an atom)
   * and the id of the algorithm. */
  const char *keyalgo;
  enum gcry_pk_algos keyalgo_id;

  /* An optional malloced label for the key.  */
  char *label;

  /* The three next items are mostly useful for OpenPGP cards.  */
  unsigned char fprlen;  /* Use length of the next item.  */
  unsigned char fpr[32]; /* The binary fingerprint of length FPRLEN.  */
  u32 created;           /* The time the key was created.  */
  unsigned int usage;    /* Usage flags.  (GCRY_PK_USAGE_*) */
  char keyref[1];        /* String with the keyref (e.g. OPENPGP.1).  */
};
typedef struct key_info_s *key_info_t;


/*
 * The object used to store information about a card.
 */
struct card_info_s
{
  int initialized;   /* True if a learn command was successful. */
  int need_sn_cmd;   /* The SERIALNO command needs to be issued.  */
  int card_removed;  /* Helper flag set by some listing functions.  */
  int error;         /* private. */
  char *reader;      /* Reader information.  */
  char *cardtype;    /* NULL or type of the card.  */
  unsigned int cardversion; /* Firmware version of the card.  */
  char *apptypestr;  /* Malloced application type string.  */
  app_type_t apptype;/* Translated from APPTYPESTR.  */
  unsigned int appversion; /* Version of the application.  */
  unsigned int manufacturer_id;
  char *manufacturer_name; /* malloced. */
  char *serialno;    /* malloced hex string. */
  char *dispserialno;/* malloced string. */
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
  key_info_t kinfo;  /* Linked list with all keypair related data.  */
  unsigned long sig_counter;
  int chv1_cached;   /* For openpgp this is true if a PIN is not
                        required for each signing.  Note that the
                        gpg-agent might cache it anyway. */
  int is_v2;         /* True if this is a v2 openpgp card.  */
  byte nchvmaxlen;   /* Number of valid items in CHVMAXLEN.  */
  int chvmaxlen[4];  /* Maximum allowed length of a CHV. */
  byte nchvinfo;     /* Number of valid items in CHVINFO.  */
  int chvinfo[4];    /* Allowed retries for the CHV; 0 = blocked. */
  char *chvlabels;   /* Malloced String with CHV labels.  */
  unsigned char chvusage[2]; /* Data object 5F2F */
  struct {
    unsigned int ki:1;     /* Key import available.  */
    unsigned int aac:1;    /* Algorithm attributes are changeable.  */
    unsigned int kdf:1;    /* KDF object to support PIN hashing available.  */
    unsigned int bt:1;     /* Button for confirmation available.     */
    unsigned int sm:1;     /* Secure messaging available.            */
    unsigned int smalgo:15;/* Secure messaging cipher algorithm.     */
    unsigned int private_dos:1;/* Support fpr private use DOs.       */
    unsigned int mcl3:16;  /* Max. length for a OpenPGP card cert.3  */
  } extcap;
  unsigned int status_indicator;
  int kdf_do_enabled;      /* True if card has a KDF object.  */
  int uif[3];              /* True if User Interaction Flag is on.   */
                           /* 1 = on, 2 = permanent on.              */
  strlist_t supported_keyalgo[3];
};
typedef struct card_info_s *card_info_t;


/*-- card-keys.c --*/
void release_keyblock (keyblock_t keyblock);
void flush_keyblock_cache (void);
gpg_error_t get_matching_keys (const unsigned char *keygrip, int protocol,
                               keyblock_t *r_keyblock);
gpg_error_t test_get_matching_keys (const char *hexgrip);
gpg_error_t get_minimal_openpgp_key (estream_t *r_key, const char *fingerprint);


/*-- card-misc.c --*/
key_info_t find_kinfo (card_info_t info, const char *keyref);
void *hex_to_buffer (const char *string, size_t *r_length);
gpg_error_t send_apdu (const char *hexapdu, const char *desc,
                       unsigned int ignore,
                       unsigned char **r_data, size_t *r_datalen);

/*-- card-call-scd.c --*/
void release_card_info (card_info_t info);
const char *app_type_string (app_type_t app_type);

gpg_error_t scd_apdu (const char *hexapdu, const char *options,
                      unsigned int *r_sw,
                      unsigned char **r_data, size_t *r_datalen);

gpg_error_t scd_switchcard (const char *serialno);
gpg_error_t scd_switchapp (const char *appname);

gpg_error_t scd_learn (card_info_t info, int reread);
gpg_error_t scd_getattr (const char *name, struct card_info_s *info);
gpg_error_t scd_setattr (const char *name,
                         const unsigned char *value, size_t valuelen);
gpg_error_t scd_writecert (const char *certidstr,
                           const unsigned char *certdata, size_t certdatalen);
gpg_error_t scd_writekey (const char *keyref, int force, const char *keygrip);
gpg_error_t scd_genkey (const char *keyref, int force, const char *algo,
                        u32 *createtime);
gpg_error_t scd_serialno (char **r_serialno, const char *demand);

gpg_error_t scd_readcert (const char *certidstr,
                          void **r_buf, size_t *r_buflen);
gpg_error_t scd_readkey (const char *keyrefstr, int create_shadow,
                         gcry_sexp_t *r_result);
gpg_error_t scd_cardlist (strlist_t *result);
gpg_error_t scd_applist (strlist_t *result, int all);
gpg_error_t scd_change_pin (const char *pinref, int reset_mode, int nullpin);
gpg_error_t scd_checkpin (const char *serialno);
gpg_error_t scd_havekey_info (const unsigned char *grip, char **r_result);
gpg_error_t scd_delete_key (const unsigned char *grip, int force);

unsigned long agent_get_s2k_count (void);

char *scd_apdu_strerror (unsigned int sw);


/*-- card-yubikey.c --*/
gpg_error_t yubikey_commands (card_info_t info,
                              estream_t fp, int argc, const char *argv[]);


#endif /*GNUPG_GPG_CARD_H*/
