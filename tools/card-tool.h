/* card-tool.h - Common definitions for the gpg-card-tool
 * Copyright (C) 2019 g10 Code GmbH
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

#ifndef GNUPG_CARD_TOOL_H
#define GNUPG_CARD_TOOL_H

#include "../common/session-env.h"


/* We keep all global options in the structure OPT.  */
struct
{
  int verbose;
  unsigned int debug;
  int quiet;
  int with_colons;
  const char *gpg_program;
  const char *gpgsm_program;
  const char *agent_program;
  int autostart;

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


/* OpenPGP card key attributes.  */
struct key_attr
{
  int algo;              /* Algorithm identifier.  */
  union {
    unsigned int nbits;  /* Supported keysize.  */
    const char *curve;   /* Name of curve.  */
  };
};

/* An object to store information pertaining to a key pair.  This is
 * commonly used as a linked list with all keys known for the current
 * card.  */
struct key_info_s
{
  struct key_info_s *next;

  unsigned char grip[20];/* The keygrip.  */

  unsigned char xflag;   /* Temporary flag to help processing a list. */

  /* The three next items are mostly useful for OpenPGP cards.  */
  unsigned char fprlen;  /* Use length of the next item.  */
  unsigned char fpr[32]; /* The binary fingerprint of length FPRLEN.  */
  u32 created;           /* The time the key was created.  */

  char keyref[1];        /* String with the keyref (e.g. OPENPGP.1).  */
};
typedef struct key_info_s *key_info_t;


/*
 * The object used to store information about a card.
 */
struct card_info_s
{
  int error;         /* private. */
  char *reader;      /* Reader information.  */
  char *apptypestr;  /* Malloced application type string.  */
  app_type_t apptype;/* Translated from APPTYPESTR.  */
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
  int chvmaxlen[3];  /* Maximum allowed length of a CHV. */
  int chvinfo[3];    /* Allowed retries for the CHV; 0 = blocked. */
  struct key_attr key_attr[3]; /* OpenPGP card key attributes.  */
  struct {
    unsigned int ki:1;     /* Key import available.  */
    unsigned int aac:1;    /* Algorithm attributes are changeable.  */
    unsigned int kdf:1;    /* KDF object to support PIN hashing available.  */
    unsigned int bt:1;     /* Button for confirmation available.  */
  } extcap;
  unsigned int status_indicator;
  int kdf_do_enabled;      /* True if card has a KDF object.  */
  int uif[3];              /* True if User Interaction Flag is on.  */
};
typedef struct card_info_s *card_info_t;


/*-- card-tool-misc.c --*/
key_info_t find_kinfo (card_info_t info, const char *keyref);


/*-- card-call-scd.c --*/
void release_card_info (card_info_t info);
const char *app_type_string (app_type_t app_type);

gpg_error_t scd_apdu (const char *hexapdu, unsigned int *r_sw);
gpg_error_t scd_learn (card_info_t info);
gpg_error_t scd_getattr (const char *name, struct card_info_s *info);
gpg_error_t scd_setattr (const char *name,
                         const unsigned char *value, size_t valuelen);
gpg_error_t scd_writecert (const char *certidstr,
                           const unsigned char *certdata, size_t certdatalen);
gpg_error_t scd_writekey (int keyno,
                          const unsigned char *keydata, size_t keydatalen);
gpg_error_t scd_genkey (int keyno, int force, u32 *createtime);
gpg_error_t scd_serialno (char **r_serialno, const char *demand);
gpg_error_t scd_readcert (const char *certidstr,
                          void **r_buf, size_t *r_buflen);
gpg_error_t scd_cardlist (strlist_t *result);
gpg_error_t scd_change_pin (int chvno);
gpg_error_t scd_checkpin (const char *serialno);

unsigned long agent_get_s2k_count (void);



#endif /*GNUPG_CARD_TOOL_H*/
