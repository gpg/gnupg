/* app-p15.c - The pkcs#15 card application.
 *	Copyright (C) 2005 Free Software Foundation, Inc.
 *	Copyright (C) 2020, 2021 g10 Code GmbH
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
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* Information pertaining to the BELPIC developer card samples:

       Unblock PUK: "222222111111"
       Reset PIN:   "333333111111")

   e.g. the APDUs 00:20:00:02:08:2C:33:33:33:11:11:11:FF
              and 00:24:01:01:08:24:12:34:FF:FF:FF:FF:FF
   should change the PIN into 1234.
*/

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "scdaemon.h"

#include "iso7816.h"
#include "../common/i18n.h"
#include "../common/tlv.h"
#include "../common/host2net.h"
#include "../common/openpgpdefs.h"
#include "apdu.h" /* fixme: we should move the card detection to a
                     separate file */


static const char oid_kp_codeSigning[]    = "1.3.6.1.5.5.7.3.3";
static const char oid_kp_timeStamping[]   = "1.3.6.1.5.5.7.3.8";
static const char oid_kp_ocspSigning[]    = "1.3.6.1.5.5.7.3.9";
static const char oid_kp_ms_documentSigning[] = "1.3.6.1.4.1.311.10.3.12";
static const char oid_kp_ms_old_documentSigning[] = "1.3.6.1.4.1.311.3.10.3.12";

static const char oid_kp_emailProtection[]= "1.3.6.1.5.5.7.3.4";

static const char oid_kp_serverAuth[]     = "1.3.6.1.5.5.7.3.1";
static const char oid_kp_clientAuth[]     = "1.3.6.1.5.5.7.3.2";
static const char oid_kp_ms_smartcardLogon[] = "1.3.6.1.4.1.311.20.2.2";

static const char oid_kp_anyExtendedKeyUsage[] = "2.5.29.37.0";

static const char oid_kp_gpgUsageCert[] = "1.3.6.1.4.1.11591.2.6.1";
static const char oid_kp_gpgUsageSign[] = "1.3.6.1.4.1.11591.2.6.2";
static const char oid_kp_gpgUsageEncr[] = "1.3.6.1.4.1.11591.2.6.3";
static const char oid_kp_gpgUsageAuth[] = "1.3.6.1.4.1.11591.2.6.4";

/* Types of cards we know and which needs special treatment. */
typedef enum
  {
    CARD_TYPE_UNKNOWN,
    CARD_TYPE_TCOS,
    CARD_TYPE_MICARDO,
    CARD_TYPE_CARDOS_50,
    CARD_TYPE_CARDOS_53,
    CARD_TYPE_AET,     /* A.E.T. Europe JCOP card.  */
    CARD_TYPE_BELPIC   /* Belgian eID card specs. */
  }
card_type_t;

/* The OS of card as specified by card_type_t is not always
 * sufficient.  Thus we also distinguish the actual product build upon
 * the given OS.  */
typedef enum
  {
    CARD_PRODUCT_UNKNOWN,
    CARD_PRODUCT_RSCS,     /* Rohde&Schwarz Cybersecurity       */
    CARD_PRODUCT_DTRUST,   /* D-Trust GmbH (bundesdruckerei.de) */
    CARD_PRODUCT_GENUA     /* GeNUA mbH                         */
  }
card_product_t;


/* A list card types with ATRs noticed with these cards. */
#define X(a) ((unsigned char const *)(a))
static struct
{
  size_t atrlen;
  unsigned char const *atr;
  card_type_t type;
} card_atr_list[] = {
  { 19, X("\x3B\xBA\x13\x00\x81\x31\x86\x5D\x00\x64\x05\x0A\x02\x01\x31\x80"
          "\x90\x00\x8B"),
    CARD_TYPE_TCOS },  /* SLE44 */
  { 19, X("\x3B\xBA\x14\x00\x81\x31\x86\x5D\x00\x64\x05\x14\x02\x02\x31\x80"
          "\x90\x00\x91"),
    CARD_TYPE_TCOS }, /* SLE66S */
  { 19, X("\x3B\xBA\x96\x00\x81\x31\x86\x5D\x00\x64\x05\x60\x02\x03\x31\x80"
          "\x90\x00\x66"),
    CARD_TYPE_TCOS }, /* SLE66P */
  { 27, X("\x3B\xFF\x94\x00\xFF\x80\xB1\xFE\x45\x1F\x03\x00\x68\xD2\x76\x00"
          "\x00\x28\xFF\x05\x1E\x31\x80\x00\x90\x00\x23"),
    CARD_TYPE_MICARDO }, /* German BMI card */
  { 19, X("\x3B\x6F\x00\xFF\x00\x68\xD2\x76\x00\x00\x28\xFF\x05\x1E\x31\x80"
          "\x00\x90\x00"),
    CARD_TYPE_MICARDO }, /* German BMI card (ATR due to reader problem) */
  { 26, X("\x3B\xFE\x94\x00\xFF\x80\xB1\xFA\x45\x1F\x03\x45\x73\x74\x45\x49"
          "\x44\x20\x76\x65\x72\x20\x31\x2E\x30\x43"),
    CARD_TYPE_MICARDO }, /* EstEID (Estonian Big Brother card) */
  { 11, X("\x3b\xd2\x18\x00\x81\x31\xfe\x58\xc9\x01\x14"),
    CARD_TYPE_CARDOS_50 }, /* CardOS 5.0 */
  { 11, X("\x3b\xd2\x18\x00\x81\x31\xfe\x58\xc9\x03\x16"),
    CARD_TYPE_CARDOS_53 }, /* CardOS 5.3 */
  { 24, X("\x3b\xfe\x18\x00\x00\x80\x31\xfe\x45\x53\x43\x45"
          "\x36\x30\x2d\x43\x44\x30\x38\x31\x2d\x6e\x46\xa9"),
    CARD_TYPE_AET },
  { 0 }
};
#undef X


/* Macro to test for CardOS 5.0 and 5.3.  */
#define IS_CARDOS_5(a) ((a)->app_local->card_type == CARD_TYPE_CARDOS_50 \
                        || (a)->app_local->card_type == CARD_TYPE_CARDOS_53)

/* The default PKCS-15 home DF */
#define DEFAULT_HOME_DF 0x5015

/* The AID of PKCS15. */
static char const pkcs15_aid[] = { 0xA0, 0, 0, 0, 0x63,
                                   0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };

/* The Belgian eID variant - they didn't understood why a shared AID
   is useful for a standard.  Oh well. */
static char const pkcs15be_aid[] = { 0xA0, 0, 0, 0x01, 0x77,
                                   0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };


/* The PIN types as defined in pkcs#15 v1.1 */
typedef enum
  {
    PIN_TYPE_BCD = 0,
    PIN_TYPE_ASCII_NUMERIC = 1,
    PIN_TYPE_UTF8 = 2,
    PIN_TYPE_HALF_NIBBLE_BCD = 3,
    PIN_TYPE_ISO9564_1 = 4
  } pin_type_t;

/* The AuthenticationTypes as defined in pkcs#15 v1.1 (6.8.1) */
typedef enum
  {
    AUTH_TYPE_PIN = -1,
    AUTH_TYPE_BIOMETRIC = 0,
    AUTH_TYPE_AUTHKEY = 1,
    AUTH_TYPE_EXTERNAL = 2,
  } auth_type_t;

/* A bit array with for the key usage flags from the
   commonKeyAttributes. */
struct keyusage_flags_s
{
    unsigned int encrypt: 1;
    unsigned int decrypt: 1;
    unsigned int sign: 1;
    unsigned int sign_recover: 1;
    unsigned int wrap: 1;
    unsigned int unwrap: 1;
    unsigned int verify: 1;
    unsigned int verify_recover: 1;
    unsigned int derive: 1;
    unsigned int non_repudiation: 1;
};
typedef struct keyusage_flags_s keyusage_flags_t;


/* A bit array with for the key access flags from the
   commonKeyAttributes. */
struct keyaccess_flags_s
{
  unsigned int any:1;    /* Any access flag set.  */
  unsigned int sensitive:1;
  unsigned int extractable:1;
  unsigned int always_sensitive:1;
  unsigned int never_extractable:1;
  unsigned int local:1;
};
typedef struct keyaccess_flags_s keyaccess_flags_t;


/* A bit array with for the gpg usage flags.  */
struct gpgusage_flags_s
{
  unsigned int any:1;    /* Any of the next flags are set.  */
  unsigned int cert:1;   /* 1.3.6.1.4.1.11591.2.6.1 */
  unsigned int sign:1;   /* 1.3.6.1.4.1.11591.2.6.2 */
  unsigned int encr:1;   /* 1.3.6.1.4.1.11591.2.6.3 */
  unsigned int auth:1;   /* 1.3.6.1.4.1.11591.2.6.4 */
};
typedef struct gpgusage_flags_s gpgusage_flags_t;


/* This is an object to store information about a Certificate
   Directory File (CDF) in a format suitable for further processing by
   us. To keep memory management, simple we use a linked list of
   items; i.e. one such object represents one certificate and the list
   the entire CDF. */
struct cdf_object_s
{
  /* Link to next item when used in a linked list. */
  struct cdf_object_s *next;

  /* Flags to indicate whether fields are valid.  */
  unsigned int have_off:1;

  /* Length and allocated buffer with the Id of this object.
   * This field is used for X.509 in PKCS#11 to make it easier to
   * match a private key with a certificate.  */
  size_t objidlen;
  unsigned char *objid;

  /* Length and allocated buffer with the authId of this object or
     NULL if no authID is known. */
  size_t authidlen;
  unsigned char *authid;

  /* NULL or the malloced label of this object.  */
  char *label;

  /* To avoid reading and parsing a certificate more than once, we
   * cache the ksba object.  */
  ksba_cert_t cert;

  /* The offset and length of the object.  They are only valid if
     HAVE_OFF is true and set to 0 if HAVE_OFF is false. */
  unsigned long off, len;

  /* The length of the path as given in the CDF and the path itself.
     path[0] is the top DF (usually 0x3f00). The path will never be
     empty. */
  size_t pathlen;
  unsigned short path[1];
};
typedef struct cdf_object_s *cdf_object_t;


/* This is an object to store information about a Private Key
   Directory File (PrKDF) in a format suitable for further processing
   by us. To keep memory management, simple we use a linked list of
   items; i.e. one such object represents one certificate and the list
   the entire PrKDF. */
struct prkdf_object_s
{
  /* Link to next item when used in a linked list. */
  struct prkdf_object_s *next;

  /* Flags to indicate whether fields are valid.  */
  unsigned int keygrip_valid:1;
  unsigned int key_reference_valid:1;
  unsigned int have_off:1;
  unsigned int have_keytime:1;

  /* Flag indicating that the corresponding PIN has already been
   * verified.  Note that for cards which are able to return the
   * verification stus, this flag is not used.  */
  unsigned int pin_verified:1;

  /* PKCS#15 info whether this is an EC key.  Default is RSA.  Note
   * that there is also a KEYALGO field which is derived from the
   * publick key via Libgcrypt.  */
  unsigned int is_ecc:1;

  /* The key's usage flags. */
  keyusage_flags_t usageflags;

  /* The key's access flags. */
  keyaccess_flags_t accessflags;

  /* Extended key usage flags.  Only used if .valid is set.  This
   * information is computed from an associated certificate15.  */
  struct {
    unsigned int valid:1;
    unsigned int sign:1;
    unsigned int encr:1;
    unsigned int auth:1;
  } extusage;

  /* OpenPGP key features for this key.  This is taken from special
   * extended key usage flags different from those tracked in EXTUSAGE
   * above.  There is also no valid flag as in EXTUSAGE.  */
  gpgusage_flags_t gpgusage;

  /* The keygrip of the key.  This is used as a cache.  */
  char keygrip[2*KEYGRIP_LEN+1];

  /* A malloced algorithm string or NULL if not known.  */
  char *keyalgostr;

  /* The Gcrypt algo identifier for the key.  It is valid if the
   * keygrip is also valid.  See also is_ecc above.  */
  int keyalgo;

  /* The length of the key in bits (e.g. for RSA the length of the
   * modulus).  It is valid if the keygrip is also valid.  */
  unsigned int keynbits;

  /* The creation time of the key or 0 if not known.  */
  u32 keytime;

  /* Malloced CN from the Subject-DN of the corresponding certificate
   * or NULL if not known.  */
  char *common_name;

  /* Malloced SerialNumber from the Subject-DN of the corresponding
   * certificate or NULL if not known.  */
  char *serial_number;

  /* KDF/KEK parameter for OpenPGP's ECDH.  First byte is zero if not
   * available.  */
  unsigned char ecdh_kdf[4];

  /* Length and allocated buffer with the Id of this object. */
  size_t objidlen;
  unsigned char *objid;

  /* Length and allocated buffer with the authId of this object or
     NULL if no authID is known. */
  size_t authidlen;
  unsigned char *authid;

  /* NULL or the malloced label of this object.  */
  char *label;

  /* The keyReference and a flag telling whether it is valid. */
  unsigned long key_reference;

  /* The offset and length of the object.  They are only valid if
   * HAVE_OFF is true otherwise they are set to 0. */
  unsigned long off, len;

  /* The length of the path as given in the PrKDF and the path itself.
     path[0] is the top DF (usually 0x3f00). */
  size_t pathlen;
  unsigned short path[1];
};
typedef struct prkdf_object_s *prkdf_object_t;
typedef struct prkdf_object_s *pukdf_object_t;


/* This is an object to store information about a Authentication
   Object Directory File (AODF) in a format suitable for further
   processing by us. To keep memory management, simple we use a linked
   list of items; i.e. one such object represents one authentication
   object and the list the entire AOKDF. */
struct aodf_object_s
{
  /* Link to next item when used in a linked list. */
  struct aodf_object_s *next;

  /* Flags to indicate whether fields are valid.  */
  unsigned int have_off:1;

  /* Length and allocated buffer with the Id of this object. */
  size_t objidlen;
  unsigned char *objid;

  /* Length and allocated buffer with the authId of this object or
     NULL if no authID is known. */
  size_t authidlen;
  unsigned char *authid;

  /* NULL or the malloced label of this object.  */
  char *label;

  /* The file ID of this AODF.  */
  unsigned short fid;

  /* The type of this authentication object.  */
  auth_type_t auth_type;

  /* Info used for AUTH_TYPE_PIN: */

  /* The PIN Flags. */
  struct
  {
    unsigned int case_sensitive: 1;
    unsigned int local: 1;
    unsigned int change_disabled: 1;
    unsigned int unblock_disabled: 1;
    unsigned int initialized: 1;
    unsigned int needs_padding: 1;
    unsigned int unblocking_pin: 1;
    unsigned int so_pin: 1;
    unsigned int disable_allowed: 1;
    unsigned int integrity_protected: 1;
    unsigned int confidentiality_protected: 1;
    unsigned int exchange_ref_data: 1;
  } pinflags;

  /* The PIN Type. */
  pin_type_t pintype;

  /* The minimum length of a PIN. */
  unsigned long min_length;

  /* The stored length of a PIN. */
  unsigned long stored_length;

  /* The maximum length of a PIN and a flag telling whether it is valid. */
  unsigned long max_length;
  int max_length_valid;

  /* The pinReference and a flag telling whether it is valid. */
  unsigned long pin_reference;
  int pin_reference_valid;

  /* The padChar and a flag telling whether it is valid. */
  char pad_char;
  int pad_char_valid;

  /* The offset and length of the object.  They are only valid if
     HAVE_OFF is true and set to 0 if HAVE_OFF is false. */
  unsigned long off, len;

  /* The length of the path as given in the Aodf and the path itself.
     path[0] is the top DF (usually 0x3f00). PATH is optional and thus
     may be NULL.  Malloced.*/
  size_t pathlen;
  unsigned short *path;

  /* Info used for AUTH_TYPE_AUTHKEY: */

};
typedef struct aodf_object_s *aodf_object_t;


/* Context local to this application. */
struct app_local_s
{
  /* The home DF. Note, that we don't yet support a multilevel
     hierarchy.  Thus we assume this is directly below the MF.  */
  unsigned short home_df;

  /* The type of the card's OS. */
  card_type_t card_type;

  /* The vendor's product.  */
  card_product_t card_product;

  /* Flag indicating that extended_mode is not supported.  */
  unsigned int no_extended_mode : 1;

  /* Flag indicating whether we may use direct path selection. */
  unsigned int direct_path_selection : 1;

  /* Flag indicating whether the card has any key with a gpgusage set.  */
  unsigned int any_gpgusage : 1;

  /* Structure with the EFIDs of the objects described in the ODF
     file. */
  struct
  {
    unsigned short private_keys;
    unsigned short public_keys;
    unsigned short trusted_public_keys;
    unsigned short secret_keys;
    unsigned short certificates;
    unsigned short trusted_certificates;
    unsigned short useful_certificates;
    unsigned short data_objects;
    unsigned short auth_objects;
  } odf;

  /* The PKCS#15 serialnumber from EF(TokenInfo) or NULL.  Malloced. */
  unsigned char *serialno;
  size_t serialnolen;

  /* The manufacturerID from the TokenInfo EF.  Malloced or NULL. */
  char *manufacturer_id;

  /* The label from the TokenInfo EF.  Malloced or NULL.  */
  char *token_label;

  /* The tokenflags from the TokenInfo EF.  Malloced or NULL.  */
  unsigned char *tokenflags;
  unsigned int tokenflagslen;

  /* Information on all certificates. */
  cdf_object_t certificate_info;
  /* Information on all trusted certificates. */
  cdf_object_t trusted_certificate_info;
  /* Information on all useful certificates. */
  cdf_object_t useful_certificate_info;

  /* Information on all public keys. */
  prkdf_object_t public_key_info;

  /* Information on all private keys. */
  pukdf_object_t private_key_info;

  /* Information on all authentication objects. */
  aodf_object_t auth_object_info;

};


/*** Local prototypes.  ***/
static gpg_error_t select_ef_by_path (app_t app, const unsigned short *path,
                                      size_t pathlen);
static gpg_error_t keygrip_from_prkdf (app_t app, prkdf_object_t prkdf);
static gpg_error_t readcert_by_cdf (app_t app, cdf_object_t cdf,
                                    unsigned char **r_cert, size_t *r_certlen);
static char *get_dispserialno (app_t app, prkdf_object_t prkdf);
static gpg_error_t do_getattr (app_t app, ctrl_t ctrl, const char *name);



static const char *
cardtype2str (card_type_t cardtype)
{
  switch (cardtype)
    {
    case CARD_TYPE_UNKNOWN:   return "";
    case CARD_TYPE_TCOS:      return "TCOS";
    case CARD_TYPE_MICARDO:   return "Micardo";
    case CARD_TYPE_CARDOS_50: return "CardOS 5.0";
    case CARD_TYPE_CARDOS_53: return "CardOS 5.3";
    case CARD_TYPE_BELPIC:    return "Belgian eID";
    case CARD_TYPE_AET:       return "AET";
    }
  return "";
}

static const char *
cardproduct2str (card_product_t cardproduct)
{
  switch (cardproduct)
    {
    case CARD_PRODUCT_UNKNOWN: return "";
    case CARD_PRODUCT_RSCS:    return "R&S";
    case CARD_PRODUCT_DTRUST:  return "D-Trust";
    case CARD_PRODUCT_GENUA:   return "GeNUA";
    }
  return "";
}

/* Release the CDF object A  */
static void
release_cdflist (cdf_object_t a)
{
  while (a)
    {
      cdf_object_t tmp = a->next;
      ksba_free (a->cert);
      xfree (a->objid);
      xfree (a->authid);
      xfree (a->label);
      xfree (a);
      a = tmp;
    }
}

/* Release the PrKDF object A.  */
static void
release_prkdflist (prkdf_object_t a)
{
  while (a)
    {
      prkdf_object_t tmp = a->next;
      xfree (a->keyalgostr);
      xfree (a->common_name);
      xfree (a->serial_number);
      xfree (a->objid);
      xfree (a->authid);
      xfree (a->label);
      xfree (a);
      a = tmp;
    }
}

static void
release_pukdflist (pukdf_object_t a)
{
  release_prkdflist (a);
}

/* Release just one aodf object. */
void
release_aodf_object (aodf_object_t a)
{
  if (a)
    {
      xfree (a->objid);
      xfree (a->authid);
      xfree (a->label);
      xfree (a->path);
      xfree (a);
    }
}

/* Release the AODF list A.  */
static void
release_aodflist (aodf_object_t a)
{
  while (a)
    {
      aodf_object_t tmp = a->next;
      release_aodf_object (a);
      a = tmp;
    }
}


static void
release_lists (app_t app)
{
  release_cdflist (app->app_local->certificate_info);
  app->app_local->certificate_info = NULL;
  release_cdflist (app->app_local->trusted_certificate_info);
  app->app_local->trusted_certificate_info = NULL;
  release_cdflist (app->app_local->useful_certificate_info);
  app->app_local->useful_certificate_info = NULL;
  release_pukdflist (app->app_local->public_key_info);
  app->app_local->public_key_info = NULL;
  release_prkdflist (app->app_local->private_key_info);
  app->app_local->private_key_info = NULL;
  release_aodflist (app->app_local->auth_object_info);
  app->app_local->auth_object_info = NULL;
}


static void
release_tokeninfo (app_t app)
{
  xfree (app->app_local->manufacturer_id);
  app->app_local->manufacturer_id = NULL;
  xfree (app->app_local->token_label);
  app->app_local->token_label = NULL;
  xfree (app->app_local->tokenflags);
  app->app_local->tokenflags = NULL;
  xfree (app->app_local->serialno);
  app->app_local->serialno = NULL;
}


/* Release all local resources.  */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      release_lists (app);
      release_tokeninfo (app);
      xfree (app->app_local);
      app->app_local = NULL;
    }
}


/* Do a select and a read for the file with EFID.  EFID_DESC is a
   desctription of the EF to be used with error messages.  On success
   BUFFER and BUFLEN contain the entire content of the EF.  The caller
   must free BUFFER only on success.  If EFID is 0 no seelct is done. */
static gpg_error_t
select_and_read_binary (app_t app, unsigned short efid, const char *efid_desc,
                        unsigned char **buffer, size_t *buflen)
{
  gpg_error_t err;
  int sw;

  if (efid)
    {
      err = select_ef_by_path (app, &efid, 1);
      if (err)
        {
          log_error ("p15: error selecting %s (0x%04X): %s\n",
                     efid_desc, efid, gpg_strerror (err));
          return err;
        }
    }

  err = iso7816_read_binary_ext (app_get_slot (app),
                                 0, 0, 0, buffer, buflen, &sw);
  if (err)
    log_error ("p15: error reading %s (0x%04X): %s (sw=%04X)\n",
               efid_desc, efid, gpg_strerror (err), sw);
  return err;
}


/* If EFID is not 0 do a select and then read the record RECNO.
 * EFID_DESC is a description of the EF to be used with error
 * messages.  On success BUFFER and BUFLEN contain the entire content
 * of the EF.  The caller must free BUFFER only on success. */
static gpg_error_t
select_and_read_record (app_t app, unsigned short efid, int recno,
                        const char *efid_desc,
                        unsigned char **buffer, size_t *buflen, int *r_sw)
{
  gpg_error_t err;
  int sw;

  if (r_sw)
    *r_sw = 0x9000;

  if (efid)
    {
      err = select_ef_by_path (app, &efid, 1);
      if (err)
        {
          log_error ("p15: error selecting %s (0x%04X): %s\n",
                     efid_desc, efid, gpg_strerror (err));
          if (r_sw)
            *r_sw = sw;
          return err;
        }
    }

  err = iso7816_read_record_ext (app_get_slot (app),
                                 recno, 1, 0, buffer, buflen, &sw);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
          ;
      else if (err && sw == SW_FILE_STRUCT)
        ;
      else
        log_error ("p15: error reading %s (0x%04X) record %d: %s (sw=%04X)\n",
                   efid_desc, efid, recno, gpg_strerror (err), sw);
      if (r_sw)
        *r_sw = sw;
      return err;
    }
  /* On CardOS with a Linear TLV file structure the records starts
   * with some tag (often the record number) followed by the length
   * byte for this record.  Detect and remove this prefix.  */
  if (*buflen == 2 && !(*buffer)[0] && !(*buffer)[1])
    ;  /* deleted record.  */
  else if (*buflen > 3 && (*buffer)[0] == 0xff
           && buf16_to_uint ((*buffer)+1) == *buflen - 3)
    {
      memmove (*buffer, *buffer + 3, *buflen - 3);
      *buflen = *buflen - 3;
    }
  else if (*buflen > 2 && (*buffer)[0] != 0x30 && (*buffer)[1] == *buflen - 2)
    {
      memmove (*buffer, *buffer + 2, *buflen - 2);
      *buflen = *buflen - 2;
    }

  return 0;
}


/* This function calls select file to read a file using a complete
   path which may or may not start at the master file (MF). */
static gpg_error_t
select_ef_by_path (app_t app, const unsigned short *path, size_t pathlen)
{
  gpg_error_t err;
  int i, j;

  if (!pathlen)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* log_debug ("%s: path=", __func__); */
  /* for (j=0; j < pathlen; j++) */
  /*   log_printf ("%s%04hX", j? "/":"", path[j]); */
  /* log_printf ("%s\n",app->app_local->direct_path_selection?" (direct)":"");*/

  if (app->app_local->direct_path_selection)
    {
      if (pathlen && *path == 0x3f00 )
        {
          if (pathlen == 1)
            err = iso7816_select_mf (app_get_slot (app));
          else
            err = iso7816_select_path (app_get_slot (app), path+1, pathlen-1,
                                       0);
        }
      else
        err = iso7816_select_path (app_get_slot (app), path, pathlen,
                                   app->app_local->home_df);
      if (err)
        {
          log_error ("p15: error selecting path ");
          goto err_print_path;
        }
    }
  else if (pathlen > 1 && path[0] == 0x3fff)
    {
      err = iso7816_select_file (app_get_slot (app), 0x3f00, 0);
      if (err)
        {
          log_error ("p15: error selecting part %d from path ", 0);
          goto err_print_path;
        }
      path++;
      pathlen--;
      for (i=0; i < pathlen; i++)
        {
          err = iso7816_select_file (app_get_slot (app),
                                     path[i], (i+1 == pathlen)? 2 : 1);
          if (err)
            {
              log_error ("p15: error selecting part %d from path ", i);
              goto err_print_path;
            }
        }
    }
  else
    {
      if (pathlen && *path != 0x3f00 )
        log_error ("p15: warning: relative path select not yet implemented\n");

      /* FIXME: Use home_df.  */
      for (i=0; i < pathlen; i++)
        {
          err = iso7816_select_file (app_get_slot (app),
                                     path[i], !(i+1 == pathlen));
          if (err)
            {
              log_error ("p15: error selecting part %d from path ", i);
              goto err_print_path;
            }
        }
    }
  return 0;

 err_print_path:
  if (pathlen && *path != 0x3f00 )
    log_printf ("3F00/");
  else
    log_printf ("%04hX/", app->app_local->home_df);
  for (j=0; j < pathlen; j++)
    log_printf ("%s%04hX", j? "/":"", path[j]);
  log_printf (": %s\n", gpg_strerror (err));
  return err;
}


/* Parse a cert Id string (or a key Id string) and return the binary
   object Id string in a newly allocated buffer stored at R_OBJID and
   R_OBJIDLEN.  On Error NULL will be stored there and an error code
   returned. On success caller needs to free the buffer at R_OBJID. */
static gpg_error_t
parse_certid (app_t app, const char *certid,
              unsigned char **r_objid, size_t *r_objidlen)
{
  char tmpbuf[10];
  const char *s;
  size_t objidlen;
  unsigned char *objid;
  int i;

  *r_objid = NULL;
  *r_objidlen = 0;

  if (certid[0] != 'P' && strlen (certid) == 40)  /* This is a keygrip.  */
    {
      prkdf_object_t prkdf;

      for (prkdf = app->app_local->private_key_info;
           prkdf; prkdf = prkdf->next)
        if (!keygrip_from_prkdf (app, prkdf)
            && !strcmp (certid, prkdf->keygrip))
          break;
      if (!prkdf || !prkdf->objidlen || !prkdf->objid)
        return gpg_error (GPG_ERR_NOT_FOUND);
      objidlen = prkdf->objidlen;
      objid = xtrymalloc (objidlen);
      if (!objid)
        return gpg_error_from_syserror ();
      memcpy (objid, prkdf->objid, prkdf->objidlen);
    }
  else /* This is a usual keyref.  */
    {
      if (app->app_local->home_df != DEFAULT_HOME_DF)
        snprintf (tmpbuf, sizeof tmpbuf, "P15-%04X.",
                  (unsigned int)(app->app_local->home_df & 0xffff));
      else
        strcpy (tmpbuf, "P15.");
      if (strncmp (certid, tmpbuf, strlen (tmpbuf)) )
        {
          if (!strncmp (certid, "P15.", 4)
              || (!strncmp (certid, "P15-", 4)
                  && hexdigitp (certid+4)
                  && hexdigitp (certid+5)
                  && hexdigitp (certid+6)
                  && hexdigitp (certid+7)
                  && certid[8] == '.'))
            return gpg_error (GPG_ERR_NOT_FOUND);
          return gpg_error (GPG_ERR_INV_ID);
        }
      certid += strlen (tmpbuf);
      for (s=certid, objidlen=0; hexdigitp (s); s++, objidlen++)
        ;
      if (*s || !objidlen || (objidlen%2))
        return gpg_error (GPG_ERR_INV_ID);
      objidlen /= 2;
      objid = xtrymalloc (objidlen);
      if (!objid)
        return gpg_error_from_syserror ();
      for (s=certid, i=0; i < objidlen; i++, s+=2)
        objid[i] = xtoi_2 (s);
    }

  *r_objid = objid;
  *r_objidlen = objidlen;
  return 0;
}


/* Find a certificate object by its object ID and store a pointer to
 * it at R_CDF. */
static gpg_error_t
cdf_object_from_objid (app_t app, size_t objidlen, const unsigned char *objid,
                       cdf_object_t *r_cdf)
{
  cdf_object_t cdf;

  for (cdf = app->app_local->certificate_info; cdf; cdf = cdf->next)
    if (cdf->objidlen == objidlen && !memcmp (cdf->objid, objid, objidlen))
      break;
  if (!cdf)
    for (cdf = app->app_local->trusted_certificate_info; cdf; cdf = cdf->next)
      if (cdf->objidlen == objidlen && !memcmp (cdf->objid, objid, objidlen))
        break;
  if (!cdf)
    for (cdf = app->app_local->useful_certificate_info; cdf; cdf = cdf->next)
      if (cdf->objidlen == objidlen && !memcmp (cdf->objid, objid, objidlen))
        break;
  if (!cdf)
    return gpg_error (GPG_ERR_NOT_FOUND);
  *r_cdf = cdf;
  return 0;
}


/* Find a certificate object by its label and store a pointer to it at
 * R_CDF. */
static gpg_error_t
cdf_object_from_label (app_t app, const char *label, cdf_object_t *r_cdf)
{
  cdf_object_t cdf;

  if (!label)
    return gpg_error (GPG_ERR_NOT_FOUND);

  for (cdf = app->app_local->certificate_info; cdf; cdf = cdf->next)
    if (cdf->label && !strcmp (cdf->label, label))
      break;
  if (!cdf)
    for (cdf = app->app_local->trusted_certificate_info; cdf; cdf = cdf->next)
      if (cdf->label && !strcmp (cdf->label, label))
        break;
  if (!cdf)
    for (cdf = app->app_local->useful_certificate_info; cdf; cdf = cdf->next)
      if (cdf->label && !strcmp (cdf->label, label))
        break;
  if (!cdf)
    return gpg_error (GPG_ERR_NOT_FOUND);
  *r_cdf = cdf;
  return 0;
}


/* Find a certificate object by the certificate ID CERTID and store a
 * pointer to it at R_CDF. */
static gpg_error_t
cdf_object_from_certid (app_t app, const char *certid, cdf_object_t *r_cdf)
{
  gpg_error_t err;
  size_t objidlen;
  unsigned char *objid;
  cdf_object_t cdf;
  prkdf_object_t prkdf;

  err = parse_certid (app, certid, &objid, &objidlen);
  if (err)
    return err;

  err = cdf_object_from_objid (app, objidlen, objid, &cdf);
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    {
      /* Try again by finding the certid in the prkdf and matching by
       * label.  */
      for (prkdf = app->app_local->private_key_info; prkdf; prkdf = prkdf->next)
        if (prkdf->objidlen == objidlen
            && !memcmp (prkdf->objid, objid, objidlen))
          break;
      if (prkdf)
        err = cdf_object_from_label (app, prkdf->label, &cdf);
    }
  xfree (objid);
  if (err)
    return err;
  *r_cdf = cdf;
  return 0;
}


/* Find a private key object by the key Id string KEYIDSTR and store a
   pointer to it at R_PRKDF. */
static gpg_error_t
prkdf_object_from_keyidstr (app_t app, const char *keyidstr,
                            prkdf_object_t *r_prkdf)
{
  gpg_error_t err;
  size_t objidlen;
  unsigned char *objid;
  prkdf_object_t prkdf;

  err = parse_certid (app, keyidstr, &objid, &objidlen);
  if (err)
    return err;

  for (prkdf = app->app_local->private_key_info; prkdf; prkdf = prkdf->next)
    if (prkdf->objidlen == objidlen && !memcmp (prkdf->objid, objid, objidlen))
      break;
  xfree (objid);
  if (!prkdf)
    return gpg_error (GPG_ERR_NOT_FOUND);
  *r_prkdf = prkdf;
  return 0;
}




/* Read and parse the Object Directory File and store away the
   pointers. ODF_FID shall contain the FID of the ODF.

   Example of such a file:

   A0 06 30 04 04 02 60 34  = Private Keys
   A4 06 30 04 04 02 60 35  = Certificates
   A5 06 30 04 04 02 60 36  = Trusted Certificates
   A7 06 30 04 04 02 60 37  = Data Objects
   A8 06 30 04 04 02 60 38  = Auth Objects

   These are all PathOrObjects using the path CHOICE element.  The
   paths are octet strings of length 2.  Using this Path CHOICE
   element is recommended, so we only implement that for now.
*/
static gpg_error_t
read_ef_odf (app_t app, unsigned short odf_fid)
{
  gpg_error_t err;
  unsigned char *buffer, *p;
  size_t buflen, n;
  unsigned short value;
  size_t offset;
  unsigned short home_df = 0;


  app->app_local->odf.private_keys = 0;
  app->app_local->odf.public_keys = 0;
  app->app_local->odf.trusted_public_keys = 0;
  app->app_local->odf.secret_keys = 0;
  app->app_local->odf.certificates = 0;
  app->app_local->odf.trusted_certificates = 0;
  app->app_local->odf.useful_certificates = 0;
  app->app_local->odf.data_objects = 0;
  app->app_local->odf.auth_objects = 0;

  err = select_and_read_binary (app, odf_fid, "ODF",
                                &buffer, &buflen);
  if (err)
    return err;

  if (buflen < 8)
    {
      log_error ("p15: error: ODF too short\n");
      xfree (buffer);
      return gpg_error (GPG_ERR_INV_OBJ);
    }

  home_df = app->app_local->home_df;
  p = buffer;
  while (buflen && *p && *p != 0xff)
    {
      if ( buflen >= 8
           && (p[0] & 0xf0) == 0xA0
           && !memcmp (p+1, "\x06\x30\x04\x04\x02", 5) )
        {
          offset = 6;
        }
      else if ( buflen >= 12
                && (p[0] & 0xf0) == 0xA0
                && !memcmp (p+1, "\x0a\x30\x08\x04\x06\x3F\x00", 7)
                && (!home_df || home_df == ((p[8]<<8)|p[9])) )
        {
          /* FIXME: Is this hack still required?  */
          /* If we do not know the home DF, we take it from the first
           * ODF object.  Here are sample values:
           * a0 0a 30 08 0406 3f00 5015 4401
           * a1 0a 30 08 0406 3f00 5015 4411
           * a4 0a 30 08 0406 3f00 5015 4441
           * a5 0a 30 08 0406 3f00 5015 4451
           * a8 0a 30 08 0406 3f00 5015 4481
           * 00000000 */
          if (!home_df)
            {
              home_df = ((p[8]<<8)|p[9]);
              app->app_local->home_df = home_df;
              log_info ("p15: application directory detected as 0x%04hX\n",
                        home_df);
              /* We assume that direct path selection is possible.  */
              app->app_local->direct_path_selection = 1;
            }

          /* We only allow a full path if all files are at the same
             level and below the home directory.  To extend this we
             would need to make use of new data type capable of
             keeping a full path. */
          offset = 10;
        }
      else
        {
          log_printhex (p, buflen, "p15: ODF format not supported:");
          xfree (buffer);
          return gpg_error (GPG_ERR_INV_OBJ);
        }
      switch ((p[0] & 0x0f))
        {
        case 0: value = app->app_local->odf.private_keys; break;
        case 1: value = app->app_local->odf.public_keys; break;
        case 2: value = app->app_local->odf.trusted_public_keys; break;
        case 3: value = app->app_local->odf.secret_keys; break;
        case 4: value = app->app_local->odf.certificates; break;
        case 5: value = app->app_local->odf.trusted_certificates; break;
        case 6: value = app->app_local->odf.useful_certificates; break;
        case 7: value = app->app_local->odf.data_objects; break;
        case 8: value = app->app_local->odf.auth_objects; break;
        default: value = 0; break;
        }
      if (value)
        {
          log_error ("p15: duplicate object type %d in ODF ignored\n",
                     (p[0]&0x0f));
          continue;
        }
      value = ((p[offset] << 8) | p[offset+1]);
      switch ((p[0] & 0x0f))
        {
        case 0: app->app_local->odf.private_keys = value; break;
        case 1: app->app_local->odf.public_keys = value; break;
        case 2: app->app_local->odf.trusted_public_keys = value; break;
        case 3: app->app_local->odf.secret_keys = value; break;
        case 4: app->app_local->odf.certificates = value; break;
        case 5: app->app_local->odf.trusted_certificates = value; break;
        case 6: app->app_local->odf.useful_certificates = value; break;
        case 7: app->app_local->odf.data_objects = value; break;
        case 8: app->app_local->odf.auth_objects = value; break;
        default:
          log_error ("p15: unknown object type %d in ODF ignored\n",
                     (p[0]&0x0f));
        }
      offset += 2;

      if (buflen < offset)
        break;
      p += offset;
      buflen -= offset;
    }

  if (buflen)
    {
      /* Print a warning if non-null garbage is left over.  */
      for (n=0; n < buflen && !p[n]; n++)
        ;
      if (n < buflen)
        {
          log_info ("p15: warning: garbage detected at end of ODF: ");
          log_printhex (p, buflen, "");
        }
    }

  xfree (buffer);
  return 0;
}


/* Helper for the read_ef_foo functions to read the first record or
 * the entire data.  */
static gpg_error_t
read_first_record (app_t app, unsigned short fid, const char *fid_desc,
                   unsigned char **r_buffer, size_t *r_buflen,
                   int *r_use_read_record)
{
  gpg_error_t err;
  int sw;

  *r_buffer = NULL;
  *r_buflen = 0;
  *r_use_read_record = 0;

  if (!fid)
    return gpg_error (GPG_ERR_NO_DATA); /* No such file. */

  if (IS_CARDOS_5 (app))
    {
      *r_use_read_record = 1;
      err = select_and_read_record (app, fid, 1, fid_desc,
                                    r_buffer, r_buflen, &sw);
      if (err && sw == SW_FILE_STRUCT)
        {
          *r_use_read_record = 0;
          err = select_and_read_binary (app, 0, fid_desc, r_buffer, r_buflen);
        }
    }
  else
    err = select_and_read_binary (app, fid, fid_desc, r_buffer, r_buflen);

  /* We get a not_found state in read_record mode if the select
   * succeeded but reading the record failed.  Map that to no_data
   * which is what the caller of the read_ef_foo functions expect.  */
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    err = gpg_error (GPG_ERR_NO_DATA);

  return err;
}


/* Parse the BIT STRING with the keyUsageFlags from the
   CommonKeyAttributes. */
static gpg_error_t
parse_keyusage_flags (const unsigned char *der, size_t derlen,
                      keyusage_flags_t *usageflags)
{
  unsigned int bits, mask;
  int i, unused, full;

  memset (usageflags, 0, sizeof *usageflags);
  if (!derlen)
    return gpg_error (GPG_ERR_INV_OBJ);

  unused = *der++; derlen--;
  if ((!derlen && unused) || unused/8 > derlen)
    return gpg_error (GPG_ERR_ENCODING_PROBLEM);
  full = derlen - (unused+7)/8;
  unused %= 8;
  mask = 0;
  for (i=1; unused; i <<= 1, unused--)
    mask |= i;

  /* First octet */
  if (derlen)
    {
      bits = *der++; derlen--;
      if (full)
        full--;
      else
        {
          bits &= ~mask;
          mask = 0;
        }
    }
  else
    bits = 0;
  if ((bits & 0x80)) usageflags->encrypt = 1;
  if ((bits & 0x40)) usageflags->decrypt = 1;
  if ((bits & 0x20)) usageflags->sign = 1;
  if ((bits & 0x10)) usageflags->sign_recover = 1;
  if ((bits & 0x08)) usageflags->wrap = 1;
  if ((bits & 0x04)) usageflags->unwrap = 1;
  if ((bits & 0x02)) usageflags->verify = 1;
  if ((bits & 0x01)) usageflags->verify_recover = 1;

  /* Second octet. */
  if (derlen)
    {
      bits = *der++; derlen--;
      if (full)
        full--;
      else
        {
          bits &= ~mask;
        }
    }
  else
    bits = 0;
  if ((bits & 0x80)) usageflags->derive = 1;
  if ((bits & 0x40)) usageflags->non_repudiation = 1;

  return 0;
}


static void
dump_keyusage_flags (keyusage_flags_t usageflags)
{
  const char *s = "";

  log_info ("p15:             usage=");
  if (usageflags.encrypt)
    log_printf ("%sencrypt", s), s = ",";
  if (usageflags.decrypt)
    log_printf ("%sdecrypt", s), s = ",";
  if (usageflags.sign   )
    log_printf ("%ssign", s), s = ",";
  if (usageflags.sign_recover)
    log_printf ("%ssign_recover", s), s = ",";
  if (usageflags.wrap   )
    log_printf ("%swrap", s), s = ",";
  if (usageflags.unwrap )
    log_printf ("%sunwrap", s), s = ",";
  if (usageflags.verify )
    log_printf ("%sverify", s), s = ",";
  if (usageflags.verify_recover)
    log_printf ("%sverify_recover", s), s = ",";
  if (usageflags.derive )
    log_printf ("%sderive", s), s = ",";
  if (usageflags.non_repudiation)
    log_printf ("%snon_repudiation", s), s = ",";
}


static void
dump_keyaccess_flags (keyaccess_flags_t accessflags)
{
  const char *s = "";

  log_info ("p15:             access=");
  if (accessflags.sensitive)
    log_printf ("%ssensitive", s), s = ",";
  if (accessflags.extractable)
    log_printf ("%sextractable", s), s = ",";
  if (accessflags.always_sensitive)
    log_printf ("%salways_sensitive", s), s = ",";
  if (accessflags.never_extractable)
    log_printf ("%snever_extractable", s), s = ",";
  if (accessflags.local)
    log_printf ("%slocal", s), s = ",";
}


static void
dump_gpgusage_flags (gpgusage_flags_t gpgusage)
{
  const char *s = "";

  log_info ("p15:             gpgusage=");
  if (gpgusage.cert)
    log_printf ("%scert", s), s = ",";
  if (gpgusage.sign)
    log_printf ("%ssign", s), s = ",";
  if (gpgusage.encr)
    log_printf ("%sencr", s), s = ",";
  if (gpgusage.auth)
    log_printf ("%sauth", s), s = ",";
}


/* Parse the BIT STRING with the keyAccessFlags from the
   CommonKeyAttributes. */
static gpg_error_t
parse_keyaccess_flags (const unsigned char *der, size_t derlen,
                       keyaccess_flags_t *accessflags)
{
  unsigned int bits, mask;
  int i, unused, full;

  memset (accessflags, 0, sizeof *accessflags);
  if (!derlen)
    return gpg_error (GPG_ERR_INV_OBJ);

  unused = *der++; derlen--;
  if ((!derlen && unused) || unused/8 > derlen)
    return gpg_error (GPG_ERR_ENCODING_PROBLEM);
  full = derlen - (unused+7)/8;
  unused %= 8;
  mask = 0;
  for (i=1; unused; i <<= 1, unused--)
    mask |= i;

  /* First octet */
  if (derlen)
    {
      bits = *der++; derlen--;
      if (full)
        full--;
      else
        {
          bits &= ~mask;
          mask = 0;
        }
    }
  else
    bits = 0;
  if ((bits & 0x10)) accessflags->local = 1;
  if ((bits & 0x08)) accessflags->never_extractable = 1;
  if ((bits & 0x04)) accessflags->always_sensitive = 1;
  if ((bits & 0x02)) accessflags->extractable = 1;
  if ((bits & 0x01)) accessflags->sensitive = 1;

  accessflags->any = 1;
  return 0;
}


/* Parse the commonObjectAttributes and store a malloced authid at
 * (r_authid,r_authidlen).  (NULL,0) is stored on error or if no
 * authid is found.  IF R_LABEL is not NULL the label is stored there
 * as a malloced string (spaces are replaced by underscores).
 *
 * Example data:
 *  2 30   17:   SEQUENCE { -- commonObjectAttributes
 *  4 0C    8:     UTF8String 'SK.CH.DS'    -- label
 * 14 03    2:     BIT STRING 6 unused bits
 *           :       '01'B (bit 0)
 * 18 04    1:     OCTET STRING --authid
 *           :       07
 *           :     }
 */
static gpg_error_t
parse_common_obj_attr (unsigned char const **buffer, size_t *size,
                       unsigned char **r_authid, size_t *r_authidlen,
                       char **r_label)
{
  gpg_error_t err;
  int where;
  int class, tag, constructed, ndef;
  size_t objlen, hdrlen, nnn;
  const unsigned char *ppp;
  int ignore_eof = 0;
  char *p;

  *r_authid = NULL;
  *r_authidlen = 0;
  if (r_label)
    *r_label = NULL;

  where = __LINE__;
  err = parse_ber_header (buffer, size, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > *size || tag != TAG_SEQUENCE))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  ppp = *buffer;
  nnn = objlen;
  *buffer += objlen;
  *size   -= objlen;

  /* Search the optional AuthId.  */
  ignore_eof = 1;
  where = __LINE__;
  err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > nnn || class != CLASS_UNIVERSAL))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  if (tag == TAG_UTF8_STRING)
    {
      if (r_label)
        {
          *r_label = xtrymalloc (objlen + 1);
          if (!*r_label)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          memcpy (*r_label, ppp, objlen);
          (*r_label)[objlen] = 0;
          /* We don't want spaces in the labels due to the properties
           * of CHV-LABEL.  */
          for (p = *r_label; *p; p++)
            if (ascii_isspace (*p))
              *p = '_';
        }

      ppp += objlen;
      nnn -= objlen;

      where = __LINE__;
      err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nnn || class != CLASS_UNIVERSAL))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto leave;
    }
  if (tag == TAG_BIT_STRING)
    {
      ppp += objlen; /* Skip the CommonObjectFlags.  */
      nnn -= objlen;

      where = __LINE__;
      err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nnn || class != CLASS_UNIVERSAL))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto leave;
    }
  if (tag == TAG_OCTET_STRING && objlen)
    {
      *r_authid = xtrymalloc (objlen);
      if (!*r_authid)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (*r_authid, ppp, objlen);
      *r_authidlen = objlen;
    }

 leave:
  if (ignore_eof && gpg_err_code (err) == GPG_ERR_EOF)
    err = 0;
  else if (err)
    log_error ("p15: error parsing commonObjectAttributes at %d: %s\n",
               where, gpg_strerror (err));

  if (err && r_label)
    {
      xfree (*r_label);
      *r_label = NULL;
    }

  return err;
}


/* Parse the commonKeyAttributes.  On success store the objid at
 * (R_OBJID/R_OBJIDLEN), sets the key usage flags at USAGEFLAGS and
 * the optiona key refrence at R_KEY_REFERENCE.  The latter is only
 * valid if true is also stored at R_KEY_REFERENCE_VALID.
 *
 * Example data:
 *
 * 21 30   12:   SEQUENCE { -- commonKeyAttributes
 * 23 04    1:     OCTET STRING
 *           :       01
 * 26 03    3:     BIT STRING 6 unused bits
 *           :       '1000000000'B (bit 9)
 * 31 02    2:     INTEGER 80  -- keyReference (optional)
 *           :     }
 */
static gpg_error_t
parse_common_key_attr (unsigned char const **buffer, size_t *size,
                       unsigned char **r_objid, size_t *r_objidlen,
                       keyusage_flags_t *usageflags,
                       keyaccess_flags_t *accessflags,
                       unsigned long *r_key_reference,
                       int *r_key_reference_valid)
{
  gpg_error_t err;
  int where;
  int class, tag, constructed, ndef;
  size_t objlen, hdrlen, nnn;
  const unsigned char *ppp;
  int ignore_eof = 0;
  unsigned long ul;
  const unsigned char *objid = NULL;
  size_t objidlen;
  unsigned long key_reference = 0;
  int key_reference_valid = 0;

  *r_objid = NULL;
  *r_objidlen = 0;
  memset (usageflags, 0, sizeof *usageflags);
  memset (accessflags, 0, sizeof *accessflags);
  *r_key_reference_valid = 0;

  where = __LINE__;
  err = parse_ber_header (buffer, size, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > *size || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  ppp = *buffer;
  nnn = objlen;
  *buffer += objlen;
  *size   -= objlen;

  /* Get the Id. */
  where = __LINE__;
  err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > nnn
               || class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  objid = ppp;
  objidlen = objlen;
  ppp += objlen;
  nnn -= objlen;

  /* Get the KeyUsageFlags. */
  where = __LINE__;
  err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > nnn
               || class != CLASS_UNIVERSAL || tag != TAG_BIT_STRING))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  err = parse_keyusage_flags (ppp, objlen, usageflags);
  if (err)
    goto leave;
  ppp += objlen;
  nnn -= objlen;

  ignore_eof = 1; /* Remaining items are optional.  */

  /* Find the keyReference */
  where = __LINE__;
  err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && objlen > nnn)
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  if (class == CLASS_UNIVERSAL && tag == TAG_BOOLEAN)
    {
      /* Skip the native element. */
      ppp += objlen;
      nnn -= objlen;

      err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nnn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto leave;
    }
  if (class == CLASS_UNIVERSAL && tag == TAG_BIT_STRING)
    {
      /* These are the keyAccessFlags. */
      err = parse_keyaccess_flags (ppp, objlen, accessflags);
      if (err)
        goto leave;
      ppp += objlen;
      nnn -= objlen;

      err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nnn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto leave;
    }
  if (class == CLASS_UNIVERSAL && tag == TAG_INTEGER)
    {
      /* This is the keyReference.  */
      for (ul=0; objlen; objlen--)
        {
          ul <<= 8;
          ul |= (*ppp++) & 0xff;
          nnn--;
        }
      key_reference = ul;
      key_reference_valid = 1;
    }

 leave:
  if (ignore_eof && gpg_err_code (err) == GPG_ERR_EOF)
    err = 0;

  if (!err)
    {
      if (!objid || !objidlen)
        err = gpg_error (GPG_ERR_INV_OBJ);
      else
        {
          *r_objid = xtrymalloc (objidlen);
          if (!*r_objid)
            err = gpg_error_from_syserror ();
          else
            {
              memcpy (*r_objid, objid, objidlen);
              *r_objidlen = objidlen;
            }
        }
    }
  if (!err && key_reference_valid)
    {
      *r_key_reference = key_reference;
      *r_key_reference_valid = 1;
    }

  if (err)
    log_error ("p15: error parsing commonKeyAttributes at %d: %s\n",
               where, gpg_strerror (err));
  return err;

}


/* Read and  parse the Private Key Directory Files.
 *
 * Sample object:
 *  SEQUENCE {
 *    SEQUENCE { -- commonObjectAttributes
 *      UTF8String 'SK.CH.DS'
 *      BIT STRING 6 unused bits
 *        '01'B (bit 0) -- flags: non-modifiable,private
 *      OCTET STRING --authid
 *        07
 *      }
 *    SEQUENCE { -- commonKeyAttributes
 *      OCTET STRING
 *        01
 *      BIT STRING 6 unused bits
 *        '1000000000'B (bit 9) -- keyusage: non-repudiation
 *      INTEGER 80  -- keyReference (optional)
 *      }
 *    [1] {  -- keyAttributes
 *      SEQUENCE { -- privateRSAKeyAttributes
 *        SEQUENCE { -- objectValue
 *          OCTET STRING --path
 *            3F 00 40 16 00 50
 *          }
 *        INTEGER 1024 -- modulus
 *        }
 *      }
 *    }
 *
 * Sample part for EC objects:
 *    [1] {  -- keyAttributes
 *      [1] { -- privateECkeyAttributes
 *        SEQUENCE { -- objectValue
 *          SEQUENCE { --path
 *            OCTET STRING 50 72 4B 03
 *          }
 *        INTEGER 33  -- Not in PKCS#15v1.1, need to buy 7816-15?
 *        }
 *      }
 */
static gpg_error_t
read_ef_prkdf (app_t app, unsigned short fid, prkdf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  prkdf_object_t prkdflist = NULL;
  int i;
  int recno = 1;
  unsigned char *authid = NULL;
  size_t authidlen = 0;
  unsigned char *objid = NULL;
  size_t objidlen = 0;
  char *label = NULL;
  int record_mode;

  err = read_first_record (app, fid, "PrKDF", &buffer, &buflen, &record_mode);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  /* Loop over the records.  We stop as soon as we detect a new record
     starting with 0x00 or 0xff as these values are commonly used to
     pad data blocks and are no valid ASN.1 encoding.  Note the
     special handling for record mode at the end of the loop. */
  if (record_mode && buflen == 2 && !buffer[0] && !buffer[1])
    goto next_record;  /* Deleted record - continue with next */

  while (n && *p && *p != 0xff)
    {
      const unsigned char *pp;
      size_t nn;
      int where;
      const char *errstr = NULL;
      prkdf_object_t prkdf = NULL;
      unsigned long ul;
      keyusage_flags_t usageflags;
      keyaccess_flags_t accessflags;
      unsigned long key_reference = 0;
      int key_reference_valid = 0;
      int is_ecc = 0;

      where = __LINE__;
      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        ;
      else if (objlen > n)
        err = gpg_error (GPG_ERR_INV_OBJ);
      else if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        ; /* PrivateRSAKeyAttributes  */
      else if (class == CLASS_CONTEXT)
        {
          switch (tag)
            {
            case 0: is_ecc = 1; break; /* PrivateECKeyAttributes  */
            case 1: errstr = "DH key objects are not supported"; break;
            case 2: errstr = "DSA key objects are not supported"; break;
            case 3: errstr = "KEA key objects are not supported"; break;
            default: errstr = "unknown privateKeyObject"; break;
            }
          if (errstr)
            goto parse_error;
        }
      else
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto parse_error;
        }

      if (err)
        {
          log_error ("p15: error parsing PrKDF record: %s\n",
                     gpg_strerror (err));
          goto leave;
        }

      pp = p;
      nn = objlen;
      p += objlen;
      n -= objlen;

      /* Parse the commonObjectAttributes.  */
      where = __LINE__;
      xfree (authid);
      xfree (label);
      err = parse_common_obj_attr (&pp, &nn, &authid, &authidlen, &label);
      if (err)
        goto parse_error;

      /* Parse the commonKeyAttributes.  */
      where = __LINE__;
      xfree (objid);
      err = parse_common_key_attr (&pp, &nn,
                                   &objid, &objidlen,
                                   &usageflags, &accessflags,
                                   &key_reference, &key_reference_valid);
      if (err)
        goto parse_error;
      log_assert (objid);

      /* Skip commonPrivateKeyAttributes.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      if (class == CLASS_CONTEXT && tag == 0)
        {
          pp += objlen;
          nn -= objlen;

          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
        }
      /* Parse the keyAttributes.  */
      if (!err && (objlen > nn || class != CLASS_CONTEXT || tag != 1))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      nn = objlen;

      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        ;
      else if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      else if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        ; /* A typeAttribute always starts with a sequence.  */
      else
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;

      nn = objlen;

      /* Check that the reference is a Path object.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      if (class != CLASS_UNIVERSAL || tag != TAG_SEQUENCE)
        {
          errstr = "unsupported reference type";
          goto parse_error;
        }
      nn = objlen;

      /* Parse the Path object. */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;

      /* Make sure that the next element has a path of even length
       * (FIDs are two bytes each).  We should check that the path
       * length is non-zero but some cards return a zero length path
       * nevertheless (e.g. A.E.T. Europe Java applets). */
      if (class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING
          || (objlen & 1) )
        {
          errstr = "invalid path reference";
          goto parse_error;
        }

      /* Create a new PrKDF list item. */
      prkdf = xtrycalloc (1, (sizeof *prkdf
                              - sizeof(unsigned short)
                              + objlen/2 * sizeof(unsigned short)));
      if (!prkdf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      prkdf->is_ecc = is_ecc;

      prkdf->objidlen = objidlen;
      prkdf->objid = objid;
      objid = NULL;
      if (authid)
        {
          prkdf->authidlen = authidlen;
          prkdf->authid = authid;
          authid = NULL;
        }
      if (label)
        {
          prkdf->label = label;
          label = NULL;
        }

      prkdf->pathlen = objlen/2;
      for (i=0; i < prkdf->pathlen; i++, pp += 2, nn -= 2)
        prkdf->path[i] = ((pp[0] << 8) | pp[1]);

      prkdf->usageflags = usageflags;
      prkdf->accessflags = accessflags;
      prkdf->key_reference = key_reference;
      prkdf->key_reference_valid = key_reference_valid;

      if (nn)
        {
          /* An index and length follows. */
          prkdf->have_off = 1;
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_UNIVERSAL || tag != TAG_INTEGER))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;

          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          prkdf->off = ul;

          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_CONTEXT || tag != 0))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;

          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          prkdf->len = ul;
        }

      /* The info is printed later in read_p15_info because we also
       * want to look at the certificates.  */

      /* Put it into the list. */
      prkdf->next = prkdflist;
      prkdflist = prkdf;
      prkdf = NULL;
      goto next_record; /* Ready with this record. */

    parse_error:
      log_error ("p15: error parsing PrKDF record at %d: %s - skipped\n",
                 where, errstr? errstr : gpg_strerror (err));
      if (prkdf)
        {
          xfree (prkdf->objid);
          xfree (prkdf->authid);
          xfree (prkdf->label);
          xfree (prkdf);
        }
      err = 0;

    next_record:
      /* If the card uses a record oriented file structure, read the
       * next record.  Otherwise we keep on parsing the current buffer.  */
      recno++;
      if (record_mode)
        {
          xfree (buffer); buffer = NULL;
          err = select_and_read_record (app, 0, recno, "PrKDF",
                                        &buffer, &buflen, NULL);
          if (err) {
            if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
              err = 0;
            goto leave;
          }
          if (buflen == 2 && !buffer[0] && !buffer[1])
            goto next_record;  /* Deleted record - continue with next */
          p = buffer;
          n = buflen;
        }
    } /* End looping over all records. */

 leave:
  xfree (authid);
  xfree (label);
  xfree (objid);
  xfree (buffer);
  if (err)
    release_prkdflist (prkdflist);
  else
    *result = prkdflist;
  return err;
}


/* Read and parse the Public Keys Directory File. */
static gpg_error_t
read_ef_pukdf (app_t app, unsigned short fid, pukdf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  pukdf_object_t pukdflist = NULL;
  int i;
  int recno = 1;
  unsigned char *authid = NULL;
  size_t authidlen = 0;
  unsigned char *objid = NULL;
  size_t objidlen = 0;
  char *label = NULL;
  int record_mode;

  err = read_first_record (app, fid, "PuKDF", &buffer, &buflen, &record_mode);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  /* Loop over the records.  We stop as soon as we detect a new record
   * starting with 0x00 or 0xff as these values are commonly used to
   * pad data blocks and are no valid ASN.1 encoding.  Note the
   * special handling for record mode at the end of the loop. */
  if (record_mode && buflen == 2 && !buffer[0] && !buffer[1])
    goto next_record;  /* Deleted record - continue with next */

  while (n && *p && *p != 0xff)
    {
      const unsigned char *pp;
      size_t nn;
      int where;
      const char *errstr = NULL;
      pukdf_object_t pukdf = NULL;
      unsigned long ul;
      keyusage_flags_t usageflags;
      keyaccess_flags_t accessflags;
      unsigned long key_reference = 0;
      int key_reference_valid = 0;

      where = __LINE__;
      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        ;
      else if (objlen > n)
        err = gpg_error (GPG_ERR_INV_OBJ);
      else if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        ; /* PublicRSAKeyAttributes  */
      else if (class == CLASS_CONTEXT)
        {
          switch (tag)
            {
            case 0: break; /* EC key object */
            case 1: errstr = "DH key objects are not supported"; break;
            case 2: errstr = "DSA key objects are not supported"; break;
            case 3: errstr = "KEA key objects are not supported"; break;
            default: errstr = "unknown publicKeyObject"; break;
            }
          if (errstr)
            goto parse_error;
        }
      else
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto parse_error;
        }

      if (err)
        {
          log_error ("p15: error parsing PuKDF record: %s\n",
                     gpg_strerror (err));
          goto leave;
        }

      pp = p;
      nn = objlen;
      p += objlen;
      n -= objlen;

      /* Parse the commonObjectAttributes.  */
      where = __LINE__;
      xfree (authid);
      xfree (label);
      err = parse_common_obj_attr (&pp, &nn, &authid, &authidlen, &label);
      if (err)
        goto parse_error;

      /* Parse the commonKeyAttributes.  */
      where = __LINE__;
      xfree (objid);
      err = parse_common_key_attr (&pp, &nn,
                                   &objid, &objidlen,
                                   &usageflags, &accessflags,
                                   &key_reference, &key_reference_valid);
      if (err)
        goto parse_error;
      log_assert (objid);

      /* Parse the subClassAttributes.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      if (class == CLASS_CONTEXT && tag == 0)
        {
          /* Skip this CommonPublicKeyAttribute.  */
          pp += objlen;
          nn -= objlen;

          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
        }
      /* We expect a typeAttribute.  */
      if (!err && (objlen > nn || class != CLASS_CONTEXT || tag != 1))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;  /* No typeAttribute.  */
      nn = objlen;

      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        ;
      else if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      else if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        ; /* A typeAttribute always starts with a sequence.  */
      else
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;

      nn = objlen;

      /* Check that the reference is a Path object.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      if (class != CLASS_UNIVERSAL || tag != TAG_SEQUENCE)
        {
          errstr = "unsupported reference type";
          goto parse_error;
        }
      nn = objlen;

      /* Parse the Path object. */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;

      /* Make sure that the next element has a path of even length
       * (FIDs are two bytes each).  */
      if (class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING
          ||  (objlen & 1) )
        {
          errstr = "invalid path reference";
          goto parse_error;
        }

      /* Create a new PuKDF list item. */
      pukdf = xtrycalloc (1, (sizeof *pukdf
                              - sizeof(unsigned short)
                              + objlen/2 * sizeof(unsigned short)));
      if (!pukdf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      pukdf->objidlen = objidlen;
      pukdf->objid = objid;
      objid = NULL;
      if (authid)
        {
          pukdf->authidlen = authidlen;
          pukdf->authid = authid;
          authid = NULL;
        }
      if (label)
        {
          pukdf->label = label;
          label = NULL;
        }

      pukdf->pathlen = objlen/2;
      for (i=0; i < pukdf->pathlen; i++, pp += 2, nn -= 2)
        pukdf->path[i] = ((pp[0] << 8) | pp[1]);

      pukdf->usageflags = usageflags;
      pukdf->accessflags = accessflags;
      pukdf->key_reference = key_reference;
      pukdf->key_reference_valid = key_reference_valid;

      if (nn)
        {
          /* An index and length follows. */
          pukdf->have_off = 1;
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_UNIVERSAL || tag != TAG_INTEGER))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;

          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          pukdf->off = ul;

          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_CONTEXT || tag != 0))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;

          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          pukdf->len = ul;
        }


      if (opt.verbose)
        {
          log_info ("p15: PuKDF %04hX: id=", fid);
          for (i=0; i < pukdf->objidlen; i++)
            log_printf ("%02X", pukdf->objid[i]);
          if (pukdf->label)
            log_printf (" (%s)", pukdf->label);
          log_info ("p15:             path=");
          for (i=0; i < pukdf->pathlen; i++)
            log_printf ("%s%04hX", i?"/":"",pukdf->path[i]);
          if (pukdf->have_off)
            log_printf ("[%lu/%lu]", pukdf->off, pukdf->len);
          if (pukdf->authid)
            {
              log_printf (" authid=");
              for (i=0; i < pukdf->authidlen; i++)
                log_printf ("%02X", pukdf->authid[i]);
            }
          if (pukdf->key_reference_valid)
            log_printf (" keyref=0x%02lX", pukdf->key_reference);
          if (pukdf->accessflags.any)
            dump_keyaccess_flags (pukdf->accessflags);
          dump_keyusage_flags (pukdf->usageflags);
          log_printf ("\n");
        }

      /* Put it into the list. */
      pukdf->next = pukdflist;
      pukdflist = pukdf;
      pukdf = NULL;
      goto next_record; /* Ready with this record. */

    parse_error:
      log_error ("p15: error parsing PuKDF record at %d: %s - skipped\n",
                 where, errstr? errstr : gpg_strerror (err));
      if (pukdf)
        {
          xfree (pukdf->objid);
          xfree (pukdf->authid);
          xfree (pukdf->label);
          xfree (pukdf);
        }
      err = 0;

    next_record:
      /* If the card uses a record oriented file structure, read the
       * next record.  Otherwise we keep on parsing the current buffer.  */
      recno++;
      if (record_mode)
        {
          xfree (buffer); buffer = NULL;
          err = select_and_read_record (app, 0, recno, "PuKDF",
                                        &buffer, &buflen, NULL);
          if (err) {
            if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
              err = 0;
            goto leave;
          }
          if (buflen == 2 && !buffer[0] && !buffer[1])
            goto next_record;  /* Deleted record - continue with next */
          p = buffer;
          n = buflen;
        }
    } /* End looping over all records. */

 leave:
  xfree (authid);
  xfree (label);
  xfree (objid);
  xfree (buffer);
  if (err)
    release_pukdflist (pukdflist);
  else
    *result = pukdflist;
  return err;
}


/* Read and parse the Certificate Directory Files identified by FID.
   On success a newlist of CDF object gets stored at RESULT and the
   caller is then responsible of releasing this list.  On error a
   error code is returned and RESULT won't get changed.  */
static gpg_error_t
read_ef_cdf (app_t app, unsigned short fid, int cdftype, cdf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  cdf_object_t cdflist = NULL;
  int i;
  int recno = 1;
  unsigned char *authid = NULL;
  size_t authidlen = 0;
  char *label = NULL;
  int record_mode;

  err = read_first_record (app, fid, "CDF", &buffer, &buflen, &record_mode);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  /* Loop over the records.  We stop as soon as we detect a new record
     starting with 0x00 or 0xff as these values are commonly used to
     pad data blocks and are no valid ASN.1 encoding.  Note the
     special handling for record mode at the end of the loop. */
  if (record_mode && buflen == 2 && !buffer[0] && !buffer[1])
    goto next_record;  /* Deleted record - continue with next */

  while (n && *p && *p != 0xff)
    {
      const unsigned char *pp;
      size_t nn;
      int where;
      const char *errstr = NULL;
      cdf_object_t cdf = NULL;
      unsigned long ul;
      const unsigned char *objid;
      size_t objidlen;

      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > n || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        {
          log_error ("p15: error parsing CDF record: %s\n", gpg_strerror (err));
          goto leave;
        }
      pp = p;
      nn = objlen;
      p += objlen;
      n -= objlen;

      /* Parse the commonObjectAttributes.  */
      where = __LINE__;
      xfree (authid);
      xfree (label);
      err = parse_common_obj_attr (&pp, &nn, &authid, &authidlen, &label);
      if (err)
        goto parse_error;

      /* Parse the commonCertificateAttributes.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      {
        const unsigned char *ppp = pp;
        size_t nnn = objlen;

        pp += objlen;
        nn -= objlen;

        /* Get the Id. */
        where = __LINE__;
        err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
        if (!err && (objlen > nnn
                     || class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING))
          err = gpg_error (GPG_ERR_INV_OBJ);
        if (err)
          goto parse_error;
        objid = ppp;
        objidlen = objlen;
      }

      /* Parse the certAttribute.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn || class != CLASS_CONTEXT || tag != 1))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      nn = objlen;

      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn
                   || class != CLASS_UNIVERSAL || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      nn = objlen;

      /* Check that the reference is a Path object.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      if (class != CLASS_UNIVERSAL || tag != TAG_SEQUENCE)
        {
          errstr = "unsupported reference type";
          goto parse_error;
        }
      nn = objlen;

      /* Parse the Path object. */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;

      /* Make sure that the next element has a path of even length
       * (FIDs are two bytes each).  */
      if (class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING
          || (objlen & 1) )
        {
          errstr = "invalid path reference";
          goto parse_error;
        }
      /* Create a new CDF list item. */
      cdf = xtrycalloc (1, (sizeof *cdf
                            - sizeof(unsigned short)
                            + objlen/2 * sizeof(unsigned short)));
      if (!cdf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (authid)
        {
          cdf->authidlen = authidlen;
          cdf->authid = authid;
          authid = NULL;
        }
      if (label)
        {
          cdf->label = label;
          label = NULL;
        }

      cdf->objidlen = objidlen;
      cdf->objid = xtrymalloc (objidlen);
      if (!cdf->objid)
        {
          err = gpg_error_from_syserror ();
          xfree (cdf);
          goto leave;
        }
      memcpy (cdf->objid, objid, objidlen);

      cdf->pathlen = objlen/2;
      for (i=0; i < cdf->pathlen; i++, pp += 2, nn -= 2)
        cdf->path[i] = ((pp[0] << 8) | pp[1]);

      if (nn)
        {
          /* An index and length follows. */
          cdf->have_off = 1;
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_UNIVERSAL || tag != TAG_INTEGER))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;

          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          cdf->off = ul;

          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_CONTEXT || tag != 0))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;

          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          cdf->len = ul;
        }

      if (opt.verbose)
        {
          log_info ("p15: CDF-%c %04hX: id=", cdftype, fid);
          for (i=0; i < cdf->objidlen; i++)
            log_printf ("%02X", cdf->objid[i]);
          if (cdf->label)
            log_printf (" (%s)", cdf->label);
          log_info ("p15:             path=");
          for (i=0; i < cdf->pathlen; i++)
            log_printf ("%s%04hX", i?"/":"", cdf->path[i]);
          if (cdf->have_off)
            log_printf ("[%lu/%lu]", cdf->off, cdf->len);
          if (cdf->authid)
            {
              log_printf (" authid=");
              for (i=0; i < cdf->authidlen; i++)
                log_printf ("%02X", cdf->authid[i]);
            }
          log_printf ("\n");
        }

      /* Put it into the list. */
      cdf->next = cdflist;
      cdflist = cdf;
      cdf = NULL;
      goto next_record; /* Ready with this record. */

    parse_error:
      log_error ("p15: error parsing CDF record at %d: %s - skipped\n",
                 where, errstr? errstr : gpg_strerror (err));
      xfree (cdf);
      err = 0;

    next_record:
      xfree (authid); authid = NULL;
      xfree (label); label = NULL;
      /* If the card uses a record oriented file structure, read the
       * next record.  Otherwise we keep on parsing the current buffer.  */
      recno++;
      if (record_mode)
        {
          xfree (buffer); buffer = NULL;
          err = select_and_read_record (app, 0, recno, "CDF",
                                        &buffer, &buflen, NULL);
          if (err)
            {
              if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
                err = 0;
              goto leave;
            }
          if (buflen == 2 && !buffer[0] && !buffer[1])
            goto next_record;  /* Deleted record - continue with next */
          p = buffer;
          n = buflen;
        }
    } /* End loop over all records. */

 leave:
  xfree (authid);
  xfree (label);
  xfree (buffer);
  if (err)
    release_cdflist (cdflist);
  else
    *result = cdflist;
  return err;
}


/*
 * SEQUENCE {
 *   SEQUENCE { -- CommonObjectAttributes
 *     UTF8String 'specific PIN for DS'
 *     BIT STRING 0 unused bits
 *       '00000011'B
 *     }
 *   SEQUENCE { -- CommonAuthenticationObjectAttributes
 *     OCTET STRING
 *       07    -- iD
 *     }
 *
 *   [1] { -- typeAttributes
 *     SEQUENCE { -- PinAttributes
 *       BIT STRING 0 unused bits
 *         '0000100000110010'B  -- local,initialized,needs-padding
 *                              -- exchangeRefData
 *       ENUMERATED 1           -- ascii-numeric
 *       INTEGER 6              -- minLength
 *       INTEGER 6              -- storedLength
 *       INTEGER 8              -- maxLength
 *       [0]
 *         02                   -- pinReference
 *       GeneralizedTime 19/04/2002 12:12 GMT  -- lastPinChange
 *       SEQUENCE {
 *         OCTET STRING
 *           3F 00 40 16        -- path to DF of PIN
 *         }
 *       }
 *     }
 *   }
 *
 * Or for an authKey:
 *
 *   [1] { -- typeAttributes
 *     SEQUENCE { -- AuthKeyAttributes
 *       BOOLEAN TRUE    -- derivedKey
 *       OCTET STRING 02 -- authKeyId
 *       }
 *     }
 *   }
*/
/* Read and parse an Authentication Object Directory File identified
   by FID.  On success a newlist of AODF objects gets stored at RESULT
   and the caller is responsible of releasing this list.  On error a
   error code is returned and RESULT won't get changed.  */
static gpg_error_t
read_ef_aodf (app_t app, unsigned short fid, aodf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  aodf_object_t aodflist = NULL;
  int i;
  int recno = 1;
  int record_mode;

  err = read_first_record (app, fid, "AODF", &buffer, &buflen, &record_mode);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  /* Loop over the records.  We stop as soon as we detect a new record
     starting with 0x00 or 0xff as these values are commonly used to
     pad data blocks and are no valid ASN.1 encoding.  Note the
     special handling for record mode at the end of the loop.  */
  if (record_mode && buflen == 2 && !buffer[0] && !buffer[1])
    goto next_record;  /* Deleted record - continue with next */

  while (n && *p && *p != 0xff)
    {
      const unsigned char *pp;
      size_t nn;
      int where;
      const char *errstr = NULL;
      auth_type_t auth_type;
      aodf_object_t aodf = NULL;
      unsigned long ul;
      const char *s;

      where = __LINE__;
      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        ;
      else if (objlen > n)
        err = gpg_error (GPG_ERR_INV_OBJ);
      else if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        auth_type = AUTH_TYPE_PIN;    /* PinAttributes */
      else if (class == CLASS_CONTEXT && tag == 1 )
        auth_type = AUTH_TYPE_AUTHKEY; /* AuthKeyAttributes */
      else if (class == CLASS_CONTEXT)
        {
          switch (tag)
            {
            case 0: errstr = "biometric auth types are not supported"; break;
            case 2: errstr = "external auth type are not supported"; break;
            default: errstr = "unknown privateKeyObject"; break;
            }
          p += objlen;
          n -= objlen;
          goto parse_error;
        }
      else
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto parse_error;
        }

      if (err)
        {
          log_error ("p15: error parsing AODF record: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
      pp = p;
      nn = objlen;
      p += objlen;
      n -= objlen;

      /* Allocate memory for a new AODF list item. */
      aodf = xtrycalloc (1, sizeof *aodf);
      if (!aodf)
        goto no_core;
      aodf->fid = fid;
      aodf->auth_type = auth_type;

      /* Parse the commonObjectAttributes.  */
      where = __LINE__;
      err = parse_common_obj_attr (&pp, &nn, &aodf->authid, &aodf->authidlen,
                                   &aodf->label);
      if (err)
        goto parse_error;

      /* Parse the CommonAuthenticationObjectAttributes.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      {
        const unsigned char *ppp = pp;
        size_t nnn = objlen;

        pp += objlen;
        nn -= objlen;

        /* Get the Id. */
        where = __LINE__;
        err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                &ndef, &objlen, &hdrlen);
        if (!err && (objlen > nnn
                     || class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING))
          err = gpg_error (GPG_ERR_INV_OBJ);
        if (err)
          goto parse_error;

        aodf->objidlen = objlen;
        aodf->objid = xtrymalloc (objlen);
        if (!aodf->objid)
          goto no_core;
        memcpy (aodf->objid, ppp, objlen);
      }

      /* Parse the typeAttributes.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn || class != CLASS_CONTEXT || tag != 1))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      nn = objlen;

      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        ;
      else if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      else if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        ; /* Okay */
      else
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;

      nn = objlen;

      if (auth_type == AUTH_TYPE_PIN)
        {
          /* PinFlags */
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn || !objlen
                       || class != CLASS_UNIVERSAL || tag != TAG_BIT_STRING))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;

          {
            unsigned int bits, mask;
            int unused, full;

            unused = *pp++; nn--; objlen--;
            if ((!objlen && unused) || unused/8 > objlen)
              {
                err = gpg_error (GPG_ERR_ENCODING_PROBLEM);
                goto parse_error;
              }
            full = objlen - (unused+7)/8;
            unused %= 8;
            mask = 0;
            for (i=1; unused; i <<= 1, unused--)
              mask |= i;

            /* The first octet */
            bits = 0;
            if (objlen)
              {
                bits = *pp++; nn--; objlen--;
                if (full)
                  full--;
                else
                  {
                    bits &= ~mask;
                    mask = 0;
                  }
              }
            if ((bits & 0x80)) /* ASN.1 bit 0. */
              aodf->pinflags.case_sensitive = 1;
            if ((bits & 0x40)) /* ASN.1 bit 1. */
              aodf->pinflags.local = 1;
            if ((bits & 0x20))
              aodf->pinflags.change_disabled = 1;
            if ((bits & 0x10))
              aodf->pinflags.unblock_disabled = 1;
            if ((bits & 0x08))
              aodf->pinflags.initialized = 1;
            if ((bits & 0x04))
              aodf->pinflags.needs_padding = 1;
            if ((bits & 0x02))
              aodf->pinflags.unblocking_pin = 1;
            if ((bits & 0x01))
              aodf->pinflags.so_pin = 1;
            /* The second octet. */
            bits = 0;
            if (objlen)
              {
                bits = *pp++; nn--; objlen--;
                if (full)
                  full--;
                else
                  {
                    bits &= ~mask;
                  }
              }
            if ((bits & 0x80))
              aodf->pinflags.disable_allowed = 1;
            if ((bits & 0x40))
              aodf->pinflags.integrity_protected = 1;
            if ((bits & 0x20))
              aodf->pinflags.confidentiality_protected = 1;
            if ((bits & 0x10))
              aodf->pinflags.exchange_ref_data = 1;
            /* Skip remaining bits. */
            pp += objlen;
            nn -= objlen;
          }

          /* PinType */
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_UNIVERSAL || tag != TAG_ENUMERATED))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (!err && objlen > sizeof (ul))
            err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
          if (err)
            goto parse_error;

          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          aodf->pintype = ul;

          /* minLength */
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_UNIVERSAL || tag != TAG_INTEGER))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (!err && objlen > sizeof (ul))
            err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
          if (err)
            goto parse_error;
          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          aodf->min_length = ul;

          /* storedLength */
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (!err && (objlen > nn
                       || class != CLASS_UNIVERSAL || tag != TAG_INTEGER))
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (!err && objlen > sizeof (ul))
            err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
          if (err)
            goto parse_error;
          for (ul=0; objlen; objlen--)
            {
              ul <<= 8;
              ul |= (*pp++) & 0xff;
              nn--;
            }
          aodf->stored_length = ul;

          /* optional maxLength */
          where = __LINE__;
          err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                  &ndef, &objlen, &hdrlen);
          if (gpg_err_code (err) == GPG_ERR_EOF)
            goto ready;
          if (!err && objlen > nn)
            err = gpg_error (GPG_ERR_INV_OBJ);
          if (err)
            goto parse_error;
          if (class == CLASS_UNIVERSAL && tag == TAG_INTEGER)
            {
              if (objlen > sizeof (ul))
                {
                  err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
                  goto parse_error;
                }
              for (ul=0; objlen; objlen--)
                {
                  ul <<= 8;
                  ul |= (*pp++) & 0xff;
                  nn--;
                }
              aodf->max_length = ul;
              aodf->max_length_valid = 1;

              where = __LINE__;
              err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                      &ndef, &objlen, &hdrlen);
              if (gpg_err_code (err) == GPG_ERR_EOF)
                goto ready;
              if (!err && objlen > nn)
                err = gpg_error (GPG_ERR_INV_OBJ);
              if (err)
                goto parse_error;
            }

          /* Optional pinReference. */
          if (class == CLASS_CONTEXT && tag == 0)
            {
              if (objlen > sizeof (ul))
                {
                  err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
                  goto parse_error;
                }
              for (ul=0; objlen; objlen--)
                {
                  ul <<= 8;
                  ul |= (*pp++) & 0xff;
                  nn--;
                }
              aodf->pin_reference = ul;
              aodf->pin_reference_valid = 1;

              where = __LINE__;
              err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                      &ndef, &objlen, &hdrlen);
              if (gpg_err_code (err) == GPG_ERR_EOF)
                goto ready;
              if (!err && objlen > nn)
                err = gpg_error (GPG_ERR_INV_OBJ);
              if (err)
                goto parse_error;
            }

          /* Optional padChar. */
          if (class == CLASS_UNIVERSAL && tag == TAG_OCTET_STRING)
            {
              if (objlen != 1)
                {
                  errstr = "padChar is not of size(1)";
                  goto parse_error;
                }
              aodf->pad_char = *pp++; nn--;
              aodf->pad_char_valid = 1;

              where = __LINE__;
              err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                      &ndef, &objlen, &hdrlen);
              if (gpg_err_code (err) == GPG_ERR_EOF)
                goto ready;
              if (!err && objlen > nn)
                err = gpg_error (GPG_ERR_INV_OBJ);
              if (err)
                goto parse_error;
            }

          /* Skip optional lastPinChange. */
          if (class == CLASS_UNIVERSAL && tag == TAG_GENERALIZED_TIME)
            {
              pp += objlen;
              nn -= objlen;

              where = __LINE__;
              err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                                      &ndef, &objlen, &hdrlen);
              if (gpg_err_code (err) == GPG_ERR_EOF)
                goto ready;
              if (!err && objlen > nn)
                err = gpg_error (GPG_ERR_INV_OBJ);
              if (err)
                goto parse_error;
            }

          /* Optional Path object.  */
          if (class == CLASS_UNIVERSAL || tag == TAG_SEQUENCE)
            {
              const unsigned char *ppp = pp;
              size_t nnn = objlen;

              pp += objlen;
              nn -= objlen;

              where = __LINE__;
              err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                      &ndef, &objlen, &hdrlen);
              if (!err && objlen > nnn)
                err = gpg_error (GPG_ERR_INV_OBJ);
              if (err)
                goto parse_error;

              /* Make sure that the next element has a path of even
               * length (FIDs are two bytes each).  */
              if (class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING
                  || (objlen & 1) )
                {
                  errstr = "invalid path reference";
                  goto parse_error;
                }

              aodf->pathlen = objlen/2;
              aodf->path = xtrycalloc (aodf->pathlen, sizeof *aodf->path);
              if (!aodf->path)
                goto no_core;
              for (i=0; i < aodf->pathlen; i++, ppp += 2, nnn -= 2)
                aodf->path[i] = ((ppp[0] << 8) | ppp[1]);

              if (nnn)
                {
                  /* An index and length follows. */
                  aodf->have_off = 1;
                  where = __LINE__;
                  err = parse_ber_header (&ppp, &nnn, &class, &tag,
                                          &constructed,
                                          &ndef, &objlen, &hdrlen);
                  if (!err && (objlen > nnn
                               || class != CLASS_UNIVERSAL
                               || tag != TAG_INTEGER))
                    err = gpg_error (GPG_ERR_INV_OBJ);
                  if (err)
                    goto parse_error;

                  for (ul=0; objlen; objlen--)
                    {
                      ul <<= 8;
                      ul |= (*ppp++) & 0xff;
                      nnn--;
                    }
                  aodf->off = ul;

                  where = __LINE__;
                  err = parse_ber_header (&ppp, &nnn, &class, &tag,
                                          &constructed,
                                          &ndef, &objlen, &hdrlen);
                  if (!err && (objlen > nnn
                               || class != CLASS_CONTEXT || tag != 0))
                    err = gpg_error (GPG_ERR_INV_OBJ);
                  if (err)
                    goto parse_error;

                  for (ul=0; objlen; objlen--)
                    {
                      ul <<= 8;
                      ul |= (*ppp++) & 0xff;
                      nnn--;
                    }
                  aodf->len = ul;
                }
            }
        }
      else if (auth_type == AUTH_TYPE_AUTHKEY)
        {

        }

      /* Ignore further objects which might be there due to future
         extensions of pkcs#15. */

    ready:
      if (gpg_err_code (err) == GPG_ERR_EOF)
        err = 0;
      if (opt.verbose)
        {
          log_info ("p15: AODF %04hX:  id=", fid);
          for (i=0; i < aodf->objidlen; i++)
            log_printf ("%02X", aodf->objid[i]);
          if (aodf->label)
            log_printf (" (%s)", aodf->label);
          log_info ("p15:            ");
          log_printf (" %s",
                      aodf->auth_type == AUTH_TYPE_PIN? "pin" :
                      aodf->auth_type == AUTH_TYPE_AUTHKEY? "authkey" : "?");
          if (aodf->pathlen)
            {
              log_printf (" path=");
              for (i=0; i < aodf->pathlen; i++)
                log_printf ("%s%04hX", i?"/":"",aodf->path[i]);
              if (aodf->have_off)
                log_printf ("[%lu/%lu]", aodf->off, aodf->len);
            }
          if (aodf->authid)
            {
              log_printf (" authid=");
              for (i=0; i < aodf->authidlen; i++)
                log_printf ("%02X", aodf->authid[i]);
            }
          if (aodf->auth_type == AUTH_TYPE_PIN)
            {
              if (aodf->pin_reference_valid)
                log_printf (" pinref=0x%02lX", aodf->pin_reference);
              log_printf (" min=%lu", aodf->min_length);
              log_printf (" stored=%lu", aodf->stored_length);
              if (aodf->max_length_valid)
                log_printf (" max=%lu", aodf->max_length);
              if (aodf->pad_char_valid)
                log_printf (" pad=0x%02x", aodf->pad_char);

              log_info ("p15:             flags=");
              s = "";
              if (aodf->pinflags.case_sensitive)
                log_printf ("%scase_sensitive", s), s = ",";
              if (aodf->pinflags.local)
                log_printf ("%slocal", s), s = ",";
              if (aodf->pinflags.change_disabled)
                log_printf ("%schange_disabled", s), s = ",";
              if (aodf->pinflags.unblock_disabled)
                log_printf ("%sunblock_disabled", s), s = ",";
              if (aodf->pinflags.initialized)
                log_printf ("%sinitialized", s), s = ",";
              if (aodf->pinflags.needs_padding)
                log_printf ("%sneeds_padding", s), s = ",";
              if (aodf->pinflags.unblocking_pin)
                log_printf ("%sunblocking_pin", s), s = ",";
              if (aodf->pinflags.so_pin)
                log_printf ("%sso_pin", s), s = ",";
              if (aodf->pinflags.disable_allowed)
                log_printf ("%sdisable_allowed", s), s = ",";
              if (aodf->pinflags.integrity_protected)
                log_printf ("%sintegrity_protected", s), s = ",";
              if (aodf->pinflags.confidentiality_protected)
                log_printf ("%sconfidentiality_protected", s), s = ",";
              if (aodf->pinflags.exchange_ref_data)
                log_printf ("%sexchange_ref_data", s), s = ",";
              {
                char numbuf[50];
                const char *s2;

                switch (aodf->pintype)
                  {
                  case PIN_TYPE_BCD: s2 = "bcd"; break;
                  case PIN_TYPE_ASCII_NUMERIC: s2 = "ascii-numeric"; break;
                  case PIN_TYPE_UTF8: s2 = "utf8"; break;
                  case PIN_TYPE_HALF_NIBBLE_BCD: s2 = "half-nibble-bcd"; break;
                  case PIN_TYPE_ISO9564_1: s2 = "iso9564-1"; break;
                  default:
                    sprintf (numbuf, "%lu", (unsigned long)aodf->pintype);
                    s2 = numbuf;
                  }
                log_printf ("%stype=%s", s, s2); s = ",";
              }
            }
          else if (aodf->auth_type == AUTH_TYPE_AUTHKEY)
            {
            }
          log_printf ("\n");
        }

      /* Put it into the list. */
      aodf->next = aodflist;
      aodflist = aodf;
      aodf = NULL;
      goto next_record; /* Ready with this record. */

    no_core:
      err = gpg_error_from_syserror ();
      release_aodf_object (aodf);
      goto leave;

    parse_error:
      log_error ("p15: error parsing AODF record at %d: %s - skipped\n",
                 where, errstr? errstr : gpg_strerror (err));
      err = 0;
      release_aodf_object (aodf);

    next_record:
      /* If the card uses a record oriented file structure, read the
       * next record.  Otherwise we keep on parsing the current buffer.  */
      recno++;
      if (record_mode)
        {
          xfree (buffer); buffer = NULL;
          err = select_and_read_record (app, 0, recno, "AODF",
                                        &buffer, &buflen, NULL);
          if (err) {
            if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
              err = 0;
            goto leave;
          }
          if (buflen == 2 && !buffer[0] && !buffer[1])
            goto next_record;  /* Deleted record - continue with next */
          p = buffer;
          n = buflen;
        }
    } /* End looping over all records. */

 leave:
  xfree (buffer);
  if (err)
    release_aodflist (aodflist);
  else
    *result = aodflist;
  return err;
}


/* Print the BIT STRING with the tokenflags from the TokenInfo.  */
static void
print_tokeninfo_tokenflags (const unsigned char *der, size_t derlen)
{
  unsigned int bits, mask;
  int i, unused, full;
  int other = 0;

  if (!derlen)
    {
      log_printf (" [invalid object]");
      return;
    }

  unused = *der++; derlen--;
  if ((!derlen && unused) || unused/8 > derlen)
    {
      log_printf (" [wrong encoding]");
      return;
    }
  full = derlen - (unused+7)/8;
  unused %= 8;
  mask = 0;
  for (i=1; unused; i <<= 1, unused--)
    mask |= i;

  /* First octet */
  if (derlen)
    {
      bits = *der++; derlen--;
      if (full)
        full--;
      else
        {
          bits &= ~mask;
          mask = 0;
        }
    }
  else
    bits = 0;
  if ((bits & 0x80)) log_printf (" readonly");
  if ((bits & 0x40)) log_printf (" loginRequired");
  if ((bits & 0x20)) log_printf (" prnGeneration");
  if ((bits & 0x10)) log_printf (" eidCompliant");
  if ((bits & 0x08)) other = 1;
  if ((bits & 0x04)) other = 1;
  if ((bits & 0x02)) other = 1;
  if ((bits & 0x01)) other = 1;

  /* Next octet.  */
  if (derlen)
    other = 1;

  if (other)
    log_printf (" [unknown]");
}



/* Read and parse the EF(TokenInfo).
 *
 * TokenInfo ::= SEQUENCE {
 *     version		INTEGER {v1(0)} (v1,...),
 *     serialNumber	OCTET STRING,
 *     manufacturerID 	Label OPTIONAL,
 *     label 		[0] Label OPTIONAL,
 *     tokenflags 		TokenFlags,
 *     seInfo 		SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,
 *     recordInfo 		[1] RecordInfo OPTIONAL,
 *     supportedAlgorithms	[2] SEQUENCE OF AlgorithmInfo OPTIONAL,
 *     ...,
 *     issuerId		[3] Label OPTIONAL,
 *     holderId		[4] Label OPTIONAL,
 *     lastUpdate		[5] LastUpdate OPTIONAL,
 *     preferredLanguage	PrintableString OPTIONAL -- In accordance with
 *     -- IETF RFC 1766
 * } (CONSTRAINED BY { -- Each AlgorithmInfo.reference value must be unique --})
 *
 * TokenFlags ::= BIT STRING {
 *     readOnly		(0),
 *     loginRequired 	(1),
 *     prnGeneration 	(2),
 *     eidCompliant  	(3)
 * }
 *
 *
 * Sample EF 5032:
 * 30 31 02 01 00 04 04 05 45  36 9F 0C 0C 44 2D 54   01......E6...D-T
 * 72 75 73 74 20 47 6D 62 48  80 14 4F 66 66 69 63   rust GmbH..Offic
 * 65 20 69 64 65 6E 74 69 74  79 20 63 61 72 64 03   e identity card.
 * 02 00 40 20 63 61 72 64 03  02 00 40 00 00 00 00   ..@ card...@....
 * 00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................
 *
 *    0   49: SEQUENCE {
 *    2    1:   INTEGER 0
 *    5    4:   OCTET STRING 05 45 36 9F
 *   11   12:   UTF8String 'D-Trust GmbH'
 *   25   20:   [0] 'Office identity card'
 *   47    2:   BIT STRING
 *          :     '00000010'B (bit 1)
 *          :     Error: Spurious zero bits in bitstring.
 *          :   }
 */
static gpg_error_t
read_ef_tokeninfo (app_t app)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  unsigned long ul;

  release_tokeninfo (app);
  app->app_local->card_product = CARD_PRODUCT_UNKNOWN;

  err = select_and_read_binary (app, 0x5032, "TokenInfo", &buffer, &buflen);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > n || tag != TAG_SEQUENCE))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    {
      log_error ("p15: error parsing TokenInfo: %s\n", gpg_strerror (err));
      goto leave;
    }

  n = objlen;

  /* Version.  */
  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > n || tag != TAG_INTEGER))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  for (ul=0; objlen; objlen--)
    {
      ul <<= 8;
      ul |= (*p++) & 0xff;
      n--;
    }
  if (ul)
    {
      log_error ("p15: invalid version %lu in TokenInfo\n", ul);
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }

  /* serialNumber.  */
  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > n || tag != TAG_OCTET_STRING || !objlen))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;

  xfree (app->app_local->serialno);
  app->app_local->serialno = xtrymalloc (objlen);
  if (!app->app_local->serialno)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  memcpy (app->app_local->serialno, p, objlen);
  app->app_local->serialnolen = objlen;
  p += objlen;
  n -= objlen;

  /* Is there an optional manufacturerID?  */
  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > n || !objlen))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto leave;
  if (class == CLASS_UNIVERSAL && tag == TAG_UTF8_STRING)
    {
      app->app_local->manufacturer_id = percent_data_escape (0, NULL,
                                                             p, objlen);
      p += objlen;
      n -= objlen;
      /* Get next TLV.  */
      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > n || !objlen))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto leave;
    }
  if (class == CLASS_CONTEXT && tag == 0)
    {
      app->app_local->token_label = percent_data_escape (0, NULL, p, objlen);

      p += objlen;
      n -= objlen;
      /* Get next TLV.  */
      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > n || !objlen))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto leave;
    }
  /* The next is the mandatory tokenflags object.  */
  if (class == CLASS_UNIVERSAL && tag == TAG_BIT_STRING)
    {
      app->app_local->tokenflagslen = objlen;
      app->app_local->tokenflags = xtrymalloc (objlen);
      if (!app->app_local->tokenflags)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (app->app_local->tokenflags, p, objlen);
      p += objlen;
      n -= objlen;
    }


 leave:
  xfree (buffer);
  return err;
}


/* Get all the basic information from the pkcs#15 card, check the
   structure and initialize our local context.  This is used once at
   application initialization. */
static gpg_error_t
read_p15_info (app_t app)
{
  gpg_error_t err;
  prkdf_object_t prkdf;
  unsigned int flag;

  err = read_ef_tokeninfo (app);
  if (err)
    return err;
  /* If we don't have a serial number yet but the TokenInfo provides
   * one, use that. */
  if (!APP_CARD(app)->serialno && app->app_local->serialno)
    {
      APP_CARD(app)->serialno = app->app_local->serialno;
      APP_CARD(app)->serialnolen = app->app_local->serialnolen;
      app->app_local->serialno = NULL;
      app->app_local->serialnolen = 0;
      err = app_munge_serialno (APP_CARD(app));
      if (err)
        return err;
    }

  release_lists (app);

  if (IS_CARDOS_5 (app)
      && app->app_local->manufacturer_id
      && !ascii_strcasecmp (app->app_local->manufacturer_id, "GeNUA mbH"))
    {
      if (!app->app_local->card_product)
        app->app_local->card_product = CARD_PRODUCT_GENUA;
    }

  /* Read the ODF so that we know the location of all directory
     files. */
  /* Fixme: We might need to get a non-standard ODF FID from TokenInfo. */
  err = read_ef_odf (app, 0x5031);
  if (err)
    return err;

  /* Read certificate information. */
  log_assert (!app->app_local->certificate_info);
  log_assert (!app->app_local->trusted_certificate_info);
  log_assert (!app->app_local->useful_certificate_info);
  err = read_ef_cdf (app, app->app_local->odf.certificates, 'c',
                     &app->app_local->certificate_info);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = read_ef_cdf (app, app->app_local->odf.trusted_certificates, 't',
                       &app->app_local->trusted_certificate_info);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = read_ef_cdf (app, app->app_local->odf.useful_certificates, 'u',
                       &app->app_local->useful_certificate_info);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0;
  if (err)
    return err;

  /* Read information about public keys. */
  log_assert (!app->app_local->public_key_info);
  err = read_ef_pukdf (app, app->app_local->odf.public_keys,
                       &app->app_local->public_key_info);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = read_ef_pukdf (app, app->app_local->odf.trusted_public_keys,
                         &app->app_local->public_key_info);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0;
  if (err)
    return err;

  /* Read information about private keys. */
  log_assert (!app->app_local->private_key_info);
  err = read_ef_prkdf (app, app->app_local->odf.private_keys,
                       &app->app_local->private_key_info);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0;
  if (err)
    return err;

  /* Read information about authentication objects. */
  log_assert (!app->app_local->auth_object_info);
  err = read_ef_aodf (app, app->app_local->odf.auth_objects,
                      &app->app_local->auth_object_info);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0;


  /* See whether we can extend the private key information using
   * information from certificates.  We use only the first matching
   * certificate; if we want to change this strategy we should walk
   * over the certificates and then find the corresponsing private key
   * objects.  */
  app->app_local->any_gpgusage = 0;
  for (prkdf = app->app_local->private_key_info; prkdf; prkdf = prkdf->next)
    {
      cdf_object_t cdf;
      char *extusage;
      char *p, *pend;
      int seen, i;

      if (opt.debug)
        log_printhex (prkdf->objid, prkdf->objidlen, "p15: prkdf id=");
      if (cdf_object_from_objid (app, prkdf->objidlen, prkdf->objid, &cdf)
          && cdf_object_from_label (app, prkdf->label, &cdf))
        continue; /* No matching certificate.  */
      if (!cdf->cert)  /* Read and parse the certificate.  */
        readcert_by_cdf (app, cdf, NULL, NULL);
      if (!cdf->cert)
        continue; /* Unsupported or broken certificate.  */

      if (prkdf->is_ecc)
        {
          const char *oid;
          const unsigned char *der;
          size_t off, derlen, objlen, hdrlen;
          int class, tag, constructed, ndef;

          for (i=0; !(err = ksba_cert_get_extension
                      (cdf->cert, i, &oid, NULL, &off, &derlen)); i++)
            if (!strcmp (oid, "1.3.6.1.4.1.11591.2.2.10") )
              break;
          if (!err && (der = ksba_cert_get_image (cdf->cert, NULL)))
            {
              der += off;
              err = parse_ber_header (&der, &derlen, &class, &tag, &constructed,
                                      &ndef, &objlen, &hdrlen);
              if (!err && (objlen > derlen || tag != TAG_OCTET_STRING || ndef))
                err = gpg_error (GPG_ERR_INV_OBJ);
              if (!err)
                {
                  derlen = objlen;
                  if (opt.debug)
                    log_printhex (der, derlen, "p15: OpenPGP KDF parms:");
                  /* Store them if they match the known OpenPGP format. */
                  if (derlen == 4 && der[0] == 3 && der[1]  == 1)
                    memcpy (prkdf->ecdh_kdf, der, 4);
                }
            }
          err = 0;
        }

      if (ksba_cert_get_ext_key_usages (cdf->cert, &extusage))
        continue; /* No extended key usage attribute.  */

      if (opt.debug)
        log_debug ("p15: ExtKeyUsages: %s\n", extusage);
      p = extusage;
      while (p && (pend=strchr (p, ':')))
        {
          *pend++ = 0;
          if ( *pend == 'C' ) /* Look only at critical usages.  */
            {
              prkdf->extusage.valid = 1;
              seen = 1;
              if (!strcmp (p, oid_kp_codeSigning)
                  || !strcmp (p, oid_kp_timeStamping)
                  || !strcmp (p, oid_kp_ocspSigning)
                  || !strcmp (p, oid_kp_ms_documentSigning)
                  || !strcmp (p, oid_kp_ms_old_documentSigning))
                prkdf->extusage.sign = 1;
              else if (!strcmp (p, oid_kp_emailProtection))
                prkdf->extusage.encr = 1;
              else if (!strcmp (p, oid_kp_serverAuth)
                       || !strcmp (p, oid_kp_clientAuth)
                       || !strcmp (p, oid_kp_ms_smartcardLogon))
                prkdf->extusage.auth = 1;
              else if (!strcmp (p, oid_kp_anyExtendedKeyUsage))
                {
                  prkdf->extusage.sign = 1;
                  prkdf->extusage.encr = 1;
                  prkdf->extusage.auth = 1;
                }
              else
                seen = 0;
            }
          else
            seen = 0;

          /* Now check the gpg Usage.  Here we don't care about
           * critical or non-critical here. */
          if (seen)
            ; /* No more need to look for other caps.  */
          else if (!strcmp (p, oid_kp_gpgUsageCert))
            {
              prkdf->gpgusage.cert = 1;
              prkdf->gpgusage.any = 1;
              app->app_local->any_gpgusage = 1;
            }
          else if (!strcmp (p, oid_kp_gpgUsageSign))
            {
              prkdf->gpgusage.sign = 1;
              prkdf->gpgusage.any = 1;
              app->app_local->any_gpgusage = 1;
            }
          else if (!strcmp (p, oid_kp_gpgUsageEncr))
            {
              prkdf->gpgusage.encr = 1;
              prkdf->gpgusage.any = 1;
              app->app_local->any_gpgusage = 1;
            }
          else if (!strcmp (p, oid_kp_gpgUsageAuth))
            {
              prkdf->gpgusage.auth = 1;
              prkdf->gpgusage.any = 1;
              app->app_local->any_gpgusage = 1;
            }

          /* Skip to next item.  */
          if ((p = strchr (pend, '\n')))
            p++;
        }
      xfree (extusage);
    }

  /* See whether we can figure out something about the card.  */
  if (!app->app_local->card_product
      && app->app_local->manufacturer_id
      && !strcmp (app->app_local->manufacturer_id, "www.atos.net/cardos")
      && IS_CARDOS_5 (app))
    {
      /* This is a modern CARDOS card. */
      flag = 0;
      for (prkdf = app->app_local->private_key_info; prkdf; prkdf = prkdf->next)
        {
          if (prkdf->label && !strcmp (prkdf->label, "IdentityKey")
              && prkdf->key_reference_valid && prkdf->key_reference == 1
              && !prkdf->authid)
            flag |= 1;
          else if (prkdf->label && !strcmp (prkdf->label, "TransportKey")
                   && prkdf->key_reference_valid && prkdf->key_reference==2
                   && prkdf->authid)
            flag |= 2;
        }
      if (flag == 3)
        app->app_local->card_product = CARD_PRODUCT_RSCS;

    }
  if (!app->app_local->card_product
      && app->app_local->token_label
      && !strncmp (app->app_local->token_label, "D-TRUST Card V3", 15)
      && app->app_local->card_type == CARD_TYPE_CARDOS_50)
    {
      app->app_local->card_product = CARD_PRODUCT_DTRUST;
    }


  /* Now print the info about the PrKDF.  */
  if (opt.verbose)
    {
      int i;
      unsigned char *atr;
      size_t atrlen;
      const char *cardstr;

      for (prkdf = app->app_local->private_key_info; prkdf; prkdf = prkdf->next)
        {
          log_info ("p15: PrKDF %04hX: id=", app->app_local->odf.private_keys);
          for (i=0; i < prkdf->objidlen; i++)
            log_printf ("%02X", prkdf->objid[i]);
          if (prkdf->label)
            log_printf (" (%s)", prkdf->label);
          log_info ("p15:             path=");
          for (i=0; i < prkdf->pathlen; i++)
            log_printf ("%s%04hX", i?"/":"",prkdf->path[i]);
          if (prkdf->have_off)
            log_printf ("[%lu/%lu]", prkdf->off, prkdf->len);
          if (prkdf->authid)
            {
              log_printf (" authid=");
              for (i=0; i < prkdf->authidlen; i++)
                log_printf ("%02X", prkdf->authid[i]);
            }
          if (prkdf->key_reference_valid)
            log_printf (" keyref=0x%02lX", prkdf->key_reference);
          log_printf (" type=%s", prkdf->is_ecc? "ecc":"rsa");
          if (prkdf->accessflags.any)
            dump_keyaccess_flags (prkdf->accessflags);
          dump_keyusage_flags (prkdf->usageflags);
          if (prkdf->extusage.valid)
            log_info ("p15:             extusage=%s%s%s%s%s",
                      prkdf->extusage.sign? "sign":"",
                      (prkdf->extusage.sign
                       && prkdf->extusage.encr)?",":"",
                      prkdf->extusage.encr? "encr":"",
                      ((prkdf->extusage.sign || prkdf->extusage.encr)
                       && prkdf->extusage.auth)?",":"",
                      prkdf->extusage.auth? "auth":"");
          if (prkdf->gpgusage.any)
            dump_gpgusage_flags (prkdf->gpgusage);

          log_printf ("\n");
        }

      log_info ("p15: TokenInfo:\n");
      if (app->app_local->serialno)
        {
          log_info ("p15:  serialNumber .: ");
          log_printhex (app->app_local->serialno, app->app_local->serialnolen,
                        "");
        }
      else if (APP_CARD(app)->serialno)
        {
          log_info ("p15:  serialNumber .: ");
          log_printhex (APP_CARD(app)->serialno, APP_CARD(app)->serialnolen,
                        "");
        }

      if (app->app_local->manufacturer_id)
        log_info ("p15:  manufacturerID: %s\n",
                  app->app_local->manufacturer_id);
      if (app->app_local->card_product)
        {
          cardstr = cardproduct2str (app->app_local->card_product);
          log_info ("p15:  product ......: %d%s%s%s\n",
                    app->app_local->card_product,
                    *cardstr? " (":"", cardstr, *cardstr? ")":"");
        }
      if (app->app_local->token_label)
        log_info ("p15:  label ........: %s\n", app->app_local->token_label);
      if (app->app_local->tokenflags)
        {
          log_info ("p15:  tokenflags ...:");
          print_tokeninfo_tokenflags (app->app_local->tokenflags,
                                      app->app_local->tokenflagslen);
          log_printf ("\n");
        }

      atr = apdu_get_atr (app_get_slot (app), &atrlen);
      log_info ("p15:  atr ..........: ");
      if (!atr)
        log_printf ("[error]\n");
      else
        {
          log_printhex (atr, atrlen, "");
          xfree (atr);
        }

      cardstr = cardtype2str (app->app_local->card_type);
      log_info ("p15:  cardtype .....: %d%s%s%s\n",
                app->app_local->card_type,
                *cardstr? " (":"", cardstr, *cardstr? ")":"");
    }

  return err;
}


/* Helper to do_learn_status: Send information about all certificates
   listed in CERTINFO back.  Use CERTTYPE as type of the
   certificate. */
static gpg_error_t
send_certinfo (app_t app, ctrl_t ctrl, const char *certtype,
               cdf_object_t certinfo)
{
  for (; certinfo; certinfo = certinfo->next)
    {
      char *buf, *p;
      const char *label;
      char *labelbuf;

      buf = xtrymalloc (9 + certinfo->objidlen*2 + 1);
      if (!buf)
        return gpg_error_from_syserror ();
      p = stpcpy (buf, "P15");
      if (app->app_local->home_df != DEFAULT_HOME_DF)
        {
          snprintf (p, 6, "-%04X",
                    (unsigned int)(app->app_local->home_df & 0xffff));
          p += 5;
        }
      p = stpcpy (p, ".");
      bin2hex (certinfo->objid, certinfo->objidlen, p);

      label = (certinfo->label && *certinfo->label)? certinfo->label : "-";
      labelbuf = percent_data_escape (0, NULL, label, strlen (label));
      if (!labelbuf)
        {
          xfree (buf);
          return gpg_error_from_syserror ();
        }

      send_status_info (ctrl, "CERTINFO",
                        certtype, strlen (certtype),
                        buf, strlen (buf),
                        labelbuf, strlen (labelbuf),
                        NULL, (size_t)0);
      xfree (buf);
      xfree (labelbuf);
    }
  return 0;
}


/* Get the keygrip of the private key object PRKDF.  On success the
 * keygrip, the algo and the length are stored in the KEYGRIP,
 * KEYALGO, and KEYNBITS fields of the PRKDF object.  */
static gpg_error_t
keygrip_from_prkdf (app_t app, prkdf_object_t prkdf)
{
  gpg_error_t err;
  cdf_object_t cdf;
  unsigned char *der;
  size_t derlen;
  ksba_cert_t cert;
  gcry_sexp_t s_pkey = NULL;

  /* Easy if we got a cached version.  */
  if (prkdf->keygrip_valid)
    return 0;

  xfree (prkdf->common_name);
  prkdf->common_name = NULL;
  xfree (prkdf->serial_number);
  prkdf->serial_number = NULL;

  /* We could have also checked whether a public key directory file
   * and a matching public key for PRKDF is available.  This would
   * make extraction of the key faster.  However, this way we don't
   * have a way to look at extended key attributes to check gpgusage.
   * FIXME: Add public key lookup if no certificate was found. */

  /* Look for a matching certificate. A certificate matches if the id
   * matches the one of the private key info.  If none was found we
   * also try to match on the label.  */
  err = cdf_object_from_objid (app, prkdf->objidlen, prkdf->objid, &cdf);
  if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
    err = cdf_object_from_label (app, prkdf->label, &cdf);
  if (!err && !cdf)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  if (err)
    goto leave;

  err = readcert_by_cdf (app, cdf, &der, &derlen);
  if (err)
    goto leave;

  err = ksba_cert_new (&cert);
  if (!err)
    err = ksba_cert_init_from_mem (cert, der, derlen);
  xfree (der);
  if (!err)
    err = app_help_get_keygrip_string (cert, prkdf->keygrip, &s_pkey, NULL);
  if (!err && !prkdf->gpgusage.any)
    {
      /* Try to get the CN and the SerialNumber from the certificate;
       * we use a very simple approach here which should work in many
       * cases.  Eventually we should add a rfc-2253 parser into
       * libksba to make it easier to parse such a string.
       * We don't do this if this is marked as gpg key and thus
       * has only a dummy certificate.
       *
       * First example string:
       *   "CN=Otto Schily,O=Miniluv,C=DE"
       * Second example string:
       *   "2.5.4.5=#445452323030303236333531,2.5.4.4=#4B6F6368,"
       *   "2.5.4.42=#5765726E6572,CN=Werner Koch,OU=For testing"
       *   " purposes only!,O=Testorganisation,C=DE"
       */
      char *dn = ksba_cert_get_subject (cert, 0);
      if (dn)
        {
          char *p, *pend, *buf;

          p = strstr (dn, "CN=");
          if (p && (p==dn || p[-1] == ','))
            {
              p += 3;
              if (!(pend = strchr (p, ',')))
                pend = p + strlen (p);
              if (pend && pend > p
                  && (prkdf->common_name = xtrymalloc ((pend - p) + 1)))
                {
                  memcpy (prkdf->common_name, p, pend-p);
                  prkdf->common_name[pend-p] = 0;
                }
            }
          p = strstr (dn, "2.5.4.5=#"); /* OID of the SerialNumber */
          if (p && (p==dn || p[-1] == ','))
            {
              p += 9;
              if (!(pend = strchr (p, ',')))
                pend = p + strlen (p);
              if (pend && pend > p
                  && (buf = xtrymalloc ((pend - p) + 1)))
                {
                  memcpy (buf, p, pend-p);
                  buf[pend-p] = 0;
                  if (!hex2str (buf, buf, strlen (buf)+1, NULL))
                    xfree (buf);  /* Invalid hex encoding.  */
                  else
                    prkdf->serial_number = buf;
                }
            }
          ksba_free (dn);
        }
    }

  if (!err && !prkdf->keytime)
    {
      ksba_isotime_t isot;
      time_t t;

      ksba_cert_get_validity (cert, 0, isot);
      t = isotime2epoch (isot);
      prkdf->keytime = (t == (time_t)(-1))? 0 : (u32)t;
      prkdf->have_keytime = 1;
    }

  if (!err && !prkdf->keyalgostr)
    prkdf->keyalgostr = pubkey_algo_string (s_pkey, NULL);

  ksba_cert_release (cert);
  if (err)
    goto leave;

  prkdf->keyalgo = get_pk_algo_from_key (s_pkey);
  if (!prkdf->keyalgo)
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  prkdf->keynbits = gcry_pk_get_nbits (s_pkey);
  if (!prkdf->keynbits)
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  prkdf->keygrip_valid = 1;  /* Yeah, got everything.  */

 leave:
  gcry_sexp_release (s_pkey);
  return err;
}


/* Return a malloced keyref string for PRKDF.  Returns NULL on
 * malloc failure.  */
static char *
keyref_from_prkdf (app_t app, prkdf_object_t prkdf)
{
  char *buf, *p;

  buf = xtrymalloc (4 + 5 + prkdf->objidlen*2 + 1);
  if (!buf)
    return NULL;
  p = stpcpy (buf, "P15");
  if (app->app_local->home_df != DEFAULT_HOME_DF)
    {
      snprintf (p, 6, "-%04X",
                (unsigned int)(app->app_local->home_df & 0xffff));
      p += 5;
    }
  p = stpcpy (p, ".");
  bin2hex (prkdf->objid, prkdf->objidlen, p);
  return buf;
}


/* Helper to do_learn_status: Send information about all known
   keypairs back.  FIXME: much code duplication from
   send_certinfo(). */
static gpg_error_t
send_keypairinfo (app_t app, ctrl_t ctrl, prkdf_object_t prkdf)
{
  gpg_error_t err;

  for (; prkdf; prkdf = prkdf->next)
    {
      char *buf;
      int j;

      buf = keyref_from_prkdf (app, prkdf);
      if (!buf)
        return gpg_error_from_syserror ();

      err = keygrip_from_prkdf (app, prkdf);
      if (err)
        {
          log_error ("p15: error getting keygrip from ");
          for (j=0; j < prkdf->pathlen; j++)
            log_printf ("%s%04hX", j?"/":"", prkdf->path[j]);
          log_printf (": %s\n", gpg_strerror (err));
        }
      else
        {
          char usage[5];
          char keytime[20];
          const char *algostr;
          size_t usagelen = 0;

          if (prkdf->gpgusage.any)
            {
              if (prkdf->gpgusage.sign)
                usage[usagelen++] = 's';
              if (prkdf->gpgusage.cert)
                usage[usagelen++] = 'c';
              if (prkdf->gpgusage.encr)
                usage[usagelen++] = 'e';
              if (prkdf->gpgusage.auth)
                usage[usagelen++] = 'a';
            }
          else
            {
              if ((prkdf->usageflags.sign
                   || prkdf->usageflags.sign_recover
                   || prkdf->usageflags.non_repudiation)
                  && (!prkdf->extusage.valid
                      || prkdf->extusage.sign))
                usage[usagelen++] = 's';
              if ((prkdf->usageflags.sign
                   || prkdf->usageflags.sign_recover)
                  && (!prkdf->extusage.valid || prkdf->extusage.sign))
                usage[usagelen++] = 'c';
              if ((prkdf->usageflags.decrypt
                   || prkdf->usageflags.unwrap)
                  && (!prkdf->extusage.valid || prkdf->extusage.encr))
                usage[usagelen++] = 'e';
              if ((prkdf->usageflags.sign
                   || prkdf->usageflags.sign_recover)
                  && (!prkdf->extusage.valid || prkdf->extusage.auth))
                usage[usagelen++] = 'a';
            }

          log_assert (strlen (prkdf->keygrip) == 40);
          if (prkdf->keytime && prkdf->have_keytime)
            snprintf (keytime, sizeof keytime, "%lu",
                      (unsigned long)prkdf->keytime);
          else
            strcpy (keytime, "-");

          algostr = prkdf->keyalgostr;

          send_status_info (ctrl, "KEYPAIRINFO",
                            prkdf->keygrip, 2*KEYGRIP_LEN,
                            buf, strlen (buf),
                            usage, usagelen,
                            keytime, strlen (keytime),
                            algostr, strlen (algostr?algostr:""),
                            NULL, (size_t)0);
        }
      xfree (buf);
    }
  return 0;
}



/* This is the handler for the LEARN command.  Note that if
 * APP_LEARN_FLAG_REREAD is set and this function returns an error,
 * the caller must deinitialize this application.  */
static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;

  if (flags & APP_LEARN_FLAG_REREAD)
    {
      err = read_p15_info (app);
      if (err)
        return err;
    }

  if ((flags & APP_LEARN_FLAG_KEYPAIRINFO))
    err = 0;
  else
    {
      err = do_getattr (app, ctrl, "MANUFACTURER");
      if (!err)
        err = send_certinfo (app, ctrl, "100",
                             app->app_local->certificate_info);
      if (!err)
        err = send_certinfo (app, ctrl, "101",
                             app->app_local->trusted_certificate_info);
      if (!err)
        err = send_certinfo (app, ctrl, "102",
                             app->app_local->useful_certificate_info);
    }

  if (!err)
    err = send_keypairinfo (app, ctrl, app->app_local->private_key_info);

  if (!err)
    err = do_getattr (app, ctrl, "CHV-STATUS");
  if (!err)
    err = do_getattr (app, ctrl, "CHV-LABEL");


  return err;
}


/* Read a certificate using the information in CDF and return the
 * certificate in a newly malloced buffer R_CERT and its length
 * R_CERTLEN.  Also parses the certificate.  R_CERT and R_CERTLEN may
 * be NULL to do just the caching.  */
static gpg_error_t
readcert_by_cdf (app_t app, cdf_object_t cdf,
                 unsigned char **r_cert, size_t *r_certlen)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  const unsigned char *p, *save_p;
  size_t buflen, n;
  int class, tag, constructed, ndef;
  size_t totobjlen, objlen, hdrlen;
  int rootca;
  int i;

  if (r_cert)
    *r_cert = NULL;
  if (r_certlen)
    *r_certlen = 0;

  /* First check whether it has been cached. */
  if (cdf->cert)
    {
      const unsigned char *image;
      size_t imagelen;

      if (!r_cert || !r_certlen)
        return 0; /* Caller does not actually want the result. */

      image = ksba_cert_get_image (cdf->cert, &imagelen);
      if (!image)
        {
          log_error ("p15: ksba_cert_get_image failed\n");
          return gpg_error (GPG_ERR_INTERNAL);
        }
      *r_cert = xtrymalloc (imagelen);
      if (!*r_cert)
        return gpg_error_from_syserror ();
      memcpy (*r_cert, image, imagelen);
      *r_certlen = imagelen;
      return 0;
    }

  if (DBG_CARD)
    {
      log_info ("p15: Reading CDF: id=");
      for (i=0; i < cdf->objidlen; i++)
        log_printf ("%02X", cdf->objid[i]);
      if (cdf->label)
        log_printf (" (%s)", cdf->label);
      log_info ("p15:             path=");
      for (i=0; i < cdf->pathlen; i++)
        log_printf ("%s%04hX", i?"/":"", cdf->path[i]);
      if (cdf->have_off)
        log_printf ("[%lu/%lu]", cdf->off, cdf->len);
      if (cdf->authid)
        {
          log_printf (" authid=");
          for (i=0; i < cdf->authidlen; i++)
            log_printf ("%02X", cdf->authid[i]);
        }
      log_printf ("\n");
    }

  /* Read the entire file.  fixme: This could be optimized by first
     reading the header to figure out how long the certificate
     actually is. */
  err = select_ef_by_path (app, cdf->path, cdf->pathlen);
  if (err)
    goto leave;

  if (app->app_local->no_extended_mode || !cdf->len)
    err = iso7816_read_binary_ext (app_get_slot (app), 0, cdf->off, 0,
                                   &buffer, &buflen, NULL);
  else
    err = iso7816_read_binary_ext (app_get_slot (app), 1, cdf->off, cdf->len,
                                   &buffer, &buflen, NULL);
  if (!err && (!buflen || *buffer == 0xff))
    err = gpg_error (GPG_ERR_NOT_FOUND);
  if (err)
    {
      log_error ("p15: error reading certificate id=");
      for (i=0; i < cdf->objidlen; i++)
        log_printf ("%02X", cdf->objid[i]);
      log_printf (" at ");
      for (i=0; i < cdf->pathlen; i++)
        log_printf ("%s%04hX", i? "/":"", cdf->path[i]);
      log_printf (": %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Check whether this is really a certificate.  */
  p = buffer;
  n = buflen;
  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (err)
    goto leave;

  if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && constructed)
    rootca = 0;
  else if ( class == CLASS_UNIVERSAL && tag == TAG_SET && constructed )
    rootca = 1;
  else
    {
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  totobjlen = objlen + hdrlen;
  log_assert (totobjlen <= buflen);

  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (err)
    goto leave;

  if (!rootca
      && class == CLASS_UNIVERSAL && tag == TAG_OBJECT_ID && !constructed)
    {
      /* The certificate seems to be contained in a userCertificate
         container.  Skip this and assume the following sequence is
         the certificate. */
      if (n < objlen)
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto leave;
        }
      p += objlen;
      n -= objlen;
      save_p = p;
      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (err)
        goto leave;
      if ( !(class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && constructed) )
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto leave;
        }
      totobjlen = objlen + hdrlen;
      log_assert (save_p + totobjlen <= buffer + buflen);
      memmove (buffer, save_p, totobjlen);
    }


  /* Try to parse and cache the certificate. */
  err = ksba_cert_new (&cdf->cert);
  if (!err)
    {
      err = ksba_cert_init_from_mem (cdf->cert, buffer, totobjlen);
      if (!err) /* Call us to use the just cached cert object.  */
        err = readcert_by_cdf (app, cdf, r_cert, r_certlen);
      if (err)
        {
          ksba_cert_release (cdf->cert);
          cdf->cert = NULL;
        }

    }
  if (err)
    {
      log_error ("p15: caching certificate failed: %s\n",
                 gpg_strerror (err));
      /* We return the certificate anyway so that the caller has a
       * chance to get an even unsupported or broken certificate.  */
      if (r_cert && r_certlen)
        {
          *r_cert = buffer;
          buffer = NULL;
          *r_certlen = totobjlen;
        }
    }

 leave:
  xfree (buffer);
  return err;
}


/* Handler for the READCERT command.

   Read the certificate with id CERTID (as returned by learn_status in
   the CERTINFO status lines) and return it in the freshly allocated
   buffer to be stored at R_CERT and its length at R_CERTLEN.  A error
   code will be returned on failure and R_CERT and R_CERTLEN will be
   set to (NULL,0). */
static gpg_error_t
do_readcert (app_t app, const char *certid,
             unsigned char **r_cert, size_t *r_certlen)
{
  gpg_error_t err;
  cdf_object_t cdf;

  *r_cert = NULL;
  *r_certlen = 0;
  err = cdf_object_from_certid (app, certid, &cdf);
  if (!err)
    err = readcert_by_cdf (app, cdf, r_cert, r_certlen);
  return err;
}


/* Sort helper for an array of authentication objects.  */
static int
compare_aodf_objid (const void *arg_a, const void *arg_b)
{
  const aodf_object_t a = *(const aodf_object_t *)arg_a;
  const aodf_object_t b = *(const aodf_object_t *)arg_b;
  int rc;

  rc = memcmp (a->objid, b->objid,
               a->objidlen < b->objidlen? a->objidlen : b->objidlen);
  if (!rc)
    {
      if (a->objidlen < b->objidlen)
        rc = -1;
      else if (a->objidlen > b->objidlen)
        rc = 1;
    }
  return rc;
}


static void
send_key_fpr_line (ctrl_t ctrl, int number, const unsigned char *fpr)
{
  char buf[41];
  char numbuf[25];

  bin2hex (fpr, 20, buf);
  if (number == -1)
    *numbuf = 0; /* Don't print the key number */
  else
    snprintf (numbuf, sizeof numbuf, "%d", number);
  send_status_info (ctrl, "KEY-FPR",
                    numbuf, (size_t)strlen(numbuf),
                    buf, (size_t)strlen (buf),
                    NULL, 0);
}


/* If possible emit a FPR-KEY status line for the private key object
 * PRKDF using NUMBER as index.  */
static void
send_key_fpr (app_t app, ctrl_t ctrl, prkdf_object_t prkdf, int number)
{
  gpg_error_t err;
  cdf_object_t cdf;
  unsigned char *pk, *fixed_pk;
  size_t pklen, fixed_pklen;
  const unsigned char *m, *e, *q;
  size_t mlen, elen, qlen;
  unsigned char fpr20[20];

  if (cdf_object_from_objid (app, prkdf->objidlen, prkdf->objid, &cdf)
      && cdf_object_from_label (app, prkdf->label, &cdf))
    return;
  if (!cdf->cert)
    readcert_by_cdf (app, cdf, NULL, NULL);
  if (!cdf->cert)
    return;
  if (!prkdf->have_keytime)
    return;
  pk = ksba_cert_get_public_key (cdf->cert);
  if (!pk)
    return;
  pklen = gcry_sexp_canon_len (pk, 0, NULL, &err);

  if (uncompress_ecc_q_in_canon_sexp (pk, pklen, &fixed_pk, &fixed_pklen))
    {
      xfree (pk);
      return;
    }
  if (fixed_pk)
    {
      xfree (pk); pk = NULL;
      pk = fixed_pk;
      pklen = fixed_pklen;
    }

  switch (prkdf->keyalgo)
    {
    case GCRY_PK_RSA:
      if (!get_rsa_pk_from_canon_sexp (pk, pklen,
                                       &m, &mlen, &e, &elen)
          && !compute_openpgp_fpr_rsa (4,
                                       prkdf->keytime,
                                       m, mlen, e, elen,
                                       fpr20, NULL))
        send_key_fpr_line (ctrl, number, fpr20);
      break;

    case GCRY_PK_ECC:
    case GCRY_PK_ECDSA:
    case GCRY_PK_ECDH:
    case GCRY_PK_EDDSA:
      /* Note that NUMBER 2 indicates the encryption key.  */
      if (!get_ecc_q_from_canon_sexp (pk, pklen, &q, &qlen)
          && !compute_openpgp_fpr_ecc (4,
                                       prkdf->keytime,
                                       prkdf->keyalgostr,
                                       number == 2,
                                       q, qlen,
                                       prkdf->ecdh_kdf, 4,
                                       fpr20, NULL))
        send_key_fpr_line (ctrl, number, fpr20);
      break;

    default: /* No Fingerprint for an unknown algo.  */
      break;

    }
  xfree (pk);
}


/* Implement the GETATTR command.  This is similar to the LEARN
   command but returns just one value via the status interface. */
static gpg_error_t
do_getattr (app_t app, ctrl_t ctrl, const char *name)
{
  gpg_error_t err;
  prkdf_object_t prkdf;

  if (!strcmp (name, "$AUTHKEYID")
      || !strcmp (name, "$ENCRKEYID")
      || !strcmp (name, "$SIGNKEYID"))
    {
      char *buf;

      /* We return the ID of the first private key capable of the
       * requested action.  If any gpgusage flag has been set for the
       * card we consult the gpgusage flags and not the regualr usage
       * flags.
       */
      /* FIXME: This changed: Note that we do not yet return
       * non_repudiation keys for $SIGNKEYID because our D-Trust
       * testcard uses rsaPSS, which is not supported by gpgsm and not
       * covered by the VS-NfD approval.  */
      for (prkdf = app->app_local->private_key_info; prkdf;
           prkdf = prkdf->next)
        {
          if (app->app_local->any_gpgusage)
            {
              if ((name[1] == 'A' && prkdf->gpgusage.auth)
                  || (name[1] == 'E' && prkdf->gpgusage.encr)
                  || (name[1] == 'S' && prkdf->gpgusage.sign))
                break;
            }
          else
            {
              if ((name[1] == 'A' && (prkdf->usageflags.sign
                                      || prkdf->usageflags.sign_recover))
                  || (name[1] == 'E' && (prkdf->usageflags.decrypt
                                         || prkdf->usageflags.unwrap))
                  || (name[1] == 'S' && (prkdf->usageflags.sign
                                         || prkdf->usageflags.sign_recover)))
                break;
            }
        }
      if (prkdf)
        {
          buf = keyref_from_prkdf (app, prkdf);
          if (!buf)
            return gpg_error_from_syserror ();

          send_status_info (ctrl, name, buf, strlen (buf), NULL, 0);
          xfree (buf);
        }
      return 0;
    }
  else if (!strcmp (name, "$DISPSERIALNO"))
    {
      /* For certain cards we return special IDs.  There is no
         general rule for it so we need to decide case by case. */
      if (app->app_local->card_type == CARD_TYPE_BELPIC)
        {
          /* The eID card has a card number printed on the front matter
             which seems to be a good indication. */
          unsigned char *buffer;
          const unsigned char *p;
          size_t buflen, n;
          unsigned short path[] = { 0x3F00, 0xDF01, 0x4031 };

          err = select_ef_by_path (app, path, DIM(path) );
          if (!err)
            err = iso7816_read_binary (app_get_slot (app), 0, 0,
                                       &buffer, &buflen);
          if (err)
            {
              log_error ("p15: error accessing EF(ID): %s\n",
                         gpg_strerror (err));
              return err;
            }

          p = find_tlv (buffer, buflen, 1, &n);
          if (p && n == 12)
            {
              char tmp[12+2+1];
              memcpy (tmp, p, 3);
              tmp[3] = '-';
              memcpy (tmp+4, p+3, 7);
              tmp[11] = '-';
              memcpy (tmp+12, p+10, 2);
              tmp[14] = 0;
              send_status_info (ctrl, name, tmp, strlen (tmp), NULL, 0);
              xfree (buffer);
              return 0;
            }
          xfree (buffer);
        }
      else
        {
          char *sn;

          /* We use the first private key object which has a serial
           * number set.  If none was found, we parse the first
           * object and see whether this has then a serial number.  */
          for (prkdf = app->app_local->private_key_info; prkdf;
               prkdf = prkdf->next)
            if (prkdf->serial_number)
              break;
          if (!prkdf && app->app_local->private_key_info)
            {
              prkdf = app->app_local->private_key_info;
              keygrip_from_prkdf (app, prkdf);
              if (!prkdf->serial_number)
                prkdf = NULL;
            }
          sn = get_dispserialno (app, prkdf);
          /* Unless there is a bogus S/N in the cert, or the product
           * has a different strategy for the display-s/n, we should
           * have a suitable one from the cert now.  */
          if (sn)
            {
              err = send_status_printf (ctrl, name, "%s", sn);
              xfree (sn);
              return err;
            }
        }
      /* No abbreviated serial number. */
    }
  else if (!strcmp (name, "MANUFACTURER"))
    {
      if (app->app_local->manufacturer_id
          && !strchr (app->app_local->manufacturer_id, '[')
          && app->app_local->card_product)
        return send_status_printf (ctrl, "MANUFACTURER", "0 %s [%s]",
                              app->app_local->manufacturer_id,
                              cardproduct2str (app->app_local->card_product));
      else if (app->app_local->manufacturer_id)
        return send_status_printf (ctrl, "MANUFACTURER", "0 %s",
                                   app->app_local->manufacturer_id);
      else
        return 0;
    }
  else if (!strcmp (name, "CHV-STATUS") || !strcmp (name, "CHV-LABEL"))
    {
      int is_label = (name[4] == 'L');
      aodf_object_t aodf;
      aodf_object_t aodfarray[16];
      int naodf = 0;
      membuf_t mb;
      char *p;
      int i;

      /* Put the AODFs into an array for easier sorting.  Note that we
       * handle onl the first 16 encountrer which should be more than
       * enough.  */
      for (aodf = app->app_local->auth_object_info;
           aodf && naodf < DIM(aodfarray); aodf = aodf->next)
        if (aodf->objidlen && aodf->pin_reference_valid)
          aodfarray[naodf++] = aodf;
      qsort (aodfarray, naodf, sizeof *aodfarray, compare_aodf_objid);

      init_membuf (&mb, 256);
      for (i = 0; i < naodf; i++)
        {
          /* int j; */
          /* log_debug ("p15: AODF[%d] pinref=%lu id=", */
          /*            i, aodfarray[i]->pin_reference); */
          /* for (j=0; j < aodfarray[i]->objidlen; j++) */
          /*   log_printf ("%02X", aodfarray[i]->objid[j]); */
          /* Note that there is no need to percent escape the label
           * because all white space have been replaced by '_'.  */
          if (is_label)
            put_membuf_printf (&mb, "%s%s", i? " ":"",
                               (aodfarray[i]->label
                                && *aodfarray[i]->label)?
                               aodfarray[i]->label:"X");
          else
            put_membuf_printf
              (&mb, "%s%d", i? " ":"",
               iso7816_verify_status (app_get_slot (app),
                                      aodfarray[i]->pin_reference));
        }
      put_membuf( &mb, "", 1);
      p = get_membuf (&mb, NULL);
      if (!p)
        return gpg_error_from_syserror ();
      err = send_status_direct (ctrl, is_label? "CHV-LABEL":"CHV-STATUS", p);
      xfree (p);
      return err;
    }
  else if (!strcmp (name, "KEY-LABEL"))
    {
      /* Send KEY-LABEL lines for all private key objects.  */
      const char *label;
      char *idbuf, *labelbuf;

      for (prkdf = app->app_local->private_key_info; prkdf;
           prkdf = prkdf->next)
        {
          idbuf = keyref_from_prkdf (app, prkdf);
          if (!idbuf)
            return gpg_error_from_syserror ();

          label = (prkdf->label && *prkdf->label)? prkdf->label : "-";
          labelbuf = percent_data_escape (0, NULL, label, strlen (label));
          if (!labelbuf)
            {
              xfree (idbuf);
              return gpg_error_from_syserror ();
            }

          send_status_info (ctrl, name,
                            idbuf, strlen (idbuf),
                            labelbuf, strlen(labelbuf),
                            NULL, 0);
          xfree (idbuf);
          xfree (labelbuf);
        }
      return 0;
    }
  else if (!strcmp (name, "KEY-FPR"))
    {
      /* Send KEY-FPR for the two openpgp keys. */
      for (prkdf = app->app_local->private_key_info; prkdf;
           prkdf = prkdf->next)
        {
          if (app->app_local->any_gpgusage)
            {
              if (prkdf->gpgusage.sign)
                break;
            }
          else
            {
              if (prkdf->usageflags.sign || prkdf->usageflags.sign_recover)
                break;
            }
        }
      if (prkdf)
        send_key_fpr (app, ctrl, prkdf, 1);
      for (prkdf = app->app_local->private_key_info; prkdf;
           prkdf = prkdf->next)
        {
          if (app->app_local->any_gpgusage)
            {
              if (prkdf->gpgusage.encr)
                break;
            }
          else
            {
              if (prkdf->usageflags.decrypt || prkdf->usageflags.unwrap)
                break;
            }
        }
      if (prkdf)
        send_key_fpr (app, ctrl, prkdf, 2);
      return 0;
    }

  return gpg_error (GPG_ERR_INV_NAME);
}




/* Micardo cards require special treatment. This is a helper for the
   crypto functions to manage the security environment.  We expect that
   the key file has already been selected. FID is the one of the
   selected key. */
static gpg_error_t
micardo_mse (app_t app, unsigned short fid)
{
  gpg_error_t err;
  int recno;
  unsigned short refdata = 0;
  int se_num;
  unsigned char msebuf[10];

  /* Read the KeyD file containing extra information on keys. */
  err = iso7816_select_file (app_get_slot (app), 0x0013, 0);
  if (err)
    {
      log_error ("p15: error reading EF_keyD: %s\n", gpg_strerror (err));
      return err;
    }

  for (recno = 1, se_num = -1; ; recno++)
    {
      unsigned char *buffer;
      size_t buflen;
      size_t n, nn;
      const unsigned char *p, *pp;

      err = iso7816_read_record (app_get_slot (app), recno, 1, 0,
                                 &buffer, &buflen);
      if (gpg_err_code (err) == GPG_ERR_NOT_FOUND)
        break; /* ready */
      if (err)
        {
          log_error ("p15: error reading EF_keyD record: %s\n",
                     gpg_strerror (err));
          return err;
        }
      if (opt.verbose)
        {
          log_info (buffer, buflen, "p15: keyD record: ");
          log_printhex (buffer, buflen, "");
        }
      p = find_tlv (buffer, buflen, 0x83, &n);
      if (p && n == 4 && ((p[2]<<8)|p[3]) == fid)
        {
          refdata = ((p[0]<<8)|p[1]);
          /* Locate the SE DO and the there included sec env number. */
          p = find_tlv (buffer, buflen, 0x7b, &n);
          if (p && n)
            {
              pp = find_tlv (p, n, 0x80, &nn);
              if (pp && nn == 1)
                {
                  se_num = *pp;
                  xfree (buffer);
                  break; /* found. */
                }
            }
        }
      xfree (buffer);
    }
  if (se_num == -1)
    {
      log_error ("p15: CRT for keyfile %04hX not found\n", fid);
      return gpg_error (GPG_ERR_NOT_FOUND);
    }


  /* Restore the security environment to SE_NUM if needed */
  if (se_num)
    {
      err = iso7816_manage_security_env (app_get_slot (app),
                                         0xf3, se_num, NULL, 0);
      if (err)
        {
          log_error ("p15: restoring SE to %d failed: %s\n",
                     se_num, gpg_strerror (err));
          return err;
        }
    }

  /* Set the DST reference data. */
  msebuf[0] = 0x83;
  msebuf[1] = 0x03;
  msebuf[2] = 0x80;
  msebuf[3] = (refdata >> 8);
  msebuf[4] = refdata;
  err = iso7816_manage_security_env (app_get_slot (app), 0x41, 0xb6, msebuf, 5);
  if (err)
    {
      log_error ("p15: setting SE to reference file %04hX failed: %s\n",
                 refdata, gpg_strerror (err));
      return err;
    }
  return 0;
}



/* Prepare the verification of the PIN for the key PRKDF by checking
 * the AODF and selecting the key file.  KEYREF is used for error
 * messages.  AODF may be NULL if no verification needs to be done. */
static gpg_error_t
prepare_verify_pin (app_t app, const char *keyref,
                    prkdf_object_t prkdf, aodf_object_t aodf)
{
  gpg_error_t err;
  int i;

  if (aodf)
    {
      if (opt.verbose)
        {
          log_info ("p15: using AODF %04hX id=", aodf->fid);
          for (i=0; i < aodf->objidlen; i++)
            log_printf ("%02X", aodf->objid[i]);
          log_printf ("\n");
        }

      if (aodf->authid && opt.verbose)
        log_info ("p15: PIN is controlled by another authentication token\n");

      if (aodf->pinflags.integrity_protected
          || aodf->pinflags.confidentiality_protected)
        {
          log_error ("p15: PIN verification requires"
                     " unsupported protection method\n");
          return gpg_error (GPG_ERR_BAD_PIN_METHOD);
        }
      if (!aodf->stored_length && aodf->pinflags.needs_padding)
        {
          log_error ("p15: PIN verification requires"
                     " padding but no length known\n");
          return gpg_error (GPG_ERR_INV_CARD);
        }
    }


  if (app->app_local->card_product == CARD_PRODUCT_DTRUST)
    {
      /* According to our protocol analysis we need to select a
       * special AID here.  Before that the master file needs to be
       * selected.  (RID A000000167 is assigned to IBM) */
      static char const dtrust_aid[] =
        { 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E };

      err = iso7816_select_mf (app_get_slot (app));
      if (!err)
        err = iso7816_select_application (app_get_slot (app),
                                          dtrust_aid, sizeof dtrust_aid, 0);
      if (err)
        log_error ("p15: error selecting D-TRUST's AID for key %s: %s\n",
                   keyref, gpg_strerror (err));
    }
  else if (prkdf)
    {
      /* Standard case: Select the key file.  Note that this may
       * change the security environment thus we need to do it before
       * PIN verification. */
      err = select_ef_by_path (app, prkdf->path, prkdf->pathlen);
      if (err)
        log_error ("p15: error selecting file for key %s: %s\n",
                   keyref, gpg_strerror (err));
    }
  else
    {
      log_info ("p15: skipping EF selection for auth object '%s'\n", keyref);
      err = 0;
    }

  return err;
}


static int
any_control_or_space (const char *string)
{
  const unsigned char *s;

  for (s = string; *s; s++)
    if (*s <= 0x20 || *s >= 0x7f)
      return 1;
  return 0;
}

static int
any_control_or_space_mem (const void *buffer, size_t buflen)
{
  const unsigned char *s;

  for (s = buffer; buflen; s++, buflen--)
    if (*s <= 0x20 || *s >= 0x7f)
      return 1;
  return 0;
}


/* Return a malloced serial number to be shown to the user.  PRKDF is
 * used to get it from a certificate; PRKDF may be NULL.  */
static char *
get_dispserialno (app_t app, prkdf_object_t prkdf)
{
  char *serial;
  const unsigned char *s;
  int i;
  size_t n;

  /* We prefer the SerialNumber RDN from the Subject-DN but we don't
   * use it if it features a percent sign (special character in pin
   * prompts) or has any control character.  For some cards we use a
   * different strategy.  */
  if (app->app_local->card_product == CARD_PRODUCT_RSCS)
    {
      /* We use only the right 8 hex digits.  */
      serial = app_get_serialno (app);
      if (serial && (n=strlen (serial)) > 8)
        memmove (serial, serial + n - 8, 9);
    }
  else if (IS_CARDOS_5 (app) && app->app_local->manufacturer_id
           && !ascii_strcasecmp (app->app_local->manufacturer_id,
                                 "Technology Nexus")
           && APP_CARD(app)->serialno && APP_CARD(app)->serialnolen == 4+9
           && !memcmp (APP_CARD(app)->serialno, "\xff\x00\x00\xff", 4)
           && !any_control_or_space_mem (APP_CARD(app)->serialno + 4, 9))
    {
      /* Sample: ff0000ff354830313232363537 -> "5H01 2265 7" */
      serial = xtrymalloc (9+2+1);
      if (serial)
        {
          s = APP_CARD(app)->serialno + 4;
          for (i=0; i < 4; i++)
            serial[i] = *s++;
          serial[i++] = ' ';
          for (; i < 9; i++)
            serial[i] = *s++;
          serial[i++] = ' ';
          serial[i++] = *s;
          serial[i] = 0;
        }
    }
  else if (prkdf && prkdf->serial_number && *prkdf->serial_number
      && !strchr (prkdf->serial_number, '%')
      && !any_control_or_space (prkdf->serial_number))
    {
      serial = xtrystrdup (prkdf->serial_number);
    }
  else
    {
      serial = app_get_serialno (app);
    }

  return serial;
}


/* Return an allocated string to be used as prompt.  PRKDF may be
 * NULL.  Returns NULL on malloc error.  */
static char *
make_pin_prompt (app_t app, int remaining, const char *firstline,
                 prkdf_object_t prkdf)
{
  char *serial, *tmpbuf, *result;
  const char *holder = NULL;

  serial = get_dispserialno (app, prkdf);

  if (app->app_local->card_product == CARD_PRODUCT_GENUA)
    {
      /* The label of the first non SO-PIN is used for the holder.  */
      aodf_object_t aodf;

      for (aodf = app->app_local->auth_object_info; aodf; aodf = aodf->next)
        if (aodf->auth_type == AUTH_TYPE_PIN
            && !aodf->pinflags.so_pin
            && aodf->label)
          {
            holder = aodf->label;
            break;
          }
    }

  if (holder)
    ;
  else if (prkdf && prkdf->common_name)
    holder = prkdf->common_name;
  else if (app->app_local->token_label)
    holder = app->app_local->token_label;
  else
    holder = "";

  /* TRANSLATORS: Put a \x1f right before a colon.  This can be
   * used by pinentry to nicely align the names and values.  Keep
   * the %s at the start and end of the string.  */
  result = xtryasprintf (_("%s"
                           "Number\x1f: %s%%0A"
                           "Holder\x1f: %s"
                           "%s"),
                         "\x1e",
                         serial,
                         holder,
                         "");
  xfree (serial);
  if (!result)
    return NULL; /* Out of core.  */

  /* Append a "remaining attempts" info if needed.  */
  if (remaining != -1 && remaining < 3)
    {
      char *rembuf;

      /* TRANSLATORS: This is the number of remaining attempts to
       * enter a PIN.  Use %%0A (double-percent,0A) for a linefeed. */
      rembuf = xtryasprintf (_("Remaining attempts: %d"), remaining);
      if (rembuf)
        {
          tmpbuf = strconcat (firstline, "%0A%0A", result,
                              "%0A%0A", rembuf, NULL);
          xfree (rembuf);
        }
      else
        tmpbuf = NULL;
      xfree (result);
      result = tmpbuf;
    }
  else
    {
      tmpbuf = strconcat (firstline, "%0A%0A", result, NULL);
      xfree (result);
      result = tmpbuf;
    }

  return result;
}


/* Given the private key object PRKDF and its authentication object
 * AODF ask for the PIN and verify that PIN.  If AODF is NULL, no
 * authentication is done.  */
static gpg_error_t
verify_pin (app_t app,
            gpg_error_t (*pincb)(void*, const char *, char **), void *pincb_arg,
            prkdf_object_t prkdf, aodf_object_t aodf)
{
  gpg_error_t err;
  char *pinvalue;
  size_t pinvaluelen;
  const char *label;
  const char *errstr;
  const char *s;
  int remaining;
  unsigned int min_length;
  int pin_reference;
  int verified = 0;
  int i;

  if (!aodf)
    return 0;

  pin_reference = aodf->pin_reference_valid? aodf->pin_reference : 0;

  if (IS_CARDOS_5 (app))
    {
      /* We know that this card supports a verify status check.  Note
       * that in contrast to PIV cards ISO7816_VERIFY_NOT_NEEDED is
       * not supported.  We also don't use the pin_verified cache
       * status because that is not as reliable as to ask the card
       * about its state.  */
      if (prkdf)  /* Clear the cache which we don't use.  */
        prkdf->pin_verified = 0;

      remaining = iso7816_verify_status (app_get_slot (app), pin_reference);
      if (remaining == ISO7816_VERIFY_NOT_NEEDED)
        {
          verified = 1;
          remaining = -1;
        }
      else if (remaining < 0)
        remaining = -1; /* We don't care about the concrete error.  */
      else if (remaining < 3)
        log_info ("p15: PIN has %d attempts left\n", remaining);
    }
  else
    remaining = -1;  /* Unknown.  */

  /* Check whether we already verified it.  */
  if (prkdf && (prkdf->pin_verified || verified))
    return 0;  /* Already done.  */

  if (prkdf
      && prkdf->usageflags.non_repudiation
      && (app->app_local->card_type == CARD_TYPE_BELPIC
          || app->app_local->card_product == CARD_PRODUCT_DTRUST))
    label = _("||Please enter the PIN for the key to create "
              "qualified signatures.");
  else if (aodf->pinflags.so_pin)
    label = _("|A|Please enter the Admin PIN");
  else if (aodf->pinflags.unblocking_pin)
    label = _("|P|Please enter the PIN Unblocking Code (PUK) "
              "for the standard keys.");
  else
    label = _("||Please enter the PIN for the standard keys.");

  {
    char *prompt = make_pin_prompt (app, remaining, label, prkdf);
    if (!prompt)
      err = gpg_error_from_syserror ();
    else
      err = pincb (pincb_arg, prompt, &pinvalue);
    xfree (prompt);
  }
  if (err)
    {
      log_info ("p15: PIN callback returned error: %s\n", gpg_strerror (err));
      return err;
    }

  /* We might need to cope with UTF8 things here.  Not sure how
     min_length etc. are exactly defined, for now we take them as a
     plain octet count.  For RSCS we enforce 6 despite that some cards
     give 4 has min. length.  */
  min_length = aodf->min_length;
  if (app->app_local->card_product == CARD_PRODUCT_RSCS && min_length < 6)
    min_length = 6;

  if (strlen (pinvalue) < min_length)
    {
      log_error ("p15: PIN is too short; minimum length is %u\n", min_length);
      err = gpg_error (GPG_ERR_BAD_PIN);
    }
  else if (aodf->stored_length && strlen (pinvalue) > aodf->stored_length)
    {
      /* This would otherwise truncate the PIN silently. */
      log_error ("p15: PIN is too large; maximum length is %lu\n",
                 aodf->stored_length);
      err = gpg_error (GPG_ERR_BAD_PIN);
    }
  else if (aodf->max_length_valid && strlen (pinvalue) > aodf->max_length)
    {
      log_error ("p15: PIN is too large; maximum length is %lu\n",
                 aodf->max_length);
      err = gpg_error (GPG_ERR_BAD_PIN);
    }

  if (err)
    {
      xfree (pinvalue);
      return err;
    }

  errstr = NULL;
  err = 0;
  switch (aodf->pintype)
    {
    case PIN_TYPE_BCD:
      for (s=pinvalue; digitp (s); s++)
        ;
      if (*s)
        {
          errstr = "Non-numeric digits found in PIN";
          err = gpg_error (GPG_ERR_BAD_PIN);
        }
      break;
    case PIN_TYPE_ASCII_NUMERIC:
      for (s=pinvalue; *s && !(*s & 0x80); s++)
        ;
      if (*s)
        {
          errstr = "Non-ascii characters found in PIN";
          err = gpg_error (GPG_ERR_BAD_PIN);
        }
      break;
    case PIN_TYPE_UTF8:
      break;
    case PIN_TYPE_HALF_NIBBLE_BCD:
      errstr = "PIN type Half-Nibble-BCD is not supported";
      break;
    case PIN_TYPE_ISO9564_1:
      errstr = "PIN type ISO9564-1 is not supported";
      break;
    default:
      errstr = "Unknown PIN type";
      break;
    }
  if (errstr)
    {
      log_error ("p15: can't verify PIN: %s\n", errstr);
      xfree (pinvalue);
      return err? err : gpg_error (GPG_ERR_BAD_PIN_METHOD);
    }


  if (aodf->pintype == PIN_TYPE_BCD )
    {
      char *paddedpin;
      int ndigits;

      for (ndigits=0, s=pinvalue; *s; ndigits++, s++)
        ;
      paddedpin = xtrymalloc (aodf->stored_length+1);
      if (!paddedpin)
        {
          err = gpg_error_from_syserror ();
          xfree (pinvalue);
          return err;
        }

      i = 0;
      paddedpin[i++] = 0x20 | (ndigits & 0x0f);
      for (s=pinvalue; i < aodf->stored_length && *s && s[1]; s = s+2 )
        paddedpin[i++] = (((*s - '0') << 4) | ((s[1] - '0') & 0x0f));
      if (i < aodf->stored_length && *s)
        paddedpin[i++] = (((*s - '0') << 4)
                          |((aodf->pad_char_valid?aodf->pad_char:0)&0x0f));

      if (aodf->pinflags.needs_padding)
        {
          while (i < aodf->stored_length)
            paddedpin[i++] = aodf->pad_char_valid? aodf->pad_char : 0;
        }

      xfree (pinvalue);
      pinvalue = paddedpin;
      pinvaluelen = i;
    }
  else if (aodf->pinflags.needs_padding)
    {
      char *paddedpin;

      paddedpin = xtrymalloc (aodf->stored_length+1);
      if (!paddedpin)
        {
          err = gpg_error_from_syserror ();
          xfree (pinvalue);
          return err;
        }
      for (i=0, s=pinvalue; i < aodf->stored_length && *s; i++, s++)
        paddedpin[i] = *s;
      /* Not sure what padding char to use if none has been set.
         For now we use 0x00; maybe a space would be better. */
      for (; i < aodf->stored_length; i++)
        paddedpin[i] = aodf->pad_char_valid? aodf->pad_char : 0;
      paddedpin[i] = 0;
      pinvaluelen = i;
      xfree (pinvalue);
      pinvalue = paddedpin;
    }
  else
    pinvaluelen = strlen (pinvalue);

  /* log_printhex (pinvalue, pinvaluelen, */
  /*               "about to verify with ref %lu pin:", pin_reference); */
  err = iso7816_verify (app_get_slot (app), pin_reference,
                        pinvalue, pinvaluelen);
  xfree (pinvalue);
  if (err)
    {
      log_error ("p15: PIN verification failed: %s\n", gpg_strerror (err));
      return err;
    }
  if (opt.verbose)
    log_info ("p15: PIN verification succeeded\n");
  if (prkdf)
    prkdf->pin_verified = 1;

  return 0;
}




/* Handler for the PKSIGN command.

   Create the signature and return the allocated result in OUTDATA.
   If a PIN is required, the PINCB will be used to ask for the PIN;
   that callback should return the PIN in an allocated buffer and
   store that as the 3rd argument.  */
static gpg_error_t
do_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
         gpg_error_t (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  gpg_error_t err;
  prkdf_object_t prkdf;    /* The private key object. */
  aodf_object_t aodf;      /* The associated authentication object. */
  int mse_done = 0;        /* Set to true if the MSE has been done. */
  unsigned int digestlen;  /* Length of the hash.  */
  int exmode, le_value;
  unsigned char oidbuf[64];
  size_t oidbuflen;
  size_t n;
  unsigned char *indata_buffer = NULL; /* Malloced helper.  */

  (void)ctrl;

  if (!keyidstr || !*keyidstr || !indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err)
    return err;
  if (!(prkdf->usageflags.sign
        || prkdf->usageflags.sign_recover
        || prkdf->usageflags.non_repudiation
        || prkdf->gpgusage.cert
        || prkdf->gpgusage.sign
        || prkdf->gpgusage.auth ))
    {
      log_error ("p15: key %s may not be used for signing\n", keyidstr);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  if (!prkdf->authid)
    {
      log_error ("p15: no authentication object defined for %s\n", keyidstr);
      /* fixme: we might want to go ahead and do without PIN
         verification. */
      return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
    }

  /* Find the authentication object to this private key object. */
  for (aodf = app->app_local->auth_object_info; aodf; aodf = aodf->next)
    if (aodf->objidlen == prkdf->authidlen
        && !memcmp (aodf->objid, prkdf->authid, prkdf->authidlen))
      break;
  if (!aodf)
    log_info ("p15: no authentication for %s needed\n", keyidstr);

  /* We need some more info about the key - get the keygrip to
   * populate these fields.  */
  err = keygrip_from_prkdf (app, prkdf);
  if (err)
    {
      log_error ("p15: keygrip_from_prkdf failed: %s\n", gpg_strerror (err));
      return err;
    }


  digestlen = gcry_md_get_algo_dlen (hashalgo);

  /* We handle ECC separately from RSA so that we do not need to touch
   * working code.  In particular we prepare the input data before the
   * verify and a possible MSE.  */
  if (prkdf->is_ecc)
    {
      if (digestlen != 32 && digestlen != 48 && digestlen != 64)
        {
          log_error ("p15: ECC signing not possible: dlen=%u\n", digestlen);
          err = gpg_error (GPG_ERR_DIGEST_ALGO);
          goto leave;
        }

      if (indatalen == digestlen)
        ; /* Already prepared.  */
      else if (indatalen > digestlen)
        {
          /* Assume a PKCS#1 prefix and remove it.  */
          oidbuflen = sizeof oidbuf;
          err = gcry_md_get_asnoid (hashalgo, &oidbuf, &oidbuflen);
          if (err)
            {
              log_error ("p15: no OID for hash algo %d\n", hashalgo);
              err = gpg_error (GPG_ERR_INTERNAL);
              goto leave;
            }
          if (indatalen != oidbuflen + digestlen
              || memcmp (indata, oidbuf, oidbuflen))
            {
              log_error ("p15: input data too long for ECC: len=%zu\n",
                         indatalen);
              err = gpg_error (GPG_ERR_INV_VALUE);
              goto leave;
            }
          indata = (const char*)indata + oidbuflen;
          indatalen -= oidbuflen;
        }
      else
        {
          log_error ("p15: input data too short for ECC: len=%zu\n",
                     indatalen);
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto leave;
        }
    }
  else /* Prepare RSA input.  */
    {
      unsigned int framelen;
      unsigned char *frame;
      int i;

      framelen = (prkdf->keynbits+7) / 8;
      if (!framelen)
        {
          log_error ("p15: key length unknown"
                     " - can't prepare PKCS#v1.5 frame\n");
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto leave;
        }

      oidbuflen = sizeof oidbuf;
      if (!hashalgo)
        {
          /* We assume that indata already has the required
           * digestinfo; thus merely prepend the padding below.  */
        }
      else if ((err = gcry_md_get_asnoid (hashalgo, &oidbuf, &oidbuflen)))
        {
          log_debug ("p15: no OID for hash algo %d\n", hashalgo);
          goto leave;
        }
      else
        {
          if (indatalen == digestlen)
            {
              /* Plain hash in INDATA; prepend the digestinfo.  */
              indata_buffer = xtrymalloc (oidbuflen + indatalen);
              if (!indata_buffer)
                {
                  err = gpg_error_from_syserror ();
                  goto leave;
                }
              memcpy (indata_buffer, oidbuf, oidbuflen);
              memcpy (indata_buffer+oidbuflen, indata, indatalen);
              indata = indata_buffer;
              indatalen = oidbuflen + indatalen;
            }
          else if (indatalen == oidbuflen + digestlen
                   && !memcmp (indata, oidbuf, oidbuflen))
            ; /* We already got the correct prefix.  */
          else
            {
              err = gpg_error (GPG_ERR_INV_VALUE);
              log_error ("p15: bad input for signing with RSA and hash %d\n",
                         hashalgo);
              goto leave;
            }
        }
      /* Now prepend the pkcs#v1.5 padding.  We require at least 8
       * byte of padding and 3 extra bytes for the prefix and the
       * delimiting nul.  */
      if (!indatalen || indatalen + 8 + 4 > framelen)
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          log_error ("p15: input does not fit into a %u bit PKCS#v1.5 frame\n",
                     8*framelen);
          goto leave;
        }
      frame = xtrymalloc (framelen);
      if (!frame)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      if (app->app_local->card_type == CARD_TYPE_BELPIC)
        {
          /* This card wants only the plain hash w/o any prefix.  */
          /* FIXME: We may want to remove this code because it is unlikely
           * that such cards are still in use.  */
          memcpy (frame, indata, indatalen);
          framelen = indatalen;
        }
      else
        {
          n = 0;
          frame[n++] = 0;
          frame[n++] = 1; /* Block type. */
          i = framelen - indatalen - 3 ;
          memset (frame+n, 0xff, i);
          n += i;
          frame[n++] = 0; /* Delimiter.  */
          memcpy (frame+n, indata, indatalen);
          n += indatalen;
          log_assert (n == framelen);
        }
      /* And now put it into the indata_buffer.  */
      xfree (indata_buffer);
      indata_buffer = frame;
      indata = indata_buffer;
      indatalen = framelen;
    }

  /* Prepare PIN verification.  This is split so that we can do
   * MSE operation for some task after having selected the key file but
   * before sending the verify APDU.  */
  err = prepare_verify_pin (app, keyidstr, prkdf, aodf);
  if (err)
    return err;

  /* Due to the fact that the non-repudiation signature on a BELPIC
     card requires a verify immediately before the DSO we set the
     MSE before we do the verification.  Other cards might also allow
     this but I don't want to break anything, thus we do it only
     for the BELPIC card here.
     FIXME: see comment above about these cards.   */
  if (app->app_local->card_type == CARD_TYPE_BELPIC)
    {
      unsigned char mse[5];

      mse[0] = 4;    /* Length of the template. */
      mse[1] = 0x80; /* Algorithm reference tag. */
      if (hashalgo == MD_USER_TLS_MD5SHA1)
        mse[2] = 0x01; /* Let card do pkcs#1 0xFF padding. */
      else
        mse[2] = 0x02; /* RSASSA-PKCS1-v1.5 using SHA1. */
      mse[3] = 0x84; /* Private key reference tag. */
      mse[4] = prkdf->key_reference_valid? prkdf->key_reference : 0x82;

      err = iso7816_manage_security_env (app_get_slot (app),
                                         0x41, 0xB6,
                                         mse, sizeof mse);
      mse_done = 1;
    }
  if (err)
    {
      log_error ("p15: MSE failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Now that we have all the information available run the actual PIN
   * verification.*/
  err = verify_pin (app, pincb, pincb_arg, prkdf, aodf);
  if (err)
    return err;

  /* Manage security environment needs to be tweaked for certain cards. */
  if (mse_done)
    err = 0;
  else if (app->app_local->card_type == CARD_TYPE_TCOS)
    {
      /* TCOS creates signatures always using the local key 0.  MSE
         may not be used. */
    }
  else if (app->app_local->card_type == CARD_TYPE_MICARDO)
    {
      if (!prkdf->pathlen)
        err = gpg_error (GPG_ERR_BUG);
      else
        err = micardo_mse (app, prkdf->path[prkdf->pathlen-1]);
    }
  else if (prkdf->key_reference_valid)
    {
      unsigned char mse[3];

      mse[0] = 0x84; /* Select asym. key. */
      mse[1] = 1;
      mse[2] = prkdf->key_reference;

      err = iso7816_manage_security_env (app_get_slot (app),
                                         0x41, 0xB6,
                                         mse, sizeof mse);
    }
  if (err)
    {
      log_error ("p15: MSE failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (prkdf->keyalgo == GCRY_PK_RSA && prkdf->keynbits >= 2048)
    {
      exmode = 1;
      le_value = prkdf->keynbits / 8;
    }
  else
    {
      exmode = 0;
      le_value = 0;
    }

  err = iso7816_compute_ds (app_get_slot (app),
                            exmode, indata, indatalen,
                            le_value, outdata, outdatalen);

 leave:
  xfree (indata_buffer);
  return err;
}


/* Handler for the PKAUTH command.

   This is basically the same as the PKSIGN command but we first check
   that the requested key is suitable for authentication; that is, it
   must match the criteria used for the attribute $AUTHKEYID.  See
   do_sign for calling conventions; there is no HASHALGO, though. */
static gpg_error_t
do_auth (app_t app, ctrl_t ctrl, const char *keyidstr,
         gpg_error_t (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  gpg_error_t err;
  prkdf_object_t prkdf;
  int algo;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err)
    return err;
  if (!(prkdf->usageflags.sign || prkdf->gpgusage.auth))
    {
      log_error ("p15: key %s may not be used for authentication\n", keyidstr);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  algo = indatalen == 36? MD_USER_TLS_MD5SHA1 : GCRY_MD_SHA1;
  return do_sign (app, ctrl, keyidstr, algo, pincb, pincb_arg,
                  indata, indatalen, outdata, outdatalen);
}


/* Handler for the PKDECRYPT command.  Decrypt the data in INDATA and
 * return the allocated result in OUTDATA.  If a PIN is required the
 * PINCB will be used to ask for the PIN; it should return the PIN in
 * an allocated buffer and put it into PIN.  */
static gpg_error_t
do_decipher (app_t app, ctrl_t ctrl, const char *keyidstr,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const void *indata, size_t indatalen,
             unsigned char **outdata, size_t *outdatalen,
             unsigned int *r_info)
{
  gpg_error_t err;
  prkdf_object_t prkdf;    /* The private key object. */
  aodf_object_t aodf;      /* The associated authentication object. */
  int exmode, le_value, padind;

  (void)ctrl;
  (void)r_info;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!indatalen || !indata || !outdatalen || !outdata)
    return gpg_error (GPG_ERR_INV_ARG);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err)
    return err;
  if (!(prkdf->usageflags.decrypt
        || prkdf->usageflags.unwrap
        || prkdf->gpgusage.encr     ))
    {
      log_error ("p15: key %s may not be used for decryption\n", keyidstr);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  /* Find the authentication object to this private key object. */
  if (!prkdf->authid)
    {
      log_error ("p15: no authentication object defined for %s\n", keyidstr);
      /* fixme: we might want to go ahead and do without PIN
         verification. */
      return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
    }
  for (aodf = app->app_local->auth_object_info; aodf; aodf = aodf->next)
    if (aodf->objidlen == prkdf->authidlen
        && !memcmp (aodf->objid, prkdf->authid, prkdf->authidlen))
      break;
  if (!aodf)
    log_info ("p15: no authentication for %s needed\n", keyidstr);

  /* We need some more info about the key - get the keygrip to
   * populate these fields.  */
  err = keygrip_from_prkdf (app, prkdf);
  if (err)
    {
      log_error ("p15: keygrip_from_prkdf failed: %s\n", gpg_strerror (err));
      return err;
    }

  /* Verify the PIN.  */
  err = prepare_verify_pin (app, keyidstr, prkdf, aodf);
  if (!err)
    err = verify_pin (app, pincb, pincb_arg, prkdf, aodf);
  if (err)
    return err;

  if (prkdf->is_ecc && IS_CARDOS_5(app))
    {

      err = iso7816_manage_security_env (app_get_slot (app), 0xF3, 0x01,
                                         NULL, 0);
      if (err)
        {
          log_error ("p15: MSE failed: %s\n", gpg_strerror (err));
          return err;
        }
    }


  /* The next is guess work for CardOS.  */
  if (app->app_local->card_product == CARD_PRODUCT_DTRUST)
    {
      /* From analyzing an USB trace of a Windows signing application
       * we see that the SE is simply reset to 0x14.  It seems to be
       * sufficient to do this for decryption; signing still works
       * with the standard code despite that our trace showed that
       * there the SE is restored to 0x09.  Note that the special
       * D-Trust AID is in any case select by prepare_verify_pin.
       *
       * Hey, D-Trust please hand over the specs so that you can
       * actually sell your cards and we can properly implement it;
       * other vendors understand this and do not demand ridiculous
       * paper work or complicated procedures to get samples.  */
      err = iso7816_manage_security_env (app_get_slot (app),
                                         0xF3, 0x14, NULL, 0);

    }
  else if (prkdf->key_reference_valid)
    {
      unsigned char mse[9];
      int i;

      /* Note: This works with CardOS but the D-Trust card has the
       * problem that the next created signature would be broken.  */

      i = 0;
      if (!prkdf->is_ecc)
        {
          mse[i++] = 0x80; /* Algorithm reference.  */
          mse[i++] = 1;
          mse[i++] = 0x0a; /* RSA, no padding.  */
        }
      mse[i++] = 0x84; /* Key reference.  */
      mse[i++] = 1;
      mse[i++] = prkdf->key_reference;
      if (prkdf->is_ecc && IS_CARDOS_5(app))
        {
          mse[i++] = 0x95; /* ???.  */
          mse[i++] = 1;
          mse[i++] = 0x40;
        }
      log_assert (i <= DIM(mse));
      err = iso7816_manage_security_env (app_get_slot (app), 0x41, 0xB8,
                                         mse, i);
    }
  /* Check for MSE error.  */
  if (err)
    {
      log_error ("p15: MSE failed: %s\n", gpg_strerror (err));
      return err;
    }

  exmode = le_value = 0;
  padind = 0;
  if (prkdf->keyalgo == GCRY_PK_RSA && prkdf->keynbits >= 2048)
    {
      exmode = 1;   /* Extended length w/o a limit.  */
      le_value = prkdf->keynbits / 8;
    }

  if (app->app_local->card_product == CARD_PRODUCT_DTRUST)
    padind = 0x81;

  if (prkdf->is_ecc && IS_CARDOS_5(app))
    {
      if ((indatalen & 1) && *(const char *)indata == 0x04)
        {
          /* Strip indicator byte.  */
          indatalen--;
          indata = (const char *)indata + 1;
        }
      err = iso7816_pso_csv (app_get_slot (app), exmode,
                             indata, indatalen,
                             le_value,
                             outdata, outdatalen);
    }
  else
    {
      err = iso7816_decipher (app_get_slot (app), exmode,
                              indata, indatalen,
                              le_value, padind,
                              outdata, outdatalen);
    }

  return err;
}


/* Perform a simple verify operation for the PIN specified by
 * KEYIDSTR.  Note that we require a key reference which is then used
 * to select the authentication object.  Return GPG_ERR_NO_PIN if a
 * PIN is not required for using the private key KEYIDSTR.  */
static gpg_error_t
do_check_pin (app_t app, ctrl_t ctrl, const char *keyidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg)
{
  gpg_error_t err;
  prkdf_object_t prkdf;    /* The private key object. */
  aodf_object_t aodf;      /* The associated authentication object. */

  (void)ctrl;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err
      && gpg_err_code (err) != GPG_ERR_INV_ID
      && gpg_err_code (err) != GPG_ERR_NOT_FOUND)
    return err;

  if (err) /* Not found or invalid - assume it is the label.  */
    {
      prkdf = NULL;
      for (aodf = app->app_local->auth_object_info; aodf; aodf = aodf->next)
        if (aodf->label && !ascii_strcasecmp (aodf->label, keyidstr))
          break;
      if (!aodf)
        return err;  /* Re-use the original error code.  */
    }
  else /* Find the authentication object to this private key object. */
    {
      if (!prkdf->authid)
        {
          log_error ("p15: no authentication object defined for %s\n",
                     keyidstr);
          return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);
        }
      for (aodf = app->app_local->auth_object_info; aodf; aodf = aodf->next)
        if (aodf->objidlen == prkdf->authidlen
            && !memcmp (aodf->objid, prkdf->authid, prkdf->authidlen))
          break;
      if (!aodf) /* None found.  */
        return gpg_error (GPG_ERR_NO_PIN);
    }

  err = prepare_verify_pin (app, keyidstr, prkdf, aodf);
  if (!err)
    err = verify_pin (app, pincb, pincb_arg, prkdf, aodf);

  return err;
}


/* Process the various keygrip based info requests.  */
static gpg_error_t
do_with_keygrip (app_t app, ctrl_t ctrl, int action,
                 const char *want_keygripstr, int capability)
{
  gpg_error_t err;
  char *serialno = NULL;
  int as_data = 0;
  prkdf_object_t prkdf;

  /* First a quick check for valid parameters.  */
  switch (action)
    {
    case KEYGRIP_ACTION_LOOKUP:
      if (!want_keygripstr)
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
      break;
    case KEYGRIP_ACTION_SEND_DATA:
      as_data = 1;
      break;
    case KEYGRIP_ACTION_WRITE_STATUS:
      break;
    default:
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  /* Allocate the s/n string if needed.  */
  if (action != KEYGRIP_ACTION_LOOKUP)
    {
      serialno = app_get_serialno (app);
      if (!serialno)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  for (prkdf = app->app_local->private_key_info;
       prkdf; prkdf = prkdf->next)
    {
      if (keygrip_from_prkdf (app, prkdf))
        continue;

      if (action == KEYGRIP_ACTION_LOOKUP)
        {
          if (!strcmp (prkdf->keygrip, want_keygripstr))
            {
              err = 0; /* Found */
              goto leave;
            }
        }
      else if (!want_keygripstr || !strcmp (prkdf->keygrip, want_keygripstr))
        {
          char *keyref;

          if (capability == GCRY_PK_USAGE_SIGN)
            {
              if (!(prkdf->usageflags.sign || prkdf->usageflags.sign_recover
                    || prkdf->usageflags.non_repudiation))
                continue;
            }
          else if (capability == GCRY_PK_USAGE_ENCR)
            {
              if (!(prkdf->usageflags.decrypt || prkdf->usageflags.unwrap))
                continue;
            }
          else if (capability == GCRY_PK_USAGE_AUTH)
            {
              if (!(prkdf->usageflags.sign || prkdf->usageflags.sign_recover))
                continue;
            }

          keyref = keyref_from_prkdf (app, prkdf);
          if (!keyref)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }

          send_keyinfo (ctrl, as_data, prkdf->keygrip, serialno, keyref, NULL);
          xfree (keyref);
          if (want_keygripstr)
            {
              err = 0; /* Found */
              goto leave;
            }
        }
    }

  /* Return an error so that the dispatcher keeps on looping over the
   * other applications.  For clarity we use a different error code
   * when listing all keys.  Note that in lookup mode WANT_KEYGRIPSTR
   * is not NULL.  */
  if (!want_keygripstr)
    err = gpg_error (GPG_ERR_TRUE);
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);

 leave:
  xfree (serialno);
  return err;
}



/* Assume that EF(DIR) has been selected.  Read its content and figure
   out the home EF of pkcs#15.  Return that home DF or 0 if not found
   and the value at the address of BELPIC indicates whether it was
   found by the belpic aid. */
static unsigned short
read_home_df (int slot, int *r_belpic)
{
  gpg_error_t err;
  unsigned char *buffer;
  const unsigned char *p, *pp;
  size_t buflen, n, nn;
  unsigned short result = 0;

  *r_belpic = 0;

  err = iso7816_read_binary (slot, 0, 0, &buffer, &buflen);
  if (err)
    {
      log_error ("p15: error reading EF(DIR): %s\n", gpg_strerror (err));
      return 0;
    }

  /* FIXME: We need to scan all records. */
  p = find_tlv (buffer, buflen, 0x61, &n);
  if (p && n)
    {
      pp = find_tlv (p, n, 0x4f, &nn);
      if (pp && ((nn == sizeof pkcs15_aid && !memcmp (pp, pkcs15_aid, nn))
                 || (*r_belpic = (nn == sizeof pkcs15be_aid
                                  && !memcmp (pp, pkcs15be_aid, nn)))))
        {
          pp = find_tlv (p, n, 0x50, &nn);
          if (pp && opt.verbose)
            log_info ("p15: application label from EF(DIR) is '%.*s'\n",
                      (int)nn, pp);
          pp = find_tlv (p, n, 0x51, &nn);
          if (pp && nn == 4 && *pp == 0x3f && !pp[1])
            {
              result = ((pp[2] << 8) | pp[3]);
              if (opt.verbose)
                log_info ("p15: application directory is 0x%04hX\n", result);
            }
        }
    }
  xfree (buffer);
  return result;
}


/*
   Select the PKCS#15 application on the card in SLOT.
 */
gpg_error_t
app_select_p15 (app_t app)
{
  int slot = app_get_slot (app);
  int rc;
  unsigned short def_home_df = 0;
  card_type_t card_type = CARD_TYPE_UNKNOWN;
  int direct = 0;
  int is_belpic = 0;
  unsigned char *fci = NULL;
  size_t fcilen;

  rc = iso7816_select_application_ext (slot, pkcs15_aid, sizeof pkcs15_aid, 1,
                                       &fci, &fcilen);
  if (rc)
    { /* Not found: Try to locate it from 2F00.  We use direct path
         selection here because it seems that the Belgian eID card
         does only allow for that.  Many other cards supports this
         selection method too.  Note, that we don't use
         select_application above for the Belgian card - the call
         works but it seems that it does not switch to the correct DF.
         Using the 2f02 just works. */
      unsigned short path[1] = { 0x2f00 };

      rc = iso7816_select_path (slot, path, 1, 0);
      if (!rc)
        {
          direct = 1;
          def_home_df = read_home_df (slot, &is_belpic);
          if (def_home_df)
            {
              path[0] = def_home_df;
              rc = iso7816_select_path (slot, path, 1, 0);
            }
        }
    }
  if (rc)
    { /* Still not found:  Try the default DF. */
      def_home_df = DEFAULT_HOME_DF;
      rc = iso7816_select_file (slot, def_home_df, 1);
    }
  if (!rc)
    {
      /* Determine the type of the card.  The general case is to look
         it up from the ATR table.  For the Belgian eID card we know
         it instantly from the AID. */
      if (is_belpic)
        {
          card_type = CARD_TYPE_BELPIC;
        }
      else
        {
          unsigned char *atr;
          size_t atrlen;
          int i;

          atr = apdu_get_atr (app_get_slot (app), &atrlen);
          if (!atr)
            rc = gpg_error (GPG_ERR_INV_CARD);
          else
            {
              for (i=0; card_atr_list[i].atrlen; i++)
                if (card_atr_list[i].atrlen == atrlen
                    && !memcmp (card_atr_list[i].atr, atr, atrlen))
                  {
                    card_type = card_atr_list[i].type;
                    break;
                  }
              xfree (atr);
            }
        }
    }
  if (!rc)
    {
      app->apptype = APPTYPE_P15;

      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }

      /* Set the home DF from the FCI returned by the select.  */
      if (!def_home_df && fci)
        {
          const unsigned char *s;
          size_t n;

          s = find_tlv (fci, fcilen, 0x83, &n);
          if (s && n == 2)
            def_home_df = buf16_to_ushort (s);
          else
            {
              if (fcilen)
                log_printhex (fci, fcilen, "fci:");
              log_info ("p15: select did not return the DF - using default\n");
              def_home_df = DEFAULT_HOME_DF;
            }
        }
      app->app_local->home_df = def_home_df;

      /* Store the card type.  FIXME: We might want to put this into
         the common APP structure. */
      app->app_local->card_type = card_type;

      app->app_local->card_product = CARD_PRODUCT_UNKNOWN;

      /* Store whether we may and should use direct path selection. */
      switch (card_type)
        {
        case CARD_TYPE_CARDOS_50:
        case CARD_TYPE_CARDOS_53:
          direct = 1;
          break;
        case CARD_TYPE_AET:
          app->app_local->no_extended_mode = 1;
          break;
        default:
          /* Use whatever has been determined above.  */
          break;
        }
      app->app_local->direct_path_selection = direct;

      /* Read basic information and thus check whether this is a real
         card.  */
      rc = read_p15_info (app);
      if (rc)
        goto leave;

      /* Special serial number munging.  We need to check for a German
         prototype card right here because we need to access to
         EF(TokenInfo).  We mark such a serial number by the using a
         prefix of FF0100. */
      if (APP_CARD(app)->serialnolen == 12
          && !memcmp (APP_CARD(app)->serialno,
                      "\xD2\x76\0\0\0\0\0\0\0\0\0\0", 12))
        {
          /* This is a German card with a silly serial number.  Try to get
             the serial number from the EF(TokenInfo). . */
          unsigned char *p;

          /* FIXME: actually get it from EF(TokenInfo). */

          p = xtrymalloc (3 + APP_CARD(app)->serialnolen);
          if (!p)
            rc = gpg_error (gpg_err_code_from_errno (errno));
          else
            {
              memcpy (p, "\xff\x01", 3);
              memcpy (p+3, APP_CARD(app)->serialno, APP_CARD(app)->serialnolen);
              APP_CARD(app)->serialnolen += 3;
              xfree (APP_CARD(app)->serialno);
              APP_CARD(app)->serialno = p;
            }
        }

      app->fnc.deinit = do_deinit;
      app->fnc.prep_reselect = NULL;
      app->fnc.reselect = NULL;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.getattr = do_getattr;
      app->fnc.setattr = NULL;
      app->fnc.genkey = NULL;
      app->fnc.sign = do_sign;
      app->fnc.auth = do_auth;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = NULL;
      app->fnc.check_pin = do_check_pin;
      app->fnc.with_keygrip = do_with_keygrip;

    leave:
      if (rc)
        do_deinit (app);
   }

  xfree (fci);
  return rc;
}
