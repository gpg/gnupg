/* app-p15.c - The pkcs#15 card application.
 *	Copyright (C) 2005 Free Software Foundation, Inc.
 *	Copyright (C) 2020 g10 Code GmbH
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
#include <assert.h>
#include <time.h>

#include "scdaemon.h"

#include "iso7816.h"
#include "app-common.h"
#include "../common/i18n.h"
#include "../common/tlv.h"
#include "apdu.h" /* fixme: we should move the card detection to a
                     separate file */

/* Types of cards we know and which needs special treatment. */
typedef enum
  {
    CARD_TYPE_UNKNOWN,
    CARD_TYPE_TCOS,
    CARD_TYPE_MICARDO,
    CARD_TYPE_CARDOS_50,
    CARD_TYPE_BELPIC   /* Belgian eID card specs. */
  }
card_type_t;

/* The OS of card as specified by card_type_t is not always
 * sufficient.  Thus we also distinguish the actual product build upon
 * the given OS.  */
typedef enum
  {
    CARD_PRODUCT_UNKNOWN,
    CARD_PRODUCT_DTRUST    /* D-Trust GmbH (bundesdruckerei.de) */
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
  { 0 }
};
#undef X


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

  /* To avoid reading a certificate more than once, we cache it in an
     allocated memory IMAGE of IMAGELEN. */
  size_t imagelen;
  unsigned char *image;

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

  /* Flag indicating that the corresponding PIN has already been
   * verified. */
  unsigned int pin_verified:1;

  /* The key's usage flags. */
  keyusage_flags_t usageflags;

  /* The keygrip of the key.  This is used as a cache.  */
  char keygrip[2*KEYGRIP_LEN+1];

  /* The Gcrypt algo identifier for the key.  It is valid if the
   * keygrip is also valid.  */
  int keyalgo;

  /* The length of the key in bits (e.g. for RSA the length of the
   * modulus).  It is valid if the keygrip is also valid.  */
  unsigned int keynbits;

  /* Malloced CN from the Subject-DN of the corresponding certificate
   * or NULL if not known.  */
  char *common_name;

  /* Malloced SerialNumber from the Subject-DN of the corresponding
   * certificate or NULL if not known.  */
  char *serial_number;

  /* Length and allocated buffer with the Id of this object. */
  size_t objidlen;
  unsigned char *objid;

  /* Length and allocated buffer with the authId of this object or
     NULL if no authID is known. */
  size_t authidlen;
  unsigned char *authid;

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

  /* The file ID of this AODF.  */
  unsigned short fid;

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

  /* Flag indicating whether we may use direct path selection. */
  int direct_path_selection;

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

  /* The PKCS#15 serialnumber from EF(TokeiNFo) or NULL.  Malloced. */
  unsigned char *serialno;
  size_t serialnolen;

  /* The manufacturerID from the TokenInfo EF.  Malloced. */
  char *manufacturer_id;

  /* Information on all certificates. */
  cdf_object_t certificate_info;
  /* Information on all trusted certificates. */
  cdf_object_t trusted_certificate_info;
  /* Information on all useful certificates. */
  cdf_object_t useful_certificate_info;

  /* Information on all private keys. */
  prkdf_object_t private_key_info;

  /* Information on all authentication objects. */
  aodf_object_t auth_object_info;

};


/*** Local prototypes.  ***/
static gpg_error_t keygrip_from_prkdf (app_t app, prkdf_object_t prkdf);
static gpg_error_t readcert_by_cdf (app_t app, cdf_object_t cdf,
                                    unsigned char **r_cert, size_t *r_certlen);
static char *get_dispserialno (app_t app, prkdf_object_t prkdf);
static gpg_error_t do_getattr (app_t app, ctrl_t ctrl, const char *name);



/* Release the CDF object A  */
static void
release_cdflist (cdf_object_t a)
{
  while (a)
    {
      cdf_object_t tmp = a->next;
      xfree (a->image);
      xfree (a->objid);
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
      xfree (a->common_name);
      xfree (a->serial_number);
      xfree (a->objid);
      xfree (a->authid);
      xfree (a);
      a = tmp;
    }
}

/* Release just one aodf object. */
void
release_aodf_object (aodf_object_t a)
{
  if (a)
    {
      xfree (a->objid);
      xfree (a->authid);
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


/* Release all local resources.  */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      release_cdflist (app->app_local->certificate_info);
      release_cdflist (app->app_local->trusted_certificate_info);
      release_cdflist (app->app_local->useful_certificate_info);
      release_prkdflist (app->app_local->private_key_info);
      release_aodflist (app->app_local->auth_object_info);
      xfree (app->app_local->manufacturer_id);
      xfree (app->app_local->serialno);
      xfree (app->app_local);
      app->app_local = NULL;
    }
}



/* Do a select and a read for the file with EFID.  EFID_DESC is a
   desctription of the EF to be used with error messages.  On success
   BUFFER and BUFLEN contain the entire content of the EF.  The caller
   must free BUFFER only on success. */
static gpg_error_t
select_and_read_binary (int slot, unsigned short efid, const char *efid_desc,
                        unsigned char **buffer, size_t *buflen)
{
  gpg_error_t err;

  err = iso7816_select_file (slot, efid, 0);
  if (err)
    {
      log_error ("p15: error selecting %s (0x%04X): %s\n",
                 efid_desc, efid, gpg_strerror (err));
      return err;
    }
  err = iso7816_read_binary (slot, 0, 0, buffer, buflen);
  if (err)
    {
      log_error ("p15: error reading %s (0x%04X): %s\n",
                 efid_desc, efid, gpg_strerror (err));
      return err;
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

  if (pathlen && *path != 0x3f00 )
    log_error ("p15: warning: relative path selection not yet implemented\n");

  if (app->app_local->direct_path_selection)
    {
      err = iso7816_select_path (app->slot, path+1, pathlen-1);
      if (err)
        {
          log_error ("p15: error selecting path ");
          for (j=0; j < pathlen; j++)
            log_printf ("%04hX", path[j]);
          log_printf (": %s\n", gpg_strerror (err));
          return err;
        }
    }
  else
    {
      /* FIXME: Need code to remember the last PATH so that we can decide
         what select commands to send in case the path does not start off
         with 3F00.  We might also want to use direct path selection if
         supported by the card. */
      for (i=0; i < pathlen; i++)
        {
          err = iso7816_select_file (app->slot, path[i], !(i+1 == pathlen));
          if (err)
            {
              log_error ("p15: error selecting part %d from path ", i);
              for (j=0; j < pathlen; j++)
                log_printf ("%04hX", path[j]);
              log_printf (": %s\n", gpg_strerror (err));
              return err;
            }
        }
    }
  return 0;
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
      if (app->app_local->home_df)
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


/* Find a certificate object by the certificate ID CERTID and store a
   pointer to it at R_CDF. */
static gpg_error_t
cdf_object_from_certid (app_t app, const char *certid, cdf_object_t *r_cdf)
{
  gpg_error_t err;
  size_t objidlen;
  unsigned char *objid;
  cdf_object_t cdf;

  err = parse_certid (app, certid, &objid, &objidlen);
  if (err)
    return err;

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
  xfree (objid);
  if (!cdf)
    return gpg_error (GPG_ERR_NOT_FOUND);
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

  err = select_and_read_binary (app->slot, odf_fid, "ODF", &buffer, &buflen);
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

/* Read and  parse the Private Key Directory Files. */
/*
  6034 (privatekeys)

30 33 30 11 0C 08 53 4B 2E  43 48 2E 44 53 03 02   030...SK.CH.DS..
06 80 04 01 07 30 0C 04 01  01 03 03 06 00 40 02   .....0........@.
02 00 50 A1 10 30 0E 30 08  04 06 3F 00 40 16 00   ..P..0.0...?.@..
50 02 02 04 00 30 33 30 11  0C 08 53 4B 2E 43 48   P....030...SK.CH
2E 4B 45 03 02 06 80 04 01  0A 30 0C 04 01 0C 03   .KE.......0.....
03 06 44 00 02 02 00 52 A1  10 30 0E 30 08 04 06   ..D....R..0.0...
3F 00 40 16 00 52 02 02 04  00 30 34 30 12 0C 09   ?.@..R....040...
53 4B 2E 43 48 2E 41 55 54  03 02 06 80 04 01 0A   SK.CH.AUT.......
30 0C 04 01 0D 03 03 06 20  00 02 02 00 51 A1 10   0....... ....Q..
30 0E 30 08 04 06 3F 00 40  16 00 51 02 02 04 00   0.0...?.@..Q....
30 37 30 15 0C 0C 53 4B 2E  43 48 2E 44 53 2D 53   070...SK.CH.DS-S
50 58 03 02 06 80 04 01 0A  30 0C 04 01 02 03 03   PX.......0......
06 20 00 02 02 00 53 A1 10  30 0E 30 08 04 06 3F   . ....S..0.0...?
00 40 16 00 53 02 02 04 00  00 00 00 00 00 00 00   .@..S...........
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................

   0 30   51: SEQUENCE {
   2 30   17:   SEQUENCE { -- commonObjectAttributes
   4 0C    8:     UTF8String 'SK.CH.DS'
  14 03    2:     BIT STRING 6 unused bits
            :       '01'B (bit 0)
  18 04    1:     OCTET STRING --authid
            :       07
            :     }
  21 30   12:   SEQUENCE { -- commonKeyAttributes
  23 04    1:     OCTET STRING
            :       01
  26 03    3:     BIT STRING 6 unused bits
            :       '1000000000'B (bit 9)
  31 02    2:     INTEGER 80  -- keyReference (optional)
            :     }
  35 A1   16:   [1] {  -- keyAttributes
  37 30   14:     SEQUENCE { -- privateRSAKeyAttributes
  39 30    8:       SEQUENCE { -- objectValue
  41 04    6:         OCTET STRING --path
            :           3F 00 40 16 00 50
            :         }
  49 02    2:       INTEGER 1024 -- modulus
            :       }
            :     }
            :   }


*/
static gpg_error_t
read_ef_prkdf (app_t app, unsigned short fid, prkdf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  prkdf_object_t prkdflist = NULL;
  int i;

  if (!fid)
    return gpg_error (GPG_ERR_NO_DATA); /* No private keys. */

  err = select_and_read_binary (app->slot, fid, "PrKDF", &buffer, &buflen);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  /* FIXME: This shares a LOT of code with read_ef_cdf! */

  /* Loop over the records.  We stop as soon as we detect a new record
     starting with 0x00 or 0xff as these values are commonly used to
     pad data blocks and are no valid ASN.1 encoding. */
  while (n && *p && *p != 0xff)
    {
      const unsigned char *pp;
      size_t nn;
      int where;
      const char *errstr = NULL;
      prkdf_object_t prkdf = NULL;
      unsigned long ul;
      const unsigned char *objid;
      size_t objidlen;
      const unsigned char *authid = NULL;
      size_t authidlen = 0;
      keyusage_flags_t usageflags;
      unsigned long key_reference = 0;
      int key_reference_valid = 0;
      const char *s;

      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > n || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
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

        /* Search the optional AuthId.  We need to skip the optional
           Label (UTF8STRING) and the optional CommonObjectFlags
           (BITSTRING). */
        where = __LINE__;
        err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                &ndef, &objlen, &hdrlen);
        if (!err && (objlen > nnn || class != CLASS_UNIVERSAL))
          err = gpg_error (GPG_ERR_INV_OBJ);
        if (gpg_err_code (err) == GPG_ERR_EOF)
          goto no_authid;
        if (err)
          goto parse_error;
        if (tag == TAG_UTF8_STRING)
          {
            ppp += objlen; /* Skip the Label. */
            nnn -= objlen;

            where = __LINE__;
            err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                    &ndef, &objlen, &hdrlen);
            if (!err && (objlen > nnn || class != CLASS_UNIVERSAL))
              err = gpg_error (GPG_ERR_INV_OBJ);
            if (gpg_err_code (err) == GPG_ERR_EOF)
              goto no_authid;
            if (err)
              goto parse_error;
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
            if (gpg_err_code (err) == GPG_ERR_EOF)
              goto no_authid;
            if (err)
              goto parse_error;
          }
        if (tag == TAG_OCTET_STRING && objlen)
          {
            authid = ppp;
            authidlen = objlen;
          }
      no_authid:
        ;
      }

      /* Parse the commonKeyAttributes.  */
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
          goto parse_error;
        err = parse_keyusage_flags (ppp, objlen, &usageflags);
        if (err)
          goto parse_error;
        ppp += objlen;
        nnn -= objlen;

        /* Find the keyReference */
        where = __LINE__;
        err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
        if (gpg_err_code (err) == GPG_ERR_EOF)
          goto leave_cki;
        if (!err && objlen > nnn)
          err = gpg_error (GPG_ERR_INV_OBJ);
        if (err)
          goto parse_error;
        if (class == CLASS_UNIVERSAL && tag == TAG_BOOLEAN)
          {
            /* Skip the native element. */
            ppp += objlen;
            nnn -= objlen;

            err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                    &ndef, &objlen, &hdrlen);
            if (gpg_err_code (err) == GPG_ERR_EOF)
              goto leave_cki;
            if (!err && objlen > nnn)
              err = gpg_error (GPG_ERR_INV_OBJ);
            if (err)
              goto parse_error;
          }
        if (class == CLASS_UNIVERSAL && tag == TAG_BIT_STRING)
          {
            /* Skip the accessFlags. */
            ppp += objlen;
            nnn -= objlen;

            err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                    &ndef, &objlen, &hdrlen);
            if (gpg_err_code (err) == GPG_ERR_EOF)
              goto leave_cki;
            if (!err && objlen > nnn)
              err = gpg_error (GPG_ERR_INV_OBJ);
            if (err)
              goto parse_error;
          }
        if (class == CLASS_UNIVERSAL && tag == TAG_INTEGER)
          {
            /* Yep, this is the keyReference.  */
            for (ul=0; objlen; objlen--)
              {
                ul <<= 8;
                ul |= (*ppp++) & 0xff;
                nnn--;
            }
            key_reference = ul;
            key_reference_valid = 1;
          }

      leave_cki:
        ;
      }


      /* Skip subClassAttributes.  */
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
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        ; /* RSA */
      else if (class == CLASS_CONTEXT)
        {
          switch (tag)
            {
            case 0: errstr = "EC key objects are not supported"; break;
            case 1: errstr = "DH key objects are not supported"; break;
            case 2: errstr = "DSA key objects are not supported"; break;
            case 3: errstr = "KEA key objects are not supported"; break;
            default: errstr = "unknown privateKeyObject"; break;
            }
          goto parse_error;
        }
      else
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto parse_error;
        }

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

      /* Make sure that the next element is a non zero path and of
         even length (FID are two bytes each). */
      if (class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING
          ||  !objlen || (objlen & 1) )
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
      prkdf->objidlen = objidlen;
      prkdf->objid = xtrymalloc (objidlen);
      if (!prkdf->objid)
        {
          err = gpg_error_from_syserror ();
          xfree (prkdf);
          goto leave;
        }
      memcpy (prkdf->objid, objid, objidlen);
      if (authid)
        {
          prkdf->authidlen = authidlen;
          prkdf->authid = xtrymalloc (authidlen);
          if (!prkdf->authid)
            {
              err = gpg_error_from_syserror ();
              xfree (prkdf->objid);
              xfree (prkdf);
              goto leave;
            }
          memcpy (prkdf->authid, authid, authidlen);
        }

      prkdf->pathlen = objlen/2;
      for (i=0; i < prkdf->pathlen; i++, pp += 2, nn -= 2)
        prkdf->path[i] = ((pp[0] << 8) | pp[1]);

      prkdf->usageflags = usageflags;
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


      if (opt.verbose)
        {
          log_info ("p15: PrKDF %04hX: id=", fid);
          for (i=0; i < prkdf->objidlen; i++)
            log_printf ("%02X", prkdf->objid[i]);
          log_printf (" path=");
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
          log_info ("p15:             usage=");
          s = "";
          if (prkdf->usageflags.encrypt) log_printf ("%sencrypt", s), s = ",";
          if (prkdf->usageflags.decrypt) log_printf ("%sdecrypt", s), s = ",";
          if (prkdf->usageflags.sign   ) log_printf ("%ssign", s), s = ",";
          if (prkdf->usageflags.sign_recover)
            log_printf ("%ssign_recover", s), s = ",";
          if (prkdf->usageflags.wrap   ) log_printf ("%swrap", s), s = ",";
          if (prkdf->usageflags.unwrap ) log_printf ("%sunwrap", s), s = ",";
          if (prkdf->usageflags.verify ) log_printf ("%sverify", s), s = ",";
          if (prkdf->usageflags.verify_recover)
            log_printf ("%sverify_recover", s), s = ",";
          if (prkdf->usageflags.derive ) log_printf ("%sderive", s), s = ",";
          if (prkdf->usageflags.non_repudiation)
            log_printf ("%snon_repudiation", s), s = ",";
          log_printf ("\n");
        }

      /* Put it into the list. */
      prkdf->next = prkdflist;
      prkdflist = prkdf;
      prkdf = NULL;
      continue; /* Ready. */

    parse_error:
      log_error ("p15: error parsing PrKDF record (%d): %s - skipped\n",
                 where, errstr? errstr : gpg_strerror (err));
      if (prkdf)
        {
          xfree (prkdf->objid);
          xfree (prkdf->authid);
          xfree (prkdf);
        }
      err = 0;
    } /* End looping over all records. */

 leave:
  xfree (buffer);
  if (err)
    release_prkdflist (prkdflist);
  else
    *result = prkdflist;
  return err;
}


/* Read and parse the Certificate Directory Files identified by FID.
   On success a newlist of CDF object gets stored at RESULT and the
   caller is then responsible of releasing this list.  On error a
   error code is returned and RESULT won't get changed.  */
static gpg_error_t
read_ef_cdf (app_t app, unsigned short fid, cdf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  cdf_object_t cdflist = NULL;
  int i;

  if (!fid)
    return gpg_error (GPG_ERR_NO_DATA); /* No certificates. */

  err = select_and_read_binary (app->slot, fid, "CDF", &buffer, &buflen);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  /* Loop over the records.  We stop as soon as we detect a new record
     starting with 0x00 or 0xff as these values are commonly used to
     pad data blocks and are no valid ASN.1 encoding. */
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

      /* Skip the commonObjectAttributes.  */
      where = __LINE__;
      err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > nn || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      pp += objlen;
      nn -= objlen;

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

      /* Make sure that the next element is a non zero path and of
         even length (FID are two bytes each). */
      if (class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING
          ||  !objlen || (objlen & 1) )
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
          log_info ("p15: CDF %04hX: id=", fid);
          for (i=0; i < cdf->objidlen; i++)
            log_printf ("%02X", cdf->objid[i]);
          log_printf (" path=");
          for (i=0; i < cdf->pathlen; i++)
            log_printf ("%s%04hX", i?"/":"", cdf->path[i]);
          if (cdf->have_off)
            log_printf ("[%lu/%lu]", cdf->off, cdf->len);
          log_printf ("\n");
        }

      /* Put it into the list. */
      cdf->next = cdflist;
      cdflist = cdf;
      cdf = NULL;
      continue; /* Ready. */

    parse_error:
      log_error ("p15: error parsing CDF record (%d): %s - skipped\n",
                 where, errstr? errstr : gpg_strerror (err));
      xfree (cdf);
      err = 0;
    } /* End looping over all records. */

 leave:
  xfree (buffer);
  if (err)
    release_cdflist (cdflist);
  else
    *result = cdflist;
  return err;
}


/*
SEQUENCE {
  SEQUENCE { -- CommonObjectAttributes
    UTF8String 'specific PIN for DS'
    BIT STRING 0 unused bits
      '00000011'B
    }
  SEQUENCE { -- CommonAuthenticationObjectAttributes
    OCTET STRING
      07    -- iD
    }

  [1] { -- typeAttributes
    SEQUENCE { -- PinAttributes
      BIT STRING 0 unused bits
        '0000100000110010'B  -- local,initialized,needs-padding
                             -- exchangeRefData
      ENUMERATED 1           -- ascii-numeric
      INTEGER 6              -- minLength
      INTEGER 6              -- storedLength
      INTEGER 8              -- maxLength
      [0]
        02                   -- pinReference
      GeneralizedTime 19/04/2002 12:12 GMT  -- lastPinChange
      SEQUENCE {
        OCTET STRING
          3F 00 40 16        -- path to DF of PIN
        }
      }
    }
  }

*/
/* Read and parse an Authentication Object Directory File identified
   by FID.  On success a newlist of AODF objects gets stored at RESULT
   and the caller is responsible of releasing this list.  On error a
   error code is returned and RESULT won't get changed.  */
static gpg_error_t
read_ef_aodf (app_t app, unsigned short fid, aodf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  aodf_object_t aodflist = NULL;
  int i;

  if (!fid)
    return gpg_error (GPG_ERR_NO_DATA); /* No authentication objects. */

  err = select_and_read_binary (app->slot, fid, "AODF", &buffer, &buflen);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  /* FIXME: This shares a LOT of code with read_ef_prkdf! */

  /* Loop over the records.  We stop as soon as we detect a new record
     starting with 0x00 or 0xff as these values are commonly used to
     pad data blocks and are no valid ASN.1 encoding. */
  while (n && *p && *p != 0xff)
    {
      const unsigned char *pp;
      size_t nn;
      int where;
      const char *errstr = NULL;
      aodf_object_t aodf = NULL;
      unsigned long ul;
      const char *s;

      err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                              &ndef, &objlen, &hdrlen);
      if (!err && (objlen > n || tag != TAG_SEQUENCE))
        err = gpg_error (GPG_ERR_INV_OBJ);
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

      /* Parse the commonObjectAttributes.  */
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

        /* Search the optional AuthId.  We need to skip the optional
           Label (UTF8STRING) and the optional CommonObjectFlags
           (BITSTRING). */
        where = __LINE__;
        err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                &ndef, &objlen, &hdrlen);
        if (!err && (objlen > nnn || class != CLASS_UNIVERSAL))
          err = gpg_error (GPG_ERR_INV_OBJ);
        if (gpg_err_code (err) == GPG_ERR_EOF)
          goto no_authid;
        if (err)
          goto parse_error;
        if (tag == TAG_UTF8_STRING)
          {
            ppp += objlen; /* Skip the Label. */
            nnn -= objlen;

            where = __LINE__;
            err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                    &ndef, &objlen, &hdrlen);
            if (!err && (objlen > nnn || class != CLASS_UNIVERSAL))
              err = gpg_error (GPG_ERR_INV_OBJ);
            if (gpg_err_code (err) == GPG_ERR_EOF)
              goto no_authid;
            if (err)
              goto parse_error;
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
            if (gpg_err_code (err) == GPG_ERR_EOF)
              goto no_authid;
            if (err)
              goto parse_error;
          }
        if (tag == TAG_OCTET_STRING && objlen)
          {
            aodf->authidlen = objlen;
            aodf->authid = xtrymalloc (objlen);
            if (!aodf->authid)
              goto no_core;
            memcpy (aodf->authid, ppp, objlen);
          }
      no_authid:
        ;
      }

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
      if (!err && objlen > nn)
        err = gpg_error (GPG_ERR_INV_OBJ);
      if (err)
        goto parse_error;
      if (class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE)
        ; /* PinAttributes */
      else if (class == CLASS_CONTEXT)
        {
          switch (tag)
            {
            case 0: errstr = "biometric auth types are not supported"; break;
            case 1: errstr = "authKey auth types are not supported"; break;
            case 2: errstr = "external auth type are not supported"; break;
            default: errstr = "unknown privateKeyObject"; break;
            }
          goto parse_error;
        }
      else
        {
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto parse_error;
        }

      nn = objlen;

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

          /* Make sure that the next element is a non zero FID and of
             even length (FID are two bytes each). */
          if (class != CLASS_UNIVERSAL || tag != TAG_OCTET_STRING
              ||  !objlen || (objlen & 1) )
            {
              errstr = "invalid path reference";
              goto parse_error;
            }

          aodf->pathlen = objlen/2;
          aodf->path = xtrymalloc (aodf->pathlen);
          if (!aodf->path)
            goto no_core;
          for (i=0; i < aodf->pathlen; i++, ppp += 2, nnn -= 2)
            aodf->path[i] = ((ppp[0] << 8) | ppp[1]);

          if (nnn)
            {
              /* An index and length follows. */
              aodf->have_off = 1;
              where = __LINE__;
              err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
                                      &ndef, &objlen, &hdrlen);
              if (!err && (objlen > nnn
                       || class != CLASS_UNIVERSAL || tag != TAG_INTEGER))
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
              err = parse_ber_header (&ppp, &nnn, &class, &tag, &constructed,
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

      /* Igonore further objects which might be there due to future
         extensions of pkcs#15. */

    ready:
      if (opt.verbose)
        {
          log_info ("p15: AODF %04hX: id=", fid);
          for (i=0; i < aodf->objidlen; i++)
            log_printf ("%02X", aodf->objid[i]);
          if (aodf->authid)
            {
              log_printf (" authid=");
              for (i=0; i < aodf->authidlen; i++)
                log_printf ("%02X", aodf->authid[i]);
            }
          if (aodf->pin_reference_valid)
            log_printf (" pinref=0x%02lX", aodf->pin_reference);
          if (aodf->pathlen)
            {
              log_printf (" path=");
              for (i=0; i < aodf->pathlen; i++)
                log_printf ("%s%04hX", i?"/":"",aodf->path[i]);
              if (aodf->have_off)
                log_printf ("[%lu/%lu]", aodf->off, aodf->len);
            }
          log_printf (" min=%lu", aodf->min_length);
          log_printf (" stored=%lu", aodf->stored_length);
          if (aodf->max_length_valid)
            log_printf (" max=%lu", aodf->max_length);
          if (aodf->pad_char_valid)
            log_printf (" pad=0x%02x", aodf->pad_char);

          log_info ("p15:            flags=");
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
            switch (aodf->pintype)
              {
              case PIN_TYPE_BCD: s = "bcd"; break;
              case PIN_TYPE_ASCII_NUMERIC: s = "ascii-numeric"; break;
              case PIN_TYPE_UTF8: s = "utf8"; break;
              case PIN_TYPE_HALF_NIBBLE_BCD: s = "half-nibble-bcd"; break;
              case PIN_TYPE_ISO9564_1: s = "iso9564-1"; break;
              default:
                sprintf (numbuf, "%lu", (unsigned long)aodf->pintype);
                s = numbuf;
              }
            log_printf (" type=%s", s);
          }
          log_printf ("\n");
        }

      /* Put it into the list. */
      aodf->next = aodflist;
      aodflist = aodf;
      aodf = NULL;
      continue; /* Ready. */

    no_core:
      err = gpg_error_from_syserror ();
      release_aodf_object (aodf);
      goto leave;

    parse_error:
      log_error ("p15: error parsing AODF record (%d): %s - skipped\n",
                 where, errstr? errstr : gpg_strerror (err));
      err = 0;
      release_aodf_object (aodf);
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

TokenInfo ::= SEQUENCE {
    version		INTEGER {v1(0)} (v1,...),
    serialNumber	OCTET STRING,
    manufacturerID 	Label OPTIONAL,
    label 		[0] Label OPTIONAL,
    tokenflags 		TokenFlags,
    seInfo 		SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,
    recordInfo 		[1] RecordInfo OPTIONAL,
    supportedAlgorithms	[2] SEQUENCE OF AlgorithmInfo OPTIONAL,
    ...,
    issuerId		[3] Label OPTIONAL,
    holderId		[4] Label OPTIONAL,
    lastUpdate		[5] LastUpdate OPTIONAL,
    preferredLanguage	PrintableString OPTIONAL -- In accordance with
    -- IETF RFC 1766
} (CONSTRAINED BY { -- Each AlgorithmInfo.reference value must be unique --})

TokenFlags ::= BIT STRING {
    readOnly		(0),
    loginRequired 	(1),
    prnGeneration 	(2),
    eidCompliant  	(3)
}


 5032:

30 31 02 01 00 04 04 05 45  36 9F 0C 0C 44 2D 54   01......E6...D-T
72 75 73 74 20 47 6D 62 48  80 14 4F 66 66 69 63   rust GmbH..Offic
65 20 69 64 65 6E 74 69 74  79 20 63 61 72 64 03   e identity card.
02 00 40 20 63 61 72 64 03  02 00 40 00 00 00 00   ..@ card...@....
00 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00   ................

   0   49: SEQUENCE {
   2    1:   INTEGER 0
   5    4:   OCTET STRING 05 45 36 9F
  11   12:   UTF8String 'D-Trust GmbH'
  25   20:   [0] 'Office identity card'
  47    2:   BIT STRING
         :     '00000010'B (bit 1)
         :     Error: Spurious zero bits in bitstring.
         :   }




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

  xfree (app->app_local->manufacturer_id);
  app->app_local->manufacturer_id = NULL;
  app->app_local->card_product = CARD_PRODUCT_UNKNOWN;

  err = select_and_read_binary (app->slot, 0x5032, "TokenInfo",
                                &buffer, &buflen);
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

  if (opt.verbose)
    log_info ("p15: TokenInfo:\n");
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
  if (opt.verbose)
    {
      /* (We use a separate log_info to avoid the "DBG:" prefix.)  */
      log_info ("p15:  serialNumber .: ");
      log_printhex (p, objlen, "");
    }
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
      if (opt.verbose)
        log_info ("p15:  manufacturerID: %.*s\n", (int)objlen, p);
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
      if (opt.verbose)
        log_info ("p15:  label ........: %.*s\n", (int)objlen, p);
      if (objlen > 15 && !memcmp (p, "D-TRUST Card V3", 15)
          && app->app_local->card_type == CARD_TYPE_CARDOS_50)
        app->app_local->card_product = CARD_PRODUCT_DTRUST;

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
      if (opt.verbose)
        {
          log_info ("p15:  tokenflags ...:");
          print_tokeninfo_tokenflags (p, objlen);
          log_printf ("\n");
        }
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

  if (!read_ef_tokeninfo (app))
    {
      /* If we don't have a serial number yet but the TokenInfo provides
         one, use that. */
      if (!app->serialno && app->app_local->serialno)
        {
          app->serialno = app->app_local->serialno;
          app->serialnolen = app->app_local->serialnolen;
          app->app_local->serialno = NULL;
          app->app_local->serialnolen = 0;
          err = app_munge_serialno (app);
          if (err)
            return err;
        }
    }

  /* Read the ODF so that we know the location of all directory
     files. */
  /* Fixme: We might need to get a non-standard ODF FID from TokenInfo. */
  err = read_ef_odf (app, 0x5031);
  if (err)
    return err;

  /* Read certificate information. */
  assert (!app->app_local->certificate_info);
  assert (!app->app_local->trusted_certificate_info);
  assert (!app->app_local->useful_certificate_info);
  err = read_ef_cdf (app, app->app_local->odf.certificates,
                     &app->app_local->certificate_info);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = read_ef_cdf (app, app->app_local->odf.trusted_certificates,
                       &app->app_local->trusted_certificate_info);
  if (!err || gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = read_ef_cdf (app, app->app_local->odf.useful_certificates,
                       &app->app_local->useful_certificate_info);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0;
  if (err)
    return err;

  /* Read information about private keys. */
  assert (!app->app_local->private_key_info);
  err = read_ef_prkdf (app, app->app_local->odf.private_keys,
                       &app->app_local->private_key_info);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0;
  if (err)
    return err;

  /* Read information about authentication objects. */
  assert (!app->app_local->auth_object_info);
  err = read_ef_aodf (app, app->app_local->odf.auth_objects,
                      &app->app_local->auth_object_info);
  if (gpg_err_code (err) == GPG_ERR_NO_DATA)
    err = 0;


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

      buf = xtrymalloc (9 + certinfo->objidlen*2 + 1);
      if (!buf)
        return gpg_error_from_syserror ();
      p = stpcpy (buf, "P15");
      if (app->app_local->home_df)
        {
          snprintf (p, 6, "-%04X",
                    (unsigned int)(app->app_local->home_df & 0xffff));
          p += 5;
        }
      p = stpcpy (p, ".");
      bin2hex (certinfo->objid, certinfo->objidlen, p);

      send_status_info (ctrl, "CERTINFO",
                        certtype, strlen (certtype),
                        buf, strlen (buf),
                        NULL, (size_t)0);
      xfree (buf);
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

  /* FIXME: We should check whether a public key directory file and a
     matching public key for PRKDF is available.  This should make
     extraction of the key much easier.  My current test card doesn't
     have one, so we can only use the fallback solution by looking for
     a matching certificate and extract the key from there. */

  /* Look for a matching certificate. A certificate matches if the Id
     matches the one of the private key info. */
  for (cdf = app->app_local->certificate_info; cdf; cdf = cdf->next)
    if (cdf->objidlen == prkdf->objidlen
        && !memcmp (cdf->objid, prkdf->objid, prkdf->objidlen))
      break;
  if (!cdf)
    for (cdf = app->app_local->trusted_certificate_info; cdf; cdf = cdf->next)
      if (cdf->objidlen == prkdf->objidlen
          && !memcmp (cdf->objid, prkdf->objid, prkdf->objidlen))
        break;
  if (!cdf)
    for (cdf = app->app_local->useful_certificate_info; cdf; cdf = cdf->next)
      if (cdf->objidlen == prkdf->objidlen
          && !memcmp (cdf->objid, prkdf->objid, prkdf->objidlen))
        break;
  if (!cdf)
    {
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  err = readcert_by_cdf (app, cdf, &der, &derlen);
  if (err)
    goto leave;

  err = ksba_cert_new (&cert);
  if (!err)
    err = ksba_cert_init_from_mem (cert, der, derlen);
  xfree (der);
  if (!err)
    err = app_help_get_keygrip_string (cert, prkdf->keygrip, &s_pkey);
  if (!err)
    {
      /* Try to get the CN and the SerialNumber from the certificate;
       * we use a very simple approach here which should work in many
       * cases.  Eventually we should add a rfc-2253 parser into
       * libksba to make it easier to parse such a string.
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
  if (app->app_local->home_df)
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
          size_t usagelen = 0;

          if (prkdf->usageflags.sign
              || prkdf->usageflags.sign_recover
              || prkdf->usageflags.non_repudiation)
            usage[usagelen++] = 's';
          if (prkdf->usageflags.sign
              || prkdf->usageflags.sign_recover)
            usage[usagelen++] = 'c';
          if (prkdf->usageflags.decrypt
              || prkdf->usageflags.unwrap)
            usage[usagelen++] = 'e';
          if (prkdf->usageflags.sign
              || prkdf->usageflags.sign_recover)
            usage[usagelen++] = 'a';

          log_assert (strlen (prkdf->keygrip) == 40);
          send_status_info (ctrl, "KEYPAIRINFO",
                            prkdf->keygrip, 2*KEYGRIP_LEN,
                            buf, strlen (buf),
                            usage, usagelen,
                            NULL, (size_t)0);
        }
      xfree (buf);
    }
  return 0;
}



/* This is the handler for the LEARN command.  */
static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;

  if ((flags & 1))
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

  return err;
}


/* Read a certifciate using the information in CDF and return the
   certificate in a newly llocated buffer R_CERT and its length
   R_CERTLEN. */
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

  *r_cert = NULL;
  *r_certlen = 0;

  /* First check whether it has been cached. */
  if (cdf->image)
    {
      *r_cert = xtrymalloc (cdf->imagelen);
      if (!*r_cert)
        return gpg_error_from_syserror ();
      memcpy (*r_cert, cdf->image, cdf->imagelen);
      *r_certlen = cdf->imagelen;
      return 0;
    }

  /* Read the entire file.  fixme: This could be optimized by first
     reading the header to figure out how long the certificate
     actually is. */
  err = select_ef_by_path (app, cdf->path, cdf->pathlen);
  if (err)
    goto leave;

  err = iso7816_read_binary_ext (app_get_slot (app), 1, cdf->off, cdf->len,
                                 &buffer, &buflen);
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
  assert (totobjlen <= buflen);

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
      assert (save_p + totobjlen <= buffer + buflen);
      memmove (buffer, save_p, totobjlen);
    }

  *r_cert = buffer;
  buffer = NULL;
  *r_certlen = totobjlen;

  /* Try to cache it. */
  if (!cdf->image && (cdf->image = xtrymalloc (*r_certlen)))
    {
      memcpy (cdf->image, *r_cert, *r_certlen);
      cdf->imagelen = *r_certlen;
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
       * requested action.  Note that we do not yet return
       * non_repudiation keys for $SIGNKEYID because our D-Trust
       * testcard uses rsaPSS, which is not supported by gpgsm and not
       * covered by the VS-NfD approval.  */
      for (prkdf = app->app_local->private_key_info; prkdf;
           prkdf = prkdf->next)
        {
          if (name[1] == 'A' && (prkdf->usageflags.sign
                                 || prkdf->usageflags.sign_recover))
            break;
          else if (name[1] == 'E' && (prkdf->usageflags.decrypt
                                      || prkdf->usageflags.unwrap))
            break;
          else if (name[1] == 'S' && (prkdf->usageflags.sign
                                      || prkdf->usageflags.sign_recover))
            break;
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
            err = iso7816_read_binary (app->slot, 0, 0, &buffer, &buflen);
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
          if (prkdf)
            {
              char *sn = get_dispserialno (app, prkdf);
              /* Unless there is a bogus S/N in the cert we should
               * have a suitable one from the cert here now.  */
              err = send_status_printf (ctrl, name, "%s", sn);
              xfree (sn);
              return err;
            }
        }
      /* No abbreviated serial number. */
    }
  else if (!strcmp (name, "MANUFACTURER"))
    {
      if (app->app_local->manufacturer_id)
        return send_status_printf (ctrl, "MANUFACTURER", "0 %s",
                                   app->app_local->manufacturer_id);
      else
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
  err = iso7816_select_file (app->slot, 0x0013, 0);
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

      err = iso7816_read_record (app->slot, recno, 1, 0, &buffer, &buflen);
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
      err = iso7816_manage_security_env (app->slot, 0xf3, se_num, NULL, 0);
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
  err = iso7816_manage_security_env (app->slot, 0x41, 0xb6, msebuf, 5);
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
 * messages.  */
static gpg_error_t
prepare_verify_pin (app_t app, const char *keyref,
                    prkdf_object_t prkdf, aodf_object_t aodf)
{
  gpg_error_t err;
  int i;

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
      log_error ("p15: "
                 "PIN verification requires unsupported protection method\n");
      return gpg_error (GPG_ERR_BAD_PIN_METHOD);
    }
  if (!aodf->stored_length && aodf->pinflags.needs_padding)
    {
      log_error ("p15: "
                 "PIN verification requires padding but no length known\n");
      return gpg_error (GPG_ERR_INV_CARD);
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
  else
    {
      /* Standard case: Select the key file.  Note that this may
       * change the security environment thus we need to do it before
       * PIN verification. */
      err = select_ef_by_path (app, prkdf->path, prkdf->pathlen);
      if (err)
        log_error ("p15: error selecting file for key %s: %s\n",
                   keyref, gpg_strerror (err));
    }

  return err;
}


static int
any_control_or_space (const char *string)
{
  const unsigned char *s;

  for (s = string; *string; string++)
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

  /* We prefer the SerialNumber RDN from the Subject-DN but we don't
   * use it if it features a percent sign (special character in pin
   * prompts) or has any control character.  */
  if (prkdf && prkdf->serial_number && *prkdf->serial_number
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


/* Return an allocated string to be used as prompt.  Returns NULL on
 * malloc error.  */
static char *
make_pin_prompt (app_t app, int remaining, const char *firstline,
                 prkdf_object_t prkdf)
{
  char *serial, *tmpbuf, *result;

  serial = get_dispserialno (app, prkdf);

  /* TRANSLATORS: Put a \x1f right before a colon.  This can be
   * used by pinentry to nicely align the names and values.  Keep
   * the %s at the start and end of the string.  */
  result = xtryasprintf (_("%s"
                           "Number\x1f: %s%%0A"
                           "Holder\x1f: %s"
                           "%s"),
                         "\x1e",
                         serial,
                         prkdf->common_name? prkdf->common_name: "",
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
 * AODF ask for the PIN and verify that PIN.  */
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
  int pin_reference;
  int i;

  if (!aodf)
    return 0;

  pin_reference = aodf->pin_reference_valid? aodf->pin_reference : 0;

  if (app->app_local->card_type == CARD_TYPE_CARDOS_50)
    {
      /* We know that this card supports a verify status check.  Note
       * that in contrast to PIV cards ISO7816_VERIFY_NOT_NEEDED is
       * not supported.  */
      remaining = iso7816_verify_status (app_get_slot (app), pin_reference);
      if (remaining < 0)
        remaining = -1; /* We don't care about the concrete error.  */
      if (remaining < 3)
        {
          if (remaining >= 0)
            log_info ("p15: PIN has %d attempts left\n", remaining);
          /* On error or if less than 3 better ask. */
          prkdf->pin_verified = 0;
        }
    }
  else
    remaining = -1;  /* Unknown.  */

  /* Check whether we already verified it.  */
  if (prkdf->pin_verified)
    return 0;  /* Already done.  */

  if (prkdf->usageflags.non_repudiation
      && (app->app_local->card_type == CARD_TYPE_BELPIC
          || app->app_local->card_product == CARD_PRODUCT_DTRUST))
    label = _("||Please enter the PIN for the key to create "
              "qualified signatures.");
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
     min_length etc. are exactly defined, for now we take them as
     a plain octet count. */
  if (strlen (pinvalue) < aodf->min_length)
    {
      log_error ("p15: PIN is too short; minimum length is %lu\n",
                 aodf->min_length);
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
    case PIN_TYPE_ASCII_NUMERIC:
      for (s=pinvalue; digitp (s); s++)
        ;
      if (*s)
        {
          errstr = "Non-numeric digits found in PIN";
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
  prkdf->pin_verified = 1;

  return 0;
}




/* Handler for the PKSIGN command.

   Create the signature and return the allocated result in OUTDATA.
   If a PIN is required, the PINCB will be used to ask for the PIN;
   that callback should return the PIN in an allocated buffer and
   store that as the 3rd argument.  */
static gpg_error_t
do_sign (app_t app, const char *keyidstr, int hashalgo,
         gpg_error_t (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  static unsigned char sha256_prefix[19] = /* OID: 2.16.840.1.101.3.4.2.1 */
    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
  static unsigned char sha1_prefix[15] = /* Object ID is 1.3.14.3.2.26 */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
  static unsigned char rmd160_prefix[15] = /* Object ID is 1.3.36.3.2.1 */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
      0x02, 0x01, 0x05, 0x00, 0x04, 0x14 };

  gpg_error_t err;
  unsigned char data[32+19]; /* Must be large enough for a SHA-256 digest
                              * + the largest OID prefix above and also
                              * fit the 36 bytes of md5sha1.  */
  prkdf_object_t prkdf;    /* The private key object. */
  aodf_object_t aodf;      /* The associated authentication object. */
  int no_data_padding = 0; /* True if the card want the data without padding.*/
  int mse_done = 0;        /* Set to true if the MSE has been done. */
  unsigned int hashlen;    /* Length of the hash.  */
  unsigned int datalen;    /* Length of the data to sign (prefix+hash).  */
  unsigned char *dataptr;
  int exmode, le_value;


  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (indatalen != 20 && indatalen != 16
      && indatalen != 35 && indatalen != 36
      && indatalen != (32+19))
    return gpg_error (GPG_ERR_INV_VALUE);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err)
    return err;
  if (!(prkdf->usageflags.sign || prkdf->usageflags.sign_recover
        ||prkdf->usageflags.non_repudiation))
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
    {
      log_error ("p15: authentication object for %s missing\n", keyidstr);
      return gpg_error (GPG_ERR_INV_CARD);
    }

  /* We need some more info about the key - get the keygrip to
   * populate these fields.  */
  err = keygrip_from_prkdf (app, prkdf);
  if (err)
    {
      log_error ("p15: keygrip_from_prkdf failed: %s\n", gpg_strerror (err));
      return err;
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
     for the BELPIC card here. */
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

      err = iso7816_manage_security_env (app->slot,
                                         0x41, 0xB6,
                                         mse, sizeof mse);
      no_data_padding = 1;
      mse_done = 1;
    }
  if (err)
    {
      log_error ("p15: MSE failed: %s\n", gpg_strerror (err));
      return err;
    }

  /* Now that we have all the information available run the actual PIN
   * verification.*/
  err = verify_pin (app, pincb, pincb_arg, prkdf, aodf);
  if (err)
    return err;


  /* Prepare the DER object from INDATA. */
  if (indatalen == 36)
    {
      /* No ASN.1 container used. */
      if (hashalgo != MD_USER_TLS_MD5SHA1)
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data, indata, indatalen);
      datalen = hashlen = 36;
    }
  else if (indatalen == 35)
    {
      /* Alright, the caller was so kind to send us an already
         prepared DER object.  Check that it is what we want and that
         it matches the hash algorithm. */
      if (hashalgo == GCRY_MD_SHA1 && !memcmp (indata, sha1_prefix, 15))
        ;
      else if (hashalgo == GCRY_MD_RMD160
               && !memcmp (indata, rmd160_prefix, 15))
        ;
      else
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data, indata, indatalen);
      datalen = 35;
      hashlen = 20;
    }
  else if (indatalen == 32 + 19)
    {
      /* Seems to be a prepared SHA256 DER object.  */
      if (hashalgo == GCRY_MD_SHA256 && !memcmp (indata, sha256_prefix, 19))
        ;
      else
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data, indata, indatalen);
      datalen = 51;
      hashlen = 32;
    }
  else
    {
      /* Need to prepend the prefix. */
      if (hashalgo == GCRY_MD_SHA256)
        {
          memcpy (data, sha256_prefix, 19);
          memcpy (data+19, indata, indatalen);
          datalen = 51;
          hashlen = 32;
        }
      else if (hashalgo == GCRY_MD_SHA1)
        {
          memcpy (data, sha1_prefix, 15);
          memcpy (data+15, indata, indatalen);
          datalen = 35;
          hashlen = 20;
        }
      else if (hashalgo == GCRY_MD_RMD160)
        {
          memcpy (data, rmd160_prefix, 15);
          memcpy (data+15, indata, indatalen);
          datalen = 35;
          hashlen = 20;
        }
      else
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    }


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

      err = iso7816_manage_security_env (app->slot,
                                         0x41, 0xB6,
                                         mse, sizeof mse);
    }
  if (err)
    {
      log_error ("p15: MSE failed: %s\n", gpg_strerror (err));
      return err;
    }

  dataptr = data;
  if (no_data_padding)
    {
      dataptr += datalen - hashlen;
      datalen = hashlen;
    }

  if (prkdf->keyalgo == GCRY_PK_RSA && prkdf->keynbits > 2048)
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
                            exmode, dataptr, datalen,
                            le_value, outdata, outdatalen);

  return err;
}


/* Handler for the PKAUTH command.

   This is basically the same as the PKSIGN command but we first check
   that the requested key is suitable for authentication; that is, it
   must match the criteria used for the attribute $AUTHKEYID.  See
   do_sign for calling conventions; there is no HASHALGO, though. */
static gpg_error_t
do_auth (app_t app, const char *keyidstr,
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
  if (!prkdf->usageflags.sign)
    {
      log_error ("p15: key %s may not be used for authentication\n", keyidstr);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  algo = indatalen == 36? MD_USER_TLS_MD5SHA1 : GCRY_MD_SHA1;
  return do_sign (app, keyidstr, algo, pincb, pincb_arg,
                  indata, indatalen, outdata, outdatalen);
}


/* Handler for the PKDECRYPT command.  Decrypt the data in INDATA and
 * return the allocated result in OUTDATA.  If a PIN is required the
 * PINCB will be used to ask for the PIN; it should return the PIN in
 * an allocated buffer and put it into PIN.  */
static gpg_error_t
do_decipher (app_t app, const char *keyidstr,
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

  (void)r_info;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!indatalen || !indata || !outdatalen || !outdata)
    return gpg_error (GPG_ERR_INV_ARG);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err)
    return err;
  if (!(prkdf->usageflags.decrypt || prkdf->usageflags.unwrap))
    {
      log_error ("p15: key %s may not be used for decruption\n", keyidstr);
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
    {
      log_error ("p15: authentication object for %s missing\n", keyidstr);
      return gpg_error (GPG_ERR_INV_CARD);
    }

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
      unsigned char mse[6];

      /* Note: This works with CardOS but the D-Trust card has the
       * problem that the next created signature would be broken.  */

      mse[0] = 0x80; /* Algorithm reference.  */
      mse[1] = 1;
      mse[2] = 0x0a; /* RSA, no padding.  */
      mse[3] = 0x84;
      mse[4] = 1;
      mse[5] = prkdf->key_reference;
      err = iso7816_manage_security_env (app_get_slot (app), 0x41, 0xB8,
                                         mse, sizeof mse);
    }
  /* Check for MSE error.  */
  if (err)
    {
      log_error ("p15: MSE failed: %s\n", gpg_strerror (err));
      return err;
    }

  exmode = le_value = 0;
  padind = 0;
  if (prkdf->keyalgo == GCRY_PK_RSA && prkdf->keynbits > 2048)
    {
      exmode = 1;   /* Extended length w/o a limit.  */
      le_value = prkdf->keynbits / 8;
    }

  if (app->app_local->card_product == CARD_PRODUCT_DTRUST)
    padind = 0x81;

  err = iso7816_decipher (app_get_slot (app), exmode,
                          indata, indatalen,
                          le_value, padind,
                          outdata, outdatalen);
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
  int slot = app->slot;
  int rc;
  unsigned short def_home_df = 0;
  card_type_t card_type = CARD_TYPE_UNKNOWN;
  int direct = 0;
  int is_belpic = 0;

  rc = iso7816_select_application (slot, pkcs15_aid, sizeof pkcs15_aid, 0);
  if (rc)
    { /* Not found: Try to locate it from 2F00.  We use direct path
         selection here because it seems that the Belgian eID card
         does only allow for that.  Many other cards supports this
         selection method too.  Note, that we don't use
         select_application above for the Belgian card - the call
         works but it seems that it does not switch to the correct DF.
         Using the 2f02 just works. */
      unsigned short path[1] = { 0x2f00 };

      rc = iso7816_select_path (slot, path, 1);
      if (!rc)
        {
          direct = 1;
          def_home_df = read_home_df (slot, &is_belpic);
          if (def_home_df)
            {
              path[0] = def_home_df;
              rc = iso7816_select_path (slot, path, 1);
            }
        }
    }
  if (rc)
    { /* Still not found:  Try the default DF. */
      def_home_df = 0x5015;
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

          atr = apdu_get_atr (app->slot, &atrlen);
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
      app->apptype = "P15";

      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }

      /* Set the home DF.  Note that we currently can't do that if the
         selection via application ID worked.  This will store 0 there
         instead.  FIXME: We either need to figure the home_df via the
         DIR file or using the return values from the select file
         APDU. */
      app->app_local->home_df = def_home_df;

      /* Store the card type.  FIXME: We might want to put this into
         the common APP structure. */
      app->app_local->card_type = card_type;

      app->app_local->card_product = CARD_PRODUCT_UNKNOWN;

      /* Store whether we may and should use direct path selection. */
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
      if (app->serialnolen == 12
          && !memcmp (app->serialno, "\xD2\x76\0\0\0\0\0\0\0\0\0\0", 12))
        {
          /* This is a German card with a silly serial number.  Try to get
             the serial number from the EF(TokenInfo). . */
          unsigned char *p;

          /* FIXME: actually get it from EF(TokenInfo). */

          p = xtrymalloc (3 + app->serialnolen);
          if (!p)
            rc = gpg_error (gpg_err_code_from_errno (errno));
          else
            {
              memcpy (p, "\xff\x01", 3);
              memcpy (p+3, app->serialno, app->serialnolen);
              app->serialnolen += 3;
              xfree (app->serialno);
              app->serialno = p;
            }
        }

      app->fnc.deinit = do_deinit;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.getattr = do_getattr;
      app->fnc.setattr = NULL;
      app->fnc.genkey = NULL;
      app->fnc.sign = do_sign;
      app->fnc.auth = do_auth;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = NULL;
      app->fnc.check_pin = NULL;

    leave:
      if (rc)
        do_deinit (app);
   }

  return rc;
}
