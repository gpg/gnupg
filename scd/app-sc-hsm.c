/* app-sc-hsm.c - The SmartCard-HSM card application (www.smartcard-hsm.com).
 *	Copyright (C) 2005 Free Software Foundation, Inc.
 *	Copyright (C) 2014 Andreas Schwier <andreas.schwier@cardcontact.de>
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

/*
   Code in this driver is based on app-p15.c with modifications.
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
#include "../common/tlv.h"
#include "apdu.h"


/* The AID of the SmartCard-HSM applet. */
static char const sc_hsm_aid[] = { 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81,
                                   0xC3, 0x1F, 0x02, 0x01  };


/* Special file identifier for SmartCard-HSM */
typedef enum
{
    SC_HSM_PRKD_PREFIX = 0xC4,
    SC_HSM_CD_PREFIX = 0xC8,
    SC_HSM_DCOD_PREFIX = 0xC9,
    SC_HSM_CA_PREFIX = 0xCA,
    SC_HSM_KEY_PREFIX = 0xCC,
    SC_HSM_EE_PREFIX = 0xCE
} fid_prefix_type_t;


/* The key types supported by the SmartCard-HSM */
typedef enum
  {
    KEY_TYPE_RSA,
    KEY_TYPE_ECC
  } key_type_t;


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

  /* Length and allocated buffer with the Id of this object. */
  size_t objidlen;
  unsigned char *objid;

  /* To avoid reading a certificate more than once, we cache it in an
     allocated memory IMAGE of IMAGELEN. */
  size_t imagelen;
  unsigned char *image;

  /* EF containing certificate */
  unsigned short fid;
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

  /* Key type */
  key_type_t keytype;

  /* Key size in bits or 0 if unknown */
  size_t keysize;

  /* Length and allocated buffer with the Id of this object. */
  size_t objidlen;
  unsigned char *objid;

  /* The key's usage flags. */
  keyusage_flags_t usageflags;

  /* The keyReference */
  unsigned char key_reference;
};
typedef struct prkdf_object_s *prkdf_object_t;



/* Context local to this application. */
struct app_local_s
{
  /* Information on all certificates. */
  cdf_object_t certificate_info;
  /* Information on all trusted certificates. */
  cdf_object_t trusted_certificate_info;
  /* Information on all private keys. */
  prkdf_object_t private_key_info;
};



/*** Local prototypes.  ***/
static gpg_error_t readcert_by_cdf (app_t app, cdf_object_t cdf,
                                    unsigned char **r_cert, size_t *r_certlen);



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
      xfree (a->objid);
      xfree (a);
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
      release_prkdflist (app->app_local->private_key_info);
      xfree (app->app_local);
      app->app_local = NULL;
    }
}



/* Get the list of EFs from the SmartCard-HSM.
 * On success a dynamically buffer containing the EF list is returned.
 * The caller is responsible for freeing the buffer.
 */
static gpg_error_t
list_ef (int slot, unsigned char **result, size_t *resultlen)
{
  int sw;

  if (!result || !resultlen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *result = NULL;
  *resultlen = 0;

  sw = apdu_send_le (slot, 1, 0x80, 0x58, 0x00, 0x00, -1, NULL, 65536,
                     result, resultlen);
  if (sw != SW_SUCCESS)
    {
      /* Make sure that pending buffers are released. */
      xfree (*result);
      *result = NULL;
      *resultlen = 0;
    }
  return iso7816_map_sw (sw);
}



/* Do a select and a read for the file with EFID.  EFID_DESC is a
   description of the EF to be used with error messages.  On success
   BUFFER and BUFLEN contain the entire content of the EF.  The caller
   must free BUFFER only on success. */
static gpg_error_t
select_and_read_binary (int slot, unsigned short efid, const char *efid_desc,
                        unsigned char **buffer, size_t *buflen, int maxread)
{
  gpg_error_t err;
  unsigned char cdata[4];
  int sw;

  cdata[0] = 0x54;      /* Create ISO 7861-4 odd ins READ BINARY */
  cdata[1] = 0x02;
  cdata[2] = 0x00;
  cdata[3] = 0x00;

  sw = apdu_send_le(slot, 1, 0x00, 0xB1, efid >> 8, efid & 0xFF,
                    4, cdata, maxread, buffer, buflen);

  if (sw == SW_EOF_REACHED)
    sw = SW_SUCCESS;

  err = iso7816_map_sw (sw);
  if (err)
    {
      log_error ("error reading %s (0x%04X): %s\n",
                 efid_desc, efid, gpg_strerror (err));
      return err;
    }
  return 0;
}



/* Parse a cert Id string (or a key Id string) and return the binary
   object Id string in a newly allocated buffer stored at R_OBJID and
   R_OBJIDLEN.  On Error NULL will be stored there and an error code
   returned. On success caller needs to free the buffer at R_OBJID. */
static gpg_error_t
parse_certid (const char *certid, unsigned char **r_objid, size_t *r_objidlen)
{
  const char *s;
  size_t objidlen;
  unsigned char *objid;
  int i;

  *r_objid = NULL;
  *r_objidlen = 0;

  if (strncmp (certid, "HSM.", 4))
    return gpg_error (GPG_ERR_INV_ID);
  certid += 4;

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

  err = parse_certid (certid, &objid, &objidlen);
  if (err)
    return err;

  for (cdf = app->app_local->certificate_info; cdf; cdf = cdf->next)
    if (cdf->objidlen == objidlen && !memcmp (cdf->objid, objid, objidlen))
      break;
  if (!cdf)
    for (cdf = app->app_local->trusted_certificate_info; cdf; cdf = cdf->next)
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

  err = parse_certid (keyidstr, &objid, &objidlen);
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



/* Read and parse a Private Key Directory File containing a single key
   description in PKCS#15 format.  For each private key a matching
   certificate description is created, if the certificate EF exists
   and contains a X.509 certificate.

   Example data:

0000  30 2A 30 13 0C 11 4A 6F 65 20 44 6F 65 20 28 52  0*0...Joe Doe (R
0010  53 41 32 30 34 38 29 30 07 04 01 01 03 02 02 74  SA2048)0.......t
0020  A1 0A 30 08 30 02 04 00 02 02 08 00              ..0.0.......

   Decoded example:

SEQUENCE SIZE( 42 )
  SEQUENCE SIZE( 19 )
    UTF8-STRING SIZE( 17 )                -- label
      0000  4A 6F 65 20 44 6F 65 20 28 52 53 41 32 30 34 38  Joe Doe (RSA2048
      0010  29                                               )
  SEQUENCE SIZE( 7 )
    OCTET-STRING SIZE( 1 )                -- id
      0000  01
    BIT-STRING SIZE( 2 )                  -- key usage
      0000  02 74
  A1 [ CONTEXT 1 ] IMPLICIT SEQUENCE SIZE( 10 )
    SEQUENCE SIZE( 8 )
      SEQUENCE SIZE( 2 )
        OCTET-STRING SIZE( 0 )            -- empty path, req object in PKCS#15
      INTEGER SIZE( 2 )                   -- modulus size in bits
        0000  08 00
*/
static gpg_error_t
read_ef_prkd (app_t app, unsigned short fid, prkdf_object_t *prkdresult,
              cdf_object_t *cdresult)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  int i;
  const unsigned char *pp;
  size_t nn;
  int where;
  const char *errstr = NULL;
  prkdf_object_t prkdf = NULL;
  cdf_object_t cdf = NULL;
  unsigned long ul;
  const unsigned char *objid;
  size_t objidlen;
  keyusage_flags_t usageflags;
  const char *s;
  key_type_t keytype;
  size_t keysize;

  if (!fid)
    return gpg_error (GPG_ERR_NO_DATA); /* No private keys. */

  err = select_and_read_binary (app_get_slot (app),
                                fid, "PrKDF", &buffer, &buflen, 255);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > n || (tag != TAG_SEQUENCE && tag != 0x00)))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    {
      log_error ("error parsing PrKDF record: %s\n", gpg_strerror (err));
      goto leave;
    }

  keytype = tag == 0x00 ? KEY_TYPE_ECC : KEY_TYPE_RSA;

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

    /* Search the optional AuthId.  We need to skip the optional Label
       (UTF8STRING) and the optional CommonObjectFlags (BITSTRING). */
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
        /* AuthId ignored */
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
        /* Yep, this is the keyReference.
           Note: UL is currently not used. */
        for (ul=0; objlen; objlen--)
          {
            ul <<= 8;
            ul |= (*ppp++) & 0xff;
            nnn--;
          }
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

  pp += objlen;
  nn -= objlen;

  /* Parse the key size object. */
  where = __LINE__;
  err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && objlen > nn)
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    goto parse_error;
  keysize = 0;
  if (class == CLASS_UNIVERSAL && tag == TAG_INTEGER && objlen == 2)
    {
      keysize  = *pp++ << 8;
      keysize += *pp++;
    }

  /* Create a new PrKDF list item. */
  prkdf = xtrycalloc (1, sizeof *prkdf);
  if (!prkdf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  prkdf->keytype = keytype;
  prkdf->keysize = keysize;
  prkdf->objidlen = objidlen;
  prkdf->objid = xtrymalloc (objidlen);
  if (!prkdf->objid)
    {
      err = gpg_error_from_syserror ();
      xfree (prkdf);
      prkdf = NULL;
      goto leave;
    }
  memcpy (prkdf->objid, objid, objidlen);

  prkdf->usageflags = usageflags;
  prkdf->key_reference = fid & 0xFF;

  log_debug ("PrKDF %04hX: id=", fid);
  for (i=0; i < prkdf->objidlen; i++)
    log_printf ("%02X", prkdf->objid[i]);
  log_printf (" keyref=0x%02X", prkdf->key_reference);
  log_printf (" keysize=%zu", prkdf->keysize);
  log_printf (" usage=");
  s = "";
  if (prkdf->usageflags.encrypt)
    {
      log_printf ("%sencrypt", s);
      s = ",";
    }
  if (prkdf->usageflags.decrypt)
    {
      log_printf ("%sdecrypt", s);
      s = ",";
    }
  if (prkdf->usageflags.sign)
    {
      log_printf ("%ssign", s);
      s = ",";
    }
  if (prkdf->usageflags.sign_recover)
    {
      log_printf ("%ssign_recover", s);
      s = ",";
    }
  if (prkdf->usageflags.wrap   )
    {
      log_printf ("%swrap", s);
      s = ",";
    }
  if (prkdf->usageflags.unwrap )
    {
      log_printf ("%sunwrap", s);
      s = ",";
    }
  if (prkdf->usageflags.verify )
    {
      log_printf ("%sverify", s);
      s = ",";
    }
  if (prkdf->usageflags.verify_recover)
    {
      log_printf ("%sverify_recover", s);
      s = ",";
    }
  if (prkdf->usageflags.derive )
    {
      log_printf ("%sderive", s);
      s = ",";
    }
  if (prkdf->usageflags.non_repudiation)
    {
      log_printf ("%snon_repudiation", s);
    }
  log_printf ("\n");

  xfree (buffer);
  buffer = NULL;
  buflen = 0;
  err = select_and_read_binary (app_get_slot (app),
                                ((SC_HSM_EE_PREFIX << 8) | (fid & 0xFF)),
                                "CertEF", &buffer, &buflen, 1);
  if (!err && buffer[0] == 0x30)
    {
      /* Create a matching CDF list item. */
      cdf = xtrycalloc (1, sizeof *cdf);
      if (!cdf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      cdf->objidlen = prkdf->objidlen;
      cdf->objid = xtrymalloc (cdf->objidlen);
      if (!cdf->objid)
        {
          err = gpg_error_from_syserror ();
          xfree (cdf);
          cdf = NULL;
          goto leave;
        }
      memcpy (cdf->objid, prkdf->objid, objidlen);

      cdf->fid = (SC_HSM_EE_PREFIX << 8) | (fid & 0xFF);

      log_debug ("CDF %04hX: id=", fid);
      for (i=0; i < cdf->objidlen; i++)
        log_printf ("%02X", cdf->objid[i]);
      log_printf (" fid=%04X\n", cdf->fid);
    }

  goto leave; /* Ready. */

 parse_error:
  log_error ("error parsing PrKDF record (%d): %s - skipped\n",
             where, errstr? errstr : gpg_strerror (err));
  err = 0;

 leave:
  xfree (buffer);
  if (err)
    {
      if (prkdf)
        {
          if (prkdf->objid)
            xfree (prkdf->objid);
          xfree (prkdf);
        }
      if (cdf)
        {
          if (cdf->objid)
            xfree (cdf->objid);
          xfree (cdf);
        }
    }
  else
    {
      if (prkdf)
        prkdf->next = *prkdresult;
      *prkdresult = prkdf;
      if (cdf)
        {
          cdf->next = *cdresult;
          *cdresult = cdf;
        }
    }
  return err;
}



/* Read and parse the Certificate Description File identified by FID.
   On success a the CDF list gets stored at RESULT and the caller is
   then responsible of releasing the object.

   Example data:

0000  30 35 30 11 0C 0B 43 65 72 74 69 66 69 63 61 74  050...Certificat
0010  65 03 02 06 40 30 16 04 14 C2 01 7C 2F BA A4 4A  e...@0.....|/..J
0020  4A BB B8 49 11 DB 4A CA AA 7E 6A 2D 1B A1 08 30  J..I..J..~j-...0
0030  06 30 04 04 02 CA 00                             .0.....

   Decoded example:

SEQUENCE SIZE( 53 )
  SEQUENCE SIZE( 17 )
    UTF8-STRING SIZE( 11 )                      -- label
      0000  43 65 72 74 69 66 69 63 61 74 65                 Certificate
    BIT-STRING SIZE( 2 )                        -- common object attributes
      0000  06 40
  SEQUENCE SIZE( 22 )
    OCTET-STRING SIZE( 20 )                     -- id
      0000  C2 01 7C 2F BA A4 4A 4A BB B8 49 11 DB 4A CA AA
      0010  7E 6A 2D 1B
  A1 [ CONTEXT 1 ] IMPLICIT SEQUENCE SIZE( 8 )
    SEQUENCE SIZE( 6 )
      SEQUENCE SIZE( 4 )
        OCTET-STRING SIZE( 2 )                  -- path
          0000  CA 00                                            ..
 */
static gpg_error_t
read_ef_cd (app_t app, unsigned short fid, cdf_object_t *result)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  const unsigned char *p;
  size_t n, objlen, hdrlen;
  int class, tag, constructed, ndef;
  int i;
  const unsigned char *pp;
  size_t nn;
  int where;
  const char *errstr = NULL;
  cdf_object_t cdf = NULL;
  const unsigned char *objid;
  size_t objidlen;

  if (!fid)
    return gpg_error (GPG_ERR_NO_DATA); /* No certificates. */

  err = select_and_read_binary (app_get_slot (app), fid, "CDF",
                                &buffer, &buflen, 255);
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
      log_error ("error parsing CDF record: %s\n", gpg_strerror (err));
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
      err = gpg_error (GPG_ERR_INV_OBJ);
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
      || (objlen & 1) )
    {
      errstr = "invalid path reference";
      goto parse_error;
    }
  /* Create a new CDF list item. */
  cdf = xtrycalloc (1, sizeof *cdf);
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
      cdf = NULL;
      goto leave;
    }
  memcpy (cdf->objid, objid, objidlen);

  cdf->fid = (SC_HSM_CA_PREFIX << 8) | (fid & 0xFF);

  log_debug ("CDF %04hX: id=", fid);
  for (i=0; i < cdf->objidlen; i++)
    log_printf ("%02X", cdf->objid[i]);

  goto leave;

 parse_error:
  log_error ("error parsing CDF record (%d): %s - skipped\n",
             where, errstr? errstr : gpg_strerror (err));
  err = 0;

 leave:
  xfree (buffer);
  if (err)
    {
      if (cdf)
        {
          if (cdf->objid)
            xfree (cdf->objid);
          xfree (cdf);
        }
    }
  else
    {
      if (cdf)
        cdf->next = *result;
      *result = cdf;
    }
  return err;
}



/* Read the device certificate and extract the serial number.

   EF.C_DevAut (2F02) contains two CVCs, the first is the device
   certificate, the second is the issuer certificate.

   Example data:

0000  7F 21 81 E2 7F 4E 81 9B 5F 29 01 00 42 0B 55 54  .!...N.._)..B.UT
0010  43 43 30 32 30 30 30 30 32 7F 49 4F 06 0A 04 00  CC0200002.IO....
0020  7F 00 07 02 02 02 02 03 86 41 04 6D FF D6 85 57  .........A.m...W
0030  40 FB 10 5D 94 71 8A 94 D2 5E 50 33 E7 1E C0 6C  @..].q...^P3...l
0040  63 D5 C8 FC BA F3 02 1D 70 23 F6 47 E8 35 48 EF  c.......p#.G.5H.
0050  B5 94 72 3C 6F BE C0 EB 9A C7 FB 06 59 26 CF 65  ..r<o.......Y&.e
0060  EF A1 72 E0 98 F3 F0 44 1B B7 71 5F 20 10 55 54  ..r....D..q_ .UT
0070  43 43 30 32 30 30 30 31 33 30 30 30 30 30 7F 4C  CC020001300000.L
0080  10 06 0B 2B 06 01 04 01 81 C3 1F 03 01 01 53 01  ...+..........S.
0090  00 5F 25 06 01 04 00 07 01 01 5F 24 06 02 01 00  ._%......._$....
00A0  03 02 07 5F 37 40 7F 73 04 3B 06 63 79 41 BE 1A  ..._7@.s.;.cyA..
00B0  9F FC F6 77 67 2B 8A 41 D1 11 F6 9B 54 44 AD 19  ...wg+.A....TD..
00C0  FB B8 0C C6 2F 34 71 8E 4F F6 92 59 34 61 D9 4F  ..../4q.O..Y4a.O
00D0  4A 86 36 A8 D8 9A C6 3C 17 7E 71 CE A8 26 D0 C5  J.6....<.~q..&..
00E0  25 61 78 9D 01 F8 7F 21 81 E0 7F 4E 81 99 5F 29  %ax....!...N.._)
00F0  01 00 42 0E 55 54 53 52 43 41 43 43 31 30 30 30  ..B.UTSRCACC1000
0100  30 31 7F 49 4F 06 0A 04 00 7F 00 07 02 02 02 02  01.IO...........
0110  03 86 41 04 2F EA 33 47 7F 45 81 E2 FC CB 66 87  ..A./.3G.E....f.
0120  4B 96 21 1D 68 81 73 F2 9F 8F 6B 91 F0 DE 4B 54  K.!.h.s...k...KT
0130  8E D8 F0 82 3D CB BE 10 98 A3 1E 4F F0 72 5C E5  ....=......O.r\.
0140  7B 1E F7 3C 68 09 03 E8 A0 3F 3E 06 C1 B0 3C 18  {..<h....?>...<.
0150  6B AC 06 EA 5F 20 0B 55 54 43 43 30 32 30 30 30  k..._ .UTCC02000
0160  30 32 7F 4C 10 06 0B 2B 06 01 04 01 81 C3 1F 03  02.L...+........
0170  01 01 53 01 80 5F 25 06 01 03 00 03 02 08 5F 24  ..S.._%......._$
0180  06 02 01 00 03 02 07 5F 37 40 93 C1 42 8B B3 8E  ......._7@..B...
0190  42 61 6F 2C 19 E6 98 41 BD AA 60 BD E0 DD 4E F0  Bao,...A..`...N.
01A0  15 D5 4F 71 B7 BB C3 3A F2 AD 27 5E DD EE 6D 12  ..Oq...:..'^..m.
01B0  76 E6 2B A0 4C 01 CA C1 26 0C 45 6D C6 CB EC 92  v.+.L...&.Em....
01C0  BF 38 18 AD 8F B2 29 40 A9 51                    .8....)@.Q

   The certificate format is defined in BSI TR-03110:

7F21 [ APPLICATION 33 ] IMPLICIT SEQUENCE SIZE( 226 )
  7F4E [ APPLICATION 78 ] IMPLICIT SEQUENCE SIZE( 155 )
    5F29 [ APPLICATION 41 ] SIZE( 1 )                           -- profile id
      0000  00
    42 [ APPLICATION 2 ] SIZE( 11 )                             -- CAR
      0000  55 54 43 43 30 32 30 30 30 30 32                 UTCC0200002
    7F49 [ APPLICATION 73 ] IMPLICIT SEQUENCE SIZE( 79 )        -- public key
      OBJECT IDENTIFIER = { id-TA-ECDSA-SHA-256 }
      86 [ CONTEXT 6 ] SIZE( 65 )
        0000  04 6D FF D6 85 57 40 FB 10 5D 94 71 8A 94 D2 5E
        0010  50 33 E7 1E C0 6C 63 D5 C8 FC BA F3 02 1D 70 23
        0020  F6 47 E8 35 48 EF B5 94 72 3C 6F BE C0 EB 9A C7
        0030  FB 06 59 26 CF 65 EF A1 72 E0 98 F3 F0 44 1B B7
        0040  71
    5F20 [ APPLICATION 32 ] SIZE( 16 )                          -- CHR
      0000  55 54 43 43 30 32 30 30 30 31 33 30 30 30 30 30  UTCC020001300000
    7F4C [ APPLICATION 76 ] IMPLICIT SEQUENCE SIZE( 16 )        -- CHAT
      OBJECT IDENTIFIER = { 1 3 6 1 4 1 24991 3 1 1 }
      53 [ APPLICATION 19 ] SIZE( 1 )
        0000  00
    5F25 [ APPLICATION 37 ] SIZE( 6 )                           -- Valid from
      0000  01 04 00 07 01 01
    5F24 [ APPLICATION 36 ] SIZE( 6 )                           -- Valid to
      0000  02 01 00 03 02 07
  5F37 [ APPLICATION 55 ] SIZE( 64 )                            -- Signature
    0000  7F 73 04 3B 06 63 79 41 BE 1A 9F FC F6 77 67 2B
    0010  8A 41 D1 11 F6 9B 54 44 AD 19 FB B8 0C C6 2F 34
    0020  71 8E 4F F6 92 59 34 61 D9 4F 4A 86 36 A8 D8 9A
    0030  C6 3C 17 7E 71 CE A8 26 D0 C5 25 61 78 9D 01 F8

   The serial number is contained in tag 5F20, while the last 5 digits
   are truncated.
 */
static gpg_error_t
read_serialno(app_t app)
{
  gpg_error_t err;
  unsigned char *buffer = NULL;
  size_t buflen;
  const unsigned char *p,*chr;
  size_t n, objlen, hdrlen, chrlen;
  int class, tag, constructed, ndef;

  err = select_and_read_binary (app_get_slot (app), 0x2F02, "EF.C_DevAut",
                                &buffer, &buflen, 512);
  if (err)
    return err;

  p = buffer;
  n = buflen;

  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > n || tag != 0x21))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if (err)
    {
      log_error ("error parsing C_DevAut: %s\n", gpg_strerror (err));
      goto leave;
    }

  chr = find_tlv (p, objlen, 0x5F20, &chrlen);
  if (!chr || chrlen <= 5)
    {
      err = gpg_error (GPG_ERR_INV_OBJ);
      log_error ("CHR not found in CVC\n");
      goto leave;
    }
  chrlen -= 5;

  app->serialno = xtrymalloc (chrlen);
  if (!app->serialno)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  app->serialnolen = chrlen;
  memcpy (app->serialno, chr, chrlen);

 leave:
  xfree (buffer);
  return err;
}


/* Get all the basic information from the SmartCard-HSM, check the
   structure and initialize our local context.  This is used once at
   application initialization.  */
static gpg_error_t
read_meta (app_t app)
{
  gpg_error_t err;
  unsigned char *eflist = NULL;
  size_t eflistlen = 0;
  int i;

  err = read_serialno(app);
  if (err)
    return err;

  err = list_ef (app_get_slot (app), &eflist, &eflistlen);
  if (err)
    return err;

  for (i = 0; i < eflistlen; i += 2)
    {
      switch(eflist[i])
        {
        case SC_HSM_KEY_PREFIX:
          if (eflist[i + 1] == 0)    /* No key with ID=0 */
            break;
          err = read_ef_prkd (app, ((SC_HSM_PRKD_PREFIX << 8) | eflist[i + 1]),
                              &app->app_local->private_key_info,
                              &app->app_local->certificate_info);
          if (gpg_err_code (err) == GPG_ERR_NO_DATA)
            err = 0;
          if (err)
            return err;
          break;
        case SC_HSM_CD_PREFIX:
          err = read_ef_cd (app, ((eflist[i] << 8) | eflist[i + 1]),
                            &app->app_local->trusted_certificate_info);
          if (gpg_err_code (err) == GPG_ERR_NO_DATA)
            err = 0;
          if (err)
            return err;
          break;
        }
    }

  xfree (eflist);

  return err;
}



/* Helper to do_learn_status: Send information about all certificates
   listed in CERTINFO back.  Use CERTTYPE as type of the
   certificate. */
static gpg_error_t
send_certinfo (ctrl_t ctrl, const char *certtype, cdf_object_t certinfo)
{
  for (; certinfo; certinfo = certinfo->next)
    {
      char *buf, *p;

      buf = xtrymalloc (4 + certinfo->objidlen*2 + 1);
      if (!buf)
        return gpg_error_from_syserror ();
      p = stpcpy (buf, "HSM.");
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
   keygrip gets returned in the caller provided 41 byte buffer
   R_GRIPSTR. */
static gpg_error_t
keygripstr_from_prkdf (app_t app, prkdf_object_t prkdf, char *r_gripstr)
{
  gpg_error_t err;
  cdf_object_t cdf;
  unsigned char *der;
  size_t derlen;
  ksba_cert_t cert;

  /* Look for a matching certificate. A certificate matches if the Id
     matches the one of the private key info. */
  for (cdf = app->app_local->certificate_info; cdf; cdf = cdf->next)
    if (cdf->objidlen == prkdf->objidlen
        && !memcmp (cdf->objid, prkdf->objid, prkdf->objidlen))
      break;
  if (!cdf)
    return gpg_error (GPG_ERR_NOT_FOUND);

  err = readcert_by_cdf (app, cdf, &der, &derlen);
  if (err)
    return err;

  err = ksba_cert_new (&cert);
  if (!err)
    err = ksba_cert_init_from_mem (cert, der, derlen);
  xfree (der);
  if (!err)
    err = app_help_get_keygrip_string (cert, r_gripstr, NULL, NULL);
  ksba_cert_release (cert);

  return err;
}



/* Helper to do_learn_status: Send information about all known
   keypairs back. */
static gpg_error_t
send_keypairinfo (app_t app, ctrl_t ctrl, prkdf_object_t keyinfo)
{
  gpg_error_t err;

  for (; keyinfo; keyinfo = keyinfo->next)
    {
      char gripstr[40+1];
      char *buf, *p;

      buf = xtrymalloc (4 + keyinfo->objidlen*2 + 1);
      if (!buf)
        return gpg_error_from_syserror ();
      p = stpcpy (buf, "HSM.");
      bin2hex (keyinfo->objid, keyinfo->objidlen, p);

      err = keygripstr_from_prkdf (app, keyinfo, gripstr);
      if (err)
        {
          log_error ("can't get keygrip from %04X\n", keyinfo->key_reference);
        }
      else
        {
          assert (strlen (gripstr) == 40);
          send_status_info (ctrl, "KEYPAIRINFO",
                            gripstr, 40,
                            buf, strlen (buf),
                            NULL, (size_t)0);
        }
      xfree (buf);
    }
  return 0;
}



/* This is the handler for the LEARN command. */
static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;

  if ((flags & APP_LEARN_FLAG_KEYPAIRINFO))
    err = 0;
  else
    {
      err = send_certinfo (ctrl, "100", app->app_local->certificate_info);
      if (!err)
        err = send_certinfo (ctrl, "101",
            app->app_local->trusted_certificate_info);
    }

  if (!err)
    err = send_keypairinfo (app, ctrl, app->app_local->private_key_info);

  return err;
}



/* Read a certificate using the information in CDF and return the
   certificate in a newly allocated buffer R_CERT and its length
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

  err = select_and_read_binary (app_get_slot (app), cdf->fid, "CD",
                                &buffer, &buflen, 4096);
  if (err)
    {
      log_error ("error reading certificate with Id ");
      for (i=0; i < cdf->objidlen; i++)
        log_printf ("%02X", cdf->objid[i]);
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
  if (!strcmp (name, "$AUTHKEYID"))
    {
      char *buf, *p;
      prkdf_object_t prkdf;

      /* We return the ID of the first private key capable of
         signing. */
      for (prkdf = app->app_local->private_key_info; prkdf;
           prkdf = prkdf->next)
        if (prkdf->usageflags.sign)
          break;
      if (prkdf)
        {
          buf = xtrymalloc (4 + prkdf->objidlen*2 + 1);
          if (!buf)
            return gpg_error_from_syserror ();
          p = stpcpy (buf, "HSM.");
          bin2hex (prkdf->objid, prkdf->objidlen, p);

          send_status_info (ctrl, name, buf, strlen (buf), NULL, 0);
          xfree (buf);
          return 0;
        }
    }
  else if (!strcmp (name, "$DISPSERIALNO"))
    {
      send_status_info (ctrl, name, app->serialno, app->serialnolen, NULL, 0);
      return 0;
    }

  return gpg_error (GPG_ERR_INV_NAME);
}



/* Apply PKCS#1 V1.5 padding for signature operation.  The function
 * combines padding, digest info and the hash value.  The buffer must
 * be allocated by the caller matching the key size.  */
static void
apply_PKCS_padding(const unsigned char *dig, int diglen,
                   const unsigned char *prefix, int prefixlen,
                   unsigned char *buff, int bufflen)
{
  int i, n_ff;

  /* Caller must ensure a sufficient buffer.  */
  if (diglen + prefixlen + 4 > bufflen)
    return;
  n_ff = bufflen - diglen - prefixlen - 3;

  *buff++ = 0x00;
  *buff++ = 0x01;
  for (i=0; i < n_ff; i++)
    *buff++ = 0xFF;
  *buff++ = 0x00;

  if (prefix)
    memcpy (buff, prefix, prefixlen);
  buff += prefixlen;
  memcpy (buff, dig, diglen);
}



/* Decode a digest info structure (DI,DILEN) to extract the hash
 * value.  The buffer HASH to receive the digest must be provided by
 * the caller with HASHLEN pointing to the inbound length.  HASHLEN is
 * updated to the outbound length.  */
static int
hash_from_digestinfo (const unsigned char *di, size_t dilen,
                      unsigned char *hash, size_t *hashlen)
{
  const unsigned char *p,*pp;
  size_t n, nn, objlen, hdrlen;
  int class, tag, constructed, ndef;
  gpg_error_t err;

  p = di;
  n = dilen;

  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > n || tag != TAG_SEQUENCE))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if ( err )
    return err;

  pp = p;
  nn = objlen;

  err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > nn || tag != TAG_SEQUENCE))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if ( err )
    return err;

  pp += objlen;
  nn -= objlen;

  err = parse_ber_header (&pp, &nn, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (!err && (objlen > nn || tag != TAG_OCTET_STRING))
    err = gpg_error (GPG_ERR_INV_OBJ);
  if ( err )
    return err;

  if (*hashlen < objlen)
    return gpg_error (GPG_ERR_TOO_SHORT);
  memcpy (hash, pp, objlen);
  *hashlen = objlen;
  return 0;
}


/* Perform PIN verification
 */
static gpg_error_t
verify_pin (app_t app, gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg)
{
  gpg_error_t err;
  pininfo_t pininfo;
  char *pinvalue;
  char *prompt;
  int sw;

  sw = apdu_send_simple (app_get_slot (app),
                         0, 0x00, ISO7816_VERIFY, 0x00, 0x81, -1, NULL);

  if (sw == SW_SUCCESS)
    return 0;                   /* PIN already verified */

  if (sw == SW_REF_DATA_INV)
    {
      log_error ("SmartCard-HSM not initialized. Run sc-hsm-tool first\n");
      return gpg_error (GPG_ERR_NO_PIN);
    }

  if (sw == SW_CHV_BLOCKED)
    {
      log_error ("PIN Blocked\n");
      return gpg_error (GPG_ERR_PIN_BLOCKED);
    }

  memset (&pininfo, 0, sizeof pininfo);
  pininfo.fixedlen = 0;
  pininfo.minlen = 6;
  pininfo.maxlen = 15;

  prompt = "||Please enter the PIN";

  if (!opt.disable_pinpad
      && !iso7816_check_pinpad (app_get_slot (app), ISO7816_VERIFY, &pininfo) )
    {
      err = pincb (pincb_arg, prompt, NULL);
      if (err)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (err));
          return err;
        }

      err = iso7816_verify_kp (app_get_slot (app), 0x81, &pininfo);
      pincb (pincb_arg, NULL, NULL);  /* Dismiss the prompt. */
    }
  else
    {
      err = pincb (pincb_arg, prompt, &pinvalue);
      if (err)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (err));
          return err;
        }

      err = iso7816_verify (app_get_slot (app),
                            0x81, pinvalue, strlen(pinvalue));
      xfree (pinvalue);
    }
  if (err)
    {
      log_error ("PIN verification failed: %s\n", gpg_strerror (err));
      return err;
    }
  log_debug ("PIN verification succeeded\n");
  return err;
}



/* Handler for the PKSIGN command.

   Create the signature and return the allocated result in OUTDATA.
   If a PIN is required, the PINCB will be used to ask for the PIN;
   that callback should return the PIN in an allocated buffer and
   store that as the 3rd argument.

   The API is somewhat inconsistent: The caller can either supply
   a plain hash and the algorithm in hashalgo or a complete
   DigestInfo structure. The former is detect by characteristic length
   of the provided data (20,28,32,48 or 64 byte).

   The function returns the RSA block in the size of the modulus or
   the ECDSA signature in X9.62 format (SEQ/INT(r)/INT(s))
*/
static gpg_error_t
do_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
         gpg_error_t (*pincb)(void*, const char *, char **),
         void *pincb_arg,
         const void *indata, size_t indatalen,
         unsigned char **outdata, size_t *outdatalen )
{
  static unsigned char rmd160_prefix[15] = /* Object ID is 1.3.36.3.2.1 */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
      0x02, 0x01, 0x05, 0x00, 0x04, 0x14  };
  static unsigned char sha1_prefix[15] =   /* (1.3.14.3.2.26) */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14  };
  static unsigned char sha224_prefix[19] = /* (2.16.840.1.101.3.4.2.4) */
    { 0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
      0x1C  };
  static unsigned char sha256_prefix[19] = /* (2.16.840.1.101.3.4.2.1) */
    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
      0x00, 0x04, 0x20  };
  static unsigned char sha384_prefix[19] = /* (2.16.840.1.101.3.4.2.2) */
    { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
      0x00, 0x04, 0x30  };
  static unsigned char sha512_prefix[19] = /* (2.16.840.1.101.3.4.2.3) */
    { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
      0x00, 0x04, 0x40  };

  gpg_error_t err;
  unsigned char cdsblk[256]; /* Raw PKCS#1 V1.5 block with padding
                                (RSA) or hash.  */
  prkdf_object_t prkdf;      /* The private key object. */
  size_t cdsblklen;
  unsigned char algoid;
  int sw;

  (void)ctrl;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (indatalen > 124)          /* Limit for 1024 bit key */
    return gpg_error (GPG_ERR_INV_VALUE);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err)
    return err;
  if (!(prkdf->usageflags.sign || prkdf->usageflags.sign_recover
        ||prkdf->usageflags.non_repudiation))
    {
      log_error ("key %s may not be used for signing\n", keyidstr);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  if (prkdf->keytype == KEY_TYPE_RSA)
    {
      algoid = 0x20;

      cdsblklen = prkdf->keysize >> 3;
      if (!cdsblklen)
        cdsblklen = 256;

      if (hashalgo == GCRY_MD_SHA1 && indatalen == 20)
        apply_PKCS_padding (indata, indatalen,
                            sha1_prefix, sizeof(sha1_prefix),
                            cdsblk, cdsblklen);
      else if (hashalgo == GCRY_MD_MD5 && indatalen == 20)
        apply_PKCS_padding (indata, indatalen,
                            rmd160_prefix, sizeof(rmd160_prefix),
                            cdsblk, cdsblklen);
      else if (hashalgo == GCRY_MD_SHA224 && indatalen == 28)
        apply_PKCS_padding (indata, indatalen,
                            sha224_prefix, sizeof(sha224_prefix),
                            cdsblk, cdsblklen);
      else if (hashalgo == GCRY_MD_SHA256 && indatalen == 32)
        apply_PKCS_padding (indata, indatalen,
                            sha256_prefix, sizeof(sha256_prefix),
                            cdsblk, cdsblklen);
      else if (hashalgo == GCRY_MD_SHA384 && indatalen == 48)
        apply_PKCS_padding (indata, indatalen,
                            sha384_prefix, sizeof(sha384_prefix),
                            cdsblk, cdsblklen);
      else if (hashalgo == GCRY_MD_SHA512 && indatalen == 64)
        apply_PKCS_padding (indata, indatalen,
                            sha512_prefix, sizeof(sha512_prefix),
                            cdsblk, cdsblklen);
      else  /* Assume it's already a digest info or TLS_MD5SHA1 */
        apply_PKCS_padding (indata, indatalen, NULL, 0, cdsblk, cdsblklen);
    }
  else
    {
      algoid = 0x70;
      if (indatalen != 20 && indatalen != 28 && indatalen != 32
          && indatalen != 48 && indatalen != 64)
        {
          cdsblklen = sizeof(cdsblk);
          err = hash_from_digestinfo (indata, indatalen, cdsblk, &cdsblklen);
          if (err)
            {
              log_error ("DigestInfo invalid: %s\n", gpg_strerror (err));
              return err;
            }
        }
      else
        {
          memcpy (cdsblk, indata, indatalen);
          cdsblklen = indatalen;
        }
    }

  err = verify_pin (app, pincb, pincb_arg);
  if (err)
    return err;

  sw = apdu_send_le (app_get_slot (app),
                     1, 0x80, 0x68, prkdf->key_reference, algoid,
                     cdsblklen, cdsblk, 0, outdata, outdatalen);
  return iso7816_map_sw (sw);
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
  if (!prkdf->usageflags.sign)
    {
      log_error ("key %s may not be used for authentication\n", keyidstr);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  algo = indatalen == 36? MD_USER_TLS_MD5SHA1 : GCRY_MD_SHA1;
  return do_sign (app, ctrl, keyidstr, algo, pincb, pincb_arg,
                  indata, indatalen, outdata, outdatalen);
}



/* Check PKCS#1 V1.5 padding and extract plain text.  The function
 * allocates a buffer for the plain text.  The caller must release the
 * buffer.  */
static gpg_error_t
strip_PKCS15_padding(unsigned char *src, int srclen, unsigned char **dst,
                     size_t *dstlen)
{
  unsigned char *p;

  if (srclen < 2)
    return gpg_error (GPG_ERR_DECRYPT_FAILED);
  if (*src++ != 0x00)
    return gpg_error (GPG_ERR_DECRYPT_FAILED);
  if (*src++ != 0x02)
    return gpg_error (GPG_ERR_DECRYPT_FAILED);
  srclen -= 2;
  while ((srclen > 0) && *src)
    {
      src++;
      srclen--;
    }

  if (srclen < 2)
    return gpg_error (GPG_ERR_DECRYPT_FAILED);

  src++;
  srclen--;

  p = xtrymalloc (srclen);
  if (!p)
    return gpg_error_from_syserror ();

  memcpy (p, src, srclen);
  *dst = p;
  *dstlen = srclen;

  return 0;
}


/* Decrypt a PKCS#1 V1.5 formatted cryptogram using the referenced
   key.  */
static gpg_error_t
do_decipher (app_t app, ctrl_t ctrl, const char *keyidstr,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const void *indata, size_t indatalen,
             unsigned char **outdata, size_t *outdatalen,
             unsigned int *r_info)
{
  gpg_error_t err;
  unsigned char p1blk[256]; /* Enciphered P1 block */
  prkdf_object_t prkdf;     /* The private key object. */
  unsigned char *rspdata;
  size_t rspdatalen;
  size_t p1blklen;
  int sw;

  (void)ctrl;

  if (!keyidstr || !*keyidstr || !indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = prkdf_object_from_keyidstr (app, keyidstr, &prkdf);
  if (err)
    return err;
  if (!(prkdf->usageflags.decrypt || prkdf->usageflags.unwrap))
    {
      log_error ("key %s may not be used for deciphering\n", keyidstr);
      return gpg_error (GPG_ERR_WRONG_KEY_USAGE);
    }

  if (prkdf->keytype != KEY_TYPE_RSA)
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  p1blklen = prkdf->keysize >> 3;
  if (!p1blklen)
    p1blklen = 256;

  /* The input may be shorter (due to MPIs not storing leading zeroes)
     or longer than the block size.  We put INDATA right aligned into
     the buffer.  If INDATA is longer than the block size we truncate
     it on the left. */
  memset (p1blk, 0, sizeof(p1blk));
  if (indatalen > p1blklen)
    memcpy (p1blk, (unsigned char *)indata + (indatalen - p1blklen), p1blklen);
  else
    memcpy (p1blk + (p1blklen - indatalen), indata, indatalen);


  err = verify_pin(app, pincb, pincb_arg);
  if (err)
    return err;

  sw = apdu_send_le (app_get_slot (app),
                     1, 0x80, 0x62, prkdf->key_reference, 0x21,
                     p1blklen, p1blk, 0, &rspdata, &rspdatalen);
  err = iso7816_map_sw (sw);
  if (err)
    {
      log_error ("Decrypt failed: %s\n", gpg_strerror (err));
      return err;
    }

  err = strip_PKCS15_padding (rspdata, rspdatalen, outdata, outdatalen);
  xfree (rspdata);

  if (!err)
    *r_info |= APP_DECIPHER_INFO_NOPAD;

  return err;
}



/*
 * Select the SmartCard-HSM application on the card in SLOT.
 */
gpg_error_t
app_select_sc_hsm (app_t app)
{
  int slot = app_get_slot (app);
  int rc;

  rc = iso7816_select_application (slot, sc_hsm_aid, sizeof sc_hsm_aid, 0);
  if (!rc)
    {
      app->apptype = APPTYPE_SC_HSM;

      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          rc = gpg_error_from_syserror ();
          goto leave;
        }

      rc = read_meta (app);
      if (rc)
        goto leave;

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
