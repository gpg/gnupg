/* app-nks.c - The Telesec NKS 2.0 card application.
 *	Copyright (C) 2004 Free Software Foundation, Inc.
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
#include "tlv.h"

static struct {
  int fid;       /* File ID. */
  int certtype;  /* Type of certificate or 0 if it is not a certificate. */
  int iskeypair; /* If true has the FID of the correspoding certificate. */
  int issignkey; /* True if file is a key usable for signing. */
  int isenckey;  /* True if file is a key usable for decryption. */
} filelist[] = {
  { 0x4531, 0,  0xC000, 1, 0 }, 
  { 0xC000, 101 },
  { 0x4331, 100 },
  { 0x4332, 100 },
  { 0xB000, 110 },
  { 0x45B1, 0,  0xC200, 0, 1 },
  { 0xC200, 101 },
  { 0x43B1, 100 },
  { 0x43B2, 100 },
  { 0, 0 }
};



/* Given the slot and the File Id FID, return the length of the
   certificate contained in that file. Returns 0 if the file does not
   exists or does not contain a certificate. */
static size_t
get_length_of_cert (int slot, int fid)
{
  gpg_error_t err;
  unsigned char *buffer;
  const unsigned char *p;
  size_t buflen, n;
  int class, tag, constructed, ndef;
  size_t objlen, hdrlen;

  err = iso7816_select_file (slot, fid, 0, NULL, NULL);
  if (err)
    {
      log_info ("error selecting FID 0x%04X: %s\n", fid, gpg_strerror (err));
      return 0;
    }

  err = iso7816_read_binary (slot, 0, 32, &buffer, &buflen);
  if (err)
    {
      log_info ("error reading certificate from FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return 0;
    }
  
  if (!buflen || *buffer == 0xff)
    {
      log_info ("no certificate contained in FID 0x%04X\n", fid);
      xfree (buffer);
      return 0;
    }

  p = buffer;
  n = buflen;
  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (err)
    {
      log_info ("error parsing certificate in FID 0x%04X: %s\n",
                fid, gpg_strerror (err));
      xfree (buffer);
      return 0;
    }

  /* All certificates should commence with a SEQUENCE expect fro the
     special ROOT CA which are enclosed in a SET. */
  if ( !(class == CLASS_UNIVERSAL &&  constructed
         && (tag == TAG_SEQUENCE || tag == TAG_SET)))
    {
      log_info ("contents of FID 0x%04X does not look like a certificate\n",
                fid);
      return 0;
    }
 
  return objlen + hdrlen;
}



/* Read the file with FID, assume it contains a public key and return
   its keygrip in the caller provided 41 byte buffer R_GRIPSTR. */
static gpg_error_t
keygripstr_from_pk_file (int slot, int fid, char *r_gripstr)
{
  gpg_error_t err;
  unsigned char grip[20];
  unsigned char *buffer[2];
  size_t buflen[2];
  gcry_sexp_t sexp;
  int i;
  
  err = iso7816_select_file (slot, fid, 0, NULL, NULL);
  if (err)
    return err;
  err = iso7816_read_record (slot, 1, 1, 0, &buffer[0], &buflen[0]);
  if (err)
    return err;
  err = iso7816_read_record (slot, 2, 1, 0, &buffer[1], &buflen[1]);
  if (err)
    {
      xfree (buffer[0]);
      return err;
    }
  
  for (i=0; i < 2; i++)
    {
      /* Check that the value appears like an integer encoded as
         Simple-TLV.  We don't check the tag because the tests cards I
         have use 1 for both, the modulus and the exponent - the
         example in the documentation gives 2 for the exponent. */
      if (buflen[i] < 3)
        err = gpg_error (GPG_ERR_TOO_SHORT);
      else if (buffer[i][1] != buflen[i]-2 )
        err = gpg_error (GPG_ERR_INV_OBJ);
    }

  if (!err)
    err = gcry_sexp_build (&sexp, NULL,
                           "(public-key (rsa (n %b) (e %b)))",
                           (int)buflen[0]-2, buffer[0]+2,
                           (int)buflen[1]-2, buffer[1]+2);

  xfree (buffer[0]);
  xfree (buffer[1]);
  if (err)
    return err;

  if (!gcry_pk_get_keygrip (sexp, grip))
    {
      err = gpg_error (GPG_ERR_INTERNAL); /* i.e. RSA not supported by
                                             libgcrypt. */
    }
  else
    {
      for (i=0; i < 20; i++)
        sprintf (r_gripstr+i*2, "%02X", grip[i]);
    }
  gcry_sexp_release (sexp);
  return err;
}



static int
do_learn_status (APP app, CTRL ctrl)
{
  gpg_error_t err;
  char ct_buf[100], id_buf[100];
  int i;

  /* Output information about all useful objects. */
  for (i=0; filelist[i].fid; i++)
    {
      if (filelist[i].certtype)
        {
          size_t len = get_length_of_cert (app->slot, filelist[i].fid);

          if (len)
            {
              /* FIXME: We should store the length in the application's
                 context so that a following readcert does only need to
                 read that many bytes. */
              sprintf (ct_buf, "%d", filelist[i].certtype);
              sprintf (id_buf, "NKS-DF01.%04X", filelist[i].fid);
              send_status_info (ctrl, "CERTINFO",
                                ct_buf, strlen (ct_buf), 
                                id_buf, strlen (id_buf), 
                                NULL, (size_t)0);
            }
        }
      else if (filelist[i].iskeypair)
        {
          char gripstr[40+1];

          err = keygripstr_from_pk_file (app->slot, filelist[i].fid, gripstr);
          if (err)
            log_error ("can't get keygrip from FID 0x%04X: %s\n",
                       filelist[i].fid, gpg_strerror (err));
          else
            {
              sprintf (id_buf, "NKS-DF01.%04X", filelist[i].fid);
              send_status_info (ctrl, "KEYPAIRINFO",
                                gripstr, 40, 
                                id_buf, strlen (id_buf), 
                                NULL, (size_t)0);
            }
        }
    }

  return 0;
}




/* Read the certificate with id CERTID (as returned by learn_status in
   the CERTINFO status lines) and return it in the freshly allocated
   buffer put into CERT and the length of the certificate put into
   CERTLEN. */
static int
do_readcert (app_t app, const char *certid,
             unsigned char **cert, size_t *certlen)
{
  int i, fid;
  gpg_error_t err;
  unsigned char *buffer;
  const unsigned char *p;
  size_t buflen, n;
  int class, tag, constructed, ndef;
  size_t totobjlen, objlen, hdrlen;
  int rootca = 0;

  *cert = NULL;
  *certlen = 0;
  if (strncmp (certid, "NKS-DF01.", 9) ) 
    return gpg_error (GPG_ERR_INV_ID);
  certid += 9;
  if (!hexdigitp (certid) || !hexdigitp (certid+1)
      || !hexdigitp (certid+2) || !hexdigitp (certid+3) 
      || certid[4])
    return gpg_error (GPG_ERR_INV_ID);
  fid = xtoi_4 (certid);
  for (i=0; filelist[i].fid; i++)
    if ((filelist[i].certtype || filelist[i].iskeypair)
        && filelist[i].fid == fid)
      break;
  if (!filelist[i].fid)
    return gpg_error (GPG_ERR_NOT_FOUND);

  /* If the requested objects is a plain public key, redirect it to
     the corresponding certificate.  The whole system is a bit messy
     becuase we sometime use the key directly or let the caller
     retrieve the key from the certificate.  The valid point behind
     that is to support not-yet stored certificates. */
  if (filelist[i].iskeypair)
    fid = filelist[i].iskeypair;


  /* Read the entire file.  fixme: This could be optimized by first
     reading the header to figure out how long the certificate
     actually is. */
  err = iso7816_select_file (app->slot, fid, 0, NULL, NULL);
  if (err)
    {
      log_error ("error selecting FID 0x%04X: %s\n", fid, gpg_strerror (err));
      return err;
    }

  err = iso7816_read_binary (app->slot, 0, 0, &buffer, &buflen);
  if (err)
    {
      log_error ("error reading certificate from FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return err;
    }
  
  if (!buflen || *buffer == 0xff)
    {
      log_info ("no certificate contained in FID 0x%04X\n", fid);
      err = gpg_error (GPG_ERR_NOT_FOUND);
      goto leave;
    }

  /* Now figure something out about the object. */
  p = buffer;
  n = buflen;
  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (err)
    goto leave;
  if ( class == CLASS_UNIVERSAL && tag == TAG_SEQUENCE && constructed )
    ;
  else if ( class == CLASS_UNIVERSAL && tag == TAG_SET && constructed )
    rootca = 1;
  else
    return gpg_error (GPG_ERR_INV_OBJ);
  totobjlen = objlen + hdrlen;
  assert (totobjlen <= buflen);

  err = parse_ber_header (&p, &n, &class, &tag, &constructed,
                          &ndef, &objlen, &hdrlen);
  if (err)
    goto leave;
  
  if (rootca)
    ;
  else if (class == CLASS_UNIVERSAL && tag == TAG_OBJECT_ID && !constructed)
    {
      const unsigned char *save_p;
  
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
        return gpg_error (GPG_ERR_INV_OBJ);
      totobjlen = objlen + hdrlen;
      assert (save_p + totobjlen <= buffer + buflen);
      memmove (buffer, save_p, totobjlen);
    }
  
  *cert = buffer;
  buffer = NULL;
  *certlen = totobjlen;

 leave:
  xfree (buffer);
  return err;
}


/* Verify the PIN if required.  */
static int
verify_pin (app_t app,
            int (pincb)(void*, const char *, char **),
            void *pincb_arg)
{
  /* Note that force_chv1 is never set but we do it here anyway so
     that other applications may euse this function.  For example it
     makes sense to set force_chv1 for German signature law cards.
     NKS is very similar to the DINSIG draft standard. */
  if (!app->did_chv1 || app->force_chv1 ) 
    {
      char *pinvalue;
      int rc;

      rc = pincb (pincb_arg, "PIN", &pinvalue); 
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      /* The follwoing limits are due to TCOS but also defined in the
         NKS specs. */
      if (strlen (pinvalue) < 6)
        {
          log_error ("PIN is too short; minimum length is 6\n");
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }
      else if (strlen (pinvalue) > 16)
        {
          log_error ("PIN is too large; maximum length is 16\n");
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }

      /* Also it is possible to use a local PIN, we use the gloabl
         PIN for this application.  */
      rc = iso7816_verify (app->slot, 0, pinvalue, strlen (pinvalue));
      if (rc)
        {
          log_error ("verify PIN failed\n");
          xfree (pinvalue);
          return rc;
        }
      app->did_chv1 = 1;
      xfree (pinvalue);
    }

  return 0;
}



/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN;
   that callback should return the PIN in an allocated buffer and
   store that in the 3rd argument.  */
static int 
do_sign (app_t app, const char *keyidstr, int hashalgo,
         int (pincb)(void*, const char *, char **),
           void *pincb_arg,
           const void *indata, size_t indatalen,
           unsigned char **outdata, size_t *outdatalen )
{
  static unsigned char sha1_prefix[15] = /* Object ID is 1.3.14.3.2.26 */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
  static unsigned char rmd160_prefix[15] = /* Object ID is 1.3.36.3.2.1 */
    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
      0x02, 0x01, 0x05, 0x00, 0x04, 0x14 };
  int rc, i;
  int fid;
  unsigned char data[35];   /* Must be large enough for a SHA-1 digest
                               + the largest OID _prefix above. */

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (indatalen != 20 && indatalen != 16 && indatalen != 35)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check that the provided ID is vaid.  This is not really needed
     but we do it to to enforce correct usage by the caller. */
  if (strncmp (keyidstr, "NKS-DF01.", 9) ) 
    return gpg_error (GPG_ERR_INV_ID);
  keyidstr += 9;
  if (!hexdigitp (keyidstr) || !hexdigitp (keyidstr+1)
      || !hexdigitp (keyidstr+2) || !hexdigitp (keyidstr+3) 
      || keyidstr[4])
    return gpg_error (GPG_ERR_INV_ID);
  fid = xtoi_4 (keyidstr);
  for (i=0; filelist[i].fid; i++)
    if (filelist[i].iskeypair && filelist[i].fid == fid)
      break;
  if (!filelist[i].fid)
    return gpg_error (GPG_ERR_NOT_FOUND);
  if (!filelist[i].issignkey)
    return gpg_error (GPG_ERR_INV_ID);

  /* Prepare the DER object from INDATA. */
  if (indatalen == 35)
    {
      /* Alright, the caller was so kind to send us an already
         prepared DER object.  Check that it is waht we want and that
         it matches the hash algorithm. */
      if (hashalgo == GCRY_MD_SHA1 && !memcmp (indata, sha1_prefix, 15))
        ;
      else if (hashalgo == GCRY_MD_RMD160 && !memcmp (indata, rmd160_prefix,15))
        ;
      else 
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data, indata, indatalen);
    }
  else
    {
      if (hashalgo == GCRY_MD_SHA1)
        memcpy (data, sha1_prefix, 15);
      else if (hashalgo == GCRY_MD_RMD160)
        memcpy (data, rmd160_prefix, 15);
      else 
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data+15, indata, indatalen);
    }

  rc = verify_pin (app, pincb, pincb_arg);
  if (!rc)
    rc = iso7816_compute_ds (app->slot, data, 35, outdata, outdatalen);
  return rc;
}




/* Decrypt the data in INDATA and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
static int 
do_decipher (app_t app, const char *keyidstr,
             int (pincb)(void*, const char *, char **),
             void *pincb_arg,
             const void *indata, size_t indatalen,
             unsigned char **outdata, size_t *outdatalen )
{
  static const unsigned char mse_parm[] = {
    0x80, 1, 0x10, /* Select algorithm RSA. */
    0x84, 1, 0x81  /* Select locak secret key 1 for descryption. */
  };
  int rc, i;
  int fid;

  if (!keyidstr || !*keyidstr || !indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check that the provided ID is vaid.  This is not really needed
     but we do it to to enforce correct usage by the caller. */
  if (strncmp (keyidstr, "NKS-DF01.", 9) ) 
    return gpg_error (GPG_ERR_INV_ID);
  keyidstr += 9;
  if (!hexdigitp (keyidstr) || !hexdigitp (keyidstr+1)
      || !hexdigitp (keyidstr+2) || !hexdigitp (keyidstr+3) 
      || keyidstr[4])
    return gpg_error (GPG_ERR_INV_ID);
  fid = xtoi_4 (keyidstr);
  for (i=0; filelist[i].fid; i++)
    if (filelist[i].iskeypair && filelist[i].fid == fid)
      break;
  if (!filelist[i].fid)
    return gpg_error (GPG_ERR_NOT_FOUND);
  if (!filelist[i].isenckey)
    return gpg_error (GPG_ERR_INV_ID);

  /* Do the TCOS specific MSE. */
  rc = iso7816_manage_security_env (app->slot, 
                                    0xC1, 0xB8,
                                    mse_parm, sizeof mse_parm);
  if (!rc)
    rc = verify_pin (app, pincb, pincb_arg);
  if (!rc)
    rc = iso7816_decipher (app->slot, indata, indatalen, 0x81,
                           outdata, outdatalen);
  return rc;
}



/* Select the NKS 2.0 application on the card in SLOT.  */
int
app_select_nks (APP app)
{
  static char const aid[] = { 0xD2, 0x76, 0x00, 0x00, 0x03, 0x01, 0x02 };
  int slot = app->slot;
  int rc;
  
  rc = iso7816_select_application (slot, aid, sizeof aid);
  if (!rc)
    {
      app->apptype = "NKS";

      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.getattr = NULL;
      app->fnc.setattr = NULL;
      app->fnc.genkey = NULL;
      app->fnc.sign = do_sign;
      app->fnc.auth = NULL;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = NULL;
      app->fnc.check_pin = NULL;
   }

  return rc;
}


