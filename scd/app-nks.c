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
  int fid;      /* File ID. */
  int certtype; /* Type of certificate or 0 if it is not a certificate. */
  int iskeypair; /* If true has the FID of the correspoding certificate. */
} filelist[] = {
  { 0x4531, 0,  0xC000 }, 
  { 0xC000, 101 },
  { 0x4331, 100 },
  { 0x4332, 100 },
  { 0xB000, 110 },
  { 0x45B1, 0,  0xC200 },
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
  err = iso7816_read_record (slot, 1, 1, &buffer[0], &buflen[0]);
  if (err)
    return err;
  err = iso7816_read_record (slot, 2, 1, &buffer[1], &buflen[1]);
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
      app->fnc.sign = NULL;
      app->fnc.auth = NULL;
      app->fnc.decipher = NULL;
      app->fnc.change_pin = NULL;
      app->fnc.check_pin = NULL;
   }

  return rc;
}


