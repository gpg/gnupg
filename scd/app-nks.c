/* app-nks.c - The Telesec NKS card application.
 * Copyright (C) 2004, 2007, 2008, 2009 Free Software Foundation, Inc.
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

/* Notes:

  - This is still work in progress.  We are now targeting TCOS 3 cards
    but try to keep compatibility to TCOS 2.  Both are not fully
    working as of now.  TCOS 3 PIN management seems to work.  Use GPA
    from SVN trunk to test it.

  - If required, we automagically switch between the NKS application
    and the SigG application.  This avoids to use the DINSIG
    application which is somewhat limited, has no support for Secure
    Messaging as required by TCOS 3 and has no way to change the PIN
    or even set the NullPIN.

  - We use the prefix NKS-DF01 for TCOS 2 cards and NKS-NKS3 for newer
    cards.  This is because the NKS application has moved to DF02 with
    TCOS 3 and thus we better use a DF independent tag.

  - We use only the global PINs for the NKS application.

 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "scdaemon.h"
#include "i18n.h"
#include "iso7816.h"
#include "app-common.h"
#include "tlv.h"
#include "apdu.h"

static char const aid_nks[]  = { 0xD2, 0x76, 0x00, 0x00, 0x03, 0x01, 0x02 };
static char const aid_sigg[] = { 0xD2, 0x76, 0x00, 0x00, 0x66, 0x01 };


static struct
{
  int is_sigg;   /* Valid for SigG application.  */
  int fid;       /* File ID. */
  int nks_ver;   /* 0 for NKS version 2, 3 for version 3. */
  int certtype;  /* Type of certificate or 0 if it is not a certificate. */
  int iskeypair; /* If true has the FID of the correspoding certificate. */
  int issignkey; /* True if file is a key usable for signing. */
  int isenckey;  /* True if file is a key usable for decryption. */
} filelist[] = {
  { 0, 0x4531, 0, 0,  0xC000, 1, 0 }, /* EF_PK.NKS.SIG */
  { 1, 0x4531, 3, 0,  0x0000, 1, 1 }, /* EF_PK.CH.SIG  */
  { 0, 0xC000, 0, 101 },              /* EF_C.NKS.SIG  */
  { 1, 0xC000, 0, 101 },              /* EF_C.CH.SIG  */
  { 0, 0x4331, 0, 100 },
  { 0, 0x4332, 0, 100 },
  { 0, 0xB000, 0, 110 },              /* EF_PK.RCA.NKS */
  { 0, 0x45B1, 0, 0,  0xC200, 0, 1 }, /* EF_PK.NKS.ENC */
  { 0, 0xC200, 0, 101 },              /* EF_C.NKS.ENC  */
  { 0, 0x43B1, 0, 100 },
  { 0, 0x43B2, 0, 100 },
  { 0, 0x4571, 3, 0,  0xc500, 0, 0 }, /* EF_PK.NKS.AUT */
  { 0, 0xC500, 3, 101 },              /* EF_C.NKS.AUT  */
  { 0, 0x45B2, 3, 0,  0xC201, 0, 1 }, /* EF_PK.NKS.ENC1024 */
  { 0, 0xC201, 3, 101 },              /* EF_C.NKS.ENC1024  */
/*   { 1, 0xB000, 3, ...  */
  { 0, 0 }
};



/* Object with application (i.e. NKS) specific data.  */
struct app_local_s {
  int nks_version;  /* NKS version.  */

  int sigg_active;  /* True if switched to the SigG application.  */
};



static gpg_error_t switch_application (app_t app, int enable_sigg);



/* Release local data. */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      xfree (app->app_local);
      app->app_local = NULL;
    }
}


/* Read the file with FID, assume it contains a public key and return
   its keygrip in the caller provided 41 byte buffer R_GRIPSTR. */
static gpg_error_t
keygripstr_from_pk_file (app_t app, int fid, char *r_gripstr)
{
  gpg_error_t err;
  unsigned char grip[20];
  unsigned char *buffer[2];
  size_t buflen[2];
  gcry_sexp_t sexp;
  int i;
  
  err = iso7816_select_file (app->slot, fid, 0, NULL, NULL);
  if (err)
    return err;
  err = iso7816_read_record (app->slot, 1, 1, 0, &buffer[0], &buflen[0]);
  if (err)
    return err;
  err = iso7816_read_record (app->slot, 2, 1, 0, &buffer[1], &buflen[1]);
  if (err)
    {
      xfree (buffer[0]);
      return err;
    }
  
  if (app->app_local->nks_version < 3)
    {
      /* Old versions of NKS store the values in a TLV encoded format.
         We need to do some checks.  */
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
      bin2hex (grip, 20, r_gripstr);
    }
  gcry_sexp_release (sexp);
  return err;
}


/* TCOS responds to a verify with empty data (i.e. without the Lc
   byte) with the status of the PIN.  PWID is the PIN ID, If SIGG is
   true, the application is switched into SigG mode.
   Returns:
            -1 = Error retrieving the data,
            -2 = No such PIN,
            -3 = PIN blocked,
            -4 = NullPIN activ,
        n >= 0 = Number of verification attempts left.  */
static int
get_chv_status (app_t app, int sigg, int pwid)
{
  unsigned char *result = NULL;
  size_t resultlen;
  char command[4];
  int rc;

  if (switch_application (app, sigg))
    return sigg? -2 : -1; /* No such PIN / General error.  */

  command[0] = 0x00;
  command[1] = 0x20;
  command[2] = 0x00;
  command[3] = pwid;

  if (apdu_send_direct (app->slot, command, 4, 0, &result, &resultlen))
    rc = -1; /* Error. */
  else if (resultlen < 2)
    rc = -1; /* Error. */
  else
    {
      unsigned int sw = ((result[resultlen-2] << 8) | result[resultlen-1]);

      if (sw == 0x6a88)
        rc = -2; /* No such PIN.  */
      else if (sw == 0x6983)
        rc = -3; /* PIN is blocked.  */
      else if (sw == 0x6985)
        rc = -4; /* NullPIN is activ.  */
      else if ((sw & 0xfff0) == 0x63C0)
        rc = (sw & 0x000f); /* PIN has N tries left.  */
      else
        rc = -1; /* Other error.  */
    }
  xfree (result);

  return rc;
}


/* Implement the GETATTR command.  This is similar to the LEARN
   command but returns just one value via the status interface. */
static gpg_error_t 
do_getattr (app_t app, ctrl_t ctrl, const char *name)
{
  static struct {
    const char *name;
    int special;
  } table[] = {
    { "$AUTHKEYID",   1 },
    { "NKS-VERSION",  2 },
    { "CHV-STATUS",   3 },
    { NULL, 0 }
  };
  gpg_error_t err = 0;
  int idx;
  char buffer[100];

  err = switch_application (app, 0);
  if (err)
    return err;

  for (idx=0; table[idx].name && strcmp (table[idx].name, name); idx++)
    ;
  if (!table[idx].name)
    return gpg_error (GPG_ERR_INV_NAME); 

  switch (table[idx].special)
    {
    case 1: /* $AUTHKEYID */
      {
        /* NetKey 3.0 cards define this key for authentication.
           FIXME: We don't have the readkey command, so this
           information is pretty useless.  */
        char const tmp[] = "NKS-NKS3.4571";
        send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      }
      break;

    case 2: /* NKS-VERSION */
      snprintf (buffer, sizeof buffer, "%d", app->app_local->nks_version);
      send_status_info (ctrl, table[idx].name,
                        buffer, strlen (buffer), NULL, 0);
      break;

    case 3: /* CHV-STATUS */
      {
        /* Returns: PW1.CH PW2.CH PW1.CH.SIG PW2.CH.SIG That are the
           two global passwords followed by the two SigG passwords.
           For the values, see the function get_chv_status.  */
        int tmp[4];
        
        /* We use a helper array so that we can control that there is
           no superfluous application switch.  Note that PW2.CH.SIG
           really has the identifier 0x83 and not 0x82 as one would
           expect.  */
        tmp[0] = get_chv_status (app, 0, 0x00);
        tmp[1] = get_chv_status (app, 0, 0x01);
        tmp[2] = get_chv_status (app, 1, 0x81);
        tmp[3] = get_chv_status (app, 1, 0x83); 
        snprintf (buffer, sizeof buffer, 
                  "%d %d %d %d", tmp[0], tmp[1], tmp[2], tmp[3]);
        send_status_info (ctrl, table[idx].name,
                          buffer, strlen (buffer), NULL, 0);
      }
      break;


    default:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      break;
    }

  return err;
}



static void
do_learn_status_core (app_t app, ctrl_t ctrl, int is_sigg)
{
  gpg_error_t err;
  char ct_buf[100], id_buf[100];
  int i;
  const char *tag;

  if (is_sigg)
    tag = "SIGG";
  else if (app->app_local->nks_version < 3)
    tag = "DF01";
  else
    tag = "NKS3";

  /* Output information about all useful objects in the NKS application. */
  for (i=0; filelist[i].fid; i++)
    {
      if (filelist[i].nks_ver > app->app_local->nks_version)
        continue;

      if (!!filelist[i].is_sigg != !!is_sigg)
        continue;

      if (filelist[i].certtype)
        {
          size_t len;

          len = app_help_read_length_of_cert (app->slot,
                                              filelist[i].fid, NULL);
          if (len)
            {
              /* FIXME: We should store the length in the application's
                 context so that a following readcert does only need to
                 read that many bytes. */
              snprintf (ct_buf, sizeof ct_buf, "%d", filelist[i].certtype);
              snprintf (id_buf, sizeof id_buf, "NKS-%s.%04X", 
                        tag, filelist[i].fid);
              send_status_info (ctrl, "CERTINFO",
                                ct_buf, strlen (ct_buf), 
                                id_buf, strlen (id_buf), 
                                NULL, (size_t)0);
            }
        }
      else if (filelist[i].iskeypair)
        {
          char gripstr[40+1];

          err = keygripstr_from_pk_file (app, filelist[i].fid, gripstr);
          if (err)
            log_error ("can't get keygrip from FID 0x%04X: %s\n",
                       filelist[i].fid, gpg_strerror (err));
          else
            {
              snprintf (id_buf, sizeof id_buf, "NKS-%s.%04X",
                        tag, filelist[i].fid);
              send_status_info (ctrl, "KEYPAIRINFO",
                                gripstr, 40, 
                                id_buf, strlen (id_buf), 
                                NULL, (size_t)0);
            }
        }
    }


}


static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl)
{
  gpg_error_t err;

  err = switch_application (app, 0);
  if (err)
    return err;
  
  do_learn_status_core (app, ctrl, 0);

  err = switch_application (app, 1);
  if (err)
    return 0;  /* Silently ignore if we can't switch to SigG.  */

  do_learn_status_core (app, ctrl, 1);

  return 0;
}




/* Read the certificate with id CERTID (as returned by learn_status in
   the CERTINFO status lines) and return it in the freshly allocated
   buffer put into CERT and the length of the certificate put into
   CERTLEN. */
static gpg_error_t
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
  int is_sigg = 0;

  *cert = NULL;
  *certlen = 0;

  if (!strncmp (certid, "NKS-NKS3.", 9)) 
    ;
  else if (!strncmp (certid, "NKS-DF01.", 9)) 
    ;
  else if (!strncmp (certid, "NKS-SIGG.", 9)) 
    is_sigg = 1;
  else
    return gpg_error (GPG_ERR_INV_ID);

  err = switch_application (app, is_sigg);
  if (err)
    return err;

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
     because we sometime use the key directly or let the caller
     retrieve the key from the certificate.  The rationale for
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


static gpg_error_t
basic_pin_checks (const char *pinvalue, int minlen, int maxlen)
{
  if (strlen (pinvalue) < minlen)
    {
      log_error ("PIN is too short; minimum length is %d\n", minlen);
      return gpg_error (GPG_ERR_BAD_PIN);
    }
  if (strlen (pinvalue) > maxlen)
    {
      log_error ("PIN is too large; maximum length is %d\n", maxlen);
      return gpg_error (GPG_ERR_BAD_PIN);
    }
  return 0;
}


/* Verify the PIN if required.  */
static gpg_error_t
verify_pin (app_t app, int pwid, const char *desc,
            gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg)
{
  iso7816_pininfo_t pininfo;
  int rc;

  if (!desc)
    desc = "PIN";

  memset (&pininfo, 0, sizeof pininfo);
  pininfo.mode = 1;
  pininfo.minlen = 6;
  pininfo.maxlen = 16;

  if (!opt.disable_keypad
      && !iso7816_check_keypad (app->slot, ISO7816_VERIFY, &pininfo) )
    {
      rc = pincb (pincb_arg, desc, NULL);
      if (rc)
        {
          log_info (_("PIN callback returned error: %s\n"),
                    gpg_strerror (rc));
          return rc;
        }
 
      rc = iso7816_verify_kp (app->slot, pwid, "", 0, &pininfo); 
      pincb (pincb_arg, NULL, NULL);  /* Dismiss the prompt. */
    }
  else
    {
      char *pinvalue;

      rc = pincb (pincb_arg, desc, &pinvalue); 
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      rc = basic_pin_checks (pinvalue, pininfo.minlen, pininfo.maxlen);
      if (rc)
        {
          xfree (pinvalue);
          return rc;
        }

      rc = iso7816_verify (app->slot, pwid, pinvalue, strlen (pinvalue));
      xfree (pinvalue);
    }

  if (rc)
    {
      if ( gpg_err_code (rc) == GPG_ERR_USE_CONDITIONS )
        log_error (_("the NullPIN has not yet been changed\n"));
      else
        log_error ("verify PIN failed\n");
      return rc;
    }

  return 0;
}



/* Create the signature and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN;
   that callback should return the PIN in an allocated buffer and
   store that in the 3rd argument.  */
static gpg_error_t 
do_sign (app_t app, const char *keyidstr, int hashalgo,
         gpg_error_t (*pincb)(void*, const char *, char **),
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
  int is_sigg = 0;
  int fid;
  unsigned char data[35];   /* Must be large enough for a SHA-1 digest
                               + the largest OID _prefix above. */

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (indatalen != 20 && indatalen != 16 && indatalen != 35)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check that the provided ID is valid.  This is not really needed
     but we do it to enforce correct usage by the caller. */
  if (!strncmp (keyidstr, "NKS-NKS3.", 9) ) 
    ;
  else if (!strncmp (keyidstr, "NKS-DF01.", 9) ) 
    ;
  else if (!strncmp (keyidstr, "NKS-SIGG.", 9) ) 
    is_sigg = 1;
  else
    return gpg_error (GPG_ERR_INV_ID);
  keyidstr += 9;

  rc = switch_application (app, is_sigg);
  if (rc)
    return rc;

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

  rc = verify_pin (app, 0, NULL, pincb, pincb_arg);
  if (!rc)
    rc = iso7816_compute_ds (app->slot, data, 35, outdata, outdatalen);
  return rc;
}



/* Decrypt the data in INDATA and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
static gpg_error_t 
do_decipher (app_t app, const char *keyidstr,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const void *indata, size_t indatalen,
             unsigned char **outdata, size_t *outdatalen )
{
  static const unsigned char mse_parm[] = {
    0x80, 1, 0x10, /* Select algorithm RSA. */
    0x84, 1, 0x81  /* Select local secret key 1 for decryption. */
  };
  int rc, i;
  int is_sigg = 0;
  int fid;

  if (!keyidstr || !*keyidstr || !indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check that the provided ID is valid.  This is not really needed
     but we do it to to enforce correct usage by the caller. */
  if (!strncmp (keyidstr, "NKS-NKS3.", 9) ) 
    ;
  else if (!strncmp (keyidstr, "NKS-DF01.", 9) ) 
    ;
  else if (!strncmp (keyidstr, "NKS-SIGG.", 9) ) 
    is_sigg = 1;
  else
    return gpg_error (GPG_ERR_INV_ID);
  keyidstr += 9;

  rc = switch_application (app, is_sigg);
  if (rc)
    return rc;

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
    rc = verify_pin (app, 0, NULL, pincb, pincb_arg);
  if (!rc)
    rc = iso7816_decipher (app->slot, indata, indatalen, 0x81,
                           outdata, outdatalen);
  return rc;
}



/* Parse a password ID string.  Returns NULL on error or a string
   suitable as passpahrse prompt on success.  On success stores the
   reference value for the password at R_PWID and a flag indicating
   that the SigG application is to be used at R_SIGG.  If NEW_MODE is
   true, the returned description is suitable for a new Password.
   Supported values for PWIDSTR are:

     PW1.CH       - Global password 1
     PW2.CH       - Global password 2
     PW1.CH.SIG   - SigG password 1
     PW2.CH.SIG   - SigG password 2
 */
static const char *
parse_pwidstr (const char *pwidstr, int new_mode, int *r_sigg, int *r_pwid)
{
  const char *desc;

  if (!pwidstr)
    desc = NULL;
  else if (!strcmp (pwidstr, "PW1.CH"))
    {
      *r_sigg = 0;
      *r_pwid = 0x00;
      /* TRANSLATORS: Do not translate the "|*|" prefixes but keep
         them verbatim at the start of the string.  */
      desc = (new_mode
              ? _("|N|Please enter a new PIN for the standard keys.")
              : _("||Please enter the PIN for the standard keys."));
    }
  else if (!strcmp (pwidstr, "PW2.CH"))
    {
      *r_pwid = 0x01;
      desc = (new_mode
              ? _("|NP|Please enter a new PIN Unblocking Code (PUK) "
                  "for the standard keys.")
              : _("|P|Please enter the PIN Unblocking Code (PUK) "
                  "for the standard keys."));
    }
  else if (!strcmp (pwidstr, "PW1.CH.SIG"))
    {
      *r_pwid = 0x81;
      *r_sigg = 1;
      desc = (new_mode
              ? _("|N|Please enter a new PIN for the key to create "
                  "qualified signatures.")
              : _("||Please enter the PIN for the key to create "
                  "qualified signatures."));
    }
  else if (!strcmp (pwidstr, "PW2.CH.SIG"))
    {
      *r_pwid = 0x83;  /* Yes, that is 83 and not 82.  */
      *r_sigg = 1;
      desc = (new_mode
              ? _("|NP|Please enter a new PIN Unblocking Code (PUK) "
                  "for the key to create qualified signatures.")
              : _("|P|Please enter the PIN Unblocking Code (PUK) "
                  "for the key to create qualified signatures."));
    }
  else
    desc = NULL;

  return desc;
}


/* Handle the PASSWD command. See parse_pwidstr() for allowed values
   for CHVNOSTR.  */
static gpg_error_t 
do_change_pin (app_t app, ctrl_t ctrl,  const char *pwidstr, 
               unsigned int flags,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  gpg_error_t err;
  char *newpin = NULL;
  char *oldpin = NULL;
  size_t newpinlen;
  size_t oldpinlen;
  int is_sigg;
  const char *newdesc;
  int pwid;
  iso7816_pininfo_t pininfo;

  (void)ctrl;

  /* The minimum length is enforced by TCOS, the maximum length is
     just a reasonable value.  */
  memset (&pininfo, 0, sizeof pininfo);
  pininfo.minlen = 6;
  pininfo.maxlen = 16;
  
  newdesc = parse_pwidstr (pwidstr, 1, &is_sigg, &pwid);
  if (!newdesc)
    return gpg_error (GPG_ERR_INV_ID);

  err = switch_application (app, is_sigg);
  if (err)
    return err;

  if ((flags & APP_CHANGE_FLAG_NULLPIN))
    {
      /* With the nullpin flag, we do not verify the PIN - it would
         fail if the Nullpin is still set.  */
      oldpin = xtrycalloc (1, 6);
      if (!oldpin)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      oldpinlen = 6;
    }
  else
    {
      const char *desc;
      int dummy1, dummy2;

      if ((flags & APP_CHANGE_FLAG_RESET))
        {
          /* Reset mode: Ask for the alternate PIN.  */
          const char *altpwidstr;

          if (!strcmp (pwidstr, "PW1.CH"))
            altpwidstr = "PW2.CH";
          else if (!strcmp (pwidstr, "PW2.CH"))
            altpwidstr = "PW1.CH";
          else if (!strcmp (pwidstr, "PW1.CH.SIG"))
            altpwidstr = "PW2.CH.SIG";
          else if (!strcmp (pwidstr, "PW2.CH.SIG"))
            altpwidstr = "PW1.CH.SIG";
          else
            {
              err = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          desc = parse_pwidstr (altpwidstr, 0, &dummy1, &dummy2);
        }
      else
        {
          /* Regular change mode:  Ask for the old PIN.  */
          desc = parse_pwidstr (pwidstr, 0, &dummy1, &dummy2);
        }
      err = pincb (pincb_arg, desc, &oldpin); 
      if (err)
        {
          log_error ("error getting old PIN: %s\n", gpg_strerror (err));
          goto leave;
        }
      oldpinlen = strlen (oldpin);
      err = basic_pin_checks (oldpin, pininfo.minlen, pininfo.maxlen);
      if (err)
        goto leave;
    }

  err = pincb (pincb_arg, newdesc, &newpin); 
  if (err)
    {
      log_error (_("error getting new PIN: %s\n"), gpg_strerror (err));
      goto leave;
    }
  newpinlen = strlen (newpin);
  
  err = basic_pin_checks (newpin, pininfo.minlen, pininfo.maxlen);
  if (err)
    goto leave;

  if ((flags & APP_CHANGE_FLAG_RESET))
    {
      char *data;
      size_t datalen = oldpinlen + newpinlen;

      data = xtrymalloc (datalen);
      if (!data)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      memcpy (data, oldpin, oldpinlen);
      memcpy (data+oldpinlen, newpin, newpinlen);
      err = iso7816_reset_retry_counter_with_rc (app->slot, pwid,
                                                 data, datalen);
      wipememory (data, datalen);
      xfree (data);
    }
  else 
    err = iso7816_change_reference_data (app->slot, pwid, 
                                         oldpin, oldpinlen,
                                         newpin, newpinlen);
 leave:
  xfree (oldpin);
  xfree (newpin);
  return err;
}


/* Perform a simple verify operation.  KEYIDSTR should be NULL or empty.  */
static gpg_error_t 
do_check_pin (app_t app, const char *pwidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg)
{
  gpg_error_t err;
  int pwid;
  int is_sigg;
  const char *desc;

  desc = parse_pwidstr (pwidstr, 0, &is_sigg, &pwid);
  if (!desc)
    return gpg_error (GPG_ERR_INV_ID);

  err = switch_application (app, is_sigg);
  if (err)
    return err;

  return verify_pin (app, pwid, desc, pincb, pincb_arg);
}


/* Return the version of the NKS application.  */
static int
get_nks_version (int slot)
{
  unsigned char *result = NULL;
  size_t resultlen;
  int type;

  if (iso7816_apdu_direct (slot, "\x80\xaa\x06\x00\x00", 5, 0, 
                           &result, &resultlen))
    return 2; /* NKS 2 does not support this command.  */
  
  /* Example value:    04 11 19 22 21 6A 20 80 03 03 01 01 01 00 00 00
                       vv tt ccccccccccccccccc aa bb cc vvvvvvvvvvv xx
     vendor (Philips) -+  |  |                 |  |  |  |           |
     chip type -----------+  |                 |  |  |  |           |
     chip id ----------------+                 |  |  |  |           |
     card type (3 - tcos 3) -------------------+  |  |  |           |
     OS version of card type ---------------------+  |  |           |
     OS release of card type ------------------------+  |           |
     OS vendor internal version ------------------------+           |
     RFU -----------------------------------------------------------+
  */
  if (resultlen < 16)
    type = 0;  /* Invalid data returned.  */
  else
    type = result[8];
  xfree (result);

  return type;
}


/* If ENABLE_SIGG is true switch to the SigG application if not yet
   active.  If false switch to the NKS application if not yet active.
   Returns 0 on success.  */
static gpg_error_t
switch_application (app_t app, int enable_sigg)
{
  gpg_error_t err;

  if ((app->app_local->sigg_active && enable_sigg)
      || (!app->app_local->sigg_active && !enable_sigg) )
    return 0;  /* Already switched.  */

  log_info ("app-nks: switching to %s\n", enable_sigg? "SigG":"NKS");
  if (enable_sigg)
    err = iso7816_select_application (app->slot, aid_sigg, sizeof aid_sigg, 0);
  else
    err = iso7816_select_application (app->slot, aid_nks, sizeof aid_nks, 0);
  
  if (!err)
    app->app_local->sigg_active = enable_sigg;
  else
    log_error ("app-nks: error switching to %s: %s\n",
               enable_sigg? "SigG":"NKS", gpg_strerror (err));

  return err;
}


/* Select the NKS application.  */
gpg_error_t
app_select_nks (app_t app)
{
  int slot = app->slot;
  int rc;
  
  rc = iso7816_select_application (slot, aid_nks, sizeof aid_nks, 0);
  if (!rc)
    {
      app->apptype = "NKS";

      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          rc = gpg_error (gpg_err_code_from_errno (errno));
          goto leave;
        }

      app->app_local->nks_version = get_nks_version (slot);
      if (opt.verbose)
        log_info ("Detected NKS version: %d\n", app->app_local->nks_version);

      app->fnc.deinit = do_deinit;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.getattr = do_getattr;
      app->fnc.setattr = NULL;
      app->fnc.genkey = NULL;
      app->fnc.sign = do_sign;
      app->fnc.auth = NULL;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = do_change_pin;
      app->fnc.check_pin = do_check_pin;
   }

 leave:
  if (rc)
    do_deinit (app);
  return rc;
}


