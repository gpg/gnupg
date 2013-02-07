/* app-dinsig.c - The DINSIG (DIN V 66291-1) card application.
 * Copyright (C) 2002, 2004, 2005, 2007, 2008 Free Software Foundation, Inc.
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


/* The German signature law and its bylaw (SigG and SigV) is currently
   used with an interface specification described in DIN V 66291-1.
   The AID to be used is: 'D27600006601'.

   The file IDs for certificates utilize the generic format: 
        Cxyz
    C being the hex digit 'C' (12).
    x being the service indicator:
         '0' := SigG conform digital signature.
         '1' := entity authentication.
         '2' := key encipherment.
         '3' := data encipherment.
         '4' := key agreement.
         other values are reserved for future use.
    y being the security environment number using '0' for cards
      not supporting a SE number.
    z being the certificate type:
         '0'        := C.CH (base certificate of card holder) or C.ICC.
         '1' .. '7' := C.CH (business or professional certificate
                       of card holder.
         '8' .. 'D' := C.CA (certificate of a CA issue by the Root-CA).
         'E'        := C.RCA (self certified certificate of the Root-CA).
         'F'        := reserved.
   
   The file IDs used by default are:
   '1F00'  EF.SSD (security service descriptor). [o,o]
   '2F02'  EF.GDO (global data objects) [m,m]
   'A000'  EF.PROT (signature log).  Cyclic file with 20 records of 53 byte.
           Read and update after user authentication. [o,o]
   'B000'  EF.PK.RCA.DS (public keys of Root-CA).  Size is 512b or size 
           of keys. [m (unless a 'C00E' is present),m]
   'B001'  EF.PK.CA.DS (public keys of CAs).  Size is 512b or size
           of keys. [o,o]
   'C00n'  EF.C.CH.DS (digital signature certificate of card holder)
           with n := 0 .. 7.  Size is 2k or size of cert.  Read and
           update allowed after user authentication. [m,m]
   'C00m'  EF.C.CA.DS (digital signature certificate of CA)
           with m := 8 .. E.  Size is 1k or size of cert.  Read always 
           allowed, update after user authentication. [o,o]
   'C100'  EF.C.ICC.AUT (AUT certificate of ICC) [o,m]
   'C108'  EF.C.CA.AUT (AUT certificate of CA) [o,m]
   'D000'  EF.DM (display message) [-,m]
   
   The letters in brackets indicate optional or mandatory files: The
   first for card terminals under full control and the second for
   "business" card terminals.
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


static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;
  char ct_buf[100], id_buf[100];
  char hexkeygrip[41];
  size_t len, certoff;
  unsigned char *der;
  size_t derlen;
  ksba_cert_t cert;
  int fid;

  (void)flags;

  /* Return the certificate of the card holder. */
  fid = 0xC000;
  len = app_help_read_length_of_cert (app->slot, fid, &certoff); 
  if (!len)
    return 0; /* Card has not been personalized. */

  sprintf (ct_buf, "%d", 101);
  sprintf (id_buf, "DINSIG.%04X", fid);
  send_status_info (ctrl, "CERTINFO",
                    ct_buf, strlen (ct_buf), 
                    id_buf, strlen (id_buf), 
                    NULL, (size_t)0);

  /* Now we need to read the certificate, so that we can get the
     public key out of it.  */
  err = iso7816_read_binary (app->slot, certoff, len-certoff, &der, &derlen);
  if (err)
    {
      log_info ("error reading entire certificate from FID 0x%04X: %s\n",
                fid, gpg_strerror (err));
      return 0;
    }

  err = ksba_cert_new (&cert);
  if (err)
    {
      xfree (der);
      return err;
    }
  err = ksba_cert_init_from_mem (cert, der, derlen); 
  xfree (der); der = NULL;
  if (err)
    {
      log_error ("failed to parse the certificate at FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      ksba_cert_release (cert);
      return err;
    }
  err = app_help_get_keygrip_string (cert, hexkeygrip);
  if (err)
    {
      log_error ("failed to calculate the keygrip for FID 0x%04X\n", fid);
      ksba_cert_release (cert);
      return gpg_error (GPG_ERR_CARD);
    }      
  ksba_cert_release (cert);

  sprintf (id_buf, "DINSIG.%04X", fid);
  send_status_info (ctrl, "KEYPAIRINFO",
                    hexkeygrip, 40, 
                    id_buf, strlen (id_buf), 
                    NULL, (size_t)0);
  return 0;
}




/* Read the certificate with id CERTID (as returned by learn_status in
   the CERTINFO status lines) and return it in the freshly allocated
   buffer put into CERT and the length of the certificate put into
   CERTLEN. 

   FIXME: This needs some cleanups and caching with do_learn_status.
*/
static gpg_error_t
do_readcert (app_t app, const char *certid,
             unsigned char **cert, size_t *certlen)
{
  int fid;
  gpg_error_t err;
  unsigned char *buffer;
  const unsigned char *p;
  size_t buflen, n;
  int class, tag, constructed, ndef;
  size_t totobjlen, objlen, hdrlen;
  int rootca = 0;

  *cert = NULL;
  *certlen = 0;
  if (strncmp (certid, "DINSIG.", 7) ) 
    return gpg_error (GPG_ERR_INV_ID);
  certid += 7;
  if (!hexdigitp (certid) || !hexdigitp (certid+1)
      || !hexdigitp (certid+2) || !hexdigitp (certid+3) 
      || certid[4])
    return gpg_error (GPG_ERR_INV_ID);
  fid = xtoi_4 (certid);
  if (fid != 0xC000 )
    return gpg_error (GPG_ERR_NOT_FOUND);

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
static gpg_error_t
verify_pin (app_t app,
            gpg_error_t (*pincb)(void*, const char *, char **),
            void *pincb_arg)
{
  const char *s;
  int rc;
  pininfo_t pininfo;

  if ( app->did_chv1 && !app->force_chv1 ) 
    return 0;  /* No need to verify it again.  */

  memset (&pininfo, 0, sizeof pininfo);
  pininfo.fixedlen = -1;
  pininfo.minlen = 6;
  pininfo.maxlen = 8;

  if (!opt.disable_pinpad
      && !iso7816_check_pinpad (app->slot, ISO7816_VERIFY, &pininfo) )
    {
      rc = pincb (pincb_arg,
                  _("||Please enter your PIN at the reader's pinpad"),
                  NULL);
      if (rc)
        {
          log_info (_("PIN callback returned error: %s\n"),
                    gpg_strerror (rc));
          return rc;
        }
      rc = iso7816_verify_kp (app->slot, 0x81, &pininfo);
      /* Dismiss the prompt. */
      pincb (pincb_arg, NULL, NULL);
    }
  else  /* No Pinpad.  */
    {
      char *pinvalue;

      rc = pincb (pincb_arg, "PIN", &pinvalue);
      if (rc)
        {
          log_info ("PIN callback returned error: %s\n", gpg_strerror (rc));
          return rc;
        }

      /* We require the PIN to be at least 6 and at max 8 bytes.
         According to the specs, this should all be ASCII.  */
      for (s=pinvalue; digitp (s); s++)
        ;
      if (*s)
        {
          log_error ("Non-numeric digits found in PIN\n");
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }

      if (strlen (pinvalue) < pininfo.minlen)
        {
          log_error ("PIN is too short; minimum length is %d\n",
                     pininfo.minlen);
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }
      else if (strlen (pinvalue) > pininfo.maxlen)
        {
          log_error ("PIN is too large; maximum length is %d\n",
                     pininfo.maxlen);
          xfree (pinvalue);
          return gpg_error (GPG_ERR_BAD_PIN);
        }

      rc = iso7816_verify (app->slot, 0x81, pinvalue, strlen (pinvalue));
      if (gpg_err_code (rc) == GPG_ERR_INV_VALUE)
        {
          /* We assume that ISO 9564-1 encoding is used and we failed
             because the first nibble we passed was 3 and not 2.  DIN
             says something about looking up such an encoding in the
             SSD but I was not able to find any tag relevant to
             this. */
          char paddedpin[8];
          int i, ndigits;
          
          for (ndigits=0, s=pinvalue; *s; ndigits++, s++)
            ;
          i = 0;
          paddedpin[i++] = 0x20 | (ndigits & 0x0f);
          for (s=pinvalue; i < sizeof paddedpin && *s && s[1]; s = s+2 )
            paddedpin[i++] = (((*s - '0') << 4) | ((s[1] - '0') & 0x0f));
          if (i < sizeof paddedpin && *s)
            paddedpin[i++] = (((*s - '0') << 4) | 0x0f);
          while (i < sizeof paddedpin)
            paddedpin[i++] = 0xff;
          rc = iso7816_verify (app->slot, 0x81, paddedpin, sizeof paddedpin);
        }
      xfree (pinvalue);
    }

  if (rc)
    {
      log_error ("verify PIN failed\n");
      return rc;
    }
  app->did_chv1 = 1;
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
  static unsigned char sha256_prefix[19] = /* OID is 2.16.840.1.101.3.4.2.1 */
    { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
      0x00, 0x04, 0x20 };
  int rc;
  int fid;
  unsigned char data[19+32]; /* Must be large enough for a SHA-256 digest
                                + the largest OID _prefix above. */
  int datalen;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (indatalen != 20 && indatalen != 16 && indatalen != 32
      && indatalen != (15+20) && indatalen != (19+32))
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check that the provided ID is vaid.  This is not really needed
     but we do it to to enforce correct usage by the caller. */
  if (strncmp (keyidstr, "DINSIG.", 7) ) 
    return gpg_error (GPG_ERR_INV_ID);
  keyidstr += 7;
  if (!hexdigitp (keyidstr) || !hexdigitp (keyidstr+1)
      || !hexdigitp (keyidstr+2) || !hexdigitp (keyidstr+3) 
      || keyidstr[4])
    return gpg_error (GPG_ERR_INV_ID);
  fid = xtoi_4 (keyidstr);
  if (fid != 0xC000)
    return gpg_error (GPG_ERR_NOT_FOUND);

  /* Prepare the DER object from INDATA. */
  datalen = 35;
  if (indatalen == 15+20)
    {
      /* Alright, the caller was so kind to send us an already
         prepared DER object.  Check that it is what we want and that
         it matches the hash algorithm. */
      if (hashalgo == GCRY_MD_SHA1 && !memcmp (indata, sha1_prefix, 15))
        ;
      else if (hashalgo == GCRY_MD_RMD160 && !memcmp (indata, rmd160_prefix,15))
        ;
      else 
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data, indata, indatalen);
    }
  else if (indatalen == 19+32)
    {
      /* Alright, the caller was so kind to send us an already
         prepared DER object.  Check that it is what we want and that
         it matches the hash algorithm. */
      datalen = indatalen;
      if (hashalgo == GCRY_MD_SHA256 && !memcmp (indata, sha256_prefix, 19))
        ;
      else if (hashalgo == GCRY_MD_SHA1 && !memcmp (indata, sha256_prefix, 19))
        {
          /* Fixme: This is a kludge.  A better solution is not to use
             SHA1 as default but use an autodetection.  However this
             needs changes in all app-*.c */
          hashalgo = GCRY_MD_SHA256;
          datalen  = indatalen;
        }
      else 
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data, indata, indatalen);
    }
  else
    {
      int len = 15;
      if (hashalgo == GCRY_MD_SHA1)
        memcpy (data, sha1_prefix, len);
      else if (hashalgo == GCRY_MD_RMD160)
        memcpy (data, rmd160_prefix, len);
      else if (hashalgo == GCRY_MD_SHA256)
        {
          len = 19;
          datalen = len + indatalen;
          memcpy (data, sha256_prefix, len);
        }
      else 
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data+len, indata, indatalen);
    }

  rc = verify_pin (app, pincb, pincb_arg);
  if (!rc)
    rc = iso7816_compute_ds (app->slot, 0, data, datalen, 0, 
                             outdata, outdatalen);
  return rc;
}


#if 0
#warning test function - works but may brick your card
/* Handle the PASSWD command.  CHVNOSTR is currently ignored; we
   always use VHV0.  RESET_MODE is not yet implemented.  */
static gpg_error_t 
do_change_pin (app_t app, ctrl_t ctrl,  const char *chvnostr, 
               unsigned int flags,
               gpg_error_t (*pincb)(void*, const char *, char **),
               void *pincb_arg)
{
  gpg_error_t err;
  char *pinvalue;
  const char *oldpin;
  size_t oldpinlen;

  if ((flags & APP_CHANGE_FLAG_RESET))
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  if ((flags & APP_CHANGE_FLAG_NULLPIN))
    {
      /* With the nullpin flag, we do not verify the PIN - it would fail
         if the Nullpin is still set.  */
      oldpin = "\0\0\0\0\0";
      oldpinlen = 6;
    }
  else
    {
      err = verify_pin (app, pincb, pincb_arg);
      if (err)
        return err;
      oldpin = NULL;
      oldpinlen = 0;
    }

  /* TRANSLATORS: Do not translate the "|*|" prefixes but
     keep it at the start of the string.  We need this elsewhere
     to get some infos on the string. */
  err = pincb (pincb_arg, _("|N|Initial New PIN"), &pinvalue); 
  if (err)
    {
      log_error (_("error getting new PIN: %s\n"), gpg_strerror (err));
      return err;
    }

  err = iso7816_change_reference_data (app->slot, 0x81, 
                                       oldpin, oldpinlen,
                                       pinvalue, strlen (pinvalue));
  xfree (pinvalue);
  return err;
}
#endif /*0*/


/* Select the DINSIG application on the card in SLOT.  This function
   must be used before any other DINSIG application functions. */
gpg_error_t
app_select_dinsig (app_t app)
{
  static char const aid[] = { 0xD2, 0x76, 0x00, 0x00, 0x66, 0x01 };
  int slot = app->slot;
  int rc;
  
  rc = iso7816_select_application (slot, aid, sizeof aid, 0);
  if (!rc)
    {
      app->apptype = "DINSIG";

      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.getattr = NULL;
      app->fnc.setattr = NULL;
      app->fnc.genkey = NULL;
      app->fnc.sign = do_sign;
      app->fnc.auth = NULL;
      app->fnc.decipher = NULL;
      app->fnc.change_pin = NULL /*do_change_pin*/;
      app->fnc.check_pin = NULL;

      app->force_chv1 = 1;
   }

  return rc;
}
