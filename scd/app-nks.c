/* app-nks.c - The Telesec NKS card application.
 * Copyright (C) 2004, 2007-2009 Free Software Foundation, Inc.
 * Copyright (C) 2004, 2007-2009, 2013-2015, 2020 g10 Code GmbH
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

/* Notes:

  - We are now targeting TCOS 3 cards and it may happen that there is
    a regression towards TCOS 2 cards.  Please report.

  - The NKS3 AUT key is not used.  It seems that it is only useful for
    the internal authentication command and not accessible by other
    applications.  The key itself is in the encryption class but the
    corresponding certificate has only the digitalSignature
    capability.
    Update: This changed for the Signature Card V2 (nks version 15)

  - If required, we automagically switch between the NKS application
    and the SigG or eSign application.  This avoids to use the DINSIG
    application which is somewhat limited, has no support for Secure
    Messaging as required by TCOS 3 and has no way to change the PIN
    or even set the NullPIN.  With the Signature Card v2 (nks version
    15) the Esign application is used instead of the SigG.

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
#include <time.h>

#include "scdaemon.h"
#include "../common/i18n.h"
#include "iso7816.h"
#include "../common/tlv.h"
#include "apdu.h"
#include "../common/host2net.h"

static char const aid_nks[]  = { 0xD2, 0x76, 0x00, 0x00, 0x03, 0x01, 0x02 };
static char const aid_sigg[] = { 0xD2, 0x76, 0x00, 0x00, 0x66, 0x01 };
static char const aid_esign[] =
  { 0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E };

/* The 3 ids of the different apps on our Netkey cards.  */
#define NKS_APP_NKS   0
#define NKS_APP_SIGG  1
#define NKS_APP_ESIGN 2


static struct
{
  int nks_app_id;/* One of the NKS_APP_ constants.  */
  int fid;       /* File ID. */
  int nks_ver;   /* 0 for NKS version 2, 3 for version 3, etc.  */
  int certtype;  /* Type of certificate or 0 if it is not a certificate. */
  int iskeypair; /* If true has the FID of the corresponding certificate. */
  int isauthkey; /* True if file is a key usable for authentication. */
  int issignkey; /* True if file is a key usable for signing. */
  int isencrkey; /* True if file is a key usable for decryption. */
  unsigned char kid;  /* Corresponding key references.  */
} filelist[] = {
  { 0, 0x4531, 0, 0,  0xC000, 1,1,0, 0x80}, /* EF_PK.NKS.SIG */
  /* */                              /* nks15: EF.PK.NKS.ADS */
  { 0, 0xC000, 0, 101 },                    /* EF_C.NKS.SIG  */
  /* */                              /* nks15: EF.C.ICC.ADS  (sign key)  */

  { 0, 0x4331, 0, 100 },                    /* Unnamed.                  */
  /* */                              /* nks15: EF.C.ICC.RFU1             */
  /* */                              /* (second cert for sign key)       */

  { 0, 0x4332, 0, 100 },
  { 0, 0xB000, 0, 110 },                    /* EF_PK.RCA.NKS             */

  { 0, 0x45B1, 0, 0,  0xC200, 0,0,1, 0x81}, /* EF_PK.NKS.ENC             */
  /* */                              /* nks15: EF.PK.ICC.ENC1            */
  { 0, 0xC200, 0, 101 },                    /* EF_C.NKS.ENC              */
                                     /* nks15: EF.C.ICC.ENC1 (Cert-encr) */

  { 0, 0x43B1, 0, 100 },                    /* Unnamed */
  /* */                              /* nks15: EF.C.ICC.RFU2             */
  /* */                              /* (second cert for enc1 key)       */

  { 0, 0x43B2, 0, 100 },
  { 0, 0x4371,15, 100 },                    /* EF.C.ICC.RFU3             */
  /* */                              /* (second cert for auth key)       */

  { 0, 0x45B2, 3, 0,  0xC201, 0,0,1, 0x83}, /* EF_PK.NKS.ENC1024         */
  /* */                              /* nks15: EF.PK.ICC.ENC2            */
  { 0, 0xC201, 3, 101 },                    /* EF_C.NKS.ENC1024  */

  { 0, 0xC20E,15, 111 },                    /* EF.C.CSP.RCA1 (RootCA 1) */
  { 0, 0xC208,15, 101 },                    /* EF.C.CSP.SCA1 (SubCA 1) */
  { 0, 0xC10E,15, 111 },                    /* EF.C.CSP.RCA2 (RootCA 2) */
  { 0, 0xC108,15, 101 },                    /* EF.C.CSP.SCA2 (SubCA 2) */

  { 0, 0x4571,15, 0,  0xC500, 1,0,0, 0x82}, /* EF.PK.ICC.AUT */
  { 0, 0xC500,15, 101 },                    /* EF.C.ICC.AUT  (Cert-auth) */

  { 0, 0xC201,15, 101 },                    /* EF.C.ICC.ENC2 (Cert-encr) */
                                            /* (empty on delivery) */

  { 1, 0x4531, 3, 0,  0xC000, 0,1,1, 0x84}, /* EF_PK.CH.SIG  */
  { 1, 0xC000, 0, 101 },                    /* EF_C.CH.SIG  */

  { 1, 0xC008, 3, 101 },                    /* EF_C.CA.SIG  */
  { 1, 0xC00E, 3, 111 },                    /* EF_C.RCA.SIG  */

  { 2, 0xC000, 15,101 },                    /* EF.C.SCA.QES (SubCA) */
  { 2, 0xC001, 15,100 },                    /* EF.C.ICC.QES (Cert)  */
  { 2, 0xC00E, 15,111 },                    /* EF.C.RCA.QES (RootCA */
  { 0, 0 }
};



/* Object with application (i.e. NKS) specific data.  */
struct app_local_s {
  int nks_version;  /* NKS version.  */

  int active_nks_app;   /* One of the NKS_APP_ constants.  */

  int qes_app_id;       /* Either NKS_APP_SIGG or NKS_APP_ESIGN.  */

  int sigg_msig_checked;/*  True if we checked for a mass signature card.  */
  int sigg_is_msig;     /* True if this is a mass signature card.  */

  int need_app_select;  /* Need to re-select the application.  */

};



static gpg_error_t readcert_from_ef (app_t app, int fid,
                                     unsigned char **cert, size_t *certlen);
static gpg_error_t switch_application (app_t app, int nks_app_id);



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


static int
all_zero_p (void *buffer, size_t length)
{
  char *p;

  for (p=buffer; length; length--, p++)
    if (*p)
      return 0;
  return 1;
}


/* Read the file with PKFID, assume it contains a public key and
 * return its keygrip in the caller provided 41 byte buffer R_GRIPSTR.
 * This works only for RSA card.  For the Signature Card v2 ECC is
 * used and Read Record needs to be replaced by read binary.  Given
 * all the ECC parameters required, we don't do that but rely that the
 * corresponding certificate at CFID is already available and get the
 * public key from there. */
static gpg_error_t
keygripstr_from_pk_file (app_t app, int pkfid, int cfid, char *r_gripstr)
{
  gpg_error_t err;
  unsigned char grip[20];
  unsigned char *buffer[2];
  size_t buflen[2];
  gcry_sexp_t sexp;
  int i;
  int offset[2] = { 0, 0 };

  if (app->app_local->nks_version == 15)
    {
      /* Signature Card v2 - get keygrip from the certificate.  */
      unsigned char *cert, *pk;
      size_t certlen, pklen;

      /* Fall back to certificate reading.  */
      err = readcert_from_ef (app, cfid, &cert, &certlen);
      if (err)
        {
          log_error ("nks: error reading certificate %04X: %s\n",
                     cfid, gpg_strerror (err));
          return err;
        }

      err = app_help_pubkey_from_cert (cert, certlen, &pk, &pklen);
      xfree (cert);
      if (err)
        {
          log_error ("nks: error parsing certificate %04X: %s\n",
                     cfid, gpg_strerror (err));
          return err;
        }

      err = app_help_get_keygrip_string_pk (pk, pklen, r_gripstr, NULL,
                                            NULL, NULL);
      xfree (pk);
      if (err)
        log_error ("nks: error getting keygrip for certificate %04X: %s\n",
                   cfid, gpg_strerror (err));

      return err;
    }

  err = iso7816_select_file (app_get_slot (app), pkfid, 0);
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
          else
            offset[i] = 2;
        }
    }
  else
    {
      /* Remove leading zeroes to get a correct keygrip.  Take care of
         negative numbers.  We should also fix it the same way in
         libgcrypt but we can't yet rely on it yet.  */
      for (i=0; i < 2; i++)
        {
          while (buflen[i]-offset[i] > 1
                 && !buffer[i][offset[i]]
                 && !(buffer[i][offset[i]+1] & 0x80))
            offset[i]++;
        }
    }

  /* Check whether negative values are not prefixed with a zero and
     fix that.  */
  for (i=0; i < 2; i++)
    {
      if ((buflen[i]-offset[i]) && (buffer[i][offset[i]] & 0x80))
        {
          unsigned char *newbuf;
          size_t newlen;

          newlen = 1 + buflen[i] - offset[i];
          newbuf = xtrymalloc (newlen);
          if (!newbuf)
            {
              xfree (buffer[0]);
              xfree (buffer[1]);
              return gpg_error_from_syserror ();
            }
          newbuf[0] = 0;
          memcpy (newbuf+1, buffer[i]+offset[i], buflen[i] - offset[i]);
          xfree (buffer[i]);
          buffer[i] = newbuf;
          buflen[i] = newlen;
          offset[i] = 0;
        }
    }

  if (!err)
    err = gcry_sexp_build (&sexp, NULL,
                           "(public-key (rsa (n %b) (e %b)))",
                           (int)buflen[0]-offset[0], buffer[0]+offset[0],
                           (int)buflen[1]-offset[1], buffer[1]+offset[1]);

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
 * byte) with the status of the PIN.  PWID is the PIN ID. NKS_APP_ID
 * gives the application to first switch to.  Returns:
 * ISO7816_VERIFY_* codes or non-negative number of verification
 * attempts left.  */
static int
get_chv_status (app_t app, int nks_app_id, int pwid)
{
  if (switch_application (app, nks_app_id))
    return (nks_app_id == NKS_APP_NKS
            ? ISO7816_VERIFY_ERROR
            : ISO7816_VERIFY_NO_PIN);

  return iso7816_verify_status (app_get_slot (app), pwid);
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
    { "$ENCRKEYID",   2 },
    { "$SIGNKEYID",   3 },
    { "NKS-VERSION",  4 },
    { "CHV-STATUS",   5 },
    { NULL, 0 }
  };
  gpg_error_t err = 0;
  int idx;
  char buffer[100];
  int nksver = app->app_local->nks_version;

  err = switch_application (app, NKS_APP_NKS);
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
        /* NetKey 3.0 cards define an authentication key but according
           to the specs this key is only usable for encryption and not
           signing.  it might work anyway but it has not yet been
           tested - fixme.  Thus for now we use the NKS signature key
           for authentication for netkey 3.  For the Signature Card
           V2.0 the auth key is defined and thus we use it. */
        const char *tmp = nksver == 15? "NKS-NKS3.4571" : "NKS-NKS3.4531";
        send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      }
      break;

    case 2: /* $ENCRKEYID */
      {
        char const tmp[] = "NKS-NKS3.45B1";
        send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      }
      break;

    case 3: /* $SIGNKEYID */
      {
        char const tmp[] = "NKS-NKS3.4531";
        send_status_info (ctrl, table[idx].name, tmp, strlen (tmp), NULL, 0);
      }
      break;

    case 4: /* NKS-VERSION */
      snprintf (buffer, sizeof buffer, "%d", app->app_local->nks_version);
      send_status_info (ctrl, table[idx].name,
                        buffer, strlen (buffer), NULL, 0);
      break;

    case 5: /* CHV-STATUS */
      {
        /* Returns: PW1.CH PW2.CH PW1.CH.SIG PW2.CH.SIG That are the
           two global passwords followed by the two SigG passwords.
           For the values, see the function get_chv_status.  */
        /* FIXME: Check this for the NKS15!! */
        int tmp[4];

        /* We use a helper array so that we can control that there is
           no superfluous application switch.  Note that PW2.CH.SIG
           really has the identifier 0x83 and not 0x82 as one would
           expect.  */
        tmp[0] = get_chv_status (app, 0, 0x00);
        tmp[1] = get_chv_status (app, 0, 0x01);
        tmp[2] = get_chv_status (app, app->app_local->qes_app_id, 0x81);
        tmp[3] = get_chv_status (app, app->app_local->qes_app_id, 0x83);
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
do_learn_status_core (app_t app, ctrl_t ctrl, unsigned int flags,
                      int nks_app_id)
{
  gpg_error_t err;
  char ct_buf[100], id_buf[100];
  int i;
  const char *tag;

  if (nks_app_id == NKS_APP_ESIGN)
    tag = "ESIGN";
  else if (nks_app_id == NKS_APP_SIGG)
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

      if (filelist[i].nks_app_id != nks_app_id)
        continue;

      if (filelist[i].certtype && !(flags &1))
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
          char usagebuf[5];
          int usageidx = 0;

          err = keygripstr_from_pk_file (app, filelist[i].fid,
                                         filelist[i].iskeypair, gripstr);
          if (err)
            log_error ("can't get keygrip from FID 0x%04X: %s\n",
                       filelist[i].fid, gpg_strerror (err));
          else
            {
              snprintf (id_buf, sizeof id_buf, "NKS-%s.%04X",
                        tag, filelist[i].fid);
              if (filelist[i].issignkey)
                usagebuf[usageidx++] = 's';
              if (filelist[i].isauthkey)
                usagebuf[usageidx++] = 'a';
              if (filelist[i].isencrkey)
                usagebuf[usageidx++] = 'e';
              usagebuf[usageidx] = 0;
              send_status_info (ctrl, "KEYPAIRINFO",
                                gripstr, 40,
                                id_buf, strlen (id_buf),
                                usagebuf, strlen (usagebuf),
                                NULL, (size_t)0);
            }
        }
    }
}


static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;

  err = switch_application (app, NKS_APP_NKS);
  if (err)
    return err;

  do_learn_status_core (app, ctrl, flags, NKS_APP_NKS);

  err = switch_application (app, app->app_local->qes_app_id);
  if (err)
    return 0;  /* Silently ignore if we can't switch to SigG.  */

  do_learn_status_core (app, ctrl, flags, app->app_local->qes_app_id);

  return 0;
}



/* Helper to read a certificate from the file FID.  The function
 * assumes that the the application has already been selected.  */
static gpg_error_t
readcert_from_ef (app_t app, int fid, unsigned char **cert, size_t *certlen)
{
  gpg_error_t err;
  unsigned char *buffer;
  const unsigned char *p;
  size_t buflen, n;
  int class, tag, constructed, ndef;
  size_t totobjlen, objlen, hdrlen;
  int rootca = 0;

  *cert = NULL;
  *certlen = 0;

  /* Read the entire file.  fixme: This could be optimized by first
     reading the header to figure out how long the certificate
     actually is. */
  err = iso7816_select_file (app->slot, fid, 0);
  if (err)
    {
      log_error ("nks: error selecting FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return err;
    }

  err = iso7816_read_binary (app->slot, 0, 0, &buffer, &buflen);
  if (err)
    {
      log_error ("nks: error reading certificate from FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return err;
    }

  if (!buflen || *buffer == 0xff)
    {
      log_info ("nks: no certificate contained in FID 0x%04X\n", fid);
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
  log_assert (totobjlen <= buflen);

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
      log_assert (save_p + totobjlen <= buffer + buflen);
      memmove (buffer, save_p, totobjlen);
    }

  *cert = buffer;
  buffer = NULL;
  *certlen = totobjlen;

 leave:
  xfree (buffer);
  return err;
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
  int nks_app_id;

  *cert = NULL;
  *certlen = 0;

  if (!strncmp (certid, "NKS-NKS3.", 9))
    nks_app_id = NKS_APP_NKS;
  else if (!strncmp (certid, "NKS-ESIGN.", 10))
    nks_app_id = NKS_APP_ESIGN;
  else if (!strncmp (certid, "NKS-SIGG.", 9))
    nks_app_id = NKS_APP_SIGG;
  else if (!strncmp (certid, "NKS-DF01.", 9))
    nks_app_id = NKS_APP_NKS;
  else
    return gpg_error (GPG_ERR_INV_ID);
  certid += nks_app_id == NKS_APP_ESIGN? 10 : 9;

  err = switch_application (app, nks_app_id);
  if (err)
    return err;

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

  return readcert_from_ef (app, fid, cert, certlen);
}


/* Handle the READKEY command. On success a canonical encoded
   S-expression with the public key will get stored at PK and its
   length at PKLEN; the caller must release that buffer.  On error PK
   and PKLEN are not changed and an error code is returned.  As of now
   this function is only useful for the internal authentication key.
   Other keys are automagically retrieved by means of the
   certificate parsing code in commands.c:cmd_readkey.  For internal
   use PK and PKLEN may be NULL to just check for an existing key.  */
static gpg_error_t
do_readkey (app_t app, ctrl_t ctrl, const char *keyid, unsigned int flags,
            unsigned char **pk, size_t *pklen)
{
  gpg_error_t err;
  unsigned char *buffer[2];
  size_t buflen[2];
  unsigned short path[1] = { 0x4500 };

  (void)ctrl;

  if ((flags & APP_READKEY_FLAG_ADVANCED))
    return GPG_ERR_NOT_SUPPORTED;

  /* We use a generic name to retrieve PK.AUT.IFD-SPK.  */
  if (!strcmp (keyid, "$IFDAUTHKEY") && app->app_local->nks_version >= 3)
    ;
  else /* Return the error code expected by cmd_readkey.  */
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  /* Access the KEYD file which is always in the master directory.  */
  err = iso7816_select_path (app_get_slot (app), path, DIM (path), 0);
  if (err)
    return err;
  /* Due to the above select we need to re-select our application.  */
  app->app_local->need_app_select = 1;
  /* Get the two records.  */
  err = iso7816_read_record (app->slot, 5, 1, 0, &buffer[0], &buflen[0]);
  if (err)
    return err;
  if (all_zero_p (buffer[0], buflen[0]))
    {
      xfree (buffer[0]);
      return gpg_error (GPG_ERR_NOT_FOUND);
    }
  err = iso7816_read_record (app->slot, 6, 1, 0, &buffer[1], &buflen[1]);
  if (err)
    {
      xfree (buffer[0]);
      return err;
    }

  if (pk && pklen)
    {
      *pk = make_canon_sexp_from_rsa_pk (buffer[0], buflen[0],
                                         buffer[1], buflen[1],
                                         pklen);
      if (!*pk)
        err = gpg_error_from_syserror ();
    }

  xfree (buffer[0]);
  xfree (buffer[1]);
  return err;
}


/* Handle the WRITEKEY command for NKS.  This function expects a
   canonical encoded S-expression with the public key in KEYDATA and
   its length in KEYDATALEN.  The only supported KEYID is
   "$IFDAUTHKEY" to store the terminal key on the card.  Bit 0 of
   FLAGS indicates whether an existing key shall get overwritten.
   PINCB and PINCB_ARG are the usual arguments for the pinentry
   callback.  */
static gpg_error_t
do_writekey (app_t app, ctrl_t ctrl,
             const char *keyid, unsigned int flags,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const unsigned char *keydata, size_t keydatalen)
{
  gpg_error_t err;
  int force = (flags & 1);
  const unsigned char *rsa_n = NULL;
  const unsigned char *rsa_e = NULL;
  size_t rsa_n_len, rsa_e_len;
  unsigned int nbits;

  (void)pincb;
  (void)pincb_arg;

  if (!strcmp (keyid, "$IFDAUTHKEY") && app->app_local->nks_version >= 3)
    ;
  else
    return gpg_error (GPG_ERR_INV_ID);

  if (!force && !do_readkey (app, ctrl, keyid, 0, NULL, NULL))
    return gpg_error (GPG_ERR_EEXIST);

  /* Parse the S-expression.  */
  err = get_rsa_pk_from_canon_sexp (keydata, keydatalen,
                                    &rsa_n, &rsa_n_len, &rsa_e, &rsa_e_len);
  if (err)
    goto leave;

  /* Check that the parameters match the requirements.  */
  nbits = app_help_count_bits (rsa_n, rsa_n_len);
  if (nbits != 1024)
    {
      log_error (_("RSA modulus missing or not of size %d bits\n"), 1024);
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

  nbits = app_help_count_bits (rsa_e, rsa_e_len);
  if (nbits < 2 || nbits > 32)
    {
      log_error (_("RSA public exponent missing or larger than %d bits\n"),
                 32);
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

/*   /\* Store them.  *\/ */
/*   err = verify_pin (app, 0, NULL, pincb, pincb_arg); */
/*   if (err) */
/*     goto leave; */

  /* Send the MSE:Store_Public_Key.  */
  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
/*   mse = xtrymalloc (1000); */

/*   mse[0] = 0x80; /\* Algorithm reference.  *\/ */
/*   mse[1] = 1; */
/*   mse[2] = 0x17; */
/*   mse[3] = 0x84; /\* Private key reference.  *\/ */
/*   mse[4] = 1; */
/*   mse[5] = 0x77; */
/*   mse[6] = 0x7F; /\* Public key parameter.  *\/ */
/*   mse[7] = 0x49; */
/*   mse[8] = 0x81; */
/*   mse[9] = 3 + 0x80 + 2 + rsa_e_len; */
/*   mse[10] = 0x81; /\* RSA modulus of 128 byte.  *\/ */
/*   mse[11] = 0x81; */
/*   mse[12] = rsa_n_len; */
/*   memcpy (mse+12, rsa_n, rsa_n_len); */
/*   mse[10] = 0x82; /\* RSA public exponent of up to 4 bytes.  *\/ */
/*   mse[12] = rsa_e_len; */
/*   memcpy (mse+12, rsa_e, rsa_e_len); */
/*   err = iso7816_manage_security_env (app->slot, 0x81, 0xB6, */
/*                                      mse, sizeof mse); */

 leave:
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
  pininfo_t pininfo;
  int rc;

  if (!desc)
    desc = "PIN";

  memset (&pininfo, 0, sizeof pininfo);
  pininfo.fixedlen = -1;
  pininfo.minlen = 6;
  pininfo.maxlen = 16;

  if (!opt.disable_pinpad
      && !iso7816_check_pinpad (app->slot, ISO7816_VERIFY, &pininfo) )
    {
      rc = pincb (pincb_arg, desc, NULL);
      if (rc)
        {
          log_info (_("PIN callback returned error: %s\n"),
                    gpg_strerror (rc));
          return rc;
        }

      rc = iso7816_verify_kp (app->slot, pwid, &pininfo);
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
do_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
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
  int nks_app_id;
  int fid;
  unsigned char kid;
  unsigned char data[83];   /* Must be large enough for a SHA-1 digest
                               + the largest OID prefix. */
  size_t datalen;

  (void)ctrl;

  if (!keyidstr || !*keyidstr)
    return gpg_error (GPG_ERR_INV_VALUE);
  switch (indatalen)
    {
    case 16: case 20: case 35: case 47: case 51: case 67: case 83: break;
    default: return gpg_error (GPG_ERR_INV_VALUE);
    }

  /* Check that the provided ID is valid.  This is not really needed
     but we do it to enforce correct usage by the caller. */
  if (!strncmp (keyidstr, "NKS-NKS3.", 9))
    nks_app_id = NKS_APP_NKS;
  else if (!strncmp (keyidstr, "NKS-ESIGN.", 10))
    nks_app_id = NKS_APP_ESIGN;
  else if (!strncmp (keyidstr, "NKS-SIGG.", 9))
    nks_app_id = NKS_APP_SIGG;
  else if (!strncmp (keyidstr, "NKS-DF01.", 9))
    nks_app_id = NKS_APP_NKS;
  else
    return gpg_error (GPG_ERR_INV_ID);
  keyidstr += nks_app_id == NKS_APP_ESIGN? 10 : 9;

  rc = switch_application (app, nks_app_id);
  if (rc)
    return rc;

  if (nks_app_id == NKS_APP_SIGG && app->app_local->sigg_is_msig)
    {
      log_info ("mass signature cards are not allowed\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

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
  kid = filelist[i].kid;

  /* Prepare the DER object from INDATA.  */
  if (app->app_local->nks_version > 2 && (indatalen == 35
                                          || indatalen == 47
                                          || indatalen == 51
                                          || indatalen == 67
                                          || indatalen == 83))
    {
      /* The caller send data matching the length of the ASN.1 encoded
         hash for SHA-{1,224,256,384,512}.  Assume that is okay.  */
      log_assert (indatalen <= sizeof data);
      memcpy (data, indata, indatalen);
      datalen = indatalen;
    }
  else if (indatalen == 35)
    {
      /* Alright, the caller was so kind to send us an already
         prepared DER object.  This is for TCOS 2. */
      if (hashalgo == GCRY_MD_SHA1 && !memcmp (indata, sha1_prefix, 15))
        ;
      else if (hashalgo == GCRY_MD_RMD160 && !memcmp (indata,rmd160_prefix,15))
        ;
      else
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data, indata, indatalen);
      datalen = 35;
    }
  else if (indatalen == 20)
    {
      if (hashalgo == GCRY_MD_SHA1)
        memcpy (data, sha1_prefix, 15);
      else if (hashalgo == GCRY_MD_RMD160)
        memcpy (data, rmd160_prefix, 15);
      else
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
      memcpy (data+15, indata, indatalen);
      datalen = 35;
    }
  else
    return gpg_error (GPG_ERR_INV_VALUE);


  /* Send an MSE for PSO:Computer_Signature.  */
  if (app->app_local->nks_version > 2)
    {
      unsigned char mse[6];

      mse[0] = 0x80; /* Algorithm reference.  */
      mse[1] = 1;
      mse[2] = 2;    /* RSA, card does pkcs#1 v1.5 padding, no ASN.1 check.  */
      mse[3] = 0x84; /* Private key reference.  */
      mse[4] = 1;
      mse[5] = kid;
      rc = iso7816_manage_security_env (app->slot, 0x41, 0xB6,
                                        mse, sizeof mse);
    }
  /* Verify using PW1.CH.  */
  if (!rc)
    rc = verify_pin (app, 0, NULL, pincb, pincb_arg);
  /* Compute the signature.  */
  if (!rc)
    rc = iso7816_compute_ds (app->slot, 0, data, datalen, 0,
                             outdata, outdatalen);
  return rc;
}



/* Decrypt the data in INDATA and return the allocated result in OUTDATA.
   If a PIN is required the PINCB will be used to ask for the PIN; it
   should return the PIN in an allocated buffer and put it into PIN.  */
static gpg_error_t
do_decipher (app_t app, ctrl_t ctrl, const char *keyidstr,
             gpg_error_t (*pincb)(void*, const char *, char **),
             void *pincb_arg,
             const void *indata, size_t indatalen,
             unsigned char **outdata, size_t *outdatalen,
             unsigned int *r_info)
{
  int rc, i;
  int nks_app_id;
  int fid;
  int kid;

  (void)ctrl;
  (void)r_info;

  if (!keyidstr || !*keyidstr || !indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Check that the provided ID is valid.  This is not really needed
     but we do it to enforce correct usage by the caller. */
  if (!strncmp (keyidstr, "NKS-NKS3.", 9))
    nks_app_id = NKS_APP_NKS;
  else if (!strncmp (keyidstr, "NKS-ESIGN.", 10))
    nks_app_id = NKS_APP_ESIGN;
  else if (!strncmp (keyidstr, "NKS-SIGG.", 9))
    nks_app_id = NKS_APP_SIGG;
  else if (!strncmp (keyidstr, "NKS-DF01.", 9))
    nks_app_id = NKS_APP_NKS;
  else
    return gpg_error (GPG_ERR_INV_ID);
  keyidstr += nks_app_id == NKS_APP_ESIGN? 10 : 9;

  rc = switch_application (app, nks_app_id);
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
  if (!filelist[i].isencrkey)
    return gpg_error (GPG_ERR_INV_ID);
  kid = filelist[i].kid;

  if (app->app_local->nks_version > 2)
    {
      unsigned char mse[6];
      mse[0] = 0x80; /* Algorithm reference.  */
      mse[1] = 1;
      mse[2] = 0x0a; /* RSA no padding.  (0x1A is pkcs#1.5 padding.)  */
      mse[3] = 0x84; /* Private key reference.  */
      mse[4] = 1;
      mse[5] = kid;
      rc = iso7816_manage_security_env (app->slot, 0x41, 0xB8,
                                        mse, sizeof mse);
    }
  else
    {
      static const unsigned char mse[] =
        {
          0x80, 1, 0x10, /* Select algorithm RSA. */
          0x84, 1, 0x81  /* Select local secret key 1 for decryption. */
        };
      rc = iso7816_manage_security_env (app->slot, 0xC1, 0xB8,
                                        mse, sizeof mse);

    }

  if (!rc)
    rc = verify_pin (app, 0, NULL, pincb, pincb_arg);

  /* Note that we need to use extended length APDUs for TCOS 3 cards.
     Command chaining does not work.  */
  if (!rc)
    rc = iso7816_decipher (app->slot, app->app_local->nks_version > 2? 1:0,
                           indata, indatalen, 0, 0x81,
                           outdata, outdatalen);
  return rc;
}



/* Parse a password ID string.  Returns NULL on error or a string
   suitable as passphrase prompt on success.  On success stores the
   reference value for the password at R_PWID and a flag indicating
   that the SigG application is to be used at R_SIGG.  If NEW_MODE is
   true, the returned description is suitable for a new Password.
   Supported values for PWIDSTR are:

     PW1.CH       - Global password 1
     PW2.CH       - Global password 2
     PW1.CH.SIG   - SigG password 1
     PW2.CH.SIG   - SigG password 2
     FIXME: What about the ESIGN passwords?
 */
static const char *
parse_pwidstr (const char *pwidstr, int new_mode
               , int *r_nks_app_id, int *r_pwid)
{
  const char *desc;

  if (!pwidstr)
    desc = NULL;
  else if (!strcmp (pwidstr, "PW1.CH"))
    {
      *r_nks_app_id = NKS_APP_NKS;
      *r_pwid = 0x00;
      /* TRANSLATORS: Do not translate the "|*|" prefixes but keep
         them verbatim at the start of the string.  */
      desc = (new_mode
              ? _("|N|Please enter a new PIN for the standard keys.")
              : _("||Please enter the PIN for the standard keys."));
    }
  else if (!strcmp (pwidstr, "PW2.CH"))
    {
      *r_nks_app_id = NKS_APP_NKS;
      *r_pwid = 0x01;
      desc = (new_mode
              ? _("|NP|Please enter a new PIN Unblocking Code (PUK) "
                  "for the standard keys.")
              : _("|P|Please enter the PIN Unblocking Code (PUK) "
                  "for the standard keys."));
    }
  else if (!strcmp (pwidstr, "PW1.CH.SIG"))
    {
      *r_nks_app_id = NKS_APP_SIGG;
      *r_pwid = 0x81;
      desc = (new_mode
              ? _("|N|Please enter a new PIN for the key to create "
                  "qualified signatures.")
              : _("||Please enter the PIN for the key to create "
                  "qualified signatures."));
    }
  else if (!strcmp (pwidstr, "PW2.CH.SIG"))
    {
      *r_nks_app_id = NKS_APP_SIGG;
      *r_pwid = 0x83;  /* Yes, that is 83 and not 82.  */
      desc = (new_mode
              ? _("|NP|Please enter a new PIN Unblocking Code (PUK) "
                  "for the key to create qualified signatures.")
              : _("|P|Please enter the PIN Unblocking Code (PUK) "
                  "for the key to create qualified signatures."));
    }
  else
    {
      *r_pwid = 0; /* Only to avoid gcc warning in calling function.  */
      desc = NULL; /* Error.  */
    }

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
  int nks_app_id;
  const char *newdesc;
  int pwid;
  pininfo_t pininfo;

  (void)ctrl;

  /* The minimum length is enforced by TCOS, the maximum length is
     just a reasonable value.  */
  memset (&pininfo, 0, sizeof pininfo);
  pininfo.minlen = 6;
  pininfo.maxlen = 16;

  newdesc = parse_pwidstr (pwidstr, 1, &nks_app_id, &pwid);
  if (!newdesc)
    return gpg_error (GPG_ERR_INV_ID);

  if ((flags & APP_CHANGE_FLAG_CLEAR))
    return gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

  err = switch_application (app, nks_app_id);
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
do_check_pin (app_t app, ctrl_t ctrl, const char *pwidstr,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg)
{
  gpg_error_t err;
  int pwid;
  int nks_app_id;
  const char *desc;

  (void)ctrl;

  desc = parse_pwidstr (pwidstr, 0, &nks_app_id, &pwid);
  if (!desc)
    return gpg_error (GPG_ERR_INV_ID);

  err = switch_application (app, nks_app_id);
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
                           NULL, &result, &resultlen))
    return 2; /* NKS 2 does not support this command.  */
  /* Example values:   04 11 19 22 21 6A 20 80 03 03 01 01 01 00 00 00
   *                   05 a0 22 3e c8 0c 04 20 0f 01 b6 01 01 00 00 02
   *                   vv tt ccccccccccccccccc aa bb cc vv ff rr rr xx
   * vendor -----------+  |  |                 |  |  |  |  |  |  |  |
   * chip type -----------+  |                 |  |  |  |  |  |  |  |
   * chip id ----------------+                 |  |  |  |  |  |  |  |
   * card type --------------------------------+  |  |  |  |  |  |  |
   * OS version of card type ---------------------+  |  |  |  |  |  |
   * OS release of card type ------------------------+  |  |  |  |  |
   * Completion code version number --------------------+  |  |  |  |
   * File system version ----------------------------------+  |  |  |
   * RFU (00) ------------------------------------------------+  |  |
   * RFU (00) ---------------------------------------------------+  |
   * Authentication key identifier ---------------------------------+
   *
   * vendor    4 := Philips
   *           5 := Infinion
   * card type 3 := TCOS 3
   *          15 := TCOS Signature Card
   * Completion code version number Bit 7..5 := pre-completion code version
   *                                Bit 4..0 := completion code version
   *                                (pre-completion by chip vendor)
   *                                (completion by OS developer)
   */
  if (resultlen < 16)
    type = 0;  /* Invalid data returned.  */
  else
    type = result[8];
  xfree (result);

  return type;
}


/* Switch to the NKS app identified by NKS_APP_ID if not yet done.
 * Returns 0 on success.  */
static gpg_error_t
switch_application (app_t app, int nks_app_id)
{
  gpg_error_t err;

  if (app->app_local->active_nks_app == nks_app_id
      && !app->app_local->need_app_select)
    return 0;  /* Already switched.  */

  log_info ("nks: switching to %s\n",
            nks_app_id == NKS_APP_ESIGN? "eSign" :
            nks_app_id == NKS_APP_SIGG?  "SigG"  : "NKS");

  if (nks_app_id == NKS_APP_ESIGN)
    err = iso7816_select_application (app_get_slot (app),
                                      aid_esign, sizeof aid_esign, 0);
  else if (nks_app_id == NKS_APP_SIGG)
    err = iso7816_select_application (app_get_slot (app),
                                      aid_sigg, sizeof aid_sigg, 0);
  else
    err = iso7816_select_application (app->slot, aid_nks, sizeof aid_nks, 0);

  if (!err && nks_app_id == NKS_APP_SIGG
      && app->app_local->nks_version >= 3
      && !app->app_local->sigg_msig_checked)
    {
      /* Check whether this card is a mass signature card.  */
      unsigned char *buffer;
      size_t buflen;
      const unsigned char *tmpl;
      size_t tmpllen;

      app->app_local->sigg_msig_checked = 1;
      app->app_local->sigg_is_msig = 1;
      err = iso7816_select_file (app->slot, 0x5349, 0);
      if (!err)
        err = iso7816_read_record (app->slot, 1, 1, 0, &buffer, &buflen);
      if (!err)
        {
          tmpl = find_tlv (buffer, buflen, 0x7a, &tmpllen);
          if (tmpl && tmpllen == 12
              && !memcmp (tmpl,
                          "\x93\x02\x00\x01\xA4\x06\x83\x01\x81\x83\x01\x83",
                          12))
            app->app_local->sigg_is_msig = 0;
          xfree (buffer);
        }
      if (app->app_local->sigg_is_msig)
        log_info ("nks: This is a mass signature card\n");
    }

  if (!err)
    {
      app->app_local->need_app_select = 0;
      app->app_local->active_nks_app = nks_app_id;
    }
  else
    log_error ("nks: error switching to %s: %s\n",
               nks_app_id == NKS_APP_ESIGN? "eSign" :
               nks_app_id == NKS_APP_SIGG?  "SigG"  : "NKS",
               gpg_strerror (err));

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
      app->apptype = APPTYPE_NKS;

      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          rc = gpg_error (gpg_err_code_from_errno (errno));
          goto leave;
        }

      app->app_local->nks_version = get_nks_version (slot);
      if (opt.verbose)
        log_info ("Detected NKS version: %d\n", app->app_local->nks_version);
      if (app->app_local->nks_version == 15)
        app->app_local->qes_app_id = NKS_APP_ESIGN;
      else
        app->app_local->qes_app_id = NKS_APP_SIGG;

      app->fnc.deinit = do_deinit;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.readkey = do_readkey;
      app->fnc.getattr = do_getattr;
      app->fnc.setattr = NULL;
      app->fnc.writekey = do_writekey;
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
