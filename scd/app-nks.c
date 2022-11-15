/* app-nks.c - The Telesec NKS card application.
 * Copyright (C) 2004, 2007-2009 Free Software Foundation, Inc.
 * Copyright (C) 2004, 2007-2009, 2013-2015, 2020, 2022 g10 Code GmbH
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
 *
 * - We are now targeting TCOS 3 cards and it may happen that there is
 *   a regression towards TCOS 2 cards.  Please report.
 *
 * - The NKS3 AUT key is not used.  It seems that it is only useful for
 *   the internal authentication command and not accessible by other
 *   applications.  The key itself is in the encryption class but the
 *   corresponding certificate has only the digitalSignature
 *   capability.
 *   Update: This changed for the Signature Card V2 (nks version 15)
 *
 * - If required, we automagically switch between the NKS application
 *   and the SigG or eSign application.  This avoids to use the DINSIG
 *   application which is somewhat limited, has no support for Secure
 *   Messaging as required by TCOS 3 and has no way to change the PIN
 *   or even set the NullPIN.  With the Signature Card v2 (nks version
 *   15) the Esign application is used instead of the SigG.
 *
 * - We use the prefix NKS-DF01 for TCOS 2 cards and NKS-NKS3 for newer
 *   cards.  This is because the NKS application has moved to DF02 with
 *   TCOS 3 and thus we better use a DF independent tag.
 *
 * - We use only the global PINs for the NKS application.
 *
 *
 *
 * Here is a table with PIN stati collected from 3 cards.
 *
 *  | app | pwid | NKS3      | SIG_B     | SIG_N     |
 *  |-----+------+-----------+-----------+-----------|
 *  | NKS | 0x00 | null -    | -    -    | -    -    |
 *  |     | 0x01 | 0    3    | -    -    | -    -    |
 *  |     | 0x02 | 3    null | 15   3    | 15   null |
 *  |     | 0x03 | -    3    | null -    | 3    -    |
 *  |     | 0x04 |           | null 0    | 3    3    |
 *  | SIG | 0x00 | null -    | -    -    | -    -    |
 *  |     | 0x01 | 0    null | -    null | -    null |
 *  |     | 0x02 | 3    null | 15   0    | 15   0    |
 *  |     | 0x03 | -    0    | null null | null null |
 *  - SIG is either SIGG or ESIGN.
 *  - "-" indicates reference not found (SW 6A88).
 *  - "null" indicates a NULLPIN (SW 6985).
 *  - The first value in each cell is the global PIN;
 *    the second is the local PIN (high bit of pwid set).
 *  - The NKS3 card is some older test card.
 *  - The SIG_B is a Signature Card V2.0 with Brainpool curves.
 *    Here the PIN 0x82 has been changed from the NULLPIN.
 *  - The SIG_N is a Signature Card V2.0 with NIST curves.
 *    The PIN was enabled using the TCOS Windows tool.
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
static char const aid_idlm[] = { 0xD2, 0x76, 0x00, 0x00, 0x03, 0x0c, 0x01 };


/* The ids of the different apps on our TCOS cards.  */
#define NKS_APP_NKS   0
#define NKS_APP_SIGG  1
#define NKS_APP_ESIGN 2
#define NKS_APP_IDLM  3


static struct
{
  int nks_app_id;/* One of NKS_APP_*.  Keep them sorted so that no
                  * unnecessary application switching is needed.  */
  int fid;       /* File ID. */
  int nks_ver;   /* 0 for NKS version 2, 3 for version 3, etc.  */
  int certtype;  /* Type of certificate or 0 if it is not a certificate. */
  int iskeypair; /* If true has the FID of the corresponding certificate.
                  * If no certificate is known a value of -1 is used. */
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

  { 2, 0x4531, 15, 0, 0xC001, 0,1,0, 0x84}, /* EF_PK.CH.SIG  */
  { 2, 0xC000, 15,101 },                    /* EF.C.SCA.QES (SubCA) */
  { 2, 0xC001, 15,100 },                    /* EF.C.ICC.QES (Cert)  */
  { 2, 0xC00E, 15,111 },                    /* EF.C.RCA.QES (RootCA */

  { 3, 0x4E03,  3, 0, -1 },                 /* EK_PK_03 */
  { 3, 0x4E04,  3, 0, -1 },                 /* EK_PK_04 */
  { 3, 0x4E05,  3, 0, -1 },                 /* EK_PK_05 */
  { 3, 0x4E06,  3, 0, -1 },                 /* EK_PK_06 */
  { 3, 0x4E07,  3, 0, -1 },                 /* EK_PK_07 */
  { 3, 0x4E08,  3, 0, -1 },                 /* EK_PK_08 */

  { 0, 0 }
};


/* Object to cache information gathered from FIDs. */
struct fid_cache_s {
  struct fid_cache_s *next;
  int nks_app_id;
  int fid;                          /* Zero for an unused slot.  */
  unsigned int  got_keygrip:1;      /* The keygrip and algo are valid.  */
  int algo;
  char *algostr;                    /* malloced.  */
  char keygripstr[2*KEYGRIP_LEN+1];
};


/* Object with application (i.e. NKS) specific data.  */
struct app_local_s {
  int active_nks_app;   /* One of the NKS_APP_ constants.  */

  int only_idlm;        /* The application is fixed to IDLM (IDKey card).  */
  int qes_app_id;       /* Either NKS_APP_SIGG or NKS_APP_ESIGN.  */

  int sigg_msig_checked;/* True if we checked for a mass signature card.  */
  int sigg_is_msig;     /* True if this is a mass signature card.  */

  int need_app_select;  /* Need to re-select the application.  */

  struct fid_cache_s *fid_cache; /* Linked list with cached infos.  */
};



static gpg_error_t readcert_from_ef (app_t app, int fid,
                                     unsigned char **cert, size_t *certlen);
static gpg_error_t switch_application (app_t app, int nks_app_id);
static const char *parse_pwidstr (app_t app, const char *pwidstr, int new_mode,
                                  int *r_nks_app_id, int *r_pwid);
static gpg_error_t verify_pin (app_t app, int pwid, const char *desc,
                               gpg_error_t (*pincb)(void*, const char *,
                                                    char **),
                               void *pincb_arg);
static gpg_error_t parse_keyref (app_t app, const char *keyref,
                                 int want_keypair, int *r_fididx);



static void
flush_fid_cache (app_t app)
{
  while (app->app_local->fid_cache)
    {
      struct fid_cache_s *next = app->app_local->fid_cache->next;
      if (app->app_local->fid_cache)
        xfree (app->app_local->fid_cache->algostr);
      xfree (app->app_local->fid_cache);
      app->app_local->fid_cache = next;
    }
}

/* Release local data. */
static void
do_deinit (app_t app)
{
  if (app && app->app_local)
    {
      flush_fid_cache (app);
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


/* Return an allocated string with the serial number in a format to be
 * show to the user.  May return NULL on malloc problem.  */
static char *
get_dispserialno (app_t app)
{
  char *result;

  /* We only need to strip the last zero which is not printed on the
   * card.  */
  result = app_get_serialno (app);
  if (result && *result && result[strlen(result)-1] == '0')
    result[strlen(result)-1] = 0;
  return result;
}


static gpg_error_t
pubkey_from_pk_file (app_t app, int pkfid, int cfid,
                     unsigned char **r_pk, size_t *r_pklen)
{
  gpg_error_t err;
  unsigned char *buffer[2];
  size_t buflen[2];
  int i;
  int offset[2] = { 0, 0 };

  *r_pk = NULL;
  *r_pklen = 0;

  if (app->appversion == 15)
    {
      /* Signature Card v2 - get keygrip from the certificate.  */
      unsigned char *cert;
      size_t certlen;

      if (cfid == -1)
        return gpg_error (GPG_ERR_NOT_SUPPORTED);

      /* Fall back to certificate reading.  */
      err = readcert_from_ef (app, cfid, &cert, &certlen);
      if (err)
        {
          log_error ("nks: error reading certificate %04X: %s\n",
                     cfid, gpg_strerror (err));
          return err;
        }

      err = app_help_pubkey_from_cert (cert, certlen, r_pk, r_pklen);
      xfree (cert);
      if (err)
        log_error ("nks: error parsing certificate %04X: %s\n",
                   cfid, gpg_strerror (err));

      return err;
    }

  err = iso7816_select_file (app_get_slot (app), pkfid, 0);
  if (err)
    return err;
  err = iso7816_read_record (app_get_slot (app), 1, 1, 0,
                             &buffer[0], &buflen[0]);
  if (err)
    return err;
  err = iso7816_read_record (app_get_slot (app), 2, 1, 0,
                             &buffer[1], &buflen[1]);
  if (err)
    {
      xfree (buffer[0]);
      return err;
    }

  if (app->appversion < 3)
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
          if (err)
            {
              xfree (buffer[0]);
              xfree (buffer[1]);
              return err;
            }
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
              err = gpg_error_from_syserror ();
              xfree (buffer[0]);
              xfree (buffer[1]);
              return err;
            }
          newbuf[0] = 0;
          memcpy (newbuf+1, buffer[i]+offset[i], buflen[i] - offset[i]);
          xfree (buffer[i]);
          buffer[i] = newbuf;
          buflen[i] = newlen;
          offset[i] = 0;
        }
    }

  *r_pk = make_canon_sexp_from_rsa_pk (buffer[0]+offset[0], buflen[0]-offset[0],
                                       buffer[1]+offset[1], buflen[1]-offset[1],
                                       r_pklen);

  xfree (buffer[0]);
  xfree (buffer[1]);
  return err;
}

/* Read the file with PKFID, assume it contains a public key and
 * return its keygrip in the caller provided 41 byte buffer R_GRIPSTR.
 * This works only for RSA card.  For the Signature Card v2 ECC is
 * used and Read Record needs to be replaced by read binary.  Given
 * all the ECC parameters required, we don't do that but rely that the
 * corresponding certificate at CFID is already available and get the
 * public key from there.  Note that a CFID of 1 is indicates that a
 * certificate is not known.  If R_ALGO is not NULL the public key
 * algorithm for the returned KEYGRIP is stored there.  If R_ALGOSTR
 * is not NULL the public key algo string (e.g. "rsa2048") is stored
 * there.  */
static gpg_error_t
keygripstr_from_pk_file (app_t app, int pkfid, int cfid, char *r_gripstr,
                         int *r_algo, char **r_algostr)
{
  gpg_error_t err;
  int algo = 0;  /* Public key algo.  */
  char *algostr = NULL; /* Public key algo string.  */
  struct fid_cache_s *ci;
  unsigned char *pk;
  size_t pklen;

  for (ci = app->app_local->fid_cache; ci; ci = ci->next)
    if (ci->fid && ci->nks_app_id == app->app_local->active_nks_app
        && ci->fid == pkfid)
      {
        if (!ci->got_keygrip)
          return gpg_error (GPG_ERR_NOT_FOUND);
        if (r_algostr && !ci->algostr)
          break;  /* Not in the cache - try w/o cache.  */
        memcpy (r_gripstr, ci->keygripstr, 2*KEYGRIP_LEN+1);
        if (r_algo)
          *r_algo = ci->algo;
        if (r_algostr)
          {
            *r_algostr = xtrystrdup (ci->algostr);
            if (!*r_algostr)
              return gpg_error_from_syserror ();
          }
        return 0;  /* Found in cache.  */
      }

  err = pubkey_from_pk_file (app, pkfid, cfid, &pk, &pklen);
  if (!err)
    err = app_help_get_keygrip_string_pk (pk, pklen, r_gripstr, NULL,
                                          &algo, &algostr);
  xfree (pk);

  if (!err)
    {
      if (r_algo)
        *r_algo = algo;
      if (r_algostr)
        {
          *r_algostr = algostr;
          algostr = NULL;
        }

      /* FIXME: We need to implement not_found caching.  */
      for (ci = app->app_local->fid_cache; ci; ci = ci->next)
        if (ci->fid
            && ci->nks_app_id == app->app_local->active_nks_app
            && ci->fid == pkfid)
          {
            /* Update the keygrip.  */
            memcpy (ci->keygripstr, r_gripstr, 2*KEYGRIP_LEN+1);
            ci->algo = algo;
            xfree (ci->algostr);
            ci->algostr = algostr? xtrystrdup (algostr) : NULL;
            ci->got_keygrip = 1;
            break;
          }
      if (!ci)
        {
          for (ci = app->app_local->fid_cache; ci; ci = ci->next)
            if (!ci->fid)
              break;
          if (!ci)
            ci = xtrycalloc (1, sizeof *ci);
          if (!ci)
            ; /* Out of memory - it is a cache, so we ignore it.  */
          else
            {
              ci->nks_app_id = app->app_local->active_nks_app;
              ci->fid = pkfid;
              memcpy (ci->keygripstr, r_gripstr, 2*KEYGRIP_LEN+1);
              ci->algo = algo;
              ci->got_keygrip = 1;
              ci->next = app->app_local->fid_cache;
              app->app_local->fid_cache = ci;
            }
        }
    }
  xfree (algostr);
  return err;
}


/* Parse KEYREF and return the index into the FILELIST at R_IDX.
 * Returns 0 on success and switches to the requested application.
 * The public key algo is stored at R_ALGO unless it is NULL.  */
static gpg_error_t
find_fid_by_keyref (app_t app, const char *keyref, int *r_idx, int *r_algo)
{
  gpg_error_t err;
  int idx;
  char keygripstr[2*KEYGRIP_LEN+1];

  if (!keyref || !keyref[0])
    err = gpg_error (GPG_ERR_INV_ID);
  else if (keyref[0] != 'N' && strlen (keyref) == 40)  /* This is a keygrip.  */
    {
      struct fid_cache_s *ci;

      /* FIXME: Our cache structure needs to be revised.  It doesn't
       * take the app_id into account and we don't have a way to
       * directly access the FID item if there are several of them
       * with different app_ids.  We disable the cache for now. */
      for (ci = app->app_local->fid_cache ; ci; ci = ci->next)
        if (ci->fid && ci->got_keygrip && !strcmp (ci->keygripstr, keyref))
          break;
      if (ci && 0 ) /* Cached (disabled) */
        {
          for (idx=0; filelist[idx].fid; idx++)
            if (filelist[idx].fid == ci->fid)
              break;
          if (!filelist[idx].fid)
            {
              log_debug ("nks: Ooops: Unkown FID cached!\n");
              err = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          err = switch_application (app, filelist[idx].nks_app_id);
          if (err)
            goto leave;
          if (r_algo)
            *r_algo = ci->algo;
        }
      else  /* Not cached.  */
        {
          for (idx=0; filelist[idx].fid; idx++)
            {
              if (!filelist[idx].iskeypair)
                continue;

              if (app->app_local->only_idlm)
                {
                  if (filelist[idx].nks_app_id != NKS_APP_IDLM)
                    continue;
                }
              else
                {
                  if (filelist[idx].nks_app_id != NKS_APP_NKS
                      && filelist[idx].nks_app_id != app->app_local->qes_app_id)
                    continue;

                  err = switch_application (app, filelist[idx].nks_app_id);
                  if (err)
                    goto leave;
                }

              err = keygripstr_from_pk_file (app, filelist[idx].fid,
                                             filelist[idx].iskeypair,
                                             keygripstr, r_algo, NULL);
              if (err)
                {
                  log_info ("nks: no keygrip for FID 0x%04X: %s - ignored\n",
                            filelist[idx].fid, gpg_strerror (err));
                  continue;
                }
              if (!strcmp (keygripstr, keyref))
                break; /* Found */
            }
          if (!filelist[idx].fid)
            {
              err = gpg_error (GPG_ERR_NOT_FOUND);
              goto leave;
            }
          /* (No need to switch the app as that has already been done
           * in the loop.)  */
        }
      *r_idx = idx;
      err = 0;
    }
  else /* This is a usual keyref.  */
    {
      err = parse_keyref (app, keyref, 1, &idx);
      if (err)
        goto leave;
      *r_idx = idx;

      err = switch_application (app, filelist[idx].nks_app_id);
      if (err)
        goto leave;
      if (r_algo)
        {
          /* We need to get the public key algo.  */
          err = keygripstr_from_pk_file (app, filelist[idx].fid,
                                         filelist[idx].iskeypair,
                                         keygripstr, r_algo, NULL);
          if (err)
            log_error ("nks: no keygrip for FID 0x%04X: %s\n",
                       filelist[idx].fid, gpg_strerror (err));
        }
    }

 leave:
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
    { "NKS-VERSION",  4 },  /* Legacy (printed decimal)  */
    { "CHV-STATUS",   5 },
    { "$DISPSERIALNO",6 },
    { "SERIALNO",     0 }
  };
  gpg_error_t err = 0;
  int idx;
  char *p, *p2;
  char buffer[100];
  int nksver = app->appversion;

  err = switch_application (app, NKS_APP_NKS);
  if (err)
    return err;

  for (idx=0; (idx < DIM(table)
               && ascii_strcasecmp (table[idx].name, name)); idx++)
    ;
  if (!(idx < DIM (table)))
    return gpg_error (GPG_ERR_INV_NAME);

  switch (table[idx].special)
    {
    case 0: /* SERIALNO */
      {
        p = app_get_serialno (app);
        if (p)
          {
            send_status_direct (ctrl, "SERIALNO", p);
            xfree (p);
          }
      }
      break;

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
      snprintf (buffer, sizeof buffer, "%d", app->appversion);
      send_status_info (ctrl, table[idx].name,
                        buffer, strlen (buffer), NULL, 0);
      break;

    case 5: /* CHV-STATUS */
      {
        /* Return the status for the the PINs as described in the
         * table below.  See the macros ISO7816_VERIFY_* for a list
         * for each slot.  The order is
         *
         * | idx | name       |
         * |-----+------------|
         * |   0 | PW1.CH     |
         * |   1 | PW2.CH     |
         * |   2 | PW1.CH.SIG |
         * |   3 | PW2.CH.SIG |
         *
         * See parse_pwidstr for details of the mapping.
         */
        int tmp[4];

        /* We use a helper array so that we can control that there is
         * no superfluous application switches.  */
        if (app->appversion == 15)
          {
            tmp[0] = get_chv_status (app, 0, 0x03);
            tmp[1] = get_chv_status (app, 0, 0x04);
          }
        else
          {
            tmp[0] = get_chv_status (app, 0, 0x00);
            tmp[1] = get_chv_status (app, 0, 0x01);
          }
        tmp[2] = get_chv_status (app, app->app_local->qes_app_id, 0x81);
        if (app->appversion == 15)
          tmp[3] = get_chv_status (app, app->app_local->qes_app_id, 0x82);
        else
          tmp[3] = get_chv_status (app, app->app_local->qes_app_id, 0x83);
        snprintf (buffer, sizeof buffer, "%d %d %d %d",
                  tmp[0], tmp[1], tmp[2], tmp[3]);
        send_status_info (ctrl, table[idx].name,
                          buffer, strlen (buffer), NULL, 0);
      }
      break;

    case 6: /* $DISPSERIALNO */
      {
        p = app_get_serialno (app);
        p2 = get_dispserialno (app);
        if (p && p2 && strcmp (p, p2))
          send_status_info (ctrl, table[idx].name, p2, strlen (p2),
                            NULL, (size_t)0);
        else /* No abbreviated S/N or identical to the full full S/N.  */
          err = gpg_error (GPG_ERR_INV_NAME);  /* No Abbreviated S/N.  */
        xfree (p);
        xfree (p2);
      }
      break;

    default:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      break;
    }

  return err;
}


/* Parse a keyref (NKS_*.*) and return the corresponding EF as an
 * index into the filetable.  With WANT_KEYPAIR set a keypair EF is
 * requested; otherwise also cert EFs are returned.  */
static gpg_error_t
parse_keyref (app_t app, const char *keyref, int want_keypair, int *r_fididx)
{
  int nks_app_id, fid, idx;

  if (!ascii_strncasecmp (keyref, "NKS-NKS3.", 9))
    nks_app_id = NKS_APP_NKS;
  else if (!ascii_strncasecmp (keyref, "NKS-ESIGN.", 10)
           && (!want_keypair || app->app_local->qes_app_id == NKS_APP_ESIGN))
    nks_app_id = NKS_APP_ESIGN;
  else if (!ascii_strncasecmp (keyref, "NKS-SIGG.", 9)
           && (!want_keypair || app->app_local->qes_app_id == NKS_APP_SIGG))
    nks_app_id = NKS_APP_SIGG;
  else if (!ascii_strncasecmp (keyref, "NKS-IDLM.", 9))
    nks_app_id = NKS_APP_IDLM;
  else if (!ascii_strncasecmp (keyref, "NKS-DF01.", 9))
    nks_app_id = NKS_APP_NKS;
  else
    return gpg_error (GPG_ERR_INV_ID);

  keyref += nks_app_id == NKS_APP_ESIGN? 10 : 9;

  if (!hexdigitp (keyref) || !hexdigitp (keyref+1)
      || !hexdigitp (keyref+2) || !hexdigitp (keyref+3)
      || keyref[4])
    return gpg_error (GPG_ERR_INV_ID);
  fid = xtoi_4 (keyref);
  for (idx=0; filelist[idx].fid; idx++)
    if (filelist[idx].fid == fid
        && filelist[idx].nks_app_id == nks_app_id
        && ((want_keypair && filelist[idx].iskeypair)
            || (!want_keypair
                && (filelist[idx].certtype || filelist[idx].iskeypair > 0))))
      break;
  if (!filelist[idx].fid)
    return gpg_error (GPG_ERR_NOT_FOUND);

  *r_fididx = idx;
  return 0;
}


const char *
get_nks_tag (app_t app, int nks_app_id)
{
  const char *tag;

  if (nks_app_id == NKS_APP_ESIGN)
    tag = "ESIGN";
  else if (nks_app_id == NKS_APP_SIGG)
    tag = "SIGG";
  else if (nks_app_id == NKS_APP_IDLM)
    tag = "IDLM";
  else if (app->appversion < 3)
    tag = "DF01";
  else
    tag = "NKS3";

  return tag;
}

static void
set_usage_string (char usagebuf[5], int i)
{
  int usageidx = 0;
  if (filelist[i].issignkey)
    usagebuf[usageidx++] = 's';
  if (filelist[i].isauthkey)
    usagebuf[usageidx++] = 'a';
  if (filelist[i].isencrkey)
    usagebuf[usageidx++] = 'e';
  if (!usageidx)
    usagebuf[usageidx++] = '-';
  usagebuf[usageidx] = 0;
}

static void
do_learn_status_core (app_t app, ctrl_t ctrl, unsigned int flags,
                      int nks_app_id)
{
  gpg_error_t err;
  char ct_buf[100], id_buf[100];
  int i;
  const char *tag = get_nks_tag (app, nks_app_id);

  /* Output information about all useful objects in the NKS application. */
  for (i=0; filelist[i].fid; i++)
    {
      if (filelist[i].nks_ver > app->appversion)
        continue;

      if (filelist[i].nks_app_id != nks_app_id)
        continue;

      if (filelist[i].certtype && !(flags & APP_LEARN_FLAG_KEYPAIRINFO))
        {
          size_t len;

          len = app_help_read_length_of_cert (app_get_slot (app),
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
          char *algostr = NULL;

          err = keygripstr_from_pk_file (app, filelist[i].fid,
                                         filelist[i].iskeypair, gripstr,
                                         NULL, &algostr);
          if (err)
            log_error ("can't get keygrip from FID 0x%04X: %s\n",
                       filelist[i].fid, gpg_strerror (err));
          else
            {
              snprintf (id_buf, sizeof id_buf, "NKS-%s.%04X",
                        tag, filelist[i].fid);
              set_usage_string (usagebuf, i);
              send_status_info (ctrl, "KEYPAIRINFO",
                                gripstr, 40,
                                id_buf, strlen (id_buf),
                                usagebuf, strlen (usagebuf),
                                "-", (size_t)1,
                                algostr, strlen (algostr),
                                NULL, (size_t)0);
            }
          xfree (algostr);
        }
    }
}


static gpg_error_t
do_learn_status (app_t app, ctrl_t ctrl, unsigned int flags)
{
  gpg_error_t err;

  do_getattr (app, ctrl, "CHV-STATUS");

  err = switch_application (app, NKS_APP_NKS);
  if (err)
    return err;

  do_learn_status_core (app, ctrl, flags, app->app_local->active_nks_app);

  if (app->app_local->only_idlm)
    return 0;  /* ready.  */

  err = switch_application (app, app->app_local->qes_app_id);
  if (err)
    return 0;  /* Silently ignore if we can't switch to SigG.  */

  do_learn_status_core (app, ctrl, flags, app->app_local->qes_app_id);

  return 0;
}


/* Helper to read a certificate from the file FID.  The function
 * assumes that the application has already been selected.  */
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
  err = iso7816_select_file (app_get_slot (app), fid, 0);
  if (err)
    {
      log_error ("nks: error selecting FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return err;
    }

  err = iso7816_read_binary (app_get_slot (app), 0, 0, &buffer, &buflen);
  if (err)
    {
      log_error ("nks: error reading certificate from FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return err;
    }

  if (!buflen || *buffer == 0xff || all_zero_p (buffer, buflen))
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


/*
 * Iterate over FILELIST, supporting two use cases:
 *
 * (1) With WANT_KEYGRIPSTR=<GRIP>, finding matching entry.
 * (2) With WANT_KEYGRIPSTR=NULL, listing entries
 *     by CAPABILITY (possibly == 0, for all entries).
 *
 * Caller supplies an array KEYGRIPSTR.
 * Caller should start *IDX_P == -1, and keep the index value in IDX_P.
 *
 * Returns 0 on success, otherwise returns error value.
 *
 * When all entries are tried, returns GPG_ERR_NOT_FOUND for the use
 * case of (1).  Returns GPG_ERR_TRUE for the use case of (2).
 */
static gpg_error_t
iterate_over_filelist (app_t app, const char *want_keygripstr, int capability,
                       char keygripstr[2*KEYGRIP_LEN+1], int *idx_p)
{
  gpg_error_t err;
  int idx = *idx_p;

  for (idx++; filelist[idx].fid; idx++)
    {
      if (filelist[idx].nks_ver > app->appversion)
        continue; /* EF not support by this card version.  */

      if (!filelist[idx].iskeypair)
        continue; /* Skip - We are only interested in keypairs.  */

      if (app->app_local->only_idlm)
        {
          /* IDLM cards have no other applications we want to switch
           * to.  We skip all EFs which are not known for IDLM.  */
          if (filelist[idx].nks_app_id != NKS_APP_IDLM)
            continue;
        }
      else
        {
          /* Skip all EFs which are not for NKS or the card's
           * implementation for a qualified electoric signature (QES)
           * which is either the old SIGG or the newer ESIGN.  */
          if (filelist[idx].nks_app_id != NKS_APP_NKS
              && filelist[idx].nks_app_id != app->app_local->qes_app_id)
            continue;

          /* Switch if needed.  Note that the filelist should be
           * sorted to avoid unnecessary switches.  */
          err = switch_application (app, filelist[idx].nks_app_id);
          if (err)
            {
              *idx_p = idx;
              return err;
            }
        }

      /* Get the keygrip from the EF.  Note that this functions
       * consults the cache to avoid computing the keygrip again.  */
      err = keygripstr_from_pk_file (app, filelist[idx].fid,
                                     filelist[idx].iskeypair, keygripstr,
                                     NULL, NULL);
      if (err)
        {
          log_error ("can't get keygrip from FID 0x%04X: %s\n",
                     filelist[idx].fid, gpg_strerror (err));
          continue;
        }

      if (want_keygripstr)
        {
          /* If the keygrip matches the requested one we are ready.  */
          if (!strcmp (keygripstr, want_keygripstr))
            {
              /* Found */
              *idx_p = idx;
              return 0;
            }
        }
      else /* No keygrip requested - list all .  */
        {
          /* If a capability has been requested return only keys with
           * that capability.  */
          if (capability == GCRY_PK_USAGE_SIGN)
            {
              if (!filelist[idx].issignkey)
                continue;
            }
          if (capability == GCRY_PK_USAGE_ENCR)
            {
              if (!filelist[idx].isencrkey)
                continue;
            }
          if (capability == GCRY_PK_USAGE_AUTH)
            {
              if (!filelist[idx].isauthkey)
                continue;
            }

          /* Found.  Return but save the last idenx of the loop.  */
          *idx_p = idx;
          return 0;
        }
    }

  if (!want_keygripstr)
    err = gpg_error (GPG_ERR_TRUE);
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);

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
  int idx, fid;
  gpg_error_t err;

  *cert = NULL;
  *certlen = 0;

  /* Handle the case with KEYGRIP.  We got a keygrip if the string has
   * a length of 40 and does not start with an N as in NKS-* */
  if (certid[0] != 'N' && strlen (certid) == 40)
    {
      char keygripstr[2*KEYGRIP_LEN+1];

      idx = -1;
      err = iterate_over_filelist (app, certid, 0, keygripstr, &idx);
      if (err)
        return err;

      /* Switching is not required here because iterate_over_filelist
       * has already done that.  */
    }
  else /* This is not a keygrip.  */
    {
      err = parse_keyref (app, certid, 0, &idx);
      if (err)
        return err;

      err = switch_application (app, filelist[idx].nks_app_id);
      if (err)
        return err;
    }

  /* If the requested objects is a plain public key, redirect it to
     the corresponding certificate.  The whole system is a bit messy
     because we sometime use the key directly or let the caller
     retrieve the key from the certificate.  The rationale for
     that is to support not-yet stored certificates. */
  if (filelist[idx].iskeypair > 0)
    fid = filelist[idx].iskeypair;
  else
    fid = filelist[idx].fid;

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
  unsigned char *dummy_pk = NULL;
  size_t  dummy_pklen = 0;

  if (!pk)
    pk = &dummy_pk;
  if (!pklen)
    pklen = &dummy_pklen;

  (void)ctrl;

  if ((flags & APP_READKEY_FLAG_ADVANCED))
    return GPG_ERR_NOT_SUPPORTED;

  /* We use a generic name to retrieve PK.AUT.IFD-SPK.  */
  if (!strcmp (keyid, "$IFDAUTHKEY") && app->appversion >= 3)
    {
      unsigned short path[1] = { 0x4500 };
      unsigned char *buffer[2];
      size_t buflen[2];

      /* Access the KEYD file which is always in the master directory.  */
      err = iso7816_select_path (app_get_slot (app), path, DIM (path), 0);
      if (err)
        goto leave;
      /* Due to the above select we need to re-select our application.  */
      app->app_local->need_app_select = 1;
      /* Get the two records.  */
      err = iso7816_read_record (app_get_slot (app), 5, 1, 0,
                                 &buffer[0], &buflen[0]);
      if (err)
        goto leave;
      if (all_zero_p (buffer[0], buflen[0]))
        {
          xfree (buffer[0]);
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
      err = iso7816_read_record (app_get_slot (app), 6, 1, 0,
                                 &buffer[1], &buflen[1]);
      if (err)
        {
          xfree (buffer[0]);
          goto leave;
        }

      if ((flags & APP_READKEY_FLAG_INFO))
        {
          /* FIXME */
        }

      if (pk && pklen && pk != &dummy_pk)
        {
          *pk = make_canon_sexp_from_rsa_pk (buffer[0], buflen[0],
                                             buffer[1], buflen[1],
                                             pklen);
          if (!*pk)
            err = gpg_error_from_syserror ();
        }

      xfree (buffer[0]);
      xfree (buffer[1]);
    }
  else if (keyid[0] != 'N' && strlen (keyid) == 40)
    {
      char keygripstr[2*KEYGRIP_LEN+1];
      int i = -1;

      err = iterate_over_filelist (app, keyid, 0, keygripstr, &i);
      if (err)
        goto leave;

      err = pubkey_from_pk_file (app, filelist[i].fid, filelist[i].iskeypair,
                                 pk, pklen);
      if (!err && (flags & APP_READKEY_FLAG_INFO))
        {
          char *algostr;
          char usagebuf[5];
          char id_buf[100];

          if (app_help_get_keygrip_string_pk (*pk, *pklen, NULL, NULL, NULL,
                                              &algostr))
            algostr = NULL;  /* Ooops.  */

          snprintf (id_buf, sizeof id_buf, "NKS-%s.%04X",
                    get_nks_tag (app, filelist[i].nks_app_id),
                    filelist[i].fid);
          set_usage_string (usagebuf, i);
          send_status_info (ctrl, "KEYPAIRINFO",
                            keygripstr, strlen (keygripstr),
                            id_buf, strlen (id_buf),
                            usagebuf, strlen (usagebuf),
                            "-", (size_t)1,
                            algostr, strlen (algostr?algostr:""),
                            NULL, (size_t)0);
          xfree (algostr);
        }
    }
  else if (!strncmp (keyid, "NKS-IDLM.", 9))
    {
      keyid += 9;
      if (!hexdigitp (keyid) || !hexdigitp (keyid+1)
          || !hexdigitp (keyid+2) || !hexdigitp (keyid+3)
          || keyid[4])
        {
          err = gpg_error (GPG_ERR_INV_ID);
          goto leave;
        }

      err = pubkey_from_pk_file (app, xtoi_4 (keyid), -1, pk, pklen);
      /* FIXME: Implement KEYPAIRINFO.  */
    }
  else /* Return the error code expected by cmd_readkey.  */
    err = gpg_error (GPG_ERR_UNSUPPORTED_OPERATION);

 leave:
  xfree (dummy_pk);
  return err;
}


/* Write the certificate (CERT,CERTLEN) to the card at CERTREFSTR.
 * CERTREFSTR is of the form "NKS_<yyy>.<four_hexdigit_keyref>". */
static gpg_error_t
do_writecert (app_t app, ctrl_t ctrl,
              const char *certid,
              gpg_error_t (*pincb)(void*, const char *, char **),
              void *pincb_arg,
              const unsigned char *cert, size_t certlen)
{
  gpg_error_t err;
  int i, fid, pwid;
  int nks_app_id, tmp_app_id;
  const char *desc;

  (void)ctrl;

  if (!strncmp (certid, "NKS-NKS3.", 9))
    nks_app_id = NKS_APP_NKS;
  else if (!strncmp (certid, "NKS-ESIGN.", 10))
    nks_app_id = NKS_APP_ESIGN;
  else if (!strncmp (certid, "NKS-SIGG.", 9))
    nks_app_id = NKS_APP_SIGG;
  else if (!strncmp (certid, "NKS-DF01.", 9))
    nks_app_id = NKS_APP_NKS;
  else if (!strncmp (certid, "NKS-IDLM.", 9))
    nks_app_id = NKS_APP_IDLM;
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
    if ((filelist[i].certtype || filelist[i].iskeypair > 0)
        && filelist[i].nks_app_id == nks_app_id
        && filelist[i].fid == fid)
      break;
  if (!filelist[i].fid)
    return gpg_error (GPG_ERR_NOT_FOUND);

  /* If the requested objects is a plain public key, redirect it to
   * the corresponding certificate.  This makes it easier for the user
   * to figure out which CERTID to use.  For example gpg-card shows
   * the id of the key and not of the certificate.  */
  if (filelist[i].iskeypair > 0)
    fid = filelist[i].iskeypair;

  /* We have no selective flush mechanism and given the rare use of
   * writecert it won't harm to flush the entire cache.  */
  flush_fid_cache (app);

  /* The certificates we support all require PW1.CH.  Note that we
   * check that the nks_app_id matches which sorts out CERTID values
   * which are subkeys to a different nks_app_id.  */
  desc = parse_pwidstr (app, "PW1.CH", 0, &tmp_app_id, &pwid);
  if (!desc || tmp_app_id != nks_app_id)
    return gpg_error (GPG_ERR_INV_ID);
  err = verify_pin (app, pwid, desc, pincb, pincb_arg);
  if (err)
    return err;

  /* Select the file and write the certificate.  */
  err = iso7816_select_file (app_get_slot (app), fid, 0);
  if (err)
    {
      log_error ("nks: error selecting FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return err;
    }

  err = iso7816_update_binary (app_get_slot (app), 1, 0, cert, certlen);
  if (err)
    {
      log_error ("nks: error updating certificate at FID 0x%04X: %s\n",
                 fid, gpg_strerror (err));
      return err;
    }

  return 0;
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

  if (!strcmp (keyid, "$IFDAUTHKEY") && app->appversion >= 3)
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
  /* We will need to clear the cache here.  */
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
/*   err = iso7816_manage_security_env (app_get_slot (app), 0x81, 0xB6, */
/*                                      mse, sizeof mse); */

 leave:
  return err;
}


/* Return an allocated string to be used as prompt.  Returns NULL on
 * malloc error.  */
static char *
make_prompt (app_t app, int remaining, const char *firstline,
             const char *extraline)
{
  char *serial, *tmpbuf, *result;

  serial = get_dispserialno (app);

  /* TRANSLATORS: Put a \x1f right before a colon.  This can be
   * used by pinentry to nicely align the names and values.  Keep
   * the %s at the start and end of the string.  */
  result = xtryasprintf (_("%s"
                           "Number\x1f: %s%%0A"
                           "Holder\x1f: %s"
                           "%s"),
                         "\x1e",
                         serial,
                         "",
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
      tmpbuf = strconcat (firstline, "%0A%0A", result,
                          extraline? "%0A%0A":"", extraline,
                          NULL);
      xfree (result);
      result = tmpbuf;
    }

  return result;
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
  int rc;
  pininfo_t pininfo;
  char *prompt;
  const char *extrapromptline = NULL;
  int remaining, nullpin;

  if (!desc)
    desc = "||PIN";

  memset (&pininfo, 0, sizeof pininfo);
  pininfo.fixedlen = -1;

  /* FIXME: TCOS allows to read the min. and max. values - do this.  */
  if (app->appversion == 15)
    {
      if (app->app_local->active_nks_app == NKS_APP_NKS && pwid == 0x03)
        pininfo.minlen = 6;
      else if (app->app_local->active_nks_app == NKS_APP_ESIGN && pwid == 0x81)
        pininfo.minlen = 6;
      else
        pininfo.minlen = 8;
      pininfo.maxlen = 24;
    }
  else if (app->app_local->active_nks_app == NKS_APP_IDLM)
    {
      if (pwid == 0x00)
        pininfo.minlen = 6;
      else
        pininfo.minlen = 8;
      pininfo.maxlen = 24;
    }
  else
    {
      /* For NKS3 we used these fixed values; let's keep this.  */
      pininfo.minlen = 6;
      pininfo.maxlen = 16;
    }

  remaining = iso7816_verify_status (app_get_slot (app), pwid);
  nullpin = (remaining == ISO7816_VERIFY_NULLPIN);
  if (remaining < 0)
    remaining = -1; /* We don't care about the concrete error.  */
  if (remaining < 3)
    {
      if (remaining >= 0)
        log_info ("nks: PIN has %d attempts left\n", remaining);
    }

  if (nullpin)
    {
      log_info ("nks: The NullPIN for PIN 0x%02x has not yet been changed\n",
                pwid);
      extrapromptline = _("Note: PIN has not yet been enabled.");
    }

  if (!opt.disable_pinpad
      && !iso7816_check_pinpad (app_get_slot (app), ISO7816_VERIFY, &pininfo) )
    {
      prompt = make_prompt (app, remaining, desc, extrapromptline);
      rc = pincb (pincb_arg, prompt, NULL);
      xfree (prompt);
      if (rc)
        {
          log_info (_("PIN callback returned error: %s\n"),
                    gpg_strerror (rc));
          return rc;
        }

      rc = iso7816_verify_kp (app_get_slot (app), pwid, &pininfo);
      pincb (pincb_arg, NULL, NULL);  /* Dismiss the prompt. */
    }
  else
    {
      char *pinvalue;

      prompt = make_prompt (app, remaining, desc, extrapromptline);
      rc = pincb (pincb_arg, prompt, &pinvalue);
      xfree (prompt);
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

      rc = iso7816_verify (app_get_slot (app), pwid,
                           pinvalue, strlen (pinvalue));
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
  int idx;
  int pwid;
  unsigned char kid;
  unsigned char data[83];   /* Must be large enough for a SHA-1 digest
                               + the largest OID prefix. */
  size_t datalen;
  int algo;
  unsigned int digestlen;   /* Length of the hash.  */
  unsigned char oidbuf[64];
  size_t oidbuflen;

  (void)ctrl;

  switch (indatalen)
    {
    case 20: /* plain SHA-1 or RMD160 digest         */
    case 28: /* plain SHA-224 digest                 */
    case 32: /* plain SHA-256 digest                 */
    case 48: /* plain SHA-384 digest                 */
    case 64: /* plain SHA-512 digest                 */
    case 35: /* ASN.1 encoded SHA-1 or RMD160 digest */
    case 47: /* ASN.1 encoded SHA-224 digest         */
    case 51: /* ASN.1 encoded SHA-256 digest         */
    case 67: /* ASN.1 encoded SHA-384 digest         */
    case 83: /* ASN.1 encoded SHA-512 digest         */
      break;
    default:
      log_info ("nks: invalid length of input data: %zu\n", indatalen);
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  err = find_fid_by_keyref (app, keyidstr, &idx, &algo);
  if (err)
    return err;

  if (app->app_local->active_nks_app == NKS_APP_SIGG
      && app->app_local->sigg_is_msig)
    {
      log_info ("mass signature cards are not allowed\n");
      return gpg_error (GPG_ERR_NOT_SUPPORTED);
    }

  if (!filelist[idx].issignkey)
    {
      log_debug ("key %s is not a signing key\n", keyidstr);
      return gpg_error (GPG_ERR_INV_ID);
    }

  kid = filelist[idx].kid;

  digestlen = gcry_md_get_algo_dlen (hashalgo);

  /* Prepare the input object from INDATA.  */
  if (algo == GCRY_PK_ECC)
    {
      if (digestlen != 32 && digestlen != 48 && digestlen != 64)
        {
          log_error ("nks: ECC signing not possible: dlen=%u\n", digestlen);
          return gpg_error (GPG_ERR_DIGEST_ALGO);
        }

      if (indatalen == digestlen)
        {
          /* Already prepared.  */
          datalen = indatalen;
          log_assert (datalen <= sizeof data);
          memcpy (data, indata, datalen);
        }
      else if (indatalen > digestlen)
        {
          /* Assume a PKCS#1 prefix and remove it.  */
          oidbuflen = sizeof oidbuf;
          err = gcry_md_get_asnoid (hashalgo, &oidbuf, &oidbuflen);
          if (err)
            {
              log_error ("nks: no OID for hash algo %d\n", hashalgo);
              return gpg_error (GPG_ERR_INTERNAL);
            }
          if (indatalen != oidbuflen + digestlen
              || memcmp (indata, oidbuf, oidbuflen))
            {
              log_error ("nks: input data too long for ECC: len=%zu\n",
                         indatalen);
              return gpg_error (GPG_ERR_INV_VALUE);
            }
          datalen = indatalen - oidbuflen;
          log_assert (datalen <= sizeof data);
          memcpy (data, (const char*)indata + oidbuflen, datalen);
        }
      else
        {
          log_error ("nks: input data too short for ECC: len=%zu\n",
                     indatalen);
          return gpg_error (GPG_ERR_INV_VALUE);
        }
    }
  else if (app->appversion > 2 && (indatalen == 35
                                   || indatalen == 47
                                   || indatalen == 51
                                   || indatalen == 67
                                   || indatalen == 83))
    {
      /* Verify that the caller has sent a proper ASN.1 encoded hash
         for RMD160 or SHA-{1,224,256,384,512}. */
#define X(algo,prefix,plaindigestlen)                      \
      if (hashalgo == (algo)                               \
          && indatalen == sizeof prefix + (plaindigestlen) \
          && !memcmp (indata, prefix, sizeof prefix))      \
        ;
      X(GCRY_MD_RMD160, rmd160_prefix, 20)
      else X(GCRY_MD_SHA1, sha1_prefix, 20)
      else X(GCRY_MD_SHA224, sha224_prefix, 28)
      else X(GCRY_MD_SHA256, sha256_prefix, 32)
      else X(GCRY_MD_SHA384, sha384_prefix, 48)
      else X(GCRY_MD_SHA512, sha512_prefix, 64)
      else
        return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
#undef X

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
  /* Concatenate prefix and digest.
   * Note that the X macro creates an "else if".  Ugly - I know. */
#define X(algo,prefix,plaindigestlen) \
  if ((hashalgo == (algo)) && (indatalen == (plaindigestlen))) \
    {                                                          \
      datalen = sizeof prefix + indatalen;                     \
      log_assert (datalen <= sizeof data);                     \
      memcpy (data, prefix, sizeof prefix);                    \
      memcpy (data + sizeof prefix, indata, indatalen);        \
    }
  else X(GCRY_MD_RMD160, rmd160_prefix, 20)
  else X(GCRY_MD_SHA1, sha1_prefix, 20)
  else X(GCRY_MD_SHA224, sha224_prefix, 28)
  else X(GCRY_MD_SHA256, sha256_prefix, 32)
  else X(GCRY_MD_SHA384, sha384_prefix, 48)
  else X(GCRY_MD_SHA512, sha512_prefix, 64)
  else
    return gpg_error (GPG_ERR_INV_VALUE);
#undef X

  /* Send an MSE for PSO:Compute_Signature.  */
  if (app->appversion > 2 && app->app_local->active_nks_app != NKS_APP_ESIGN)
    {
      unsigned char mse[6];
      unsigned int mselen;

      if (algo == GCRY_PK_ECC)
        {
          mse[0] = 0x84; /* Private key reference.  */
          mse[1] = 1;
          mse[2] = kid;
          mselen = 3;
        }
      else /* RSA */
        {
          mse[0] = 0x80; /* Algorithm reference.  */
          mse[1] = 1;
          mse[2] = 2;    /* Card does pkcs#1 v1.5 padding, no ASN.1 check.  */
          mse[3] = 0x84; /* Private key reference.  */
          mse[4] = 1;
          mse[5] = kid;
          mselen = 6;
        }
      err = iso7816_manage_security_env (app_get_slot (app), 0x41, 0xB6,
                                         mse, mselen);
    }

  if (app->app_local->active_nks_app == NKS_APP_ESIGN)
    pwid = 0x81;
  else if (app->appversion == 15)
    pwid = 0x03;
  else
    pwid = 0x00;

  if (!err)
    err = verify_pin (app, pwid, NULL, pincb, pincb_arg);
  /* Compute the signature.  */
  if (!err)
    err = iso7816_compute_ds (app_get_slot (app), 0, data, datalen, 0,
                              outdata, outdatalen);
  return err;
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
  gpg_error_t err;
  int idx;
  int kid;
  int algo;
  int pwid;
  int padind;
  int extended_mode;

  (void)ctrl;
  (void)r_info;

  if (!indatalen)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = find_fid_by_keyref (app, keyidstr, &idx, &algo);
  if (err)
    return err;

  if (!filelist[idx].isencrkey)
    return gpg_error (GPG_ERR_INV_ID);

  kid = filelist[idx].kid;

  if (app->appversion <= 2)
    {
      static const unsigned char mse[] =
        {
          0x80, 1, 0x10, /* Select algorithm RSA. */
          0x84, 1, 0x81  /* Select local secret key 1 for decryption. */
        };
      err = iso7816_manage_security_env (app_get_slot (app), 0xC1, 0xB8,
                                         mse, sizeof mse);
      extended_mode = 0;
      padind = 0x81;
    }
  else if (algo == GCRY_PK_ECC)
    {
      unsigned char mse[3];
      mse[0] = 0x84; /* Private key reference.  */
      mse[1] = 1;
      mse[2] = kid;
      err = iso7816_manage_security_env (app_get_slot (app), 0x41, 0xB8,
                                         mse, sizeof mse);
      extended_mode = 0;
      padind = 0x00;
    }
  else
    {
      unsigned char mse[6];
      mse[0] = 0x80; /* Algorithm reference.  */
      mse[1] = 1;
      mse[2] = 0x0a; /* RSA no padding.  (0x1A is pkcs#1.5 padding.)  */
      mse[3] = 0x84; /* Private key reference.  */
      mse[4] = 1;
      mse[5] = kid;
      err = iso7816_manage_security_env (app_get_slot (app), 0x41, 0xB8,
                                         mse, sizeof mse);
      extended_mode = 1;
      padind = 0x81;
    }
  if (err)
    {
      log_error ("nks: MSE failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* We use the Global PIN 1 */
  if (app->appversion == 15)
    pwid = 0x03;
  else
    pwid = 0x00;

  err = verify_pin (app, pwid, NULL, pincb, pincb_arg);
  if (err)
    goto leave;

  err = iso7816_decipher (app_get_slot (app), extended_mode,
                          indata, indatalen, 0, padind,
                          outdata, outdatalen);

 leave:
  return err;
}



/* Parse a password ID string.  Returns NULL on error or a string
 * suitable as passphrase prompt on success.  On success stores the
 * reference value for the password at R_PWID and a flag indicating
 * which app is to be used at R_NKS_APP_ID.  If NEW_MODE is true, the
 * returned description is suitable for a new password.  Here is a
 * take mapping the PWIDSTR to the used PWIDs:
 *
 *  | pwidstr    |              | NKS3 | NKS15 | IDKEY1 |
 *  |------------+--------------+------+-------+--------|
 *  | PW1.CH     | Global PIN 1 | 0x00 |  0x03 | 0x00   |
 *  | PW2.CH     | Global PIN 2 | 0x01 |  0x04 | 0x01   |
 *  | PW1.CH.SIG | SigG PIN 1   | 0x81 |  0x81 | -      |
 *  | PW2.CH.SIG | SigG PIN 2   | 0x83 |  0x82 | -      |
 *
 * The names for PWIDSTR are taken from the NKS3 specs; the specs of
 * other cards use different names but we keep using the.  PIN1 can be
 * used to unlock PIN2 and vice versa; for consistence with other
 * cards we name PIN2 a "PUK".  The IDKEY card also features a Card
 * Reset Key (CR Key 0x01) which can also be used to reset PIN1.
 *
 * For testing it is possible to specify the PWID directly; the
 * prompts are then not very descriptive:
 *
 *   NKS.0xnn   - Switch to NKS and select id 0xnn
 *   SIGG.0xnn  - Switch to SigG and select id 0xnn
 *   ESIGN.0xnn - Switch to ESIGN and select id 0xnn
 */
static const char *
parse_pwidstr (app_t app, const char *pwidstr, int new_mode,
               int *r_nks_app_id, int *r_pwid)
{
  const char *desc;
  int nks15 = app->appversion == 15;

  if (!pwidstr)
    desc = NULL;
  else if (!strcmp (pwidstr, "PW1.CH"))
    {
      *r_nks_app_id = NKS_APP_NKS;
      *r_pwid = nks15? 0x03 : 0x00;
      /* TRANSLATORS: Do not translate the "|*|" prefixes but keep
         them verbatim at the start of the string.  */
      desc = (new_mode
              ? _("|N|Please enter a new PIN for the standard keys.")
              : _("||Please enter the PIN for the standard keys."));
    }
  else if (!strcmp (pwidstr, "PW2.CH"))
    {
      *r_nks_app_id = NKS_APP_NKS;
      *r_pwid = nks15? 0x04 : 0x01;
      desc = (new_mode
              ? _("|NP|Please enter a new PIN Unblocking Code (PUK) "
                  "for the standard keys.")
              : _("|P|Please enter the PIN Unblocking Code (PUK) "
                  "for the standard keys."));
    }
  else if (!strcmp (pwidstr, "PW1.CH.SIG") && !app->app_local->only_idlm)
    {
      *r_nks_app_id = app->app_local->qes_app_id;
      *r_pwid = 0x81;
      desc = (new_mode
              ? _("|N|Please enter a new PIN for the key to create "
                  "qualified signatures.")
              : _("||Please enter the PIN for the key to create "
                  "qualified signatures."));
    }
  else if (!strcmp (pwidstr, "PW2.CH.SIG") && !app->app_local->only_idlm)
    {
      *r_nks_app_id = app->app_local->qes_app_id;
      *r_pwid = nks15? 0x82 : 0x83;
      desc = (new_mode
              ? _("|NP|Please enter a new PIN Unblocking Code (PUK) "
                  "for the key to create qualified signatures.")
              : _("|P|Please enter the PIN Unblocking Code (PUK) "
                  "for the key to create qualified signatures."));
    }
  else if (!strncmp (pwidstr, "NKS.0x", 6)
           && hexdigitp (pwidstr+6) && hexdigitp (pwidstr+7) && !pwidstr[8])
    {
      /* Hack to help debugging.  */
      *r_nks_app_id = NKS_APP_NKS;
      *r_pwid = xtoi_2 (pwidstr+6);
      desc = (new_mode
              ? "|N|Please enter a new PIN for the given NKS pwid"
              : "||Please enter the PIN for the given NKS pwid" );
    }
  else if (!strncmp (pwidstr, "SIGG.0x", 7)
           && hexdigitp (pwidstr+7) && hexdigitp (pwidstr+8) && !pwidstr[9])
    {
      /* Hack to help debugging.  */
      *r_nks_app_id = NKS_APP_SIGG;
      *r_pwid = xtoi_2 (pwidstr+7);
      desc = (new_mode
              ? "|N|Please enter a new PIN for the given SIGG pwid"
              : "||Please enter the PIN for the given SIGG pwid" );
    }
  else if (!strncmp (pwidstr, "ESIGN.0x", 8)
           && hexdigitp (pwidstr+8) && hexdigitp (pwidstr+9) && !pwidstr[10])
    {
      /* Hack to help debugging.  */
      *r_nks_app_id = NKS_APP_ESIGN;
      *r_pwid = xtoi_2 (pwidstr+8);
      desc = (new_mode
              ? "|N|Please enter a new PIN for the given ESIGN pwid"
              : "||Please enter the PIN for the given ESIGN pwid" );
    }
  else if (!strncmp (pwidstr, "IDLM.0x", 7)
           && hexdigitp (pwidstr+7) && hexdigitp (pwidstr+8) && !pwidstr[9])
    {
      /* Hack to help debugging.  */
      *r_nks_app_id = NKS_APP_IDLM;
      *r_pwid = xtoi_2 (pwidstr+7);
      desc = (new_mode
              ? "|N|Please enter a new PIN for the given IDLM pwid"
              : "||Please enter the PIN for the given IDLM pwid" );
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
  int remaining;
  char *prompt;

  (void)ctrl;

  /* The minimum length is enforced by TCOS, the maximum length is
     just a reasonable value.  */
  memset (&pininfo, 0, sizeof pininfo);
  pininfo.minlen = 6;
  pininfo.maxlen = 16;

  newdesc = parse_pwidstr (app, pwidstr, 1, &nks_app_id, &pwid);
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
      if (app->appversion == 15)
        {
          memset (oldpin, '0', 5);
          oldpinlen = 5;  /* 5 ascii zeroes.  */
        }
      else
        {
          oldpinlen = 6;  /* 6 binary Nuls.  */
        }
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
          desc = parse_pwidstr (app, altpwidstr, 0, &dummy1, &dummy2);
          remaining = iso7816_verify_status (app_get_slot (app), dummy2);
        }
      else
        {
          /* Regular change mode:  Ask for the old PIN.  */
          desc = parse_pwidstr (app, pwidstr, 0, &dummy1, &dummy2);
          remaining = iso7816_verify_status (app_get_slot (app), pwid);
        }

      if (remaining < 0)
        remaining = -1; /* We don't care about the concrete error.  */
      if (remaining < 3)
        {
          if (remaining >= 0)
            log_info ("nks: PIN has %d attempts left\n", remaining);
        }

      prompt = make_prompt (app, remaining, desc, NULL);
      err = pincb (pincb_arg, prompt, &oldpin);
      xfree (prompt);
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


  prompt = make_prompt (app, -1, newdesc, NULL);
  err = pincb (pincb_arg, prompt, &newpin);
  xfree (prompt);
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

  desc = parse_pwidstr (app, pwidstr, 0, &nks_app_id, &pwid);
  if (!desc)
    return gpg_error (GPG_ERR_INV_ID);

  err = switch_application (app, nks_app_id);
  if (err)
    return err;

  return verify_pin (app, pwid, desc, pincb, pincb_arg);
}


/* Process the various keygrip based info requests.  */
static gpg_error_t
do_with_keygrip (app_t app, ctrl_t ctrl, int action,
                 const char *want_keygripstr, int capability)
{
  gpg_error_t err;
  char keygripstr[2*KEYGRIP_LEN+1];
  char *serialno = NULL;
  int data = 0;
  int idx = -1;

  /* First a quick check for valid parameters.  */
  switch (action)
    {
    case KEYGRIP_ACTION_LOOKUP:
      if (!want_keygripstr)
        {
          return gpg_error (GPG_ERR_NOT_FOUND);
        }
      break;
    case KEYGRIP_ACTION_SEND_DATA:
      data = 1;
      break;
    case KEYGRIP_ACTION_WRITE_STATUS:
      break;
    default:
      return gpg_error (GPG_ERR_INV_ARG);
    }

  /* Allocate the S/N string if needed.  */
  if (action != KEYGRIP_ACTION_LOOKUP)
    {
      serialno = app_get_serialno (app);
      if (!serialno)
        return gpg_error_from_syserror ();
    }

  while (1)
    {
      err = iterate_over_filelist (app, want_keygripstr, capability,
                                   keygripstr, &idx);
      if (err)
        break;

      if (want_keygripstr)
        {
          if (!err)
            break;
        }
      else
        {
          char idbuf[20];
          char usagebuf[5];

          snprintf (idbuf, sizeof idbuf, "NKS-%s.%04X",
                    get_nks_tag (app, app->app_local->active_nks_app),
                    filelist[idx].fid);
          set_usage_string (usagebuf, idx);
          send_keyinfo (ctrl, data, keygripstr, serialno, idbuf, usagebuf);
        }
    }

  xfree (serialno);
  return err;
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
   *          15 := TCOS Signature Card (bb,cc is the ROM mask version)
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

  if (app->app_local->only_idlm)
    return 0;  /* No switching at all */
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
      && app->appversion >= 3
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
  int is_idlm = 0;

  rc = iso7816_select_application (slot, aid_nks, sizeof aid_nks, 0);
  if (rc)
    {
      is_idlm = 1;
      rc = iso7816_select_application (slot, aid_idlm, sizeof aid_idlm, 0);
    }
  if (!rc)
    {
      app->apptype = APPTYPE_NKS;

      app->app_local = xtrycalloc (1, sizeof *app->app_local);
      if (!app->app_local)
        {
          rc = gpg_error (gpg_err_code_from_errno (errno));
          goto leave;
        }

      app->appversion = get_nks_version (slot);
      app->app_local->only_idlm = is_idlm;
      if (is_idlm) /* Set it once, there won't be any switching.  */
        app->app_local->active_nks_app = NKS_APP_IDLM;

      if (opt.verbose)
        {
          log_info ("Detected NKS version: %d\n", app->appversion);
          if (is_idlm)
            log_info ("Using only the IDLM application\n");
        }

      if (app->appversion == 15)
        app->app_local->qes_app_id = NKS_APP_ESIGN;
      else
        app->app_local->qes_app_id = NKS_APP_SIGG;

      app->fnc.deinit = do_deinit;
      app->fnc.learn_status = do_learn_status;
      app->fnc.readcert = do_readcert;
      app->fnc.readkey = do_readkey;
      app->fnc.getattr = do_getattr;
      app->fnc.setattr = NULL;
      app->fnc.writecert = do_writecert;
      app->fnc.writekey = do_writekey;
      app->fnc.genkey = NULL;
      app->fnc.sign = do_sign;
      app->fnc.auth = NULL;
      app->fnc.decipher = do_decipher;
      app->fnc.change_pin = do_change_pin;
      app->fnc.check_pin = do_check_pin;
      app->fnc.with_keygrip = do_with_keygrip;
   }

 leave:
  if (rc)
    do_deinit (app);
  return rc;
}
