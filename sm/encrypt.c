/* encrypt.c - Encrypt a message
 * Copyright (C) 2001, 2003, 2004, 2007, 2008,
 *               2010 Free Software Foundation, Inc.
 * Copyright (C) 2001-2019 Werner Koch
 * Copyright (C) 2015-2020 g10 Code GmbH
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>

#include "keydb.h"
#include "../common/i18n.h"
#include "../common/compliance.h"


struct dek_s {
  const char *algoid;
  int algo;
  gcry_cipher_hd_t chd;
  char key[32];
  int keylen;
  char iv[32];
  int ivlen;
};
typedef struct dek_s *DEK;


/* Callback parameters for the encryption.  */
struct encrypt_cb_parm_s
{
  estream_t fp;
  DEK dek;
  int eof_seen;
  int ready;
  int readerror;
  int bufsize;
  unsigned char *buffer;
  int buflen;
};





/* Initialize the data encryption key (session key). */
static int
init_dek (DEK dek)
{
  int rc=0, mode, i;

  dek->algo = gcry_cipher_map_name (dek->algoid);
  mode = gcry_cipher_mode_from_oid (dek->algoid);
  if (!dek->algo || !mode)
    {
      log_error ("unsupported algorithm '%s'\n", dek->algoid);
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    }

  /* Extra check for algorithms we consider to be too weak for
     encryption, although we support them for decryption.  Note that
     there is another check below discriminating on the key length. */
  switch (dek->algo)
    {
    case GCRY_CIPHER_DES:
    case GCRY_CIPHER_RFC2268_40:
      log_error ("cipher algorithm '%s' not allowed: too weak\n",
                 gnupg_cipher_algo_name (dek->algo));
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    default:
      break;
    }

  dek->keylen = gcry_cipher_get_algo_keylen (dek->algo);
  if (!dek->keylen || dek->keylen > sizeof (dek->key))
    return gpg_error (GPG_ERR_BUG);

  dek->ivlen = gcry_cipher_get_algo_blklen (dek->algo);
  if (!dek->ivlen || dek->ivlen > sizeof (dek->iv))
    return gpg_error (GPG_ERR_BUG);

  /* Make sure we don't use weak keys. */
  if (dek->keylen < 100/8)
    {
      log_error ("key length of '%s' too small\n", dek->algoid);
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    }

  rc = gcry_cipher_open (&dek->chd, dek->algo, mode, GCRY_CIPHER_SECURE);
  if (rc)
    {
      log_error ("failed to create cipher context: %s\n", gpg_strerror (rc));
      return rc;
    }

  for (i=0; i < 8; i++)
    {
      gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM );
      rc = gcry_cipher_setkey (dek->chd, dek->key, dek->keylen);
      if (gpg_err_code (rc) != GPG_ERR_WEAK_KEY)
        break;
      log_info(_("weak key created - retrying\n") );
    }
  if (rc)
    {
      log_error ("failed to set the key: %s\n", gpg_strerror (rc));
      gcry_cipher_close (dek->chd);
      dek->chd = NULL;
      return rc;
    }

  gcry_create_nonce (dek->iv, dek->ivlen);
  rc = gcry_cipher_setiv (dek->chd, dek->iv, dek->ivlen);
  if (rc)
    {
      log_error ("failed to set the IV: %s\n", gpg_strerror (rc));
      gcry_cipher_close (dek->chd);
      dek->chd = NULL;
      return rc;
    }

  return 0;
}

/* Encrypt an RSA session key.  */
static int
encode_session_key (DEK dek, gcry_sexp_t * r_data)
{
  gcry_sexp_t data;
  char *p;
  int rc;

  p = xtrymalloc (64 + 2 * dek->keylen);
  if (!p)
    return gpg_error_from_syserror ();
  strcpy (p, "(data\n (flags pkcs1)\n (value #");
  bin2hex (dek->key, dek->keylen, p + strlen (p));
  strcat (p, "#))\n");
  rc = gcry_sexp_sscan (&data, NULL, p, strlen (p));
  xfree (p);
  *r_data = data;
  return rc;
}


/* Encrypt DEK using ECDH.  S_PKEY is the public key.  On success the
 * result is stored at R_ENCVAL.  Example of a public key:
 *
 *   (public-key (ecc (curve "1.3.132.0.34") (q #04B0[...]B8#)))
 *
 */
static gpg_error_t
ecdh_encrypt (DEK dek, gcry_sexp_t s_pkey, gcry_sexp_t *r_encval)
{
  gpg_error_t err;
  gcry_sexp_t l1;
  char *curvebuf = NULL;
  const char *curve;
  unsigned int curvebits;
  const char *encr_algo_str;
  const char *wrap_algo_str;
  int hash_algo, cipher_algo;
  unsigned int keylen, hashlen;
  unsigned char key[32];
  gcry_sexp_t s_data = NULL;
  gcry_sexp_t s_encr = NULL;
  gcry_buffer_t ioarray[2] = { {0}, {0} };
  unsigned char *secret;  /* Alias for ioarray[0].  */
  unsigned int secretlen;
  unsigned char *pubkey;  /* Alias for ioarray[1].  */
  unsigned int pubkeylen;
  gcry_cipher_hd_t cipher_hd = NULL;
  unsigned char *result = NULL;
  unsigned int resultlen;

  *r_encval = NULL;

  /* Figure out the encryption and wrap algo OIDs.  */
  /* Get the curve name if any,  */
  l1 = gcry_sexp_find_token (s_pkey, "curve", 0);
  if (l1)
    {
      curvebuf = gcry_sexp_nth_string (l1, 1);
      gcry_sexp_release (l1);
    }
  if (!curvebuf)
    {
      err = gpg_error (GPG_ERR_INV_CURVE);
      log_error ("%s: invalid public key: no curve\n", __func__);
      goto leave;
    }

  /* We need to use our OpenPGP mapping to turn a curve name into its
   * canonical numerical OID.  We also use this to get the size of the
   * curve which we need to figure out a suitable hash algo.  We
   * should have a Libgcrypt function to do this; see bug report #4926.  */
  curve = openpgp_curve_to_oid (curvebuf, &curvebits, NULL);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      log_error ("%s: invalid public key: %s\n", __func__, gpg_strerror (err));
      goto leave;
    }
  xfree (curvebuf);
  curvebuf = NULL;

  /* Our mapping matches the recommended algorithms from RFC-5753 but
   * not supporing the short curves which would require 3DES.  */
  if (curvebits < 255)
    {
      err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      log_error ("%s: curve '%s' is not supported\n", __func__, curve);
      goto leave;
    }
  else if (curvebits <= 256)
    {
      /* dhSinglePass-stdDH-sha256kdf-scheme */
      encr_algo_str = "1.3.132.1.11.1";
      wrap_algo_str = "2.16.840.1.101.3.4.1.5";
      hash_algo     = GCRY_MD_SHA256;
      hashlen       = 32;
      cipher_algo   = GCRY_CIPHER_AES128;
      keylen        = 16;
    }
  else if (curvebits <= 384)
    {
      /* dhSinglePass-stdDH-sha384kdf-scheme */
      encr_algo_str = "1.3.132.1.11.2";
      wrap_algo_str = "2.16.840.1.101.3.4.1.25";
      hash_algo     = GCRY_MD_SHA384;
      hashlen       = 48;
      cipher_algo   = GCRY_CIPHER_AES256;
      keylen        = 24;
    }
  else
    {
      /* dhSinglePass-stdDH-sha512kdf-scheme*/
      encr_algo_str = "1.3.132.1.11.3";
      wrap_algo_str = "2.16.840.1.101.3.4.1.45";
      hash_algo     = GCRY_MD_SHA512;
      hashlen       = 64;
      cipher_algo   = GCRY_CIPHER_AES256;
      keylen        = 32;
    }


  /* Create a secret and an ephemeral key.  */
  {
    char *k;
    k = gcry_random_bytes_secure ((curvebits+7)/8, GCRY_STRONG_RANDOM);
    if (DBG_CRYPTO)
      log_printhex (k, (curvebits+7)/8, "ephm. k .:");
    err = gcry_sexp_build (&s_data, NULL, "%b", (int)(curvebits+7)/8, k);
    xfree (k);
  }
  if (err)
    {
      log_error ("%s: error building ephemeral secret: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }

  err = gcry_pk_encrypt (&s_encr, s_data, s_pkey);
  if (err)
    {
      log_error ("%s: error encrypting ephemeral secret: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }
  err = gcry_sexp_extract_param (s_encr, NULL, "&se",
                                 &ioarray+0, ioarray+1, NULL);
  if (err)
    {
      log_error ("%s: error extracting ephemeral key and secret: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }
  secret    = ioarray[0].data;
  secretlen = ioarray[0].len;
  pubkey    = ioarray[1].data;
  pubkeylen = ioarray[1].len;

  if (DBG_CRYPTO)
    {
      log_printhex (pubkey, pubkeylen, "pubkey ..:");
      log_printhex (secret, secretlen, "secret ..:");
    }

  /* Extract X coordinate from SECRET.  */
  if (secretlen < 5)  /* 5 because N could be reduced to (n-1)/2.  */
    err = gpg_error (GPG_ERR_BAD_DATA);
  else if (*secret == 0x04)
    {
      secretlen--;
      memmove (secret, secret+1, secretlen);
      if ((secretlen & 1))
        {
          err = gpg_error (GPG_ERR_BAD_DATA);
          goto leave;
        }
      secretlen /= 2;
    }
  else if (*secret == 0x40 || *secret == 0x41)
    {
      secretlen--;
      memmove (secret, secret+1, secretlen);
    }
  else
    err = gpg_error (GPG_ERR_BAD_DATA);
  if (err)
    goto leave;

  if (DBG_CRYPTO)
    log_printhex (secret, secretlen, "ECDH X ..:");

  /* Derive a KEK (key wrapping key) using MESSAGE and SECRET_X.
   * According to SEC1 3.6.1 we should check that
   *   SECRETLEN + UKMLEN + 4 < maxhashlen
   * However, we have no practical limit on the hash length and thus
   * there is no point in checking this.  The second check that
   *   KEYLEN < hashlen*(2^32-1)
   * is obviously also not needed.  Because with our allowed
   * parameters KEYLEN is always less or equal to HASHLEN so that we
   * do not need to iterate at all.
   */
  log_assert (gcry_md_get_algo_dlen (hash_algo) == hashlen);
  {
    gcry_md_hd_t hash_hd;
    err = gcry_md_open (&hash_hd, hash_algo, 0);
    if (err)
      goto leave;
    gcry_md_write(hash_hd, secret, secretlen);
    gcry_md_write(hash_hd, "\x00\x00\x00\x01", 4);  /* counter */
    err = hash_ecc_cms_shared_info (hash_hd, wrap_algo_str, keylen, NULL, 0);
    gcry_md_final (hash_hd);
    log_assert (keylen <= sizeof key && keylen <= hashlen);
    memcpy (key, gcry_md_read (hash_hd, 0), keylen);
    gcry_md_close (hash_hd);
    if (err)
      goto leave;
  }

  if (DBG_CRYPTO)
    log_printhex (key, keylen, "KEK .....:");

  /* Wrap the key.  */
  if ((dek->keylen % 8) || dek->keylen < 16)
    {
      log_error ("%s: can't use a session key of %u bytes\n",
                 __func__, dek->keylen);
      err = gpg_error (GPG_ERR_BAD_DATA);
      goto leave;
    }

  resultlen = dek->keylen + 8;
  result = xtrymalloc_secure (resultlen);
  if (!result)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_open (&cipher_hd, cipher_algo, GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    {
      log_error ("%s: failed to initialize AESWRAP: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }

  err = gcry_cipher_setkey (cipher_hd, key, keylen);
  wipememory (key, sizeof key);
  if (err)
    {
      log_error ("%s: failed in gcry_cipher_setkey: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }

  err = gcry_cipher_encrypt (cipher_hd, result, resultlen,
                             dek->key, dek->keylen);
  if (err)
    {
      log_error ("%s: failed in gcry_cipher_encrypt: %s\n",
                 __func__, gpg_strerror (err));
      goto leave;
    }

  if (DBG_CRYPTO)
    log_printhex (result, resultlen, "w(CEK) ..:");

  err = gcry_sexp_build (r_encval, NULL,
                         "(enc-val(ecdh(e%b)(s%b)(encr-algo%s)(wrap-algo%s)))",
                         (int)pubkeylen, pubkey,
                         (int)resultlen, result,
                         encr_algo_str,
                         wrap_algo_str,
                         NULL);
  if (err)
    log_error ("%s: failed building final S-exp: %s\n",
               __func__, gpg_strerror (err));

 leave:
  gcry_cipher_close (cipher_hd);
  wipememory (key, sizeof key);
  xfree (result);
  xfree (ioarray[0].data);
  xfree (ioarray[1].data);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_encr);
  xfree (curvebuf);
  return err;
}


/* Encrypt the DEK under the key contained in CERT and return it as a
 * canonical S-expressions at ENCVAL. PK_ALGO is the public key
 * algorithm which the caller has already retrieved from CERT.  */
static int
encrypt_dek (const DEK dek, ksba_cert_t cert, int pk_algo,
             unsigned char **encval)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc;
  ksba_sexp_t buf;
  size_t len;

  *encval = NULL;

  /* get the key from the cert */
  buf = ksba_cert_get_public_key (cert);
  if (!buf)
    {
      log_error ("no public key for recipient\n");
      return gpg_error (GPG_ERR_NO_PUBKEY);
    }
  len = gcry_sexp_canon_len (buf, 0, NULL, NULL);
  if (!len)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      return gpg_error (GPG_ERR_BUG);
    }
  rc = gcry_sexp_sscan (&s_pkey, NULL, (char*)buf, len);
  xfree (buf); buf = NULL;
  if (rc)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  if (DBG_CRYPTO)
    {
      log_printsexp (" pubkey:", s_pkey);
      log_printhex (dek->key, dek->keylen, "CEK .....:");
    }

  /* Put the encoded cleartext into a simple list. */
  s_data = NULL; /* (avoid compiler warning) */
  if (pk_algo == GCRY_PK_ECC)
    {
      rc = ecdh_encrypt (dek, s_pkey, &s_ciph);
    }
  else
    {
      rc = encode_session_key (dek, &s_data);
      if (rc)
        {
          log_error ("encode_session_key failed: %s\n", gpg_strerror (rc));
          return rc;
        }
      if (DBG_CRYPTO)
        log_printsexp ("   data:", s_data);

      /* pass it to libgcrypt */
      rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
    }
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (DBG_CRYPTO)
    log_printsexp ("enc-val:", s_ciph);

  /* Reformat it. */
  if (!rc)
    {
      rc = make_canon_sexp (s_ciph, encval, NULL);
      gcry_sexp_release (s_ciph);
    }
  return rc;
}



/* do the actual encryption */
static int
encrypt_cb (void *cb_value, char *buffer, size_t count, size_t *nread)
{
  struct encrypt_cb_parm_s *parm = cb_value;
  int blklen = parm->dek->ivlen;
  unsigned char *p;
  size_t n;

  *nread = 0;
  if (!buffer)
    return -1; /* not supported */

  if (parm->ready)
    return -1;

  if (count < blklen)
    BUG ();

  if (!parm->eof_seen)
    { /* fillup the buffer */
      p = parm->buffer;
      for (n=parm->buflen; n < parm->bufsize; n++)
        {
          int c = es_getc (parm->fp);
          if (c == EOF)
            {
              if (es_ferror (parm->fp))
                {
                  parm->readerror = errno;
                  return -1;
                }
              parm->eof_seen = 1;
              break;
            }
          p[n] = c;
        }
      parm->buflen = n;
    }

  n = parm->buflen < count? parm->buflen : count;
  n = n/blklen * blklen;
  if (n)
    { /* encrypt the stuff */
      gcry_cipher_encrypt (parm->dek->chd, buffer, n, parm->buffer, n);
      *nread = n;
      /* Who cares about cycles, take the easy way and shift the buffer */
      parm->buflen -= n;
      memmove (parm->buffer, parm->buffer+n, parm->buflen);
    }
  else if (parm->eof_seen)
    { /* no complete block but eof: add padding */
      /* fixme: we should try to do this also in the above code path */
      int i, npad = blklen - (parm->buflen % blklen);
      p = parm->buffer;
      for (n=parm->buflen, i=0; n < parm->bufsize && i < npad; n++, i++)
        p[n] = npad;
      gcry_cipher_encrypt (parm->dek->chd, buffer, n, parm->buffer, n);
      *nread = n;
      parm->ready = 1;
    }

  return 0;
}




/* Perform an encrypt operation.

   Encrypt the data received on DATA-FD and write it to OUT_FP.  The
   recipients are take from the certificate given in recplist; if this
   is NULL it will be encrypted for a default recipient */
int
gpgsm_encrypt (ctrl_t ctrl, certlist_t recplist, int data_fd, estream_t out_fp)
{
  gpg_error_t err = 0;
  gnupg_ksba_io_t b64writer = NULL;
  ksba_writer_t writer;
  ksba_reader_t reader = NULL;
  ksba_cms_t cms = NULL;
  ksba_stop_reason_t stopreason;
  KEYDB_HANDLE kh = NULL;
  struct encrypt_cb_parm_s encparm;
  DEK dek = NULL;
  int recpno;
  estream_t data_fp = NULL;
  certlist_t cl;
  int count;
  int compliant;

  memset (&encparm, 0, sizeof encparm);

  audit_set_type (ctrl->audit, AUDIT_TYPE_ENCRYPT);

  /* Check that the certificate list is not empty and that at least
     one certificate is not flagged as encrypt_to; i.e. is a real
     recipient. */
  for (cl = recplist; cl; cl = cl->next)
    if (!cl->is_encrypt_to)
      break;
  if (!cl)
    {
      log_error(_("no valid recipients given\n"));
      gpgsm_status (ctrl, STATUS_NO_RECP, "0");
      audit_log_i (ctrl->audit, AUDIT_GOT_RECIPIENTS, 0);
      err = gpg_error (GPG_ERR_NO_PUBKEY);
      goto leave;
    }

  for (count = 0, cl = recplist; cl; cl = cl->next)
    count++;
  audit_log_i (ctrl->audit, AUDIT_GOT_RECIPIENTS, count);

  kh = keydb_new ();
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* Fixme:  We should use the unlocked version of the es functions.  */
  data_fp = es_fdopen_nc (data_fd, "rb");
  if (!data_fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("fdopen() failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = ksba_reader_new (&reader);
  if (!err)
    err = ksba_reader_set_cb (reader, encrypt_cb, &encparm);
  if (err)
    goto leave;

  encparm.fp = data_fp;

  ctrl->pem_name = "ENCRYPTED MESSAGE";
  err = gnupg_ksba_create_writer
    (&b64writer, ((ctrl->create_pem? GNUPG_KSBA_IO_PEM : 0)
                  | (ctrl->create_base64? GNUPG_KSBA_IO_BASE64 : 0)),
     ctrl->pem_name, out_fp, &writer);
  if (err)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (err));
      goto leave;
    }

  gnupg_ksba_set_progress_cb (b64writer, gpgsm_progress_cb, ctrl);
  if (ctrl->input_size_hint)
    gnupg_ksba_set_total (b64writer, ctrl->input_size_hint);

  err = ksba_cms_new (&cms);
  if (err)
    goto leave;

  err = ksba_cms_set_reader_writer (cms, reader, writer);
  if (err)
    {
      log_error ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  audit_log (ctrl->audit, AUDIT_GOT_DATA);

  /* We are going to create enveloped data with uninterpreted data as
     inner content */
  err = ksba_cms_set_content_type (cms, 0, KSBA_CT_ENVELOPED_DATA);
  if (!err)
    err = ksba_cms_set_content_type (cms, 1, KSBA_CT_DATA);
  if (err)
    {
      log_error ("ksba_cms_set_content_type failed: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  /* Check compliance.  */
  if (!gnupg_cipher_is_allowed
      (opt.compliance, 1, gcry_cipher_map_name (opt.def_cipher_algoid),
       gcry_cipher_mode_from_oid (opt.def_cipher_algoid)))
    {
      log_error (_("cipher algorithm '%s' may not be used in %s mode\n"),
		 opt.def_cipher_algoid,
		 gnupg_compliance_option_string (opt.compliance));
      err = gpg_error (GPG_ERR_CIPHER_ALGO);
      goto leave;
    }

  if (!gnupg_rng_is_compliant (opt.compliance))
    {
      err = gpg_error (GPG_ERR_FORBIDDEN);
      log_error (_("%s is not compliant with %s mode\n"),
                 "RNG",
                 gnupg_compliance_option_string (opt.compliance));
      gpgsm_status_with_error (ctrl, STATUS_ERROR,
                               "random-compliance", err);
      goto leave;
    }

  /* Create a session key */
  dek = xtrycalloc_secure (1, sizeof *dek);
  if (!dek)
    err = gpg_error_from_syserror ();
  else
    {
      dek->algoid = opt.def_cipher_algoid;
      err = init_dek (dek);
    }
  if (err)
    {
      log_error ("failed to create the session key: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  err = ksba_cms_set_content_enc_algo (cms, dek->algoid, dek->iv, dek->ivlen);
  if (err)
    {
      log_error ("ksba_cms_set_content_enc_algo failed: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  encparm.dek = dek;
  /* Use a ~8k (AES) or ~4k (3DES) buffer */
  encparm.bufsize = 500 * dek->ivlen;
  encparm.buffer = xtrymalloc (encparm.bufsize);
  if (!encparm.buffer)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  audit_log_s (ctrl->audit, AUDIT_SESSION_KEY, dek->algoid);

  compliant = gnupg_cipher_is_compliant (CO_DE_VS, dek->algo,
                                         GCRY_CIPHER_MODE_CBC);

  /* Gather certificates of recipients, encrypt the session key for
     each and store them in the CMS object */
  for (recpno = 0, cl = recplist; cl; recpno++, cl = cl->next)
    {
      unsigned char *encval;
      unsigned int nbits;
      int pk_algo;
      char *curve = NULL;

      /* Check compliance.  */
      pk_algo = gpgsm_get_key_algo_info (cl->cert, &nbits, &curve);
      if (!gnupg_pk_is_compliant (opt.compliance, pk_algo, 0,
                                  NULL, nbits, curve))
        {
          char  kidstr[10+1];

          snprintf (kidstr, sizeof kidstr, "0x%08lX",
                    gpgsm_get_short_fingerprint (cl->cert, NULL));
          log_info (_("WARNING: key %s is not suitable for encryption"
                      " in %s mode\n"),
                    kidstr,
                    gnupg_compliance_option_string (opt.compliance));
        }

      /* Fixme: When adding ECC we need to provide the curvename and
       * the key to gnupg_pk_is_compliant.  */
      if (compliant
          && !gnupg_pk_is_compliant (CO_DE_VS, pk_algo, 0, NULL, nbits, curve))
        compliant = 0;

      xfree (curve);
      curve = NULL;

      err = encrypt_dek (dek, cl->cert, pk_algo, &encval);
      if (err)
        {
          audit_log_cert (ctrl->audit, AUDIT_ENCRYPTED_TO, cl->cert, err);
          log_error ("encryption failed for recipient no. %d: %s\n",
                     recpno, gpg_strerror (err));
          goto leave;
        }

      err = ksba_cms_add_recipient (cms, cl->cert);
      if (err)
        {
          audit_log_cert (ctrl->audit, AUDIT_ENCRYPTED_TO, cl->cert, err);
          log_error ("ksba_cms_add_recipient failed: %s\n",
                     gpg_strerror (err));
          xfree (encval);
          goto leave;
        }

      err = ksba_cms_set_enc_val (cms, recpno, encval);
      xfree (encval);
      audit_log_cert (ctrl->audit, AUDIT_ENCRYPTED_TO, cl->cert, err);
      if (err)
        {
          log_error ("ksba_cms_set_enc_val failed: %s\n",
                     gpg_strerror (err));
          goto leave;
        }
    }

  if (compliant && gnupg_gcrypt_is_compliant (CO_DE_VS))
    gpgsm_status (ctrl, STATUS_ENCRYPTION_COMPLIANCE_MODE,
                  gnupg_status_compliance_flag (CO_DE_VS));
  else if (opt.require_compliance
           && opt.compliance == CO_DE_VS)
    {
      log_error (_("operation forced to fail due to"
                   " unfulfilled compliance rules\n"));
      gpgsm_errors_seen = 1;
      err = gpg_error (GPG_ERR_FORBIDDEN);
      goto leave;
    }

  /* Main control loop for encryption. */
  recpno = 0;
  do
    {
      err = ksba_cms_build (cms, &stopreason);
      if (err)
        {
          log_error ("creating CMS object failed: %s\n", gpg_strerror (err));
          goto leave;
        }
    }
  while (stopreason != KSBA_SR_READY);

  if (encparm.readerror)
    {
      log_error ("error reading input: %s\n", strerror (encparm.readerror));
      err = gpg_error (gpg_err_code_from_errno (encparm.readerror));
      goto leave;
    }


  err = gnupg_ksba_finish_writer (b64writer);
  if (err)
    {
      log_error ("write failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  audit_log (ctrl->audit, AUDIT_ENCRYPTION_DONE);
  if (!opt.quiet)
    log_info ("encrypted data created\n");

 leave:
  ksba_cms_release (cms);
  gnupg_ksba_destroy_writer (b64writer);
  ksba_reader_release (reader);
  keydb_release (kh);
  xfree (dek);
  es_fclose (data_fp);
  xfree (encparm.buffer);
  return err;
}
