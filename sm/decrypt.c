/* decrypt.c - Decrypt a message
 * Copyright (C) 2001, 2003, 2010 Free Software Foundation, Inc.
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
#include "../common/tlv.h"
#include "../common/compliance.h"

struct decrypt_filter_parm_s
{
  int algo;
  int mode;
  int blklen;
  gcry_cipher_hd_t hd;
  char iv[16];
  size_t ivlen;
  int any_data;  /* did we push anything through the filter at all? */
  unsigned char lastblock[16];  /* to strip the padding we have to
                                   keep this one */
  char helpblock[16];  /* needed because there is no block buffering in
                          libgcrypt (yet) */
  int  helpblocklen;
};


/* Return the hash algorithm's algo id from its name given in the
 * non-null termnated string in (buffer,buflen).  Returns 0 on failure
 * or if the algo is not known.  */
static char *
string_from_gcry_buffer (gcry_buffer_t *buffer)
{
  char *string;

  string = xtrymalloc (buffer->len + 1);
  if (!string)
    return NULL;
  memcpy (string, buffer->data, buffer->len);
  string[buffer->len] = 0;
  return string;
}


/* Helper to construct and hash the
 *  ECC-CMS-SharedInfo ::= SEQUENCE {
 *      keyInfo         AlgorithmIdentifier,
 *      entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
 *      suppPubInfo [2] EXPLICIT OCTET STRING  }
 * as described in RFC-5753, 7.2.  */
gpg_error_t
hash_ecc_cms_shared_info (gcry_md_hd_t hash_hd, const char *wrap_algo_str,
                          unsigned int keylen,
                          const void *ukm, unsigned int ukmlen)
{
  gpg_error_t err;
  void *p;
  unsigned char *oid;
  size_t n, oidlen, toidlen, tkeyinfo, tukmlen, tsupppubinfo;
  unsigned char keylenbuf[6];
  membuf_t mb = MEMBUF_ZERO;

  err = ksba_oid_from_str (wrap_algo_str, &oid, &oidlen);
  if (err)
    return err;
  toidlen = get_tlv_length (CLASS_UNIVERSAL, TAG_OBJECT_ID, 0, oidlen);
  tkeyinfo = get_tlv_length (CLASS_UNIVERSAL, TAG_SEQUENCE, 1, toidlen);

  tukmlen = ukm? get_tlv_length (CLASS_CONTEXT, 0, 1, ukmlen) : 0;

  keylen *= 8;
  keylenbuf[0] = TAG_OCTET_STRING;
  keylenbuf[1] = 4;
  keylenbuf[2] = (keylen >> 24);
  keylenbuf[3] = (keylen >> 16);
  keylenbuf[4] = (keylen >> 8);
  keylenbuf[5] = keylen;

  tsupppubinfo = get_tlv_length (CLASS_CONTEXT, 2, 1, sizeof keylenbuf);

  put_tlv_to_membuf (&mb, CLASS_UNIVERSAL, TAG_SEQUENCE, 1,
                     tkeyinfo + tukmlen + tsupppubinfo);
  put_tlv_to_membuf (&mb, CLASS_UNIVERSAL, TAG_SEQUENCE, 1,
                     toidlen);
  put_tlv_to_membuf (&mb, CLASS_UNIVERSAL, TAG_OBJECT_ID, 0, oidlen);
  put_membuf (&mb, oid, oidlen);
  ksba_free (oid);

  if (ukm)
    {
      put_tlv_to_membuf (&mb, CLASS_CONTEXT, 0, 1, ukmlen);
      put_membuf (&mb, ukm, ukmlen);
    }

  put_tlv_to_membuf (&mb, CLASS_CONTEXT, 2, 1, sizeof keylenbuf);
  put_membuf (&mb, keylenbuf, sizeof keylenbuf);

  p = get_membuf (&mb, &n);
  if (!p)
    return gpg_error_from_syserror ();

  gcry_md_write (hash_hd, p, n);
  xfree (p);
  return 0;
}


/* This function will modify SECRET.  NBITS is the size of the curve
 * which which we took from the certificate.  */
static gpg_error_t
ecdh_decrypt (unsigned char *secret, size_t secretlen,
              unsigned int nbits, gcry_sexp_t enc_val,
              unsigned char **r_result, unsigned int *r_resultlen)
{
  gpg_error_t err;
  gcry_buffer_t ioarray[4] = { {0}, {0}, {0}, {0} };
  char *encr_algo_str = NULL;
  char *wrap_algo_str = NULL;
  int hash_algo, cipher_algo;
  const unsigned char *ukm;  /* Alias for ioarray[2].  */
  unsigned int ukmlen;
  const unsigned char *data;  /* Alias for ioarray[3].  */
  unsigned int datalen;
  unsigned int keylen, hashlen;
  unsigned char key[32];
  gcry_cipher_hd_t cipher_hd = NULL;
  unsigned char *result = NULL;
  unsigned int resultlen;

  *r_resultlen = 0;
  *r_result = NULL;

  /* Extract X from SECRET; this is the actual secret.  Unless a
   * smartcard diretcly returns X, it must be in the format of:
   *
   *   04 || X || Y
   *   40 || X
   *   41 || X
   */
  if (secretlen < 2)
    return gpg_error (GPG_ERR_BAD_DATA);
  if (secretlen == (nbits+7)/8)
    ; /* Matches curve length - this is already the X coordinate.  */
  else if (*secret == 0x04)
    {
      secretlen--;
      memmove (secret, secret+1, secretlen);
      if ((secretlen & 1))
        return gpg_error (GPG_ERR_BAD_DATA);
      secretlen /= 2;
    }
  else if (*secret == 0x40 || *secret == 0x41)
    {
      secretlen--;
      memmove (secret, secret+1, secretlen);
    }
  else
    return gpg_error (GPG_ERR_BAD_DATA);
  if (!secretlen)
    return gpg_error (GPG_ERR_BAD_DATA);

  if (DBG_CRYPTO)
    log_printhex (secret, secretlen, "ECDH X ..:");

  /* We have now the shared secret bytes in (SECRET,SECRETLEN).  Now
   * we will compute the KEK using a value dervied from the secret
   * bytes. */
  err = gcry_sexp_extract_param (enc_val, "enc-val",
                                 "&'encr-algo''wrap-algo''ukm'?s",
                                 ioarray+0, ioarray+1,
                                 ioarray+2, ioarray+3, NULL);
  if (err)
    {
      log_error ("extracting ECDH parameter failed: %s\n", gpg_strerror (err));
      goto leave;
    }
  encr_algo_str = string_from_gcry_buffer (ioarray);
  if (!encr_algo_str)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  wrap_algo_str = string_from_gcry_buffer (ioarray+1);
  if (!wrap_algo_str)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ukm = ioarray[2].data;
  ukmlen = ioarray[2].len;
  data = ioarray[3].data;
  datalen = ioarray[3].len;

  /* Check parameters.  */
  if (DBG_CRYPTO)
    {
      log_debug ("encr_algo: %s\n", encr_algo_str);
      log_debug ("wrap_algo: %s\n", wrap_algo_str);
      log_printhex (ukm, ukmlen, "ukm .....:");
      log_printhex (data, datalen, "data ....:");
    }

  if (!strcmp (encr_algo_str, "1.3.132.1.11.1"))
    {
      /* dhSinglePass-stdDH-sha256kdf-scheme */
      hash_algo = GCRY_MD_SHA256;
      hashlen = 32;
    }
  else if (!strcmp (encr_algo_str, "1.3.132.1.11.2"))
    {
      /* dhSinglePass-stdDH-sha384kdf-scheme */
      hash_algo = GCRY_MD_SHA384;
      hashlen = 48;
    }
  else if (!strcmp (encr_algo_str, "1.3.132.1.11.3"))
    {
      /* dhSinglePass-stdDH-sha512kdf-scheme */
      hash_algo = GCRY_MD_SHA512;
      hashlen = 64;
    }
  else
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  if (!strcmp (wrap_algo_str, "2.16.840.1.101.3.4.1.5"))
    {
      cipher_algo = GCRY_CIPHER_AES128;
      keylen = 16;
    }
  else if (!strcmp (wrap_algo_str, "2.16.840.1.101.3.4.1.25"))
    {
      cipher_algo = GCRY_CIPHER_AES192;
      keylen = 24;
    }
  else if (!strcmp (wrap_algo_str, "2.16.840.1.101.3.4.1.45"))
    {
      cipher_algo = GCRY_CIPHER_AES256;
      keylen = 32;
    }
  else
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

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
    err = hash_ecc_cms_shared_info (hash_hd, wrap_algo_str, keylen,
                                    ukm, ukmlen);
    gcry_md_final (hash_hd);
    log_assert (keylen <= sizeof key && keylen <= hashlen);
    memcpy (key, gcry_md_read (hash_hd, 0), keylen);
    gcry_md_close (hash_hd);
    if (err)
      goto leave;
  }

  if (DBG_CRYPTO)
    log_printhex (key, keylen, "KEK .....:");

  /* Unwrap the key.  */
  if ((datalen % 8) || datalen < 16)
    {
      log_error ("can't use a shared secret of %u bytes for ecdh\n", datalen);
      err = gpg_error (GPG_ERR_BAD_DATA);
      goto leave;
    }

  resultlen = datalen - 8;
  result = xtrymalloc_secure (resultlen);
  if (!result)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_open (&cipher_hd, cipher_algo, GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    {
      log_error ("ecdh failed to initialize AESWRAP: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = gcry_cipher_setkey (cipher_hd, key, keylen);
  wipememory (key, sizeof key);
  if (err)
    {
      log_error ("ecdh failed in gcry_cipher_setkey: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = gcry_cipher_decrypt (cipher_hd, result, resultlen, data, datalen);
  if (err)
    {
      log_error ("ecdh failed in gcry_cipher_decrypt: %s\n",gpg_strerror (err));
      goto leave;
    }

  *r_resultlen = resultlen;
  *r_result = result;
  result = NULL;

 leave:
  if (result)
    {
      wipememory (result, resultlen);
      xfree (result);
    }
  gcry_cipher_close (cipher_hd);
  xfree (encr_algo_str);
  xfree (wrap_algo_str);
  xfree (ioarray[0].data);
  xfree (ioarray[1].data);
  xfree (ioarray[2].data);
  xfree (ioarray[3].data);
  return err;
}



/* Decrypt the session key and fill in the parm structure.  The
   algo and the IV is expected to be already in PARM. */
static int
prepare_decryption (ctrl_t ctrl, const char *hexkeygrip,
                    int pk_algo, unsigned int nbits, const char *desc,
                    ksba_const_sexp_t enc_val,
                    struct decrypt_filter_parm_s *parm)
{
  char *seskey = NULL;
  size_t n, seskeylen;
  int rc;

  if (DBG_CRYPTO)
    log_printcanon ("decrypting:", enc_val, 0);
  rc = gpgsm_agent_pkdecrypt (ctrl, hexkeygrip, desc, enc_val,
                              &seskey, &seskeylen);
  if (rc)
    {
      log_error ("error decrypting session key: %s\n", gpg_strerror (rc));
      goto leave;
    }

  if (DBG_CRYPTO)
    log_printhex (seskey, seskeylen, "DEK frame:");

  n=0;
  if (pk_algo == GCRY_PK_ECC)
    {
      gcry_sexp_t s_enc_val;
      unsigned char *decrypted;
      unsigned int decryptedlen;

      rc = gcry_sexp_sscan (&s_enc_val, NULL, enc_val,
                            gcry_sexp_canon_len (enc_val, 0, NULL, NULL));
      if (rc)
        goto leave;

      rc = ecdh_decrypt (seskey, seskeylen, nbits, s_enc_val,
                         &decrypted, &decryptedlen);
      gcry_sexp_release (s_enc_val);
      if (rc)
        goto leave;
      xfree (seskey);
      seskey = decrypted;
      seskeylen = decryptedlen;

    }
  else if (seskeylen == 32 || seskeylen == 24 || seskeylen == 16)
    {
      /* Smells like an AES-128, 3-DES, or AES-256 key.  This might
       * happen because a SC has already done the unpacking.  A better
       * solution would be to test for this only after we triggered
       * the GPG_ERR_INV_SESSION_KEY. */
    }
  else
    {
      if (n + 7 > seskeylen )
        {
          rc = gpg_error (GPG_ERR_INV_SESSION_KEY);
          goto leave;
        }

      /* FIXME: Actually the leading zero is required but due to the way
         we encode the output in libgcrypt as an MPI we are not able to
         encode that leading zero.  However, when using a Smartcard we are
         doing it the right way and therefore we have to skip the zero.  This
         should be fixed in gpg-agent of course. */
      if (!seskey[n])
        n++;

      if (seskey[n] != 2 )  /* Wrong block type version. */
        {
          rc = gpg_error (GPG_ERR_INV_SESSION_KEY);
          goto leave;
        }

      for (n++; n < seskeylen && seskey[n]; n++) /* Skip the random bytes. */
        ;
      n++; /* and the zero byte */
      if (n >= seskeylen )
        {
          rc = gpg_error (GPG_ERR_INV_SESSION_KEY);
          goto leave;
        }
    }

  if (DBG_CRYPTO)
    log_printhex (seskey+n, seskeylen-n, "CEK .....:");

  if (opt.verbose)
    log_info (_("%s.%s encrypted data\n"),
              gcry_cipher_algo_name (parm->algo),
              cipher_mode_to_string (parm->mode));

  rc = gcry_cipher_open (&parm->hd, parm->algo, parm->mode, 0);
  if (rc)
    {
      log_error ("error creating decryptor: %s\n", gpg_strerror (rc));
      goto leave;
    }

  rc = gcry_cipher_setkey (parm->hd, seskey+n, seskeylen-n);
  if (gpg_err_code (rc) == GPG_ERR_WEAK_KEY)
    {
      log_info (_("WARNING: message was encrypted with "
                  "a weak key in the symmetric cipher.\n"));
      rc = 0;
    }
  if (rc)
    {
      log_error("key setup failed: %s\n", gpg_strerror(rc) );
      goto leave;
    }

  gcry_cipher_setiv (parm->hd, parm->iv, parm->ivlen);

 leave:
  xfree (seskey);
  return rc;
}


/* This function is called by the KSBA writer just before the actual
   write is done.  The function must take INLEN bytes from INBUF,
   decrypt it and store it inoutbuf which has a maximum size of
   maxoutlen.  The valid bytes in outbuf should be return in outlen.
   Due to different buffer sizes or different length of input and
   output, it may happen that fewer bytes are processed or fewer bytes
   are written. */
static gpg_error_t
decrypt_filter (void *arg,
                const void *inbuf, size_t inlen, size_t *inused,
                void *outbuf, size_t maxoutlen, size_t *outlen)
{
  struct decrypt_filter_parm_s *parm = arg;
  int blklen = parm->blklen;
  size_t orig_inlen = inlen;

  /* fixme: Should we issue an error when we have not seen one full block? */
  if (!inlen)
    return gpg_error (GPG_ERR_BUG);

  if (maxoutlen < 2*parm->blklen)
    return gpg_error (GPG_ERR_BUG);
  /* Make some space because we will later need an extra block at the end.  */
  maxoutlen -= blklen;

  if (parm->helpblocklen)
    {
      int i, j;

      for (i=parm->helpblocklen,j=0; i < blklen && j < inlen; i++, j++)
        parm->helpblock[i] = ((const char*)inbuf)[j];
      inlen -= j;
      if (blklen > maxoutlen)
        return gpg_error (GPG_ERR_BUG);
      if (i < blklen)
        {
          parm->helpblocklen = i;
          *outlen = 0;
        }
      else
        {
          parm->helpblocklen = 0;
          if (parm->any_data)
            {
              memcpy (outbuf, parm->lastblock, blklen);
              *outlen =blklen;
            }
          else
            *outlen = 0;
          gcry_cipher_decrypt (parm->hd, parm->lastblock, blklen,
                               parm->helpblock, blklen);
          parm->any_data = 1;
        }
      *inused = orig_inlen - inlen;
      return 0;
    }


  if (inlen > maxoutlen)
    inlen = maxoutlen;
  if (inlen % blklen)
    { /* store the remainder away */
      parm->helpblocklen = inlen%blklen;
      inlen = inlen/blklen*blklen;
      memcpy (parm->helpblock, (const char*)inbuf+inlen, parm->helpblocklen);
    }

  *inused = inlen + parm->helpblocklen;
  if (inlen)
    {
      assert (inlen >= blklen);
      if (parm->any_data)
        {
          gcry_cipher_decrypt (parm->hd, (char*)outbuf+blklen, inlen,
                               inbuf, inlen);
          memcpy (outbuf, parm->lastblock, blklen);
          memcpy (parm->lastblock,(char*)outbuf+inlen, blklen);
          *outlen = inlen;
        }
      else
        {
          gcry_cipher_decrypt (parm->hd, outbuf, inlen, inbuf, inlen);
          memcpy (parm->lastblock, (char*)outbuf+inlen-blklen, blklen);
          *outlen = inlen - blklen;
          parm->any_data = 1;
        }
    }
  else
    *outlen = 0;
  return 0;
}



/* Perform a decrypt operation.  */
int
gpgsm_decrypt (ctrl_t ctrl, int in_fd, estream_t out_fp)
{
  int rc;
  gnupg_ksba_io_t b64reader = NULL;
  gnupg_ksba_io_t b64writer = NULL;
  ksba_reader_t reader;
  ksba_writer_t writer;
  ksba_cms_t cms = NULL;
  ksba_stop_reason_t stopreason;
  KEYDB_HANDLE kh;
  int recp;
  estream_t in_fp = NULL;
  struct decrypt_filter_parm_s dfparm;

  memset (&dfparm, 0, sizeof dfparm);

  audit_set_type (ctrl->audit, AUDIT_TYPE_DECRYPT);

  kh = keydb_new ();
  if (!kh)
    {
      log_error (_("failed to allocate keyDB handle\n"));
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  in_fp = es_fdopen_nc (in_fd, "rb");
  if (!in_fp)
    {
      rc = gpg_error_from_syserror ();
      log_error ("fdopen() failed: %s\n", strerror (errno));
      goto leave;
    }

  rc = gnupg_ksba_create_reader
    (&b64reader, ((ctrl->is_pem? GNUPG_KSBA_IO_PEM : 0)
                  | (ctrl->is_base64? GNUPG_KSBA_IO_BASE64 : 0)
                  | (ctrl->autodetect_encoding? GNUPG_KSBA_IO_AUTODETECT : 0)),
     in_fp, &reader);
  if (rc)
    {
      log_error ("can't create reader: %s\n", gpg_strerror (rc));
      goto leave;
    }

  rc = gnupg_ksba_create_writer
    (&b64writer, ((ctrl->create_pem? GNUPG_KSBA_IO_PEM : 0)
                  | (ctrl->create_base64? GNUPG_KSBA_IO_BASE64 : 0)),
     ctrl->pem_name, out_fp, &writer);
  if (rc)
    {
      log_error ("can't create writer: %s\n", gpg_strerror (rc));
      goto leave;
    }

  rc = ksba_cms_new (&cms);
  if (rc)
    goto leave;

  rc = ksba_cms_set_reader_writer (cms, reader, writer);
  if (rc)
    {
      log_error ("ksba_cms_set_reader_writer failed: %s\n",
                 gpg_strerror (rc));
      goto leave;
    }

  audit_log (ctrl->audit, AUDIT_SETUP_READY);

  /* Parser loop. */
  do
    {
      rc = ksba_cms_parse (cms, &stopreason);
      if (rc)
        {
          log_error ("ksba_cms_parse failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (stopreason == KSBA_SR_BEGIN_DATA
          || stopreason == KSBA_SR_DETACHED_DATA)
        {
          int algo, mode;
          const char *algoid;
          int any_key = 0;
          int is_de_vs;	/* Computed compliance with CO_DE_VS.  */

          audit_log (ctrl->audit, AUDIT_GOT_DATA);

          algoid = ksba_cms_get_content_oid (cms, 2/* encryption algo*/);
          algo = gcry_cipher_map_name (algoid);
          mode = gcry_cipher_mode_from_oid (algoid);
          if (!algo || !mode)
            {
              rc = gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
              log_error ("unsupported algorithm '%s'\n", algoid? algoid:"?");
              if (algoid && !strcmp (algoid, "1.2.840.113549.3.2"))
                log_info (_("(this is the RC2 algorithm)\n"));
              else if (!algoid)
                log_info (_("(this does not seem to be an encrypted"
                            " message)\n"));
              {
                char numbuf[50];
                sprintf (numbuf, "%d", rc);
                gpgsm_status2 (ctrl, STATUS_ERROR, "decrypt.algorithm",
                               numbuf, algoid?algoid:"?", NULL);
                audit_log_s (ctrl->audit, AUDIT_BAD_DATA_CIPHER_ALGO, algoid);
              }

              /* If it seems that this is not an encrypted message we
                 return a more sensible error code. */
              if (!algoid)
                rc = gpg_error (GPG_ERR_NO_DATA);

              goto leave;
            }

          /* Check compliance.  */
          if (! gnupg_cipher_is_allowed (opt.compliance, 0, algo, mode))
            {
              log_error (_("cipher algorithm '%s'"
                           " may not be used in %s mode\n"),
                         gcry_cipher_algo_name (algo),
                         gnupg_compliance_option_string (opt.compliance));
              rc = gpg_error (GPG_ERR_CIPHER_ALGO);
              goto leave;
            }

          /* For CMS, CO_DE_VS demands CBC mode.  */
          is_de_vs = gnupg_cipher_is_compliant (CO_DE_VS, algo, mode);

          audit_log_i (ctrl->audit, AUDIT_DATA_CIPHER_ALGO, algo);
          dfparm.algo = algo;
          dfparm.mode = mode;
          dfparm.blklen = gcry_cipher_get_algo_blklen (algo);
          if (dfparm.blklen > sizeof (dfparm.helpblock))
            return gpg_error (GPG_ERR_BUG);

          rc = ksba_cms_get_content_enc_iv (cms,
                                            dfparm.iv,
                                            sizeof (dfparm.iv),
                                            &dfparm.ivlen);
          if (rc)
            {
              log_error ("error getting IV: %s\n", gpg_strerror (rc));
              goto leave;
            }

          for (recp=0; !any_key; recp++)
            {
              char *issuer;
              ksba_sexp_t serial;
              ksba_sexp_t enc_val;
              char *hexkeygrip = NULL;
              char *pkalgostr = NULL;
              char *pkfpr = NULL;
              char *desc = NULL;
              char kidbuf[16+1];
              int tmp_rc;
              ksba_cert_t cert = NULL;
              unsigned int nbits;
              int pk_algo = 0;

              *kidbuf = 0;

              tmp_rc = ksba_cms_get_issuer_serial (cms, recp, &issuer, &serial);
              if (tmp_rc == -1 && recp)
                break; /* no more recipients */
              audit_log_i (ctrl->audit, AUDIT_NEW_RECP, recp);
              if (tmp_rc)
                log_error ("recp %d - error getting info: %s\n",
                           recp, gpg_strerror (tmp_rc));
              else
                {
                  if (opt.verbose)
                    {
                      log_info ("recp %d - issuer: '%s'\n",
                                 recp, issuer? issuer:"[NONE]");
                      log_info ("recp %d - serial: ", recp);
                      gpgsm_dump_serial (serial);
                      log_printf ("\n");
                    }

                  if (ctrl->audit)
                    {
                      char *tmpstr = gpgsm_format_sn_issuer (serial, issuer);
                      audit_log_s (ctrl->audit, AUDIT_RECP_NAME, tmpstr);
                      xfree (tmpstr);
                    }

                  keydb_search_reset (kh);
                  rc = keydb_search_issuer_sn (ctrl, kh, issuer, serial);
                  if (rc)
                    {
                      log_error ("failed to find the certificate: %s\n",
                                 gpg_strerror(rc));
                      goto oops;
                    }

                  rc = keydb_get_cert (kh, &cert);
                  if (rc)
                    {
                      log_error ("failed to get cert: %s\n", gpg_strerror (rc));
                      goto oops;
                    }

                  /* Print the ENC_TO status line.  Note that we can
                     do so only if we have the certificate.  This is
                     in contrast to gpg where the keyID is commonly
                     included in the encrypted messages. It is too
                     cumbersome to retrieve the used algorithm, thus
                     we don't print it for now.  We also record the
                     keyid for later use.  */
                  {
                    unsigned long kid[2];

                    kid[0] = gpgsm_get_short_fingerprint (cert, kid+1);
                    snprintf (kidbuf, sizeof kidbuf, "%08lX%08lX",
                              kid[1], kid[0]);
                    gpgsm_status2 (ctrl, STATUS_ENC_TO,
                                   kidbuf, "0", "0", NULL);
                  }

                  /* Put the certificate into the audit log.  */
                  audit_log_cert (ctrl->audit, AUDIT_SAVE_CERT, cert, 0);

                  /* Just in case there is a problem with the own
                     certificate we print this message - should never
                     happen of course */
                  rc = gpgsm_cert_use_decrypt_p (cert);
                  if (rc)
                    {
                      char numbuf[50];
                      sprintf (numbuf, "%d", rc);
                      gpgsm_status2 (ctrl, STATUS_ERROR, "decrypt.keyusage",
                                     numbuf, NULL);
                      rc = 0;
                    }

                  hexkeygrip = gpgsm_get_keygrip_hexstring (cert);
                  desc = gpgsm_format_keydesc (cert);

                  pkfpr = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
                  pkalgostr = gpgsm_pubkey_algo_string (cert, NULL);
                  pk_algo = gpgsm_get_key_algo_info (cert, &nbits);
                  if (!opt.quiet)
                    log_info (_("encrypted to %s key %s\n"), pkalgostr, pkfpr);

                  /* Check compliance.  */
                  if (!gnupg_pk_is_allowed (opt.compliance,
                                            PK_USE_DECRYPTION,
                                            pk_algo, NULL, nbits, NULL))
                    {
                      char  kidstr[10+1];

                      snprintf (kidstr, sizeof kidstr, "0x%08lX",
                                gpgsm_get_short_fingerprint (cert, NULL));
                      log_info (_("key %s is not suitable for decryption"
                                  " in %s mode\n"),
                                kidstr,
                                gnupg_compliance_option_string(opt.compliance));
                      rc = gpg_error (GPG_ERR_PUBKEY_ALGO);
                      goto oops;
                    }

                  /* Check that all certs are compliant with CO_DE_VS.  */
                  is_de_vs = (is_de_vs
                              && gnupg_pk_is_compliant (CO_DE_VS, pk_algo,
                                                        NULL, nbits, NULL));

                oops:
                  if (rc)
                    {
                      /* We cannot check compliance of certs that we
                       * don't have.  */
                      is_de_vs = 0;
                    }
                  xfree (issuer);
                  xfree (serial);
                  ksba_cert_release (cert);
                }

              if (!hexkeygrip || !pk_algo)
                ;
              else if (!(enc_val = ksba_cms_get_enc_val (cms, recp)))
                log_error ("recp %d - error getting encrypted session key\n",
                           recp);
              else
                {
                  rc = prepare_decryption (ctrl, hexkeygrip, pk_algo, nbits,
                                           desc, enc_val, &dfparm);
                  xfree (enc_val);
                  if (rc)
                    {
                      log_info ("decrypting session key failed: %s\n",
                                gpg_strerror (rc));
                      if (gpg_err_code (rc) == GPG_ERR_NO_SECKEY && *kidbuf)
                        gpgsm_status2 (ctrl, STATUS_NO_SECKEY, kidbuf, NULL);
                    }
                  else
                    { /* setup the bulk decrypter */
                      any_key = 1;
                      ksba_writer_set_filter (writer,
                                              decrypt_filter,
                                              &dfparm);

                      if (is_de_vs)
                        gpgsm_status (ctrl, STATUS_DECRYPTION_COMPLIANCE_MODE,
                                      gnupg_status_compliance_flag (CO_DE_VS));

                    }
                  audit_log_ok (ctrl->audit, AUDIT_RECP_RESULT, rc);
                }
              xfree (pkalgostr);
              xfree (pkfpr);
              xfree (hexkeygrip);
              xfree (desc);
            }

          /* If we write an audit log add the unused recipients to the
             log as well.  */
          if (ctrl->audit && any_key)
            {
              for (;; recp++)
                {
                  char *issuer;
                  ksba_sexp_t serial;
                  int tmp_rc;

                  tmp_rc = ksba_cms_get_issuer_serial (cms, recp,
                                                       &issuer, &serial);
                  if (tmp_rc == -1)
                    break; /* no more recipients */
                  audit_log_i (ctrl->audit, AUDIT_NEW_RECP, recp);
                  if (tmp_rc)
                    log_error ("recp %d - error getting info: %s\n",
                               recp, gpg_strerror (tmp_rc));
                  else
                    {
                      char *tmpstr = gpgsm_format_sn_issuer (serial, issuer);
                      audit_log_s (ctrl->audit, AUDIT_RECP_NAME, tmpstr);
                      xfree (tmpstr);
                      xfree (issuer);
                      xfree (serial);
                    }
                }
            }

          if (!any_key)
            {
              if (!rc)
                rc = gpg_error (GPG_ERR_NO_SECKEY);
              goto leave;
            }
        }
      else if (stopreason == KSBA_SR_END_DATA)
        {
          ksba_writer_set_filter (writer, NULL, NULL);
          if (dfparm.any_data)
            { /* write the last block with padding removed */
              int i, npadding = dfparm.lastblock[dfparm.blklen-1];
              if (!npadding || npadding > dfparm.blklen)
                {
                  log_error ("invalid padding with value %d\n", npadding);
                  rc = gpg_error (GPG_ERR_INV_DATA);
                  goto leave;
                }
              rc = ksba_writer_write (writer,
                                      dfparm.lastblock,
                                      dfparm.blklen - npadding);
              if (rc)
                goto leave;

              for (i=dfparm.blklen - npadding; i < dfparm.blklen; i++)
                {
                  if (dfparm.lastblock[i] != npadding)
                    {
                      log_error ("inconsistent padding\n");
                      rc = gpg_error (GPG_ERR_INV_DATA);
                      goto leave;
                    }
                }
            }
        }

    }
  while (stopreason != KSBA_SR_READY);

  rc = gnupg_ksba_finish_writer (b64writer);
  if (rc)
    {
      log_error ("write failed: %s\n", gpg_strerror (rc));
      goto leave;
    }
  gpgsm_status (ctrl, STATUS_DECRYPTION_OKAY, NULL);


 leave:
  audit_log_ok (ctrl->audit, AUDIT_DECRYPTION_RESULT, rc);
  if (rc)
    {
      gpgsm_status (ctrl, STATUS_DECRYPTION_FAILED, NULL);
      log_error ("message decryption failed: %s <%s>\n",
                 gpg_strerror (rc), gpg_strsource (rc));
    }
  ksba_cms_release (cms);
  gnupg_ksba_destroy_reader (b64reader);
  gnupg_ksba_destroy_writer (b64writer);
  keydb_release (kh);
  es_fclose (in_fp);
  if (dfparm.hd)
    gcry_cipher_close (dfparm.hd);
  return rc;
}
