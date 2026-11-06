/* encrypt-kem.c - Encrypt functions using KEM approach
 * Copyright (C) 2020, 2025, 2026 g10 Code GmbH
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

#include "gpgsm.h"
#include <gcrypt.h>
#include <ksba.h>
#include "../common/tlv.h"
#include "../common/kemhelp.h"



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
  unsigned int keylen;
  unsigned char key[32];
  const unsigned char *secret;
  unsigned int secretlen;
  const unsigned char *pubkey;
  unsigned int pubkeylen;
  gcry_cipher_hd_t cipher_hd = NULL;
  unsigned char *result = NULL;
  unsigned int resultlen;

  unsigned int nbits;
  const struct gnupg_ecc_params *ecc;
  gcry_mpi_t ecc_pubkey_mpi = NULL;
  const unsigned char *ecc_pubkey;
  size_t ecc_pubkey_len;
  unsigned char ecc_ct[ECC_POINT_LEN_MAX];
  unsigned char ecc_ecdh[ECC_POINT_LEN_MAX];
  size_t ecc_ct_len, ecc_ecdh_len;

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
   * canonical name.  We also use this to get the size of the curve
   * which we need to figure out a suitable hash algo.  We should have
   * a Libgcrypt function to do this; see bug report #4926.  */
  curve = openpgp_oid_to_curve (curvebuf, 1);
  xfree (curvebuf);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      log_error ("%s: invalid public key: %s\n", __func__, gpg_strerror (err));
      goto leave;
    }

  curve = openpgp_is_curve_supported (curve, NULL, &curvebits);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      log_error ("%s: invalid public key: %s\n", __func__, gpg_strerror (err));
      goto leave;
    }

  /* Our mapping matches the recommended algorithms from RFC-5753 but
   * not supporting the short curves which would require 3DES.  */
  if (curvebits < 255)
    {
      err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      log_error ("%s: curve '%s' is not supported\n", __func__, curve);
      goto leave;
    }
  else if (opt.force_ecdh_sha1kdf)
    {
      /* dhSinglePass-stdDH-sha1kdf-scheme */
      encr_algo_str = "1.3.133.16.840.63.0.2";
      wrap_algo_str = "2.16.840.1.101.3.4.1.45";
      hash_algo     = GCRY_MD_SHA1;
      cipher_algo   = GCRY_CIPHER_AES256;
      keylen        = 32;
    }
  else if (curvebits <= 256)
    {
      /* dhSinglePass-stdDH-sha256kdf-scheme */
      encr_algo_str = "1.3.132.1.11.1";
      wrap_algo_str = "2.16.840.1.101.3.4.1.5";
      hash_algo     = GCRY_MD_SHA256;
      cipher_algo   = GCRY_CIPHER_AES128;
      keylen        = 16;
    }
  else if (curvebits <= 384)
    {
      /* dhSinglePass-stdDH-sha384kdf-scheme */
      encr_algo_str = "1.3.132.1.11.2";
      wrap_algo_str = "2.16.840.1.101.3.4.1.25";
      hash_algo     = GCRY_MD_SHA384;
      cipher_algo   = GCRY_CIPHER_AES192;
      keylen        = 24;
    }
  else
    {
      /* dhSinglePass-stdDH-sha512kdf-scheme*/
      encr_algo_str = "1.3.132.1.11.3";
      wrap_algo_str = "2.16.840.1.101.3.4.1.45";
      hash_algo     = GCRY_MD_SHA512;
      cipher_algo   = GCRY_CIPHER_AES256;
      keylen        = 32;
    }

  ecc = gnupg_get_ecc_params (curve);
  if (!ecc)
    {
      if (opt.verbose)
        log_info ("%s: ECC curve %s not supported\n", __func__, curve);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  ecc_ct_len = ecc_ecdh_len = ecc->point_len;

  err = gcry_sexp_extract_param (s_pkey, NULL, "/q",
                                 &ecc_pubkey_mpi, NULL);
  ecc_pubkey = gcry_mpi_get_opaque (ecc_pubkey_mpi, &nbits);
  ecc_pubkey_len = (nbits+7)/8;
  if (ecc_pubkey_len != ecc->pubkey_len)
    {
      if (ecc->kem_algo == GCRY_KEM_RAW_X25519
          && ecc_pubkey_len == ecc->pubkey_len - 1)
        /* For Curve25519, we also accept no prefix in the point
         * representation.  */
        ;
      else
        {
          if (opt.verbose)
            log_info ("%s: ECC public key length invalid (%zu)\n",
                      __func__, ecc_pubkey_len);
          err = gpg_error (GPG_ERR_INV_DATA);
          goto leave;
        }
    }

  if (ecc->kem_algo == GCRY_KEM_RAW_X25519)
    {
      /* Note: Legacy OID is OK here.  */
      /* Optional prefix handling */
      if (ecc_pubkey_len == 33 && *ecc_pubkey == 0x40)
        {
          ecc_pubkey++;     /* Remove the 0x40 prefix.  */
          ecc_pubkey_len--;
        }
    }

  if (DBG_CRYPTO)
    {
      log_debug ("ECC    curve: %s\n", curve);
      log_printhex (ecc_pubkey, ecc_pubkey_len, "ECC   pubkey:");
    }

  err = gcry_kem_encap (ecc->kem_algo,
                        ecc_pubkey, ecc_pubkey_len,
                        ecc_ct, ecc_ct_len,
                        ecc_ecdh, ecc_ecdh_len,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_encap for ECC (%s) failed\n",
                  __func__, curve);
      goto leave;
    }
  if (DBG_CRYPTO)
    {
      log_printhex (ecc_ct, ecc_ct_len, "ECC    ephem:");
      log_printhex (ecc_ecdh, ecc_ecdh_len, "ECC     ecdh:");
    }

  if (ecc->is_weierstrauss)
    {
      secret = ecc_ecdh + 1;
      secretlen = (ecc_ecdh_len - 1) / 2;
      pubkey = ecc_ct;
      pubkeylen = ecc_ct_len;
    }
  else
    {
      secret = ecc_ecdh;
      secretlen = ecc_ecdh_len;

      if (ecc->may_have_prefix)
        {
          pubkeylen = ecc_ct_len + 1;
          memmove (ecc_ct + 1, ecc_ct, ecc_ct_len);
          ecc_ct[0] = 0x40;
        }
      else
        pubkeylen = ecc_ct_len;

      pubkey = ecc_ct;
    }

  err = ecdh_derive_kek (key, keylen, hash_algo, wrap_algo_str,
                         secret, secretlen, NULL, 0);
  if (err)
    goto leave;

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
  gcry_mpi_release (ecc_pubkey_mpi);
  gcry_cipher_close (cipher_hd);
  wipememory (ecc_ecdh, sizeof ecc_ecdh);
  wipememory (key, sizeof key);
  xfree (result);
  return err;
}


/* Dispatcher for the KEM encrypt^Wencap functions.  PK_ALGO is the
 * algo which is either GCRY_PK_ECC or GCRY_PK_KEM.  DEK has the data
 * encryption key.  S_PKEY isthe public we want to encrypt to.
 * R_ENCVAL will reveive the encrypted key has an s-epression.  */
gpg_error_t
kem_pkencrypt (ctrl_t ctrl, int pk_algo, const DEK dek,
               gcry_sexp_t s_pkey, gcry_sexp_t *r_encval)
{

  if (pk_algo == GCRY_PK_ECC)  /* We use KEM for ECC.  */
    return ecdh_encrypt (dek, s_pkey, r_encval);
  if (pk_algo != GCRY_PK_KEM)
    return gpg_error (GPG_ERR_PUBKEY_ALGO);  /* Should not happen */
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}
