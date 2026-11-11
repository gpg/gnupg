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


/* Encrypt the DEK using boths keys along with the pqcalgostr and
 * curvestr helper values.  The created encrypted output at R_ENCVAL
 * is in this format:
 *
 *  (enc-val
 *    (kem
 *      (pqc kyberNNN)     -- The PQC algo
 *      (curve <xyz>)      -- The curve for a composite algo
 *      (ct <ciphertext>)  -- ciphertext
 *      (kdf hkdf-sha256)
 *      (kek-len 32)       -- length of the key encryption key
 *      (wrap-algo aes256-wrap)
 *      (encr-key <key>))) -- this is the encrypted session key
 */
static gpg_error_t
composite_kem_encrypt (DEK dek,
                       gcry_sexp_t s_pkey_mlk, const char *pqcalgostr,
                       gcry_sexp_t s_pkey_ecc, const char *curvestr,
                       gcry_sexp_t *r_encval)
{
  gpg_error_t err;
  enum gcry_kem_algos mlk_kem_algo, ecc_kem_algo;
  const char *label;
  gcry_buffer_t ecc_pubkey_buffer = { 0, 0, 0, NULL };
  const unsigned char *ecc_pubkey = NULL;
  size_t ecc_pubkey_len;
  unsigned char *ecc_encaps = NULL;
  unsigned char *ecc_shared = NULL;
  size_t ecc_encaps_len, ecc_shared_len;
  gcry_buffer_t mlk_pubkey_buffer = { 0, 0, 0, NULL };
  const unsigned char *mlk_pubkey = NULL;
  size_t mlk_pubkey_len;
  unsigned char *mlk_encaps = NULL;
  unsigned char *mlk_shared = NULL;
  size_t mlk_encaps_len, mlk_shared_len;
  unsigned char *comb_shared = NULL;
  size_t comb_shared_len;
  void *enckey = NULL;
  size_t enckey_len;
  unsigned char *ciphertext = NULL;
  size_t ciphertext_len;
  const char *kdfalgostr  = "hkdf-sha256";
  const char *wrapalgostr = "aes256-wrap";

  /* Get PQC algo information. */
  if (!strcmp (pqcalgostr, "kyber768"))
    {
      mlk_kem_algo = GCRY_KEM_MLKEM768;
      mlk_pubkey_len = GCRY_KEM_MLKEM768_PUBKEY_LEN;
      mlk_encaps_len = GCRY_KEM_MLKEM768_ENCAPS_LEN;
      mlk_shared_len = GCRY_KEM_MLKEM768_SHARED_LEN;
    }
  else if (!strcmp (pqcalgostr, "kyber1024"))
    {
      mlk_kem_algo = GCRY_KEM_MLKEM1024;
      mlk_pubkey_len = GCRY_KEM_MLKEM1024_PUBKEY_LEN;
      mlk_encaps_len = GCRY_KEM_MLKEM1024_ENCAPS_LEN;
      mlk_shared_len = GCRY_KEM_MLKEM1024_SHARED_LEN;
    }
  else
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      log_info ("%s: PQC algo '%s' is not supported\n", __func__, pqcalgostr);
      goto leave;
    }

  /* Get the ECC algo information.  */
  label = NULL;
  if (!strcmp (curvestr, "X25519"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_X25519;
      ecc_encaps_len = GCRY_KEM_ECC_X25519_ENCAPS_LEN;
      if (mlk_kem_algo == GCRY_KEM_MLKEM768)
        label = "\x5c\x2e\x2f\x2f\x5e\x5c";
    }
  else if (!strcmp (curvestr, "X448"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_X448;
      ecc_encaps_len = GCRY_KEM_ECC_X448_ENCAPS_LEN;
      if (mlk_kem_algo == GCRY_KEM_MLKEM1024)
        label = "MLKEM1024-X448";
    }
  else if (!strcmp (curvestr, "bp256"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_BP256;
      ecc_encaps_len = 1 + 32 + 32;
      if (mlk_kem_algo == GCRY_KEM_MLKEM768)
        label = "MLKEM768-BP256";
    }
  else if (!strcmp (curvestr, "nistp256"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_P256R1;
      ecc_encaps_len = 1 + 32 + 32;
      if (mlk_kem_algo == GCRY_KEM_MLKEM768)
        label = "MLKEM768-P256";
    }
  else if (!strcmp (curvestr, "bp384"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_BP384;
      ecc_encaps_len = 1 + 48 + 48;
      if (mlk_kem_algo == GCRY_KEM_MLKEM1024)
        label = "MLKEM1024-BP384";
    }
  else if (!strcmp (curvestr, "nistp384"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_P384R1;
      ecc_encaps_len = 1 + 48 + 48;
    }
  else if (!strcmp (curvestr, "bp512"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_BP512;
      ecc_encaps_len = 1 + 64 + 64;
    }
  else if (!strcmp (curvestr, "nistp521"))
    {
      ecc_kem_algo = GCRY_KEM_RAW_P521R1;
      ecc_encaps_len = 1 + 66 + 66;
      if (mlk_kem_algo == GCRY_KEM_MLKEM1024)
        label = "MLKEM1024-P521";
    }
  else
    {
      err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
      log_info ("%s: curve '%s' is not supported\n", __func__, curvestr);
      goto leave;
    }

  if (!label)
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      log_info ("%s: composite algo '%s' with '%s' is not specified\n",
                __func__, pqcalgostr, curvestr);
      goto leave;
    }

  /* Encrypt to the ECC part.  */
  err = gcry_sexp_extract_param (s_pkey_ecc, NULL, "&q",
                                 &ecc_pubkey_buffer, NULL);
  if (err)
    goto leave;
  ecc_pubkey = ecc_pubkey_buffer.data;
  ecc_pubkey_len = ecc_pubkey_buffer.len;

  ecc_shared_len = ecc_encaps_len;
  ecc_encaps = xtrymalloc (ecc_encaps_len);
  if (ecc_encaps)
    ecc_shared = xtrymalloc (ecc_shared_len);
  if (!ecc_encaps || !ecc_shared)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_kem_encap (ecc_kem_algo, ecc_pubkey, ecc_pubkey_len,
                        /* outputs: */ ecc_encaps, ecc_encaps_len,
                        /*          */ ecc_shared, ecc_shared_len,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_encap for ECC part (%s) failed\n",
                  __func__, curvestr);
      log_debug ("pubkey_len=%zu encaps_len=%zu shared_len=%zu\n",
                 ecc_pubkey_len, ecc_encaps_len, ecc_shared_len);
      goto leave;
    }
  /* Return only the x-coordinate: A 0x04 prefix is required and the
   * value must odd so that we can extract just the half of it.  */
  if (ecc_shared_len > 3 && ecc_shared[0] == 0x04 && ecc_shared_len % 2)
    {
      ecc_shared_len = (ecc_shared_len - 1)/2;
      memmove (ecc_shared, ecc_shared+1, ecc_shared_len);
    }

  if (DBG_CRYPTO)
    {
      log_printhex (ecc_encaps, ecc_encaps_len, "ECC    ephem:");
      log_printhex (ecc_shared, ecc_shared_len, "ECC   shared:");
    }

  /* Encrypt to the ML-KEM part.  */
  err = gcry_sexp_extract_param (s_pkey_mlk, NULL, "&p",
                                 &mlk_pubkey_buffer, NULL);
  if (err)
    goto leave;
  if (mlk_pubkey_len != mlk_pubkey_buffer.len)
    {
      log_info ("%s: Kyber public key length invalid (%zu)\n",
                __func__, mlk_pubkey_buffer.len);
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }
  mlk_pubkey = mlk_pubkey_buffer.data;

  if (DBG_CRYPTO)
    log_printhex (mlk_pubkey, mlk_pubkey_len, "|!trunc|Kyber pubkey:");

  mlk_encaps = xtrymalloc (mlk_encaps_len);
  if (mlk_encaps)
    mlk_shared = xtrymalloc (mlk_shared_len);
  if (!mlk_encaps || !mlk_shared)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_kem_encap (mlk_kem_algo, mlk_pubkey, mlk_pubkey_len,
                        /* outputs: */ mlk_encaps, mlk_encaps_len,
                        /*          */ mlk_shared, mlk_shared_len,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_encap for MLKEM part (%s) failed\n",
                  __func__, curvestr);
      goto leave;
    }
  if (DBG_CRYPTO)
    log_printhex (mlk_shared, mlk_shared_len, "MLKEM shared:");

  /* Combine the keys.  */
  comb_shared_len = 32;  /* Always 32 octets.  */
  comb_shared = xtrymalloc_secure (comb_shared_len);
  if (!comb_shared)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  err = gnupg_kem_combiner_sha3_256 (comb_shared, comb_shared_len,
                                     ecc_shared, ecc_shared_len,
                                     ecc_encaps, ecc_encaps_len,
                                     ecc_pubkey, ecc_pubkey_len,
                                     mlk_shared, mlk_shared_len,
                                     label, strlen (label));
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: PQC-CMS key combiner failed\n", __func__);
      goto leave;
    }

  if (DBG_CRYPTO)
    log_printhex (comb_shared, comb_shared_len, "Final shared:");

  enckey_len = comb_shared_len + 8;  /* 8 is for the AES tag */
  err = gnupg_kem_derive_or_gen_seskey (DBG_CRYPTO, 1/*(generate)*/,
                                        comb_shared, comb_shared_len,
                                        dek->key, dek->keylen,
                                        pqcalgostr, wrapalgostr, kdfalgostr,
                                        enckey_len, &enckey);
  if (err)
    goto leave;

  if (DBG_CRYPTO)
    log_printhex (enckey, enckey_len, "EncrKey ....:");

  ciphertext_len = mlk_encaps_len + ecc_encaps_len;
  ciphertext = xtrymalloc (ciphertext_len);
  if (!ciphertext)
    goto leave;
  memcpy (ciphertext, mlk_encaps, mlk_encaps_len);
  memcpy (ciphertext+mlk_encaps_len, ecc_encaps, ecc_encaps_len);


  err = gcry_sexp_build (r_encval, NULL,
                         "(enc-val(kem"
                         "(pqc %s)(curve %s)"
                         "(kdf %s)(wrap-algo %s)"
                         "(ct %b)(encr-key %b)))",
                         pqcalgostr, curvestr,
                         kdfalgostr, wrapalgostr,
                         (int)ciphertext_len, ciphertext,
                         (int)enckey_len, enckey,
                         NULL);
  if (err)
    log_error ("%s: failed building final S-exp: %s\n",
               __func__, gpg_strerror (err));

 leave:
  gcry_free (ecc_pubkey_buffer.data);
  gcry_free (mlk_pubkey_buffer.data);
  xfree (ecc_encaps);
  xfree (ecc_shared);
  xfree (mlk_encaps);
  xfree (mlk_shared);
  xfree (comb_shared);
  xfree (ciphertext);
  xfree (enckey);
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
  gpg_error_t err;
  const char *tag;
  size_t taglen;
  gcry_sexp_t s_pkey_ecc, s_pkey_mlk;
  char *curvestr = NULL;
  char *pqcalgostr = NULL;
  gcry_sexp_t l_tmp, l1;

  (void)ctrl;  /* Currently not used.  */

  *r_encval = NULL;

  if (pk_algo == GCRY_PK_ECC)  /* We use KEM for ECC.  */
    return ecdh_encrypt (dek, s_pkey, r_encval);
  if (pk_algo != GCRY_PK_KEM)
    return gpg_error (GPG_ERR_PUBKEY_ALGO);  /* Should not happen */

  /* We only support composite KEM algorithms.  Split the key so that
   * we can pass both parts independently.  */
  tag = gcry_sexp_nth_data (s_pkey, 0, &taglen);
  if (!(tag && taglen == 13 && !memcmp (tag, "composite-key", 13)))
    {
      log_error ("%s: invalid public key: no a composite key\n", __func__);
      return gpg_error (GPG_ERR_PUBKEY_ALGO);
    }

  s_pkey_mlk = gcry_sexp_nth (s_pkey, 1);
  s_pkey_ecc = gcry_sexp_nth (s_pkey, 2);
  if (!s_pkey_mlk || !s_pkey_ecc)
    {
      log_error ("%s: broken composite key detected\n", __func__);
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

  if ((l1 = gcry_sexp_find_token (s_pkey_ecc, "curve", 0)))
    ; /* Alright, the second key part has the ECC key.  */
  else if ((l1 = gcry_sexp_find_token (s_pkey_mlk, "curve", 0)))
    {
      /* Uncommonly the first part has the curve parameter and thus
       * is the ECC part.  Swap them to get the variables right. */
      gcry_sexp_t s_tmp = s_pkey_mlk;
      s_pkey_mlk = s_pkey_ecc;
      s_pkey_ecc = s_tmp;
    }
  else
    l1 = NULL;
  curvestr = gcry_sexp_nth_string (l1, 1);
  gcry_sexp_release (l1);
  if (!curvestr)
    {
      log_error ("%s: no curve given in any part of a composite key\n",
                 __func__);
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

  /* Get the name of the PQC algo.  */
  if ((l1 = gcry_sexp_find_token (s_pkey_mlk, "public-key", 0)))
    {
      l_tmp = gcry_sexp_cadr (l1);
      gcry_sexp_release (l1);
      l1 = l_tmp;
    }
  pqcalgostr = gcry_sexp_nth_string (l1, 0);
  gcry_sexp_release (l1);
  if (!pqcalgostr)
    {
      log_error ("%s: no PQC algo given in any part of a composite key\n",
                 __func__);
      err = gpg_error (GPG_ERR_BAD_PUBKEY);
      goto leave;
    }

  err = composite_kem_encrypt (dek, s_pkey_mlk, pqcalgostr,
                               s_pkey_ecc, curvestr,
                               r_encval);

 leave:
  gcry_sexp_release (s_pkey_mlk);
  gcry_sexp_release (s_pkey_ecc);
  xfree (curvestr);
  xfree (pqcalgostr);
  return err;
}
