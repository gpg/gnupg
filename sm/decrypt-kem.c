/* decrypt-kem.c - Decrypt functions using KEM approach
 * Copyright (C) 2025, 2026 g10 Code GmbH
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


/* Maximum buffer length of encrypted session key in S-Expression for
 * KEM API.  */
#define ENC_VAL_KEM_MAX 1024


static int
determine_wrap_cipher (unsigned char *wrap_algo, size_t len)
{
  int cipher = -1;

  if (len == 22 && !memcmp (wrap_algo, "2.16.840.1.101.3.4.1.5", len))
    cipher = GCRY_CIPHER_AES128;
  else if (len == 23 && !memcmp (wrap_algo, "2.16.840.1.101.3.4.1.25", len))
    cipher = GCRY_CIPHER_AES192;
  else if (len == 23 && !memcmp (wrap_algo, "2.16.840.1.101.3.4.1.45", len))
    cipher = GCRY_CIPHER_AES256;

  return cipher;
}

static int
determine_hashalgo (unsigned char *kdf_scheme, size_t len)
{
  int hashalgo = -1;

  if (len == 14 && !memcmp (kdf_scheme, "1.3.132.1.11.1", len))
    {
      /* dhSinglePass-stdDH-sha256kdf-scheme */
      hashalgo = GCRY_MD_SHA256;
    }
  else if (len == 14 && !memcmp (kdf_scheme, "1.3.132.1.11.2", len))
    {
      /* dhSinglePass-stdDH-sha384kdf-scheme */
      hashalgo = GCRY_MD_SHA384;
    }
  else if (len == 14 && !memcmp (kdf_scheme, "1.3.132.1.11.3", len))
    {
      /* dhSinglePass-stdDH-sha512kdf-scheme */
      hashalgo = GCRY_MD_SHA512;
    }
  else if (len == 21 && !memcmp (kdf_scheme, "1.3.133.16.840.63.0.2", len))
    {
      /* dhSinglePass-stdDH-sha1kdf-scheme */
      hashalgo = GCRY_MD_SHA1;
    }

  return hashalgo;
}


/* Construct the
 *  ECC-CMS-SharedInfo ::= SEQUENCE {
 *      keyInfo         AlgorithmIdentifier,
 *      entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
 *      suppPubInfo [2] EXPLICIT OCTET STRING  }
 * as described in RFC-5753, 7.2.  */
static gpg_error_t
build_shared_info (size_t kek_len, const char *wrap_algo_str,
                   const void *ukm, size_t ukm_len,
                   unsigned char **result_p, size_t *len_p)
{
  gpg_error_t err;
  unsigned char *oid;
  size_t oidlen, toidlen, tkeyinfo, tukmlen, tsupppubinfo;
  unsigned char keylenbuf[6];
  membuf_t mb = MEMBUF_ZERO;

  err = ksba_oid_from_str (wrap_algo_str, &oid, &oidlen);
  if (err)
    return err;

  toidlen = get_tlv_length (CLASS_UNIVERSAL, TAG_OBJECT_ID, 0, oidlen);
  tkeyinfo = get_tlv_length (CLASS_UNIVERSAL, TAG_SEQUENCE, 1, toidlen);

  tukmlen = ukm? get_tlv_length (CLASS_CONTEXT, 0, 1, ukm_len) : 0;

  kek_len *= 8;
  keylenbuf[0] = TAG_OCTET_STRING;
  keylenbuf[1] = 4;
  keylenbuf[2] = (kek_len >> 24);
  keylenbuf[3] = (kek_len >> 16);
  keylenbuf[4] = (kek_len >> 8);
  keylenbuf[5] = kek_len;

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
      put_tlv_to_membuf (&mb, CLASS_CONTEXT, 0, 1, ukm_len);
      put_membuf (&mb, ukm, ukm_len);
    }

  put_tlv_to_membuf (&mb, CLASS_CONTEXT, 2, 1, sizeof keylenbuf);
  put_membuf (&mb, keylenbuf, sizeof keylenbuf);

  if (!(*result_p = get_membuf (&mb, len_p)))
    err = gpg_error_from_syserror ();

  return err;
}


/* Derive a KEK (key wrapping/encoding key) using (SECRET,SECRETLEN), an
 * optional (UKM,ULMLEN), the wrap algorithm WRAP_ALGO_STR in decimal
 * dotted form, and the hash algorithm HASH_ALGO.  On success a key of
 * length KEK_LEN is stored at KEK_KEY.  */
gpg_error_t
ecdh_derive_kek (unsigned char *kek_key, unsigned int kek_len,
                 int hash_algo, const char *wrap_algo_str,
                 const void *secret, unsigned int secretlen,
                 const void *ukm, unsigned int ukmlen)
{
  gpg_error_t err;
  unsigned char *kdf_params = NULL;
  size_t kdf_params_len;

  err = build_shared_info (kek_len, wrap_algo_str, ukm, ukmlen,
                           &kdf_params, &kdf_params_len);
  if (err)
    return err;

  err = gnupg_ecc_kem_kdf (kek_key, kek_len, GCRY_KDF_X963_KDF, hash_algo,
                           secret, secretlen,
                           (char *)kdf_params, kdf_params_len);
  return err;
}


/* For ECC, get the session key by asking gpg-agent with KEM API.  */
gpg_error_t
ecc_kem_pkdecrypt (ctrl_t ctrl, const char *hexkeygrip,
                   const char *desc, ksba_const_sexp_t enc_val,
                   char **r_seskey, size_t *r_seskeylen)
{
  gcry_error_t err;
  gcry_sexp_t s_enc_val;

  gcry_mpi_t encrypted_sessionkey_mpi = NULL;
  gcry_mpi_t ecc_ct_mpi = NULL;
  gcry_buffer_t encr_algo = { 0, 0, 0, NULL };
  gcry_buffer_t wrap_algo = { 0, 0, 0, NULL };
  gcry_buffer_t ukm = { 0, 0, 0, NULL };

  int keywrap_cipher_algo, kdf_hash_algo;
  size_t kek_len;

  char *wrap_algo_str;

  unsigned char *kdf_params = NULL;
  size_t kdf_params_len;

  gcry_sexp_t s_enc_val_kem;
  unsigned char enc_val_kem[ENC_VAL_KEM_MAX];
  size_t enc_val_kem_len;

  /*
   * Firstly, from ENC_VAL, extract hash algo for KDF, key
   * wrap cipher algo, cipher text, wrapped session key, and
   * optional user key material (UKM).
   */
  err = gcry_sexp_sscan (&s_enc_val, NULL, enc_val,
                         gcry_sexp_canon_len (enc_val, 0, NULL, NULL));
  if (err)
    goto leave;

  err = gcry_sexp_extract_param (s_enc_val, "enc-val",
                                 "/es&'encr-algo''wrap-algo''ukm'?",
                                 &ecc_ct_mpi, &encrypted_sessionkey_mpi,
                                 &encr_algo, &wrap_algo, &ukm, NULL);
  gcry_sexp_release (s_enc_val);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting parameters failed\n", __func__);
      goto leave;
    }

  if (!encr_algo.data || !wrap_algo.data)
    {
      if (opt.verbose)
        log_info ("%s: the KDF parameters are required\n", __func__);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  kdf_hash_algo = determine_hashalgo (encr_algo.data, encr_algo.size);
  if (kdf_hash_algo < 0)
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  keywrap_cipher_algo = determine_wrap_cipher (wrap_algo.data,
                                               wrap_algo.size);
  if (keywrap_cipher_algo < 0)
    {
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;
    }

  kek_len = gcry_cipher_get_algo_keylen (keywrap_cipher_algo);
  if (kek_len == 0)
    {
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  wrap_algo_str = string_from_gcry_buffer (&wrap_algo);
  if (!wrap_algo_str)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Secondly, compose the KDF parameters.  */
  err = build_shared_info (kek_len, wrap_algo_str, ukm.data, ukm.size,
                           &kdf_params, &kdf_params_len);
  xfree (wrap_algo_str);
  if (err)
    goto leave;

  /* Thirdly, build the S-EXP for the request to the gpg-agent.  */
  err = gcry_sexp_build (&s_enc_val_kem, NULL,
                         "(enc-val(ecc(c%d)(h%d)(e%m)(s%m)(kdf-params%b)))",
                         keywrap_cipher_algo, kdf_hash_algo,
                         ecc_ct_mpi, encrypted_sessionkey_mpi,
                         (int)kdf_params_len, kdf_params);
  if (err)
    goto leave;

  enc_val_kem_len = gcry_sexp_sprint (s_enc_val_kem, GCRYSEXP_FMT_CANON,
                                      enc_val_kem, ENC_VAL_KEM_MAX);
  gcry_sexp_release (s_enc_val_kem);
  if (!enc_val_kem_len)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto leave;
    }

  /* Ask gpg-agent to decrypt the wrapped session key with KEM API.  */
  err = gpgsm_agent_pkdecrypt (ctrl, hexkeygrip, desc, 1, enc_val_kem,
                               r_seskey, r_seskeylen);
 leave:
  xfree (kdf_params);
  gcry_free (encr_algo.data);
  gcry_free (wrap_algo.data);
  gcry_free (ukm.data);
  gcry_mpi_release (ecc_ct_mpi);
  gcry_mpi_release (encrypted_sessionkey_mpi);
  return err;
}
