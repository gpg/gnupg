/* kem.c -  KEM helper functions
 * Copyright (C) 2024, 2026  g10 Code GmbH.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute and/or modify this
 * part of GnuPG under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: (LGPL-3.0-or-later OR GPL-2.0-or-later)
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <gpg-error.h>
#include <gcrypt.h>

#include "mischelp.h"
#include "util.h"
#include "kemhelp.h"

/* domSeperation as per *PGP specs. */
#define KMAC_KEY "OpenPGPCompositeKeyDerivationFunction"

/* customizationString as per *PGP specs. */
#define KMAC_CUSTOM "KDF"

/* The blocksize used for Keccak by compute_kmac256.  */
#define KECCAK512_BLOCKSIZE 136



static gpg_error_t
compute_kmac256 (void *digest, size_t digestlen,
                 const void *key, size_t keylen,
                 const void *custom, size_t customlen,
                 gcry_buffer_t *data_iov, int data_iovlen)
{
  gpg_error_t err;
  gcry_buffer_t iov[20];
  const unsigned char headPAD[2] = { 1, KECCAK512_BLOCKSIZE };
  unsigned char headK[3];
  const unsigned char pad[KECCAK512_BLOCKSIZE] = { 0 };
  unsigned char right_encode_L[3];
  unsigned int len;
  int iovcnt;

  if (data_iovlen >= DIM(iov) - 6)
    return gpg_error (GPG_ERR_TOO_LARGE);

  /* Check the validity conditions of NIST SP 800-185 */
  if (keylen >= 255 || customlen >= 255 || digestlen >= 255)
    return gpg_error (GPG_ERR_TOO_LARGE);

  iovcnt = 0;
  iov[iovcnt].data = "KMAC";
  iov[iovcnt].off = 0;
  iov[iovcnt].len = 4;
  iovcnt++;

  iov[iovcnt].data = (void *)custom;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = customlen;
  iovcnt++;

  iov[iovcnt].data = (void *)headPAD;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = sizeof (headPAD);
  iovcnt++;

  if (keylen < 32)
    {
      headK[0] = 1;
      headK[1] = (keylen*8)&0xff;
      iov[iovcnt].data = headK;
      iov[iovcnt].off = 0;
      iov[iovcnt].len = 2;
    }
  else
    {
      headK[0] = 2;
      headK[1] = (keylen*8)>>8;
      headK[2] = (keylen*8)&0xff;
      iov[iovcnt].data = headK;
      iov[iovcnt].off = 0;
      iov[iovcnt].len = 3;
    }
  iovcnt++;

  iov[iovcnt].data = (void *)key;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = keylen;
  iovcnt++;

  len = iov[2].len + iov[3].len + iov[4].len;
  len %= KECCAK512_BLOCKSIZE;

  iov[iovcnt].data = (unsigned char *)pad;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = sizeof (pad) - len;
  iovcnt++;

  memcpy (&iov[iovcnt], data_iov, data_iovlen * sizeof (gcry_buffer_t));
  iovcnt += data_iovlen;

  if (digestlen < 32)
    {
      right_encode_L[0] = (digestlen * 8) & 0xff;
      right_encode_L[1] = 1;
    }
  else
    {
      right_encode_L[0] = (digestlen * 8) >> 8;
      right_encode_L[1] = (digestlen * 8) & 0xff;
      right_encode_L[2] = 2;
    }

  iov[iovcnt].data = right_encode_L;
  iov[iovcnt].off = 0;
  iov[iovcnt].len = 3;
  iovcnt++;

  err = gcry_md_hash_buffers_ext (GCRY_MD_CSHAKE256, 0,
                                  digest, digestlen, iov, iovcnt);
  return err;
}


/* Compute KEK for ECC with KDF_ALGO, HASHALGO, ECDH result, and
 * KDF_PARAMS.
 *
 * KDF_PARAMS is specified by upper layer.
 */
gpg_error_t
gnupg_ecc_kem_kdf (void *kek, size_t kek_len, int kdf_algo,
                   int hashalgo, const void *ecdh, size_t ecdh_len,
                   const unsigned char *kdf_params, size_t kdf_params_len)
{
  /* Traditional ECC */
  gpg_error_t err;
  gcry_kdf_hd_t hd;
  unsigned long param[1];

  param[0] = kek_len;
  err = gcry_kdf_open (&hd, kdf_algo, hashalgo, param, 1,
                       ecdh, ecdh_len, NULL, 0, NULL, 0,
                       kdf_params, kdf_params_len);
  if (!err)
    {
      gcry_kdf_compute (hd, NULL);
      gcry_kdf_final (hd, kek_len, kek);
      gcry_kdf_close (hd);
    }

  return err;
}


/* Compute KEK for ECC with HASHALGO, ECDH result, ciphertext in
 * ECC_CT (which is an ephemeral key), and public key in ECC_PK.
 */
gpg_error_t
gnupg_ecc_kem_simple_kdf (void *kek, size_t kek_len,
                          int hashalgo, const void *ecdh, size_t ecdh_len,
                          const void *ecc_ct, size_t ecc_ct_len,
                          const void *ecc_pk, size_t ecc_pk_len)
{
  /* ECC part in composite KEM */
  gcry_buffer_t iov[3];
  unsigned int dlen;

  dlen = gcry_md_get_algo_dlen (hashalgo);
  if (kek_len != dlen)
    return gpg_error (GPG_ERR_INV_LENGTH);

  memset (iov, 0, sizeof (iov));

  iov[0].data = (unsigned char *)ecdh;
  iov[0].len = ecdh_len;
  iov[1].data = (unsigned char *)ecc_ct;
  iov[1].len = ecc_ct_len;
  iov[2].data = (unsigned char *)ecc_pk;
  iov[2].len = ecc_pk_len;
  gcry_md_hash_buffers (hashalgo, 0, kek, iov, 3);

  return 0;
}


/* Compute KEK by combining two KEMs.  The caller provides a buffer
 * KEK allocated with size KEK_LEN which will receive the computed
 * KEK. (ECC_SS, ECC_SS_LEN) is the shared secret of the first key.
 * (ECC_CT, ECC_CT_LEN) is the ciphertext of the first key.
 * (MLKEM_SS, ECC_SS_LEN) is the shared secret of the second key.
 * (MLKEM_CT, MLKEM_CT_LEN) is the ciphertext of the second key.
 * (FIXEDINFO, FIXEDINFO_LEN) is an octet string used to bind the KEK
 * to a the key; for PGP we use the concatenation of the session key's
 * algorithm id and the v5 fingerprint of the key.  */
gpg_error_t
gnupg_kem_combiner (void *kek, size_t kek_len,
                    const void *ecc_ss, size_t ecc_ss_len,
                    const void *ecc_ct, size_t ecc_ct_len,
                    const void *mlkem_ss, size_t mlkem_ss_len,
                    const void *mlkem_ct, size_t mlkem_ct_len,
                    const void *fixedinfo, size_t fixedinfo_len)
{
  gpg_error_t err;
  gcry_buffer_t iov[6];

  memset (iov, 0, sizeof (iov));

  iov[0].data = "\x00\x00\x00\x01"; /* Counter */
  iov[0].len = 4;

  iov[1].data = (unsigned char *)ecc_ss;
  iov[1].len = ecc_ss_len;

  iov[2].data = (unsigned char *)ecc_ct;
  iov[2].len = ecc_ct_len;

  iov[3].data = (unsigned char *)mlkem_ss;
  iov[3].len = mlkem_ss_len;

  iov[4].data = (unsigned char *)mlkem_ct;
  iov[4].len = mlkem_ct_len;

  iov[5].data = (unsigned char *)fixedinfo;
  iov[5].len = fixedinfo_len;

  err = compute_kmac256 (kek, kek_len,
                         KMAC_KEY, strlen (KMAC_KEY),
                         KMAC_CUSTOM, strlen (KMAC_CUSTOM), iov, 6);
  return err;
}


/* Compute KEK by combining two KEMs; this ise the RFC9980 version
 * using SHA3-256.  The caller provides a buffer KEK allocated with
 * size KEK_LEN which will receive the computed
 * KEK. (ECC_SS,ECC_SS_LEN) is the shared secret of the first key.
 * (ECC_CT,ECC_CT_LEN) is the ciphertext of the first key.
 * (ECC_PK,ECC_PK_LEN) is the public key of the first key.
 * (MLKEM_SS,ECC_SS_LEN) is the shared secret of the second key.
 * (FIXEDINFO, FIXEDINFO_LEN) is an octet string used to bind the KEK
 * to a the key.  */
gpg_error_t
gnupg_kem_combiner_sha3_256 (void *kek, size_t kek_len,
                             const void *ecc_ss, size_t ecc_ss_len,
                             const void *ecc_ct, size_t ecc_ct_len,
                             const void *ecc_pk, size_t ecc_pk_len,
                             const void *mlkem_ss, size_t mlkem_ss_len,
                             const void *fixedinfo, size_t fixedinfo_len)
{
  gpg_error_t err;
  gcry_buffer_t iov[5];

  memset (iov, 0, sizeof (iov));

  iov[0].data = (unsigned char *)mlkem_ss;
  iov[0].len = mlkem_ss_len;

  iov[1].data = (unsigned char *)ecc_ss;
  iov[1].len = ecc_ss_len;

  iov[2].data = (unsigned char *)ecc_ct;
  iov[2].len = ecc_ct_len;

  iov[3].data = (unsigned char *)ecc_pk;
  iov[3].len = ecc_pk_len;

  iov[4].data = (unsigned char *)fixedinfo;
  iov[4].len = fixedinfo_len;

  err = gcry_md_hash_buffers_ext (GCRY_MD_SHA3_256, 0,
                                  kek, kek_len, iov, 5);
  return err;
}




#define ECC_CURVE25519_INDEX 0
static const struct gnupg_ecc_params ecc_table[] =
  {
    {
      "Curve25519",
      33, 32, 32,
      GCRY_MD_SHA3_256, GCRY_KEM_RAW_X25519,
      1, 1, 0
    },
    {
      "ietf25",
      32, 32, 32,
      GCRY_MD_SHA3_256, GCRY_KEM_RAW_X25519,
      0, 0, 0
    },
    {
      "X448",
      56, 56, 56,
      GCRY_MD_SHA3_512, GCRY_KEM_RAW_X448,
      0, 0, 0
    },
    {
      "NIST P-256",
      65, 32, 65,
      GCRY_MD_SHA3_256, GCRY_KEM_RAW_P256R1,
      0, 0, 1
    },
    {
      "NIST P-384",
      97, 48, 97,
      GCRY_MD_SHA3_512, GCRY_KEM_RAW_P384R1,
      0, 0, 1
    },
    {
      "NIST P-521",
      133, 66, 133,
      GCRY_MD_SHA3_512, GCRY_KEM_RAW_P521R1,
      0, 0, 1
    },
    {
      "brainpoolP256r1",
      65, 32, 65,
      GCRY_MD_SHA3_256, GCRY_KEM_RAW_BP256,
      0, 0, 1
    },
    {
      "brainpoolP384r1",
      97, 48, 97,
      GCRY_MD_SHA3_512, GCRY_KEM_RAW_BP384,
      0, 0, 1
    },
    {
      "brainpoolP512r1",
      129, 64, 129,
      GCRY_MD_SHA3_512, GCRY_KEM_RAW_BP512,
      0, 0, 1
    },
#ifdef GCRY_KEM_RAW_P256K1
    {
      "secp256k1",
      65, 32, 65,
      GCRY_MD_SHA3_256, GCRY_KEM_RAW_P256K1,
      0, 0, 1
    },
#endif
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0 }
};


/* Return the ECC parameters for CURVE.  CURVE is expected to be the
 * canonical name.  */
const struct gnupg_ecc_params *
gnupg_get_ecc_params (const char *curve)
{
  int i;

  for (i = 0; ecc_table[i].curve; i++)
    if (!strcmp (ecc_table[i].curve, curve))
      return &ecc_table[i];

  return NULL;
}



/* Derive a session key for composite CMS algos. With GENERATE set the
 * input is a session key, with GENERATE clear the input is the
 * encrypted key; reversed if GENERATE is not set.
 * (SHARED,SHARED_LEN) gives the shared secret from which a KEK is
 * derived.  (INPKEY,INPKEY_LEN) is the the encrypted key or in
 * generate mode the session key.  That key will be
 * decrypted/encrypted and hashed to formthe session key or the
 * encrypted key.  PQCALGOSTR, WRAPALSOSTR, and KDFALGOSTR derscribe
 * the used algorithms.  OUTKEY_LEN is the requested length for the
 * output.  On success the allocated output is stored at R_OUTKEY.
 * ENABLE_DEBUG enables debug output.  */
gpg_error_t
gnupg_kem_derive_or_gen_seskey (int enable_debug, int generate,
                                const void *shared, size_t shared_len,
                                const void *inpkey, size_t inpkey_len,
                                const char *pqcalgostr,
                                const char *wrapalgostr,
                                const char *kdfalgostr,
                                size_t outkey_len,
                                void **r_outkey)
{
  gpg_error_t err;
  void *outkey;
  gcry_cipher_hd_t hd;
  gcry_kdf_hd_t kdfhd;
  unsigned long kdfparam[1];
  int wrapalgo, kdfalgo, kdfmacalgo;
  void *kek = NULL;
  size_t kek_len;
  /* Template for the RFC-9629 key derivation:
   *  CMSORIforKEMOtherInfo ::= SEQUENCE {
   *    wrap KeyEncryptionAlgorithmIdentifier,
   *    kekLength INTEGER (1..65535),
   *    ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL } */
  unsigned char cmsoriforkemotherinfo[18] =
    { 0x30, 0x10, 0x30, 0x0b, 0x06,
      0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d,
      0x02, 0x01, 0x20 };
#define CMSORIFORKEMOTHERINFO_OID 14    /* Offset to the last OID byte.  */
#define CMSORIFORKEMOTHERINFO_KEKLEN 17 /* Offset to the KEK_LEN byte.   */


  if (!strcmp (wrapalgostr, "aes256-wrap"))
    {
      wrapalgo = GCRY_CIPHER_AES256;
      cmsoriforkemotherinfo[CMSORIFORKEMOTHERINFO_OID] = 45;
    }
  else if (!strcmp (wrapalgostr, "aes192-wrap"))
    {
      wrapalgo = GCRY_CIPHER_AES192;
      cmsoriforkemotherinfo[CMSORIFORKEMOTHERINFO_OID] = 25;
    }
  else if (!strcmp (wrapalgostr, "aes128-wrap"))
    {
      wrapalgo = GCRY_CIPHER_AES128;
      cmsoriforkemotherinfo[CMSORIFORKEMOTHERINFO_OID] = 5;
    }
  else
    return gpg_error (GPG_ERR_CIPHER_ALGO);

  if (!strcmp (kdfalgostr, "hkdf-sha256"))
    {
      kdfalgo = GCRY_KDF_HKDF;
      kdfmacalgo = GCRY_MAC_HMAC_SHA256;
    }
  else
    return gpg_error (GPG_ERR_DIGEST_ALGO);

  /* Check that the requested length matches and then allocate.  */
  if (generate)
    {
      if (inpkey_len + 8 != outkey_len)
        {
          log_info ("%s: session key size %zu does not fit for '%s'\n",
                    __func__, outkey_len, pqcalgostr);
          return gpg_error (GPG_ERR_INV_DATA);
        }
    }
  else
    {
      if (inpkey_len != outkey_len + 8)
        {
          log_info ("%s: encrypted key size %zu does not fit for '%s'\n",
                    __func__, inpkey_len, pqcalgostr);
          return gpg_error (GPG_ERR_INV_DATA);
        }
    }

  /* Note: From here on jump to the leave label on error.  */
  kek_len = generate? inpkey_len : outkey_len;

  /* Check the length of the KEK.  This also makes sure that it fits
   * the DER encoding in the template. */
  if (kek_len < 16 || kek_len > 127)
    {
      log_info ("%s: requested output key length is wrong (%zu)\n",
                __func__, outkey_len);
      err = gpg_error (GPG_ERR_INV_LENGTH);
      goto leave;
    }
  cmsoriforkemotherinfo[CMSORIFORKEMOTHERINFO_KEKLEN] = kek_len;

  kek = xtrymalloc_secure (kek_len);
  if (!kek)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  outkey = xtrymalloc_secure (outkey_len);
  if (!outkey)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_open (&hd, wrapalgo, GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    {
      log_error ("%s: failed to initialize '%s': %s\n",
                 __func__, wrapalgostr, gpg_strerror (err));
      goto leave;
    }

  kdfparam[0] = kek_len;
  /* log_debug ("%s: kdfalgo=%d kdfmacalgo=%d kddparm[0]=%lu\n", __func__, */
  /*            kdfalgo, kdfmacalgo, kdfparam[0]); */
  /* log_printhex (shared, shared_len, "%s: shared", __func__); */
  /* log_printhex (cmsoriforkemotherinfo, sizeof cmsoriforkemotherinfo, */
  /*               "%s: cmsoriforkemotherinfo", __func__); */
  err = gcry_kdf_open (&kdfhd, kdfalgo, kdfmacalgo,
                       kdfparam, 1,
                       shared, shared_len,
                       NULL, 0, NULL, 0,
                       cmsoriforkemotherinfo, sizeof cmsoriforkemotherinfo);
  if (err)
    {
      log_error ("%s: failed to open the HKDF function: %s\n",
                 __func__, gpg_strerror (err));
      gcry_cipher_close (hd);
      goto leave;
    }

  err = gcry_kdf_compute (kdfhd, NULL);
  if (!err)
    err = gcry_kdf_final (kdfhd, kek_len, kek);
  gcry_kdf_close (kdfhd);

  if (enable_debug)
    log_printhex (kek, kek_len, "Derived KEK :");

  err = gcry_cipher_setkey (hd, kek, kek_len);
  if (!err)
    {
      if (generate)
        err = gcry_cipher_encrypt (hd, outkey, outkey_len,
                                   inpkey, inpkey_len);
      else
        err = gcry_cipher_decrypt (hd, outkey, outkey_len,
                                   inpkey, inpkey_len);
    }
  gcry_cipher_close (hd);
  if (err)
    {
      log_error ("%s: error %s key using %s: %s\n",
                 __func__, generate? "encrypting": "decrypting",
                 wrapalgostr, gpg_strerror (err));
      goto leave;
    }

  /* Success:  Return the key.  */
  *r_outkey = outkey;
  outkey = NULL;

 leave:
  if (kek)
    {
      wipememory (kek, kek_len);
      xfree (kek);
    }
  if (outkey)
    {
      wipememory (outkey, outkey_len);
      xfree (outkey);
    }
  return err;
}
