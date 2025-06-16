/* gost-util.c - Some common code for GOST crypto.
 * Copyright (C) 2019 Paul Wolneykien <manowar@altlinux.org>
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

#include <config.h>
#include <stdlib.h>
#include "gost-util.h"
//#include "logging.h"
#include "util.h"

gpg_error_t
gost_generate_ukm (unsigned int ukm_blen, gcry_mpi_t *r_ukm)
{
  if (!*r_ukm)
    {
      *r_ukm = gcry_mpi_new (ukm_blen);
      if (!*r_ukm)
        return gpg_error_from_syserror ();
    }

  gcry_mpi_randomize (*r_ukm, ukm_blen, GCRY_STRONG_RANDOM);

  return GPG_ERR_NO_ERROR;
}

static gpg_error_t
set_cipher_sbox (gcry_cipher_hd_t hd, const char *sbox)
{
  if (sbox)
    {
      char *_sbox = xstrdup (sbox);
      if (!_sbox)
        return gpg_error_from_syserror ();
      gpg_error_t ret = gcry_cipher_ctl (hd, GCRYCTL_SET_SBOX, _sbox,
                                         strlen (_sbox));
      xfree (_sbox);
      return ret;
    }

  return GPG_ERR_NO_ERROR;
}

static gpg_error_t
set_mac_sbox (gcry_mac_hd_t hd, const char *sbox)
{
  if (sbox)
    {
      char *_sbox = xstrdup (sbox);
      if (!_sbox)
        return gpg_error_from_syserror ();
      gpg_error_t ret = gcry_mac_ctl (hd, GCRYCTL_SET_SBOX, _sbox,
                                      strlen (_sbox));
      xfree (_sbox);
      return ret;
    }

  return GPG_ERR_NO_ERROR;
}

/**
 * Diversifies the key using the given UKM.
 * Implements RFC 4357 p 6.5 key diversification algorithm.
 *
 * The UKM value can be opaque.
 *
 * Thanks to Dmitry Belyavskiy.
 *
 * @param result MPI to store the diversified key (32 bytes)
 * @param key 32-byte key to be diversified
 * @param ukm 8-byte user key material
 *
 */
gpg_error_t
gost_cpdiversify_key (gcry_mpi_t *result,
                      enum gcry_cipher_algos cipher_algo,
                      const char *cipher_sbox,
                      const unsigned char *key, size_t key_len,
                      gcry_mpi_t ukm)
{
  byte* result_buf = NULL;
  byte* ukm_buf = NULL;
  size_t ukm_len;
  gcry_cipher_hd_t hd = NULL;
  gpg_error_t ret = GPG_ERR_NO_ERROR;

  if (gcry_mpi_get_flag (ukm, GCRYMPI_FLAG_OPAQUE))
    {
      unsigned int ukm_blen;
      byte *_ukm_buf = gcry_mpi_get_opaque (ukm, &ukm_blen);
      ukm_len = (ukm_blen + 7)/8;
      if (_ukm_buf)
        ukm_buf = xtrymalloc (ukm_len);
      if (ukm_buf)
        memcpy (ukm_buf, _ukm_buf, ukm_len);
    }
  else
    ret = gcry_mpi_aprint (GCRYMPI_FMT_USG, &ukm_buf, &ukm_len, ukm);
  if (ret != GPG_ERR_NO_ERROR)
    goto exit;

  flip_buffer (ukm_buf, ukm_len);

  /*if (DBG_CRYPTO) {
    log_printhex ("in UKM:", ukm_buf, ukm_len);
    log_printhex ("in KEY:", key, key_len);
  }*/

  if (ukm_len < 8) {
    ret = GPG_ERR_TOO_SHORT;
    goto exit;
  }

  result_buf = xtrymalloc_secure (key_len);
  if (!result_buf) {
    ret = gpg_error_from_syserror ();
    goto exit;
  }

  ret = gcry_cipher_open (&hd, cipher_algo, GCRY_CIPHER_MODE_CFB, 0);
  if (ret != GPG_ERR_NO_ERROR)
    goto exit;

  u32 k, s1, s2;
  int i, j, mask;
  unsigned char S[8];

  memcpy (result_buf, key, key_len);

  for (i = 0; i < 8; i++) {
    /* Make array of integers from the key */
    /* Compute IV S */
    s1 = 0, s2 = 0;
    for (j = 0, mask = 1; j < 8; j++, mask <<= 1) {
      k = ((u32) result_buf[4 * j]) | (result_buf[4 * j + 1] << 8) |
        (result_buf[4 * j + 2] << 16) | (result_buf[4 * j + 3] << 24);
      if (mask & ukm_buf[i]) {
        s1 += k;
      } else {
        s2 += k;
      }
    }
    S[0] = (unsigned char)(s1 & 0xff);
    S[1] = (unsigned char)((s1 >> 8) & 0xff);
    S[2] = (unsigned char)((s1 >> 16) & 0xff);
    S[3] = (unsigned char)((s1 >> 24) & 0xff);
    S[4] = (unsigned char)(s2 & 0xff);
    S[5] = (unsigned char)((s2 >> 8) & 0xff);
    S[6] = (unsigned char)((s2 >> 16) & 0xff);
    S[7] = (unsigned char)((s2 >> 24) & 0xff);

    ret = gcry_cipher_reset (hd);
    if (ret) goto exit;
    ret = gcry_cipher_setkey (hd, result_buf, key_len);
    if (ret) goto exit;
    ret = gcry_cipher_setiv (hd, S, sizeof S);
    if (ret) goto exit;
    ret = set_cipher_sbox (hd, cipher_sbox);
    if (ret) goto exit;

    ret = gcry_cipher_encrypt (hd, result_buf, key_len,
                               NULL, 0);
  }

  /*if (DBG_CRYPTO) {
    log_printhex ("diversified KEY:", result_buf, key_len);
  }*/

  *result = gcry_mpi_set_opaque_copy (*result, result_buf, 8 * key_len);

 exit:
  gcry_cipher_close (hd);
  xfree (ukm_buf);
  xfree (result_buf);

  return ret;
}

/**
 * Wraps the key using RFC 4357 6.3 or RFC 7836 4.6. However, the UKM
 * value isn't included into the result value.
 *
 * The UKM value can be opaque.
 *
 * Thanks to Dmitry Belyavskiy.
 *
 * @param result reference to store the resulting MPI with the wrapped key
 * @param cipher_algo Cipher algorithm
 * @param cipher_sbox Cipher algorithm parameters (S-box)
 * @param mac_algo MAC algorithm
 * @param mac_sbox MAC algorithm parameters (S-box for CMAC)
 * @param key 32-byte (256-bit) session key to be wrapped
 * @param ukm 8--16 byte (64--128 bit) user key material
 * @param kek 32-byte (256-bit) shared key (with KDF already applied)
 */
gpg_error_t
gost_keywrap (gcry_mpi_t *result,
              enum gcry_cipher_algos cipher_algo,
              const char *cipher_sbox,
              enum gcry_mac_algos mac_algo,
              const char *mac_sbox,
              gcry_mpi_t key, gcry_mpi_t ukm, gcry_mpi_t kek)
{
	gpg_error_t err = 0;
	gcry_cipher_hd_t cipher_hd = NULL;
	gcry_mac_hd_t mac_hd = NULL;
	byte *ekey_buf = NULL;
	byte *result_buf = NULL;
	byte *ukm_buf = NULL;

	err = gcry_cipher_open (&cipher_hd, cipher_algo, GCRY_CIPHER_MODE_ECB, 0);
	if (err) goto exit;

	size_t keylen = (gcry_mpi_get_nbits (key) + 7)/8;
	ekey_buf = xtrymalloc_secure (keylen);
	size_t mac_len = gcry_mac_get_algo_maclen (mac_algo);
	size_t result_len = keylen + mac_len;
	result_buf = xmalloc (result_len);
    if (!ekey_buf || !result_buf) {
      err = gpg_error_from_syserror ();
      goto exit;
	}

    size_t ukm_len = (gcry_mpi_get_nbits (ukm) + 7)/8;
    ukm_buf = xmalloc (ukm_len);
    if (!ukm_buf)
      {
        err = gpg_error_from_syserror ();
        goto exit;
      }

	unsigned int kek_len = gcry_cipher_get_algo_keylen (cipher_algo);
	unsigned int kek_nbits;
	unsigned char *kek_buf = gcry_mpi_get_opaque (kek, &kek_nbits);
	if (!kek_buf)
      {
		err = gpg_error_from_syserror ();
		goto exit;
      }
	if ((kek_nbits + 7)/8 != kek_len)
      {
        err = GPG_ERR_INV_KEYLEN;
		goto exit;
      }

	err = gcry_cipher_setkey (cipher_hd, kek_buf, kek_len);
    if (err) goto exit;

    err = set_cipher_sbox (cipher_hd, cipher_sbox);
    if (err) goto exit;

	err = gcry_mpi_print (GCRYMPI_FMT_USG, ekey_buf, keylen,
						   NULL, key);
	if (err) goto exit;
	err = gcry_cipher_encrypt (cipher_hd, result_buf, keylen,
                               ekey_buf, keylen);
	if (err) goto exit;

    if (gcry_mpi_get_flag (ukm, GCRYMPI_FLAG_OPAQUE))
      {
        unsigned int ukm_blen;
        byte *_ukm_buf = gcry_mpi_get_opaque (ukm, &ukm_blen);
        if (_ukm_buf)
          memcpy (ukm_buf, _ukm_buf, ukm_len);
      }
    else
      {
        size_t ukm_wrt;
        err = gcry_mpi_print (GCRYMPI_FMT_USG, ukm_buf, ukm_len,
                              &ukm_wrt, ukm);
        if (err) goto exit;
        if (ukm_wrt < ukm_len)
          {
            memmove (ukm_buf + (ukm_len - ukm_wrt), ukm_buf, ukm_wrt);
            memset (ukm_buf, 0, ukm_len - ukm_wrt);
          }
      }
    if (err) goto exit;
	flip_buffer (ukm_buf, ukm_len);

    err = gcry_mac_open (&mac_hd, mac_algo, 0, NULL);
	if (err) goto exit;

    err = set_mac_sbox (mac_hd, mac_sbox);
    if (err) goto exit;

	err = gcry_mac_setkey (mac_hd, kek_buf, kek_len);
	if (err) goto exit;
	err = gcry_mac_setiv (mac_hd, ukm_buf, ukm_len);
	if (err) goto exit;
	err = gcry_mac_write (mac_hd, ekey_buf, keylen);
	if (err) goto exit;

	err = gcry_mac_read (mac_hd, result_buf + keylen, &mac_len);
	if (err) goto exit;

	*result = gcry_mpi_set_opaque_copy (*result, result_buf, 8 * result_len);

	/*if (DBG_CRYPTO) {
		log_printmpi ("wrapped key value: ", result);
    }*/

 exit:
	gcry_cipher_close (cipher_hd);
    gcry_mac_close (mac_hd);
	xfree (ukm_buf);
	xfree (ekey_buf);
	xfree (result_buf);

	return err;
}

gpg_error_t
gost_vko (gcry_mpi_t shared, enum gcry_md_algos digest_algo,
          const char *digest_params, unsigned char **keyout,
          size_t *keyout_len)
{
  byte *secret = NULL;
  gcry_md_hd_t md = NULL;
  unsigned char *_keyout = NULL;
  gpg_error_t ret = GPG_ERR_NO_ERROR;

  switch (digest_algo)
    {
    case GCRY_MD_GOSTR3411_94:
      if (!digest_params || strcmp (digest_params, "1.2.643.2.2.30.1"))
        {
          /* No other possible values exist and no explicit parameters
             are supported in Libgcrypt -- the actual GCRY value for
             the digest algo is GCRY_MD_GOSTR3411_CP --- GOST R 34.11-94
             with CryptoPro-A S-box.*/
          ret = GPG_ERR_DIGEST_ALGO;
        }
      else
        digest_algo = GCRY_MD_GOSTR3411_CP;
      break;
    case GCRY_MD_GOSTR3411_CP:
      if (digest_params && strcmp (digest_params, "1.2.643.2.2.30.1"))
        ret = GPG_ERR_DIGEST_ALGO;
      break;
    case GCRY_MD_STRIBOG256:
    case GCRY_MD_STRIBOG512:
      if (digest_params)
        {
          /* No parameter values exist for GOST R 34.11-2012. */
          ret = GPG_ERR_DIGEST_ALGO;
        }
      break;
    default:
      ret = GPG_ERR_DIGEST_ALGO;
    }

  if (ret != GPG_ERR_NO_ERROR)
    {
      log_error ("Wrong digest parameters for VKO 7836\n");
      return ret;
    }

  size_t secret_len = (mpi_get_nbits (shared) + 7)/8;
  secret = xtrymalloc_secure (secret_len);
  if (!secret)
    {
      ret = gpg_error_from_syserror ();
      goto exit;
    }
  ret = gcry_mpi_print (GCRYMPI_FMT_USG, secret, secret_len, NULL,
                        shared);
  if (ret != GPG_ERR_NO_ERROR)
    return ret;

  /* Remove the prefix. */
  if (secret_len % 2)
    {
      memmove (secret, secret + 1, secret_len - 1);
      secret_len -= 1;
    }

  flip_buffer (secret, secret_len/2);
  flip_buffer (secret + secret_len/2, secret_len/2);

  ret = gcry_md_open (&md, digest_algo, GCRY_MD_FLAG_SECURE);
  if (ret != GPG_ERR_NO_ERROR)
    goto exit;

  gcry_md_write (md, secret, secret_len);

  size_t _keyout_len = gcry_md_get_algo_dlen (digest_algo);
  if (*keyout && (!keyout_len || *keyout_len < _keyout_len))
    {
      ret = GPG_ERR_TOO_SHORT;
      goto exit;
    }

  _keyout = gcry_md_read (md, digest_algo);
  if (!_keyout)
    {
      ret = gpg_error_from_syserror ();
      goto exit;
    }

  if (!*keyout)
    {
      *keyout = xtrymalloc_secure (_keyout_len);
      if (!*keyout) {
        ret = gpg_error_from_syserror ();
        goto exit;
      }
    }

  memcpy (*keyout, _keyout, _keyout_len);
  *keyout_len = _keyout_len;

 exit:
  xfree (secret);
  gcry_md_close (md);

  if (ret != GPG_ERR_NO_ERROR)
    {
      if (!*keyout)
        *keyout_len = 0;
    }

  return ret;
}

/**
 * Unwraps the key that was wrapped using RFC 4357 6.3 or
 * RFC 7836 4.6. However the UKM value is passed separately
 * from the wrapped key value.
 *
 * The UKM value can be opaque.
 *
 * Thanks to Dmitry Belyavskiy.
 *
 * @param result MPI to store the unwrapped key (32-byte)
 * @param cipher_algo Cipher algorithm
 * @param cipher_sbox Cipher algorithm parameters (S-box)
 * @param mac_algo MAC algorithm
 * @param mac_sbox MAC algorithm parameters (S-box for CMAC)
 * @param wrapped wrapped key
 * @param wrapped_len wrapped key length
 * @param ukm 8--16 byte (64--128 bit) user key material
 * @param kek 32-byte (256-bit) shared key (with KDF already applied)
 */
gpg_error_t
gost_keyunwrap (gcry_mpi_t *result,
                enum gcry_cipher_algos cipher_algo,
                const char *cipher_sbox,
                enum gcry_mac_algos mac_algo,
                const char *mac_sbox,
                const unsigned char *wrapped, size_t wrapped_len,
                gcry_mpi_t ukm, gcry_mpi_t kek)
{
  gpg_error_t err = 0;
  gcry_cipher_hd_t cipher_hd = NULL;
  gcry_mac_hd_t mac_hd = NULL;
  unsigned char *ukm_buf = NULL;
  unsigned char *result_buf = NULL;

  /*if (DBG_CRYPTO)
    log_printhex ("encrypted value: ", wrapped, wrapped_len);*/

  err = gcry_cipher_open (&cipher_hd, cipher_algo, GCRY_CIPHER_MODE_ECB, 0);
  if (err) goto exit;

  size_t mac_len = gcry_mac_get_algo_maclen (mac_algo);

  size_t result_len = wrapped_len - mac_len;
  result_buf = xtrymalloc_secure (result_len);
  if (!result_buf)
    {
      err = gpg_error_from_syserror ();
      goto exit;
    }

  size_t ukm_len = (gcry_mpi_get_nbits (ukm) + 7)/8;
  ukm_buf = xmalloc (ukm_len);
  if (!ukm_buf)
    {
      err = gpg_error_from_syserror ();
      goto exit;
    }

  unsigned int kek_len = gcry_cipher_get_algo_keylen (cipher_algo);
  unsigned int kek_nbits;
  unsigned char *kek_buf = gcry_mpi_get_opaque (kek, &kek_nbits);
  if (!kek_buf)
    {
      err = gpg_error_from_syserror ();
      goto exit;
    }
  if ((kek_nbits + 7)/8 != kek_len)
    {
      err = GPG_ERR_INV_KEYLEN;
      goto exit;
    }

  err = gcry_cipher_setkey (cipher_hd, kek_buf, kek_len);
  if (err) goto exit;

  err = set_cipher_sbox (cipher_hd, cipher_sbox);
  if (err) goto exit;

  err = gcry_cipher_decrypt (cipher_hd, result_buf, result_len,
                             wrapped, wrapped_len - mac_len);
  if (err) goto exit;

  if (gcry_mpi_get_flag (ukm, GCRYMPI_FLAG_OPAQUE))
    {
      unsigned int ukm_blen;
      byte *_ukm_buf = gcry_mpi_get_opaque (ukm, &ukm_blen);
      if (_ukm_buf)
        memcpy (ukm_buf, _ukm_buf, ukm_len);
    }
  else
    {
      size_t ukm_wrt;
      err = gcry_mpi_print (GCRYMPI_FMT_USG, ukm_buf, ukm_len,
                            &ukm_wrt, ukm);
      if (err) goto exit;
      if (ukm_wrt < ukm_len)
        {
          memmove (ukm_buf + (ukm_len - ukm_wrt), ukm_buf, ukm_wrt);
          memset (ukm_buf, 0, ukm_len - ukm_wrt);
        }
    }
  if (err) goto exit;
  flip_buffer (ukm_buf, ukm_len);

  err = gcry_mac_open (&mac_hd, mac_algo, 0, NULL);
  if (err) goto exit;

  err = set_mac_sbox (mac_hd, mac_sbox);
  if (err) goto exit;

  err = gcry_mac_setkey (mac_hd, kek_buf, kek_len);
  if (err) goto exit;
  err = gcry_mac_setiv (mac_hd, ukm_buf, ukm_len);
  if (err) goto exit;
  err = gcry_mac_write (mac_hd, result_buf, result_len);
  if (err) goto exit;

  err = gcry_mac_verify (mac_hd, wrapped + (wrapped_len - mac_len), mac_len);
  if (err) goto exit;

  *result = gcry_mpi_set_opaque_copy (*result, result_buf, 8 * result_len);

 exit:
  gcry_cipher_close (cipher_hd);
  gcry_mac_close (mac_hd);
  xfree (ukm_buf);
  xfree (result_buf);

  return err;
}
