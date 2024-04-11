/* pkdecrypt.c - public key decryption (well, actually using a secret key)
 *	Copyright (C) 2001, 2003 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include "../common/openpgpdefs.h"

/* DECRYPT the stuff in ciphertext which is expected to be a S-Exp.
   Try to get the key from CTRL and write the decoded stuff back to
   OUTFP.   The padding information is stored at R_PADDING with -1
   for not known.  */
gpg_error_t
agent_pkdecrypt (ctrl_t ctrl, const char *desc_text,
                 const unsigned char *ciphertext, size_t ciphertextlen,
                 membuf_t *outbuf, int *r_padding)
{
  gcry_sexp_t s_skey = NULL, s_cipher = NULL, s_plain = NULL;
  unsigned char *shadow_info = NULL;
  gpg_error_t err = 0;
  int no_shadow_info = 0;
  char *buf = NULL;
  size_t len;

  *r_padding = -1;

  if (!ctrl->have_keygrip)
    {
      log_error ("speculative decryption not yet supported\n");
      err = gpg_error (GPG_ERR_NO_SECKEY);
      goto leave;
    }

  err = gcry_sexp_sscan (&s_cipher, NULL, (char*)ciphertext, ciphertextlen);
  if (err)
    {
      log_error ("failed to convert ciphertext: %s\n", gpg_strerror (err));
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  if (DBG_CRYPTO)
    {
      log_printhex (ctrl->keygrip, 20, "keygrip:");
      log_printhex (ciphertext, ciphertextlen, "cipher: ");
    }
  err = agent_key_from_file (ctrl, NULL, desc_text,
                             NULL, &shadow_info,
                             CACHE_MODE_NORMAL, NULL, &s_skey, NULL, NULL);
  if (gpg_err_code (err) == GPG_ERR_NO_SECKEY)
    no_shadow_info = 1;
  else if (err)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  if (shadow_info || no_shadow_info)
    { /* divert operation to the smartcard */

      if (!gcry_sexp_canon_len (ciphertext, ciphertextlen, NULL, NULL))
        {
          err = gpg_error (GPG_ERR_INV_SEXP);
          goto leave;
        }

      if (s_skey && agent_is_tpm2_key (s_skey))
	err = divert_tpm2_pkdecrypt (ctrl, ciphertext, shadow_info,
                                     &buf, &len, r_padding);
      else
        err = divert_pkdecrypt (ctrl, ctrl->keygrip, ciphertext,
                                &buf, &len, r_padding);
      if (err)
        {
          /* We restore the original error (ie. no seckey) is no card
           * has been found and we have no shadow key.  This avoids a
           * surprising "card removed" error code.  */
          if ((gpg_err_code (err) == GPG_ERR_CARD_REMOVED
               || gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
              && no_shadow_info)
            err = gpg_error (GPG_ERR_NO_SECKEY);
          else
            log_error ("smartcard decryption failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      put_membuf_printf (outbuf, "(5:value%u:", (unsigned int)len);
      put_membuf (outbuf, buf, len);
      put_membuf (outbuf, ")", 2);
    }
  else
    { /* No smartcard, but a private key */
/*       if (DBG_CRYPTO ) */
/*         { */
/*           log_debug ("skey: "); */
/*           gcry_sexp_dump (s_skey); */
/*         } */

      err = gcry_pk_decrypt (&s_plain, s_cipher, s_skey);
      if (err)
        {
          log_error ("decryption failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      if (DBG_CRYPTO)
        {
          log_debug ("plain: ");
          gcry_sexp_dump (s_plain);
        }
      len = gcry_sexp_sprint (s_plain, GCRYSEXP_FMT_CANON, NULL, 0);
      log_assert (len);
      buf = xmalloc (len);
      len = gcry_sexp_sprint (s_plain, GCRYSEXP_FMT_CANON, buf, len);
      log_assert (len);
      if (*buf == '(')
        put_membuf (outbuf, buf, len);
      else
        {
          /* Old style libgcrypt: This is only an S-expression
             part. Turn it into a complete S-expression. */
          put_membuf (outbuf, "(5:value", 8);
          put_membuf (outbuf, buf, len);
          put_membuf (outbuf, ")", 2);
        }
    }


 leave:
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_plain);
  gcry_sexp_release (s_cipher);
  xfree (buf);
  xfree (shadow_info);
  return err;
}


/* Reverse BUFFER to change the endianness.  */
static void
reverse_buffer (unsigned char *buffer, unsigned int length)
{
  unsigned int tmp, i;

  for (i=0; i < length/2; i++)
    {
      tmp = buffer[i];
      buffer[i] = buffer[length-1-i];
      buffer[length-1-i] = tmp;
    }
}

/* For composite PGP KEM (ECC+ML-KEM), decrypt CIPHERTEXT using KEM API.
   First keygrip is for ECC, second keygrip is for PQC.  CIPHERTEXT
   should follow the format of:

	(enc-val(pqc(c%d)(e%m)(k%m)(s%m)(fixed-info&)))
        c: cipher identifier (symmetric)
        e: ECDH ciphertext
        k: ML-KEM ciphertext
        s: encrypted session key
        fixed-info: A buffer with the fixed info.

   FIXME: For now, possible keys on smartcard are not supported.
  */
static gpg_error_t
composite_pgp_kem_decrypt (ctrl_t ctrl, const char *desc_text,
                           gcry_sexp_t s_cipher, membuf_t *outbuf)
{
#if GCRYPT_VERSION_NUMBER >= 0x010b00
  gcry_sexp_t s_skey0 = NULL;
  gcry_sexp_t s_skey1 = NULL;
  unsigned char *shadow_info = NULL;
  gpg_error_t err = 0;

  unsigned int nbits;
  const unsigned char *p;
  size_t len;

  int algo;
  gcry_mpi_t encrypted_sessionkey_mpi = NULL;
  const unsigned char *encrypted_sessionkey;
  size_t encrypted_sessionkey_len;

  gcry_mpi_t ecc_sk_mpi = NULL;
  unsigned char ecc_sk[32];
  gcry_mpi_t ecc_pk_mpi = NULL;
  unsigned char ecc_pk[32];
  gcry_mpi_t ecc_ct_mpi = NULL;
  const unsigned char *ecc_ct;
  size_t ecc_ct_len;
  unsigned char ecc_ecdh[32];
  unsigned char ecc_ss[32];

  gcry_mpi_t mlkem_sk_mpi = NULL;
  gcry_mpi_t mlkem_ct_mpi = NULL;
  const unsigned char *mlkem_sk;
  const unsigned char *mlkem_ct;
  unsigned char mlkem_ss[GCRY_KEM_MLKEM768_SHARED_LEN];

  unsigned char kek[32];
  size_t kek_len = 32;        /* AES-256 is mandatory */

  gcry_cipher_hd_t hd;
  unsigned char sessionkey[256];
  size_t sessionkey_len;
  gcry_buffer_t fixed_info = { 0, 0, 0, NULL };

  gcry_sexp_t curve = NULL;
  const char *curve_name;

  err = agent_key_from_file (ctrl, NULL, desc_text,
                             ctrl->keygrip, &shadow_info,
                             CACHE_MODE_NORMAL, NULL, &s_skey0, NULL, NULL);
  if (err)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  err = agent_key_from_file (ctrl, NULL, desc_text,
                             ctrl->keygrip1, &shadow_info,
                             CACHE_MODE_NORMAL, NULL, &s_skey1, NULL, NULL);
  if (err)
    {
      log_error ("failed to read the another secret key\n");
      goto leave;
    }

  /* Here assumes no smartcard, but private keys */

  err = gcry_sexp_extract_param (s_cipher, NULL, "%dc/eks&'fixed-info'",
                                 &algo, &ecc_ct_mpi, &mlkem_ct_mpi,
                                 &encrypted_sessionkey_mpi, &fixed_info, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting parameters failed\n", __func__);
      goto leave;
    }

  len = gcry_cipher_get_algo_keylen (algo);
  encrypted_sessionkey = gcry_mpi_get_opaque (encrypted_sessionkey_mpi, &nbits);
  encrypted_sessionkey_len = (nbits+7)/8;
  if (len == 0 || encrypted_sessionkey_len != len + 8)
    {
      if (opt.verbose)
        log_info ("%s: encrypted session key length %zu"
                  " does not match the length for algo %d\n",
                  __func__, encrypted_sessionkey_len, algo);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  /* Fistly, ECC part.  FIXME: For now, we assume X25519.  */
  curve = gcry_sexp_find_token (s_skey0, "curve", 0);
  if (!curve)
    {
      if (opt.verbose)
        log_info ("%s: no curve given\n", __func__);
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  curve_name = gcry_sexp_nth_data (curve, 1, &len);
  if (len != 10 || memcmp (curve_name, "Curve25519", len))
    {
      if (opt.verbose)
        log_info ("%s: curve '%s' not supported\n", __func__, curve_name);
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  err = gcry_sexp_extract_param (s_skey0, NULL, "/qd",
                                 &ecc_pk_mpi, &ecc_sk_mpi, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting q and d from ECC key failed\n", __func__);
      goto leave;
    }

  p = gcry_mpi_get_opaque (ecc_pk_mpi, &nbits);
  len = (nbits+7)/8;
  if (len != 33)
    {
      if (opt.verbose)
        log_info ("%s: ECC public key length invalid (%zu)\n", __func__, len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  memcpy (ecc_pk, p+1, 32);     /* Remove the 0x40 prefix */
  mpi_release (ecc_pk_mpi);

  p = gcry_mpi_get_opaque (ecc_sk_mpi, &nbits);
  len = (nbits+7)/8;
  if (len > 32)
    {
      if (opt.verbose)
        log_info ("%s: ECC secret key too long (%zu)\n", __func__, len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  memset (ecc_sk, 0, 32);
  memcpy (ecc_sk + 32 - len, p, len);
  reverse_buffer (ecc_sk, 32);
  mpi_release (ecc_sk_mpi);
  ecc_pk_mpi = NULL;
  ecc_sk_mpi = NULL;

  ecc_ct = gcry_mpi_get_opaque (ecc_ct_mpi, &nbits);
  ecc_ct_len = (nbits+7)/8;
  if (ecc_ct_len != 32)
    {
      if (opt.verbose)
        log_info ("%s: ECC cipher text length invalid (%zu)\n",
                   __func__, ecc_ct_len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  err = gcry_kem_decap (GCRY_KEM_RAW_X25519, ecc_sk, 32, ecc_ct, ecc_ct_len,
                        ecc_ecdh, 32, NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_decap for ECC failed\n", __func__);
      goto leave;
    }

  err = gnupg_ecc_kem_kdf (ecc_ss, 32, GCRY_MD_SHA3_256,
                           ecc_ecdh, 32, ecc_ct, 32, ecc_pk, 32);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: kdf for ECC failed\n", __func__);
      goto leave;
    }

  /* Secondly, PQC part.  For now, we assume ML-KEM.  */
  err = gcry_sexp_extract_param (s_skey1, NULL, "/s", &mlkem_sk_mpi, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting s from PQ key failed\n", __func__);
      goto leave;
    }
  mlkem_sk = gcry_mpi_get_opaque (mlkem_sk_mpi, &nbits);
  len = (nbits+7)/8;
  if (len != GCRY_KEM_MLKEM768_SECKEY_LEN)
    {
      if (opt.verbose)
        log_info ("%s: PQ key length invalid (%zu)\n", __func__, len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  mlkem_ct = gcry_mpi_get_opaque (mlkem_ct_mpi, &nbits);
  len = (nbits+7)/8;
  if (len != GCRY_KEM_MLKEM768_CIPHER_LEN)
    {
      if (opt.verbose)
        log_info ("%s: PQ cipher text length invalid (%zu)\n", __func__, len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  err = gcry_kem_decap (GCRY_KEM_MLKEM768,
                        mlkem_sk, GCRY_KEM_MLKEM768_SECKEY_LEN,
                        mlkem_ct, GCRY_KEM_MLKEM768_CIPHER_LEN,
                        mlkem_ss, GCRY_KEM_MLKEM768_SHARED_LEN,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_decap for PQ failed\n", __func__);
      goto leave;
    }

  mpi_release (mlkem_sk_mpi);
  mlkem_sk_mpi = NULL;

  /* Then, combine two shared secrets and ciphertexts into one KEK */
  err = gnupg_kem_combiner (kek, kek_len,
                            ecc_ss, 32, ecc_ct, 32,
                            mlkem_ss, GCRY_KEM_MLKEM768_SHARED_LEN,
                            mlkem_ct, GCRY_KEM_MLKEM768_CIPHER_LEN,
                            fixed_info.data, fixed_info.size);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: KEM combiner failed\n", __func__);
      goto leave;
    }

  mpi_release (ecc_ct_mpi);
  mpi_release (mlkem_ct_mpi);
  ecc_ct_mpi = NULL;
  mlkem_ct_mpi = NULL;

  if (DBG_CRYPTO)
    {
      log_printhex (kek, kek_len, "KEK key: ");
    }

  err = gcry_cipher_open (&hd, GCRY_CIPHER_AES256,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    {
      if (opt.verbose)
        log_error ("ecdh failed to initialize AESWRAP: %s\n",
                   gpg_strerror (err));
      goto leave;
    }

  err = gcry_cipher_setkey (hd, kek, kek_len);

  sessionkey_len = encrypted_sessionkey_len - 8;
  err = gcry_cipher_decrypt (hd, sessionkey, sessionkey_len,
                             encrypted_sessionkey, encrypted_sessionkey_len);
  gcry_cipher_close (hd);

  mpi_release (encrypted_sessionkey_mpi);
  encrypted_sessionkey_mpi = NULL;

  if (err)
    {
      log_error ("KEM decrypt failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  put_membuf_printf (outbuf,
                     "(5:value%u:", (unsigned int)sessionkey_len);
  put_membuf (outbuf, sessionkey, sessionkey_len);
  put_membuf (outbuf, ")", 2);

 leave:
  mpi_release (mlkem_sk_mpi);
  mpi_release (ecc_pk_mpi);
  mpi_release (ecc_sk_mpi);
  mpi_release (ecc_ct_mpi);
  mpi_release (mlkem_ct_mpi);
  mpi_release (encrypted_sessionkey_mpi);
  gcry_free (fixed_info.data);
  gcry_sexp_release (curve);
  gcry_sexp_release (s_skey0);
  gcry_sexp_release (s_skey1);
  return err;
#else
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}

/* DECRYPT the encrypted stuff (like encrypted session key) in
   CIPHERTEXT using KEM API, with KEMID.  Keys (or a key) are
   specified in CTRL.  DESC_TEXT is used to retrieve private key.
   OPTION can be specified for upper layer option for KEM.  Decrypted
   stuff (like session key) is written to OUTBUF.
 */
gpg_error_t
agent_kem_decrypt (ctrl_t ctrl, const char *desc_text, int kemid,
                   const unsigned char *ciphertext, size_t ciphertextlen,
                   const unsigned char *option, size_t optionlen,
                   membuf_t *outbuf)
{
  gcry_sexp_t s_cipher = NULL;
  gpg_error_t err = 0;

  /* For now, only PQC-PGP is supported.  */
  if (kemid != KEM_PQC_PGP)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  (void)optionlen;
  if (kemid == KEM_PQC_PGP && option)
    {
      log_error ("PQC-PGP requires no option\n");
      return gpg_error (GPG_ERR_INV_ARG);
    }

  if (!ctrl->have_keygrip)
    {
      log_error ("speculative decryption not yet supported\n");
      return gpg_error (GPG_ERR_NO_SECKEY);
    }

  if (!ctrl->have_keygrip1)
    {
      log_error ("Composite KEM requires two KEYGRIPs\n");
      return gpg_error (GPG_ERR_NO_SECKEY);
    }

  err = gcry_sexp_sscan (&s_cipher, NULL, (char*)ciphertext, ciphertextlen);
  if (err)
    {
      log_error ("failed to convert ciphertext: %s\n", gpg_strerror (err));
      return gpg_error (GPG_ERR_INV_DATA);
    }

  if (DBG_CRYPTO)
    {
      log_printhex (ctrl->keygrip, 20, "keygrip0:");
      log_printhex (ctrl->keygrip1, 20, "keygrip1:");
      gcry_log_debugsxp ("cipher", s_cipher);
    }

  err = composite_pgp_kem_decrypt (ctrl, desc_text, s_cipher, outbuf);

  gcry_sexp_release (s_cipher);
  return err;
}
