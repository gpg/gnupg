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
#include "../common/util.h"


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
  if (err && gpg_err_code (err) != GPG_ERR_NO_SECKEY)
    {
      log_error ("failed to read the secret key\n");
    }
  else if (shadow_info
           || err /* gpg_err_code (err) == GPG_ERR_NO_SECKEY */)
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
          /* We restore the original error (ie. no seckey) as no card
           * has been found and we have no shadow key.  This avoids a
           * surprising "card removed" error code.  */
          if ((gpg_err_code (err) == GPG_ERR_CARD_REMOVED
               || gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
              && !shadow_info)
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


static gpg_error_t
ecc_extract_pk_from_key (const struct gnupg_ecc_params *ecc,
                         gcry_sexp_t s_skey, unsigned char *ecc_pk)
{
  gpg_error_t err;
  unsigned int nbits;
  const unsigned char *p;
  size_t len;
  gcry_mpi_t ecc_pk_mpi = NULL;

  err = gcry_sexp_extract_param (s_skey, NULL, "/q", &ecc_pk_mpi, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting q and d from ECC key failed\n", __func__);
      return err;
    }

  p = gcry_mpi_get_opaque (ecc_pk_mpi, &nbits);
  len = (nbits+7)/8;
  if (len != ecc->pubkey_len)
    {
      if (opt.verbose)
        log_info ("%s: ECC public key length invalid (%zu)\n", __func__, len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  else if (len == ecc->point_len)
    memcpy (ecc_pk, p, ecc->point_len);
  else if (len == ecc->point_len + 1 && p[0] == 0x40)
    /* Remove the 0x40 prefix (for Curve25519) */
    memcpy (ecc_pk, p+1, ecc->point_len);
  else
    {
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  if (DBG_CRYPTO)
    log_printhex (ecc_pk, ecc->pubkey_len, "ECC   pubkey:");

 leave:
  mpi_release (ecc_pk_mpi);
  return err;
}

static gpg_error_t
ecc_extract_sk_from_key (const struct gnupg_ecc_params *ecc,
                         gcry_sexp_t s_skey, unsigned char *ecc_sk)
{
  gpg_error_t err;
  unsigned int nbits;
  const unsigned char *p;
  size_t len;
  gcry_mpi_t ecc_sk_mpi = NULL;

  err = gcry_sexp_extract_param (s_skey, NULL, "/d", &ecc_sk_mpi, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting d from ECC key failed\n", __func__);
      return err;
    }

  p = gcry_mpi_get_opaque (ecc_sk_mpi, &nbits);
  len = (nbits+7)/8;
  if (len > ecc->scalar_len)
    {
      if (opt.verbose)
        log_info ("%s: ECC secret key too long (%zu)\n", __func__, len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  memset (ecc_sk, 0, ecc->scalar_len - len);
  memcpy (ecc_sk + ecc->scalar_len - len, p, len);
  if (ecc->scalar_reverse)
    reverse_buffer (ecc_sk, ecc->scalar_len);
  mpi_release (ecc_sk_mpi);
  ecc_sk_mpi = NULL;

  if (DBG_CRYPTO)
    log_printhex (ecc_sk, ecc->scalar_len, "ECC   seckey:");

 leave:
  mpi_release (ecc_sk_mpi);
  return err;
}

static gpg_error_t
ecc_raw_kem (const struct gnupg_ecc_params *ecc, gcry_sexp_t s_skey,
             const unsigned char *ecc_ct, unsigned char *ecc_ecdh)
{
  gpg_error_t err = 0;
  unsigned char ecc_sk[ECC_SCALAR_LEN_MAX];

  if (ecc->scalar_len > ECC_SCALAR_LEN_MAX)
    {
      if (opt.verbose)
        log_info ("%s: ECC scalar length invalid (%zu)\n",
                  __func__, ecc->scalar_len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  err = ecc_extract_sk_from_key  (ecc, s_skey, ecc_sk);
  if (err)
    goto leave;

  err = gcry_kem_decap (ecc->kem_algo, ecc_sk, ecc->scalar_len,
                        ecc_ct, ecc->point_len, ecc_ecdh, ecc->point_len,
                        NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: gcry_kem_decap for ECC failed\n", __func__);
    }

 leave:
  wipememory (ecc_sk, sizeof ecc_sk);

  return err;
}

static gpg_error_t
get_cardkey (ctrl_t ctrl, const char *keygrip, gcry_sexp_t *r_s_pk)
{
  gpg_error_t err;
  unsigned char *pkbuf;
  size_t pkbuflen;

  err = agent_card_readkey (ctrl, keygrip, &pkbuf, NULL);
  if (err)
    return err;

  pkbuflen = gcry_sexp_canon_len (pkbuf, 0, NULL, NULL);
  err = gcry_sexp_sscan (r_s_pk, NULL, (char*)pkbuf, pkbuflen);
  if (err)
    log_error ("failed to build S-Exp from received card key: %s\n",
               gpg_strerror (err));

  xfree (pkbuf);
  return err;
}

static gpg_error_t
ecc_get_curve (ctrl_t ctrl, gcry_sexp_t s_skey, const char **r_curve)
{
  gpg_error_t err = 0;
  gcry_sexp_t s_skey_card = NULL;
  const char *curve = NULL;
  gcry_sexp_t key;

  *r_curve = NULL;

  if (!s_skey)
    {
      err = get_cardkey (ctrl, ctrl->keygrip, &s_skey_card);
      if (err)
        goto leave;

      key = s_skey_card;
    }
  else
    key = s_skey;

  curve = get_ecc_curve_from_key (key);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_BAD_SECKEY);
      goto leave;
    }

  *r_curve = curve;

 leave:
  gcry_sexp_release (s_skey_card);
  return err;
}

/* Given a private key in SEXP by S_SKEY0 and a cipher text by ECC_CT
 * with length ECC_POINT_LEN, do ECC KEM decap (== raw ECDH)
 * operation.  Result is returned in the memory referred by ECC_ECDH.
 * Public key is extracted and put into ECC_PK.  The pointer to ECC
 * parameters is stored into R_ECC.  SHADOW_INFO0 is used to determine
 * if the private key is actually on smartcard.  CTRL is used to
 * access smartcard, internally.  */
static gpg_error_t
ecc_pgp_kem_decap (ctrl_t ctrl, gcry_sexp_t s_skey0,
                   const unsigned char *shadow_info0,
                   const unsigned char *ecc_ct, size_t ecc_point_len,
                   unsigned char ecc_ecdh[ECC_POINT_LEN_MAX],
                   unsigned char ecc_pk[ECC_POINT_LEN_MAX],
                   const struct gnupg_ecc_params **r_ecc)
{
  gpg_error_t err;
  const char *curve;
  const struct gnupg_ecc_params *ecc = NULL;

  if (ecc_point_len > ECC_POINT_LEN_MAX)
    return gpg_error (GPG_ERR_INV_DATA);

  err = ecc_get_curve (ctrl, s_skey0, &curve);
  if (err)
    {
      if ((gpg_err_code (err) == GPG_ERR_CARD_REMOVED
           || gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)
          && !s_skey0)
        err = gpg_error (GPG_ERR_NO_SECKEY);
      return err;
    }

  if (DBG_CRYPTO)
    log_debug ("ECC    curve: %s\n", curve);

  ecc = gnupg_get_ecc_params (curve);
  if (!ecc)
    {
      if (opt.verbose)
        log_info ("%s: curve '%s' not supported\n", __func__, curve);
      return gpg_error (GPG_ERR_BAD_SECKEY);
    }
  *r_ecc = ecc;

  if (ecc->may_have_prefix && ecc_point_len == ecc->point_len + 1
      && *ecc_ct == 0x40)
    {
      ecc_ct++;
      ecc_point_len--;
    }

  if (ecc->point_len != ecc_point_len)
    {
      if (opt.verbose)
        log_info ("%s: ECC cipher text length invalid (%zu != %zu)\n",
                  __func__, ecc->point_len, ecc_point_len);
      return gpg_error (GPG_ERR_INV_DATA);
    }

  err = ecc_extract_pk_from_key  (ecc, s_skey0, ecc_pk);
  if (err)
    return err;

  if (DBG_CRYPTO)
    log_printhex (ecc_ct, ecc->point_len, "ECC    ephem:");

  if (shadow_info0 || !s_skey0)
    {
      if (s_skey0 && agent_is_tpm2_key (s_skey0))
        {
          err = agent_tpm2d_ecc_kem (ctrl, shadow_info0,
                                     ecc_ct, ecc->point_len, ecc_ecdh);
          if (err)
            {
              log_error ("TPM decryption failed: %s\n", gpg_strerror (err));
              return err;
            }
        }
      else
        {
          err = agent_card_ecc_kem (ctrl, ecc_ct, ecc->point_len, ecc_ecdh);
          if (err)
            {
              log_error ("smartcard decryption failed: %s\n",
                         gpg_strerror (err));
              return err;
            }
        }
    }
  else
    err = ecc_raw_kem (ecc, s_skey0, ecc_ct, ecc_ecdh);

  if (err)
    return err;

  if (DBG_CRYPTO)
    log_printhex (ecc_ecdh, ecc_point_len, "ECC     ecdh:");

  return 0;
}

/* For composite PGP KEM (ECC+ML-KEM), decrypt CIPHERTEXT using KEM API.
   First keygrip is for ECC, second keygrip is for PQC.  CIPHERTEXT
   should follow the format of:

	(enc-val(pqc(c%d)(e%m)(k%m)(s%m)(fixed-info&)))
        c: cipher identifier (of session key (wrapped key))
        e: ECDH ciphertext
        k: ML-KEM ciphertext
        s: encrypted session key
        fixed-info: A buffer with the fixed info.

   FIXME: For now, possible PQC key on smartcard is not yet supported.
  */
static gpg_error_t
composite_pgp_kem_decrypt (ctrl_t ctrl, const char *desc_text,
                           gcry_sexp_t s_cipher, membuf_t *outbuf)
{
  gcry_sexp_t s_skey0 = NULL;
  gcry_sexp_t s_skey1 = NULL;
  unsigned char *shadow_info0 = NULL;
  unsigned char *shadow_info1 = NULL;
  gpg_error_t err = 0;

  unsigned int nbits;
  size_t len;

  int algo;
  gcry_mpi_t encrypted_sessionkey_mpi = NULL;
  const unsigned char *encrypted_sessionkey;
  size_t encrypted_sessionkey_len;

  gcry_mpi_t ecc_ct_mpi = NULL;
  const unsigned char *ecc_ct;
  size_t ecc_ct_len;
  unsigned char ecc_ecdh[ECC_POINT_LEN_MAX];
  unsigned char ecc_pk[ECC_POINT_LEN_MAX];
  unsigned char ecc_ss[ECC_HASH_LEN_MAX];
  int ecc_hashalgo;
  size_t ecc_shared_len, ecc_point_len;
  const struct gnupg_ecc_params *ecc;

  enum gcry_kem_algos mlkem_kem_algo;
  gcry_mpi_t mlkem_sk_mpi = NULL;
  gcry_mpi_t mlkem_ct_mpi = NULL;
  const unsigned char *mlkem_sk;
  size_t mlkem_sk_len;
  const unsigned char *mlkem_ct;
  size_t mlkem_ct_len;
  unsigned char mlkem_ss[GCRY_KEM_MLKEM1024_SHARED_LEN];
  size_t mlkem_ss_len;

  unsigned char kek[32];
  size_t kek_len = 32;        /* AES-256 is mandatory */

  gcry_cipher_hd_t hd;
  unsigned char sessionkey[256];
  size_t sessionkey_len;
  gcry_buffer_t fixed_info = { 0, 0, 0, NULL };

  err = agent_key_from_file (ctrl, NULL, desc_text,
                             NULL, &shadow_info0,
                             CACHE_MODE_NORMAL, NULL, &s_skey0, NULL, NULL);
  if (err && gpg_err_code (err) != GPG_ERR_NO_SECKEY)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  err = agent_key_from_file (ctrl, NULL, desc_text,
                             ctrl->keygrip1, &shadow_info1,
                             CACHE_MODE_NORMAL, NULL, &s_skey1, NULL, NULL);
  /* Here assumes no smartcard for ML-KEM, but private key in a file.  */
  if (err)
    {
      log_error ("failed to read the another secret key\n");
      goto leave;
    }

  err = gcry_sexp_extract_param (s_cipher, NULL, "%dc/eks&'fixed-info'",
                                 &algo, &ecc_ct_mpi, &mlkem_ct_mpi,
                                 &encrypted_sessionkey_mpi, &fixed_info, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting parameters failed\n", __func__);
      goto leave;
    }

  ecc_ct = gcry_mpi_get_opaque (ecc_ct_mpi, &nbits);
  ecc_ct_len = (nbits+7)/8;

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

  /* Firstly, ECC part.  */
  ecc_point_len = ecc_ct_len;
  err = ecc_pgp_kem_decap (ctrl, s_skey0, shadow_info0, ecc_ct, ecc_point_len,
                           ecc_ecdh, ecc_pk, &ecc);
  if (err)
    goto leave;
  ecc_hashalgo = ecc->hash_algo;
  ecc_shared_len = gcry_md_get_algo_dlen (ecc_hashalgo);
  err = gnupg_ecc_kem_kdf (ecc_ss, ecc_shared_len, ecc_hashalgo,
                           ecc_ecdh, ecc_point_len, ecc_ct, ecc_point_len,
                           ecc_pk, ecc_point_len, NULL, 0);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: kdf for ECC failed\n", __func__);
      goto leave;
    }
  wipememory (ecc_ecdh, sizeof ecc_ecdh);
  if (DBG_CRYPTO)
    log_printhex (ecc_ss, ecc_shared_len, "ECC   shared:");

  /* Secondly, PQC part.  For now, we assume ML-KEM.  */
  err = gcry_sexp_extract_param (s_skey1, NULL, "/s", &mlkem_sk_mpi, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting s from PQ key failed\n", __func__);
      goto leave;
    }
  mlkem_sk = gcry_mpi_get_opaque (mlkem_sk_mpi, &nbits);
  mlkem_sk_len = (nbits+7)/8;
  if (mlkem_sk_len == GCRY_KEM_MLKEM512_SECKEY_LEN)
    {
      mlkem_kem_algo = GCRY_KEM_MLKEM512;
      mlkem_ss_len   = GCRY_KEM_MLKEM512_SHARED_LEN;
      mlkem_ct_len   = GCRY_KEM_MLKEM512_CIPHER_LEN;
    }
  else if (mlkem_sk_len == GCRY_KEM_MLKEM768_SECKEY_LEN)
    {
      mlkem_kem_algo = GCRY_KEM_MLKEM768;
      mlkem_ss_len   = GCRY_KEM_MLKEM768_SHARED_LEN;
      mlkem_ct_len   = GCRY_KEM_MLKEM768_CIPHER_LEN;
    }
  else if (mlkem_sk_len == GCRY_KEM_MLKEM1024_SECKEY_LEN)
    {
      mlkem_kem_algo = GCRY_KEM_MLKEM1024;
      mlkem_ss_len   = GCRY_KEM_MLKEM1024_SHARED_LEN;
      mlkem_ct_len   = GCRY_KEM_MLKEM1024_CIPHER_LEN;
    }
  else
    {
      if (opt.verbose)
        log_info ("%s: PQ key length invalid (%zu)\n", __func__, mlkem_sk_len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  mlkem_ct = gcry_mpi_get_opaque (mlkem_ct_mpi, &nbits);
  len = (nbits+7)/8;
  if (len != mlkem_ct_len)
    {
      if (opt.verbose)
        log_info ("%s: PQ cipher text length invalid (%zu)\n",
                  __func__, mlkem_ct_len);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }
  err = gcry_kem_decap (mlkem_kem_algo, mlkem_sk, mlkem_sk_len,
                        mlkem_ct, mlkem_ct_len, mlkem_ss, mlkem_ss_len,
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
                            ecc_ss, ecc_shared_len, ecc_ct, ecc_point_len,
                            mlkem_ss, mlkem_ss_len, mlkem_ct, mlkem_ct_len,
                            fixed_info.data, fixed_info.size);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: KEM combiner failed\n", __func__);
      goto leave;
    }

  mpi_release (ecc_ct_mpi);
  ecc_ct_mpi = NULL;
  mpi_release (mlkem_ct_mpi);
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
  if (!err)
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
  wipememory (ecc_ss, sizeof ecc_ss);
  wipememory (mlkem_ss, sizeof mlkem_ss);
  wipememory (kek, sizeof kek);
  wipememory (sessionkey, sizeof sessionkey);

  mpi_release (ecc_ct_mpi);
  mpi_release (mlkem_sk_mpi);
  mpi_release (mlkem_ct_mpi);
  mpi_release (encrypted_sessionkey_mpi);
  gcry_free (fixed_info.data);
  gcry_sexp_release (s_skey0);
  gcry_sexp_release (s_skey1);
  xfree (shadow_info0);
  xfree (shadow_info1);
  return err;
}

/* For ECC PGP KEM, decrypt CIPHERTEXT using KEM API.  CIPHERTEXT
   should follow the format of:

	(enc-val(ecc(c%d)(h%d)(e%m)(s%m)(kdf-params&)))
        c: cipher identifier (of wrapping key)
        h: hash identifier
        e: ECDH ciphertext
        s: encrypted session key
        fixed-info: A buffer with the fixed info (the KDF parameters).

  */
static gpg_error_t
ecc_kem_decrypt (ctrl_t ctrl, const char *desc_text,
                 gcry_sexp_t s_cipher, membuf_t *outbuf)
{
  gcry_sexp_t s_skey = NULL;
  unsigned char *shadow_info = NULL;
  gpg_error_t err = 0;

  unsigned int nbits;

  int algo;
  int hashalgo;
  gcry_mpi_t encrypted_sessionkey_mpi = NULL;
  const unsigned char *encrypted_sessionkey;
  size_t encrypted_sessionkey_len;

  gcry_mpi_t ecc_ct_mpi = NULL;
  const unsigned char *ecc_ct;
  size_t ecc_ct_len;
  unsigned char ecc_ecdh[ECC_POINT_LEN_MAX];
  unsigned char ecc_pk[ECC_POINT_LEN_MAX];
  size_t ecc_point_len;
  const struct gnupg_ecc_params *ecc;

  unsigned char *kek = NULL;
  size_t kek_len;

  gcry_cipher_hd_t hd;
  unsigned char sessionkey[256];
  size_t sessionkey_len;
  gcry_buffer_t kdf_params = { 0, 0, 0, NULL };

  err = agent_key_from_file (ctrl, NULL, desc_text,
                             NULL, &shadow_info,
                             CACHE_MODE_NORMAL, NULL, &s_skey, NULL, NULL);
  if (err && gpg_err_code (err) != GPG_ERR_NO_SECKEY)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  err = gcry_sexp_extract_param (s_cipher, NULL, "%dc%dh/es&'kdf-params'",
                                 &algo, &hashalgo, &ecc_ct_mpi,
                                 &encrypted_sessionkey_mpi, &kdf_params, NULL);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: extracting parameters failed\n", __func__);
      goto leave;
    }

  if (!kdf_params.data)
    {
      if (opt.verbose)
        log_info ("%s: the KDF parameters is required\n", __func__);
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  ecc_ct = gcry_mpi_get_opaque (ecc_ct_mpi, &nbits);
  ecc_ct_len = (nbits+7)/8;

  encrypted_sessionkey = gcry_mpi_get_opaque (encrypted_sessionkey_mpi, &nbits);
  encrypted_sessionkey_len = (nbits+7)/8;

  kek_len = gcry_cipher_get_algo_keylen (algo);
  if (kek_len == 0 || kek_len > gcry_md_get_algo_dlen (hashalgo))
    {
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  kek = xtrymalloc (kek_len);
  if (!kek)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  ecc_point_len = ecc_ct_len;
  err = ecc_pgp_kem_decap (ctrl, s_skey, shadow_info,
                           ecc_ct, ecc_point_len,
                           ecc_ecdh, ecc_pk, &ecc);
  if (err)
    goto leave;
  err = gnupg_ecc_kem_kdf (kek, kek_len, hashalgo,
                           ecc->point_len > ecc->scalar_len ?
                           /* For Weierstrass curve, extract
                              x-component from the point.  */
                           ecc_ecdh + 1 : ecc_ecdh,
                           ecc->scalar_len, ecc_ct, ecc_point_len,
                           ecc_pk, ecc_point_len,
                           (char *)kdf_params.data+kdf_params.off,
                           kdf_params.len);
  if (err)
    {
      if (opt.verbose)
        log_info ("%s: kdf for ECC failed\n", __func__);
      goto leave;
    }
  wipememory (ecc_ecdh, sizeof ecc_ecdh);
  if (DBG_CRYPTO)
    {
      log_printhex (kek, kek_len, "KEK key: ");
    }

  err = gcry_cipher_open (&hd, algo, GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    {
      if (opt.verbose)
        log_error ("ecdh failed to initialize AESWRAP: %s\n",
                   gpg_strerror (err));
      goto leave;
    }

  if (encrypted_sessionkey[0] != encrypted_sessionkey_len - 1)
    {
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  err = gcry_cipher_setkey (hd, kek, kek_len);
  sessionkey_len = encrypted_sessionkey_len - 8 - 1;
  if (!err)
    err = gcry_cipher_decrypt (hd, sessionkey, sessionkey_len,
                               encrypted_sessionkey + 1,
                               encrypted_sessionkey_len - 1);
  gcry_cipher_close (hd);

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
  wipememory (sessionkey, sizeof sessionkey);
  wipememory (kek, sizeof kek);
  xfree (kek);
  mpi_release (ecc_ct_mpi);
  mpi_release (encrypted_sessionkey_mpi);
  gcry_free (kdf_params.data);
  gcry_sexp_release (s_skey);
  xfree (shadow_info);
  return err;
}


/* DECRYPT the encrypted stuff (like encrypted session key) in
 * CIPHERTEXT using KEM API, with KEMID.  Keys (or a key) are
 * specified in CTRL.  DESC_TEXT is used to retrieve private key.
 * OPTION can be specified for upper layer option for KEM.  Decrypted
 * stuff (like session key) is written to OUTBUF.  For now,
 * KEMID==KEM_CMS is _not_ yet supported.
 */
gpg_error_t
agent_kem_decrypt (ctrl_t ctrl, const char *desc_text, int kemid,
                   const unsigned char *ciphertext, size_t ciphertextlen,
                   const unsigned char *option, size_t optionlen,
                   membuf_t *outbuf)
{
  gcry_sexp_t s_cipher = NULL;
  gpg_error_t err = 0;

  (void)optionlen;

  err = gcry_sexp_sscan (&s_cipher, NULL, (char*)ciphertext, ciphertextlen);
  if (err)
    {
      log_error ("failed to convert ciphertext: %s\n", gpg_strerror (err));
      return gpg_error (GPG_ERR_INV_DATA);
    }

  if (option)
    {
      log_error ("KEM (%d) requires no option\n", kemid);
      err = gpg_error (GPG_ERR_INV_ARG);
      goto leave;
    }

  if (kemid == KEM_PGP)
    err = ecc_kem_decrypt  (ctrl, desc_text, s_cipher, outbuf);
  else if (kemid == KEM_PQC_PGP)
    {
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

      if (DBG_CRYPTO)
        {
          log_printhex (ctrl->keygrip, 20, "keygrip0:");
          log_printhex (ctrl->keygrip1, 20, "keygrip1:");
          gcry_log_debugsxp ("cipher", s_cipher);
        }

      err = composite_pgp_kem_decrypt (ctrl, desc_text, s_cipher, outbuf);
    }

 leave:
  gcry_sexp_release (s_cipher);
  return err;
}
