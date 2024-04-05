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

/* For hybrid PGP KEM (ECC+ML-KEM), decrypt CIPHERTEXT using KEM API.
   First keygrip is for ECC, second keygrip is for PQC.  CIPHERTEXT
   should follow the format of:

	(enc-val(pqc(s%m)(e%m)(k%m))))
        s: encrypted session key
        e: ECDH ciphertext
        k: ML-KEM ciphertext

   FIXME: For now, possibile keys on smartcard are not supported.
  */
static gpg_error_t
agent_hybrid_pgp_kem_decrypt (ctrl_t ctrl, const char *desc_text,
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

  gcry_mpi_t encrypted_sessionkey_mpi;
  const unsigned char *encrypted_sessionkey;
  size_t encrypted_sessionkey_len;

  gcry_mpi_t ecc_sk_mpi;
  unsigned char ecc_sk[32];
  gcry_mpi_t ecc_pk_mpi;
  unsigned char ecc_pk[32];
  gcry_mpi_t ecc_ct_mpi;
  const unsigned char *ecc_ct;
  size_t ecc_ct_len;
  unsigned char ecc_ecdh[32];
  unsigned char ecc_ss[32];

  gcry_mpi_t mlkem_sk_mpi;
  gcry_mpi_t mlkem_ct_mpi;
  const unsigned char *mlkem_sk;
  const unsigned char *mlkem_ct;
  unsigned char mlkem_ss[GCRY_KEM_MLKEM768_SHARED_LEN];

  gcry_buffer_t iov[6];

  unsigned char kekkey[32];
  size_t kekkeylen = 32;        /* AES-256 is mandatory */

  gcry_cipher_hd_t hd;
  unsigned char sessionkey[256];
  size_t sessionkey_len;
  const unsigned char fixedinfo[1] = { 105 };

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

  gcry_sexp_extract_param (s_cipher, NULL, "/e/k/s",
                           &ecc_ct_mpi,
                           &mlkem_ct_mpi,
                           &encrypted_sessionkey_mpi, NULL);

  encrypted_sessionkey = gcry_mpi_get_opaque (encrypted_sessionkey_mpi, &nbits);
  encrypted_sessionkey_len = (nbits+7)/8;
  encrypted_sessionkey_len--;

  if (encrypted_sessionkey[0] != encrypted_sessionkey_len)
    {
      err = GPG_ERR_INV_DATA;
      goto leave;
    }
  encrypted_sessionkey++;       /* Skip the length.  */

  if (encrypted_sessionkey[0] != CIPHER_ALGO_AES256)
    {
      err = GPG_ERR_INV_DATA;
      goto leave;
    }
  encrypted_sessionkey_len--;
  encrypted_sessionkey++;       /* Skip the sym algo */

  /* Fistly, ECC part.  FIXME: For now, we assume X25519.  */
  gcry_sexp_extract_param (s_skey0, NULL, "/q/d",
                           &ecc_pk_mpi, &ecc_sk_mpi, NULL);
  p = gcry_mpi_get_opaque (ecc_pk_mpi, &nbits);
  len = (nbits+7)/8;
  memcpy (ecc_pk, p+1, 32);     /* Remove the 0x40 prefix */
  p = gcry_mpi_get_opaque (ecc_sk_mpi, &nbits);
  len = (nbits+7)/8;
  if (len > 32)
    {
      err = GPG_ERR_INV_DATA;
      goto leave;
    }
  memset (ecc_sk, 0, 32);
  memcpy (ecc_sk + 32 - len, p, len);
  reverse_buffer (ecc_sk, 32);
  mpi_release (ecc_pk_mpi);
  mpi_release (ecc_sk_mpi);

  ecc_ct = gcry_mpi_get_opaque (ecc_ct_mpi, &nbits);
  ecc_ct_len = (nbits+7)/8;
  if (ecc_ct_len != 32)
    {
      err = GPG_ERR_INV_DATA;
      goto leave;
    }

  err = gcry_kem_decap (GCRY_KEM_RAW_X25519, ecc_sk, 32, ecc_ct, ecc_ct_len,
                        ecc_ecdh, 32, NULL, 0);

  iov[0].data = ecc_ecdh;
  iov[0].off = 0;
  iov[0].len = 32;
  iov[1].data = (unsigned char *)ecc_ct;
  iov[1].off = 0;
  iov[1].len = 32;
  iov[2].data = ecc_pk;
  iov[2].off = 0;
  iov[2].len = 32;
  gcry_md_hash_buffers (GCRY_MD_SHA3_256, 0, ecc_ss, iov, 3);

  /* Secondly, PQC part.  For now, we assume ML-KEM.  */
  gcry_sexp_extract_param (s_skey1, NULL, "/s", &mlkem_sk_mpi, NULL);
  mlkem_sk = gcry_mpi_get_opaque (mlkem_sk_mpi, &nbits);
  len = (nbits+7)/8;
  if (len != GCRY_KEM_MLKEM768_SECKEY_LEN)
    {
      err = GPG_ERR_INV_DATA;
      goto leave;
    }
  mlkem_ct = gcry_mpi_get_opaque (mlkem_ct_mpi, &nbits);
  len = (nbits+7)/8;
  if (len != GCRY_KEM_MLKEM768_CIPHER_LEN)
    {
      err = GPG_ERR_INV_DATA;
      goto leave;
    }
  err = gcry_kem_decap (GCRY_KEM_MLKEM768,
                        mlkem_sk, GCRY_KEM_MLKEM768_SECKEY_LEN,
                        mlkem_ct, GCRY_KEM_MLKEM768_CIPHER_LEN,
                        mlkem_ss, GCRY_KEM_MLKEM768_SHARED_LEN,
                        NULL, 0);

  mpi_release (mlkem_sk_mpi);

  /* Then, combine two shared secrets into one */

  iov[0].data = "\x00\x00\x00\x01"; /* Counter */
  iov[0].off = 0;
  iov[0].len = 4;

  iov[1].data = ecc_ss;
  iov[1].off = 0;
  iov[1].len = 32;

  iov[2].data = (unsigned char *)ecc_ct;
  iov[2].off = 0;
  iov[2].len = 32;

  iov[3].data = mlkem_ss;
  iov[3].off = 0;
  iov[3].len = GCRY_KEM_MLKEM768_SHARED_LEN;

  iov[4].data = (unsigned char *)mlkem_ct;
  iov[4].off = 0;
  iov[4].len = GCRY_KEM_MLKEM768_ENCAPS_LEN;

  iov[5].data = (unsigned char *)fixedinfo;
  iov[5].off = 0;
  iov[5].len = 1;

  err = compute_kmac256 (kekkey, kekkeylen,
                         "OpenPGPCompositeKeyDerivationFunction", 37,
                         "KDF", 3, iov, 6);

  mpi_release (ecc_ct_mpi);
  mpi_release (mlkem_ct_mpi);

  if (DBG_CRYPTO)
    {
      log_printhex (kekkey, kekkeylen, "KEK key: ");
    }

  err = gcry_cipher_open (&hd, GCRY_CIPHER_AES256,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    {
      log_error ("ecdh failed to initialize AESWRAP: %s\n",
                 gpg_strerror (err));
      mpi_release (encrypted_sessionkey_mpi);
      goto leave;
    }

  err = gcry_cipher_setkey (hd, kekkey, kekkeylen);

  sessionkey_len = encrypted_sessionkey_len - 8;
  err = gcry_cipher_decrypt (hd, sessionkey, sessionkey_len,
                             encrypted_sessionkey, encrypted_sessionkey_len);
  gcry_cipher_close (hd);

  mpi_release (encrypted_sessionkey_mpi);

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
      log_error ("hybrid KEM requires two KEYGRIPs\n");
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
      log_printhex (ctrl->keygrip, 20, "keygrip:");
      log_printhex (ctrl->keygrip1, 20, "keygrip1:");
      log_printhex (ciphertext, ciphertextlen, "cipher: ");
    }

  err = agent_hybrid_pgp_kem_decrypt (ctrl, desc_text, s_cipher, outbuf);

  gcry_sexp_release (s_cipher);
  return err;
}
