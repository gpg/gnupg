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
agent_hybrid_kem_decap (ctrl_t ctrl, const char *desc_text, int kemid,
                        gcry_sexp_t s_cipher, membuf_t *outbuf)
{
  gcry_sexp_t s_skey0 = NULL;
  gcry_sexp_t s_skey1 = NULL;
  unsigned char *shadow_info = NULL;
  gpg_error_t err = 0;
  int no_shadow_info = 0;

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

  gcry_buffer_t iov[13];
  unsigned char head136[2];
  unsigned char headK[2];
  const unsigned char pad[95] = { 0 };
  unsigned char right_encode_L[3];

  unsigned char kekkey[16];
  size_t kekkeylen = 16;        /* AES, perhaps */

  gcry_cipher_hd_t hd;
  unsigned char sessionkey_encoded[256];
  size_t sessionkey_encoded_len;
  const unsigned char fixedinfo[1] = { 105 };

  (void)kemid; /* For now, only PGP.  */
  /*
    (enc-val(pqc(s%m)(e%m)(k%m))))
  */
  err = agent_key_from_file (ctrl, NULL, desc_text,
                             NULL, &shadow_info,
                             CACHE_MODE_NORMAL, NULL, &s_skey0, NULL, NULL);
  if (gpg_err_code (err) == GPG_ERR_NO_SECKEY)
    no_shadow_info = 1;
  else if (err)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  if (shadow_info || no_shadow_info)
    { /* divert operation to the smartcard */
      err = gpg_error (GPG_ERR_NO_SECKEY); /* Not implemented yet.  */
      goto leave;
    }

  err = agent_key_from_file (ctrl, NULL, desc_text,
                             NULL, &shadow_info,
                             CACHE_MODE_NORMAL, NULL, &s_skey1, NULL, NULL);
  if (gpg_err_code (err) == GPG_ERR_NO_SECKEY)
    no_shadow_info = 1;
  else if (err)
    {
      log_error ("failed to read the secret key\n");
      goto leave;
    }

  if (shadow_info || no_shadow_info)
    { /* divert operation to the smartcard */
      err = gpg_error (GPG_ERR_NO_SECKEY); /* Not implemented yet.  */
      goto leave;
    }

  /* No smartcard, but private keys */


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
  encrypted_sessionkey++;

  /* Fistly, ECC.  */
  gcry_sexp_extract_param (s_skey0, NULL, "/q/d",
                           &ecc_pk_mpi, &ecc_sk_mpi, NULL);
  p = gcry_mpi_get_opaque (ecc_pk_mpi, &nbits);
  len = (nbits+7)/8;
  memcpy (ecc_pk, p+1, 32);
  p = gcry_mpi_get_opaque (ecc_sk_mpi, &nbits);
  len = (nbits+7)/8;
  memset (ecc_sk, 0, 32);
  memcpy (ecc_sk + 32 - len, p, len);
  reverse_buffer (ecc_sk, 32);
  mpi_release (ecc_pk_mpi);
  mpi_release (ecc_sk_mpi);

  ecc_ct = gcry_mpi_get_opaque (ecc_ct_mpi, &nbits);
  ecc_ct_len = (nbits+7)/8;
  /* Remove the 0x40 prefix*/
  ecc_ct++;
  ecc_ct_len--;
  /*FIXME make sure the lengths are all correct.  */
  /*FIXME: check the internal of optional to determine the KEK-algo and KEKKEYLEN.  */
  err = gcry_kem_decap (GCRY_KEM_RAW_X25519,
                        ecc_sk, 32,
                        ecc_ct, ecc_ct_len,
                        ecc_ecdh, 32,
                        NULL, 0);
  mpi_release (ecc_ct_mpi);

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

  /* Secondly, ML-KEM */
  gcry_sexp_extract_param (s_skey1, NULL, "/s", &mlkem_sk_mpi, NULL);
  mlkem_sk = gcry_mpi_get_opaque (mlkem_sk_mpi, &nbits);
  len = (nbits+7)/8;

  mlkem_ct = gcry_mpi_get_opaque (mlkem_ct_mpi, &nbits);
  len = (nbits+7)/8;
  err = gcry_kem_decap (GCRY_KEM_MLKEM768,
                        mlkem_sk, GCRY_KEM_MLKEM768_SECKEY_LEN,
                        mlkem_ct, GCRY_KEM_MLKEM768_ENCAPS_LEN,
                        mlkem_ss, GCRY_KEM_MLKEM768_SHARED_LEN,
                        NULL, 0);

  mpi_release (mlkem_sk_mpi);
  mpi_release (mlkem_ct_mpi);

  /* Then, combine two shared secrets into one */

  //   multiKeyCombine(eccKeyShare, eccCipherText,
  //                   mlkemKeyShare, mlkemCipherText,
  //                   fixedInfo, oBits)
  //
  //   Input:
  //   eccKeyShare     - the ECC key share encoded as an octet string
  //   eccCipherText   - the ECC ciphertext encoded as an octet string
  //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
  //   mlkemCipherText - the ML-KEM ciphertext encoded as an octet string
  //   fixedInfo       - the fixed information octet string
  //   oBits           - the size of the output keying material in bits
  //
  //   Constants:
  //   domSeparation       - the UTF-8 encoding of the string
  //                         "OpenPGPCompositeKeyDerivationFunction"
  //   counter             - the 4 byte value 00 00 00 01
  //   customizationString - the UTF-8 encoding of the string "KDF"
  //
  //  eccData = eccKeyShare || eccCipherText
  //    mlkemData = mlkemKeyShare || mlkemCipherText
  //    encData = counter || eccData || mlkemData || fixedInfo
  //
  //    KEK = KMAC256(domSeparation, encData, oBits, customizationString)
  //    return KEK
  //
  // fixedInfo = algID (105 for ML-KEM-768-x25519kem)
  //
  // KMAC256(K,X,L,S):
  // newX = bytepad(encode_string(K), 136) || X || right_encode(L)
  // cSHAKE256(newX,L,"KMAC",S)
  len = 4 + 32 + 32 + GCRY_KEM_MLKEM768_SHARED_LEN + GCRY_KEM_MLKEM768_ENCAPS_LEN;

  iov[0].data = "KMAC";
  iov[0].off = 0;
  iov[0].len = 4;

  iov[1].data = "KDF";
  iov[1].off = 0;
  iov[1].len = 3;

  head136[0] = 1;
  head136[1] = 136;
  iov[2].data = head136;
  iov[2].off = 0;
  iov[2].len = 2;

  headK[0] = 1;
  headK[1] = 37;
  iov[3].data = headK;
  iov[3].off = 0;
  iov[3].len = 2;

  iov[4].data = "OpenPGPCompositeKeyDerivationFunction";
  iov[4].off = 0;
  iov[4].len = 37;

  iov[5].data = (unsigned char *)pad;
  iov[5].off = 0;
  iov[5].len = sizeof (pad);

  iov[6].data = "\x00\x00\x00\x01"; /* Counter */
  iov[6].off = 0;
  iov[6].len = 4;

  iov[7].data = ecc_ss;
  iov[7].off = 0;
  iov[7].len = 32;

  iov[8].data = (unsigned char *)ecc_ct;
  iov[8].off = 0;
  iov[8].len = 32;

  iov[9].data = mlkem_ss;
  iov[9].off = 0;
  iov[9].len = GCRY_KEM_MLKEM768_SHARED_LEN;

  iov[10].data = (unsigned char *)mlkem_ct;
  iov[10].off = 0;
  iov[10].len = GCRY_KEM_MLKEM768_ENCAPS_LEN;

  iov[11].data = (unsigned char *)fixedinfo;
  iov[11].off = 0;
  iov[11].len = 1;

  right_encode_L[0] = (kekkeylen * 8);
  right_encode_L[1] = 1;
  iov[12].data = right_encode_L;
  iov[12].off = 0;
  iov[12].len = 2;

  gcry_md_hash_buffers_extract (GCRY_MD_CSHAKE256, 0, kekkey, kekkeylen,
                                iov, DIM (iov));

  if (DBG_CRYPTO)
    {
      log_printhex (kekkey, kekkeylen, "KEK key: ");
    }

  /*FIXME: KEK may be AES256, for example */
  err = gcry_cipher_open (&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP, 0);
  if (err)
    {
      log_error ("ecdh failed to initialize AESWRAP: %s\n",
                 gpg_strerror (err));
      mpi_release (encrypted_sessionkey_mpi);
      goto leave;
    }

  err = gcry_cipher_setkey (hd, kekkey, kekkeylen);

  sessionkey_encoded_len = encrypted_sessionkey_len - 8;
  gcry_cipher_decrypt (hd, sessionkey_encoded, sessionkey_encoded_len,
                       encrypted_sessionkey, encrypted_sessionkey_len);
  gcry_cipher_close (hd);

  mpi_release (encrypted_sessionkey_mpi);

  if (err)
    {
      log_error ("KEM decap failed: %s\n", gpg_strerror (err));
      goto leave;
    }

  put_membuf_printf (outbuf, "(5:value%u:", (unsigned int)sessionkey_encoded_len);
  put_membuf (outbuf, sessionkey_encoded, sessionkey_encoded_len);
  put_membuf (outbuf, ")", 2);

 leave:
  gcry_sexp_release (s_skey0);
  gcry_sexp_release (s_skey1);
  xfree (shadow_info);
  return err;
}


gpg_error_t
agent_kem_decap (ctrl_t ctrl, const char *desc_text, int kemid,
                 const unsigned char *ciphertext, size_t ciphertextlen,
                 membuf_t *outbuf,
                 const unsigned char *option, size_t optionlen)
{
  gcry_sexp_t s_skey = NULL, s_cipher = NULL;
  unsigned char *shadow_info = NULL;
  gpg_error_t err = 0;
  int no_shadow_info = 0;

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

  if (ctrl->have_keygrip1)
    {
      err = agent_hybrid_kem_decap (ctrl, desc_text, kemid, s_cipher, outbuf);
      goto leave;
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
      err = gpg_error (GPG_ERR_NO_SECKEY); /* Not implemented yet.  */
      goto leave;
    }
  else
    { /* No smartcard, but a private key */
      unsigned int nbits;
      gcry_mpi_t seckey_mpi;
      gcry_mpi_t ephemkey_mpi;
      gcry_mpi_t encrypted_sessionkey_mpi;
      const unsigned char *p;
      size_t len;
      unsigned char seckey[32];
      size_t seckeylen;
      const unsigned char *ephemkey;
      size_t ephemkeylen;
      const unsigned char *encrypted_sessionkey;
      size_t encrypted_sessionkey_len;
      unsigned char kekkey[32];    /* FIXME */
      size_t kekkeylen;
      gcry_cipher_hd_t hd;
      unsigned char sessionkey_encoded[256];
      size_t sessionkey_encoded_len;


      gcry_sexp_extract_param (s_skey, NULL, "/d", &seckey_mpi, NULL);
      gcry_sexp_extract_param (s_cipher, NULL, "/e/s",
                               &ephemkey_mpi,
                               &encrypted_sessionkey_mpi, NULL);

      p = gcry_mpi_get_opaque (seckey_mpi, &nbits);
      len = (nbits+7)/8;
      memset (seckey, 0, 32);
      memcpy (seckey + 32 - len, p, len);
      seckeylen = 32;
      reverse_buffer (seckey, seckeylen);

      ephemkey = gcry_mpi_get_opaque (ephemkey_mpi, &nbits);
      ephemkeylen = (nbits+7)/8;
      /* Remove the 0x40 prefix*/
      ephemkey++;
      ephemkeylen--;
      encrypted_sessionkey = gcry_mpi_get_opaque (encrypted_sessionkey_mpi, &nbits);
      encrypted_sessionkey_len = (nbits+7)/8;
      /*FIXME make sure the lengths are all correct.  */

      encrypted_sessionkey_len--;
      if (encrypted_sessionkey[0] != encrypted_sessionkey_len)
        {
          err = GPG_ERR_INV_DATA;
          goto leave;
        }

      encrypted_sessionkey++;

      /*FIXME: check the internal of optional to determine the KEK-algo and KEKKEYLEN.  */
      kekkeylen = 16;

      err = gcry_kem_decap (GCRY_KEM_PGP_X25519,
                            seckey, seckeylen,
                            ephemkey, ephemkeylen,
                            kekkey, kekkeylen,
                            option, optionlen);

      mpi_release (seckey_mpi);
      mpi_release (ephemkey_mpi);

      if (DBG_CRYPTO)
        {
          log_printhex (kekkey, kekkeylen, "KEK key: ");
        }

      /*FIXME*/
      err = gcry_cipher_open (&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP, 0);
      if (err)
        {
          log_error ("ecdh failed to initialize AESWRAP: %s\n",
                     gpg_strerror (err));
          mpi_release (encrypted_sessionkey_mpi);
          goto leave;
        }

      err = gcry_cipher_setkey (hd, kekkey, kekkeylen);

      sessionkey_encoded_len = encrypted_sessionkey_len - 8;
      gcry_cipher_decrypt (hd, sessionkey_encoded, sessionkey_encoded_len,
                           encrypted_sessionkey, encrypted_sessionkey_len);
      gcry_cipher_close (hd);

      mpi_release (encrypted_sessionkey_mpi);

      if (err)
        {
          log_error ("KEM decap failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      put_membuf_printf (outbuf, "(5:value%u:", (unsigned int)sessionkey_encoded_len);
      put_membuf (outbuf, sessionkey_encoded, sessionkey_encoded_len);
      put_membuf (outbuf, ")", 2);
    }


 leave:
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_cipher);
  xfree (shadow_info);
  return err;
}
