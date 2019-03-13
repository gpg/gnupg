/* ecdh.c - ECDH public key operations used in public key glue code
 *	Copyright (C) 2010, 2011 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "gpg.h"
#include "../common/util.h"
#include "pkglue.h"
#include "main.h"
#include "options.h"

/* A table with the default KEK parameters used by GnuPG.  */
static const struct
{
  unsigned int qbits;
  int openpgp_hash_id;   /* KEK digest algorithm. */
  int openpgp_cipher_id; /* KEK cipher algorithm. */
} kek_params_table[] =
  /* Note: Must be sorted by ascending values for QBITS.  */
  {
    { 256, DIGEST_ALGO_SHA256, CIPHER_ALGO_AES    },
    { 384, DIGEST_ALGO_SHA384, CIPHER_ALGO_AES192 },

    /* Note: 528 is 521 rounded to the 8 bit boundary */
    { 528, DIGEST_ALGO_SHA512, CIPHER_ALGO_AES256 }
  };



/* Return KEK parameters as an opaque MPI The caller must free the
   returned value.  Returns NULL and sets ERRNO on error.  */
gcry_mpi_t
pk_ecdh_default_params (unsigned int qbits)
{
  byte *kek_params;
  int i;

  kek_params = xtrymalloc (4);
  if (!kek_params)
    return NULL;
  kek_params[0] = 3; /* Number of bytes to follow. */
  kek_params[1] = 1; /* Version for KDF+AESWRAP.   */

  /* Search for matching KEK parameter.  Defaults to the strongest
     possible choices.  Performance is not an issue here, only
     interoperability.  */
  for (i=0; i < DIM (kek_params_table); i++)
    {
      if (kek_params_table[i].qbits >= qbits
          || i+1 == DIM (kek_params_table))
        {
          kek_params[2] = kek_params_table[i].openpgp_hash_id;
          kek_params[3] = kek_params_table[i].openpgp_cipher_id;
          break;
        }
    }
  log_assert (i < DIM (kek_params_table));
  if (DBG_CRYPTO)
    log_printhex (kek_params, sizeof(kek_params), "ECDH KEK params are");

  return gcry_mpi_set_opaque (NULL, kek_params, 4 * 8);
}


/* Encrypts/decrypts DATA using a key derived from the ECC shared
   point SHARED_MPI using the FIPS SP 800-56A compliant method
   key_derivation+key_wrapping.  If IS_ENCRYPT is true the function
   encrypts; if false, it decrypts.  PKEY is the public key and PK_FP
   the fingerprint of this public key.  On success the result is
   stored at R_RESULT; on failure NULL is stored at R_RESULT and an
   error code returned.  */
gpg_error_t
pk_ecdh_encrypt_with_shared_point (int is_encrypt, gcry_mpi_t shared_mpi,
                                   const byte pk_fp[MAX_FINGERPRINT_LEN],
                                   gcry_mpi_t data, gcry_mpi_t *pkey,
                                   gcry_mpi_t *r_result)
{
  gpg_error_t err;
  byte *secret_x;
  int secret_x_size;
  unsigned int nbits;
  const unsigned char *kek_params;
  size_t kek_params_size;
  int kdf_hash_algo;
  int kdf_encr_algo;
  unsigned char message[256];
  size_t message_size;

  *r_result = NULL;

  nbits = pubkey_nbits (PUBKEY_ALGO_ECDH, pkey);
  if (!nbits)
    return gpg_error (GPG_ERR_TOO_SHORT);

  {
    size_t nbytes;

    /* Extract x component of the shared point: this is the actual
       shared secret. */
    nbytes = (mpi_get_nbits (pkey[1] /* public point */)+7)/8;
    secret_x = xtrymalloc_secure (nbytes);
    if (!secret_x)
      return gpg_error_from_syserror ();

    err = gcry_mpi_print (GCRYMPI_FMT_USG, secret_x, nbytes,
                          &nbytes, shared_mpi);
    if (err)
      {
        xfree (secret_x);
        log_error ("ECDH ephemeral export of shared point failed: %s\n",
                   gpg_strerror (err));
        return err;
      }

    /* Expected size of the x component */
    secret_x_size = (nbits+7)/8;

    /* Extract X from the result.  It must be in the format of:
           04 || X || Y
           40 || X
           41 || X

       Since it always comes with the prefix, it's larger than X.  In
       old experimental version of libgcrypt, there is a case where it
       returns X with no prefix of 40, so, nbytes == secret_x_size
       is allowed.  */
    if (nbytes < secret_x_size)
      {
        xfree (secret_x);
        return gpg_error (GPG_ERR_BAD_DATA);
      }

    /* Remove the prefix.  */
    if ((nbytes & 1))
      memmove (secret_x, secret_x+1, secret_x_size);

    /* Clear the rest of data.  */
    if (nbytes - secret_x_size)
      memset (secret_x+secret_x_size, 0, nbytes-secret_x_size);

    if (DBG_CRYPTO)
      log_printhex (secret_x, secret_x_size, "ECDH shared secret X is:");
  }

  /*** We have now the shared secret bytes in secret_x. ***/

  /* At this point we are done with PK encryption and the rest of the
   * function uses symmetric key encryption techniques to protect the
   * input DATA.  The following two sections will simply replace
   * current secret_x with a value derived from it.  This will become
   * a KEK.
   */
  if (!gcry_mpi_get_flag (pkey[2], GCRYMPI_FLAG_OPAQUE))
    {
      xfree (secret_x);
      return gpg_error (GPG_ERR_BUG);
    }
  kek_params = gcry_mpi_get_opaque (pkey[2], &nbits);
  kek_params_size = (nbits+7)/8;

  if (DBG_CRYPTO)
    log_printhex (kek_params, kek_params_size, "ecdh KDF params:");

  /* Expect 4 bytes  03 01 hash_alg symm_alg.  */
  if (kek_params_size != 4 || kek_params[0] != 3 || kek_params[1] != 1)
    {
      xfree (secret_x);
      return gpg_error (GPG_ERR_BAD_PUBKEY);
    }

  kdf_hash_algo = kek_params[2];
  kdf_encr_algo = kek_params[3];

  if (DBG_CRYPTO)
    log_debug ("ecdh KDF algorithms %s+%s with aeswrap\n",
               openpgp_md_algo_name (kdf_hash_algo),
               openpgp_cipher_algo_name (kdf_encr_algo));

  if (kdf_hash_algo != GCRY_MD_SHA256
      && kdf_hash_algo != GCRY_MD_SHA384
      && kdf_hash_algo != GCRY_MD_SHA512)
    {
      xfree (secret_x);
      return gpg_error (GPG_ERR_BAD_PUBKEY);
    }
  if (kdf_encr_algo != CIPHER_ALGO_AES
      && kdf_encr_algo != CIPHER_ALGO_AES192
      && kdf_encr_algo != CIPHER_ALGO_AES256)
    {
      xfree (secret_x);
      return gpg_error (GPG_ERR_BAD_PUBKEY);
    }

  /* Build kdf_params.  */
  {
    IOBUF obuf;

    obuf = iobuf_temp();
    /* variable-length field 1, curve name OID */
    err = gpg_mpi_write_nohdr (obuf, pkey[0]);
    /* fixed-length field 2 */
    iobuf_put (obuf, PUBKEY_ALGO_ECDH);
    /* variable-length field 3, KDF params */
    err = (err ? err : gpg_mpi_write_nohdr (obuf, pkey[2]));
    /* fixed-length field 4 */
    iobuf_write (obuf, "Anonymous Sender    ", 20);
    /* fixed-length field 5, recipient fp */
    iobuf_write (obuf, pk_fp, 20);

    message_size = iobuf_temp_to_buffer (obuf, message, sizeof message);
    iobuf_close (obuf);
    if (err)
      {
        xfree (secret_x);
        return err;
      }

    if(DBG_CRYPTO)
      log_printhex (message, message_size, "ecdh KDF message params are:");
  }

  /* Derive a KEK (key wrapping key) using MESSAGE and SECRET_X. */
  {
    gcry_md_hd_t h;
    int old_size;

    err = gcry_md_open (&h, kdf_hash_algo, 0);
    if (err)
      {
        log_error ("gcry_md_open failed for kdf_hash_algo %d: %s",
                   kdf_hash_algo, gpg_strerror (err));
        xfree (secret_x);
        return err;
      }
    gcry_md_write(h, "\x00\x00\x00\x01", 4);      /* counter = 1 */
    gcry_md_write(h, secret_x, secret_x_size);    /* x of the point X */
    gcry_md_write(h, message, message_size);      /* KDF parameters */

    gcry_md_final (h);

    log_assert( gcry_md_get_algo_dlen (kdf_hash_algo) >= 32 );

    memcpy (secret_x, gcry_md_read (h, kdf_hash_algo),
            gcry_md_get_algo_dlen (kdf_hash_algo));
    gcry_md_close (h);

    old_size = secret_x_size;
    log_assert( old_size >= gcry_cipher_get_algo_keylen( kdf_encr_algo ) );
    secret_x_size = gcry_cipher_get_algo_keylen( kdf_encr_algo );
    log_assert( secret_x_size <= gcry_md_get_algo_dlen (kdf_hash_algo) );

    /* We could have allocated more, so clean the tail before returning.  */
    memset (secret_x+secret_x_size, 0, old_size - secret_x_size);
    if (DBG_CRYPTO)
      log_printhex (secret_x, secret_x_size, "ecdh KEK is:");
  }

  /* And, finally, aeswrap with key secret_x.  */
  {
    gcry_cipher_hd_t hd;
    size_t nbytes;

    byte *data_buf;
    int data_buf_size;

    gcry_mpi_t result;

    err = gcry_cipher_open (&hd, kdf_encr_algo, GCRY_CIPHER_MODE_AESWRAP, 0);
    if (err)
      {
        log_error ("ecdh failed to initialize AESWRAP: %s\n",
                   gpg_strerror (err));
        xfree (secret_x);
        return err;
      }

    err = gcry_cipher_setkey (hd, secret_x, secret_x_size);
    xfree (secret_x);
    secret_x = NULL;
    if (err)
      {
        gcry_cipher_close (hd);
        log_error ("ecdh failed in gcry_cipher_setkey: %s\n",
                   gpg_strerror (err));
        return err;
      }

    data_buf_size = (gcry_mpi_get_nbits(data)+7)/8;
    if ((data_buf_size & 7) != (is_encrypt ? 0 : 1))
      {
        log_error ("can't use a shared secret of %d bytes for ecdh\n",
                   data_buf_size);
        return gpg_error (GPG_ERR_BAD_DATA);
      }

    data_buf = xtrymalloc_secure( 1 + 2*data_buf_size + 8);
    if (!data_buf)
      {
        err = gpg_error_from_syserror ();
        gcry_cipher_close (hd);
        return err;
      }

    if (is_encrypt)
      {
        byte *in = data_buf+1+data_buf_size+8;

        /* Write data MPI into the end of data_buf. data_buf is size
           aeswrap data.  */
        err = gcry_mpi_print (GCRYMPI_FMT_USG, in,
                             data_buf_size, &nbytes, data/*in*/);
        if (err)
          {
            log_error ("ecdh failed to export DEK: %s\n", gpg_strerror (err));
            gcry_cipher_close (hd);
            xfree (data_buf);
            return err;
          }

        if (DBG_CRYPTO)
          log_printhex (in, data_buf_size, "ecdh encrypting  :");

        err = gcry_cipher_encrypt (hd, data_buf+1, data_buf_size+8,
                                   in, data_buf_size);
        memset (in, 0, data_buf_size);
        gcry_cipher_close (hd);
        if (err)
          {
            log_error ("ecdh failed in gcry_cipher_encrypt: %s\n",
                       gpg_strerror (err));
            xfree (data_buf);
            return err;
          }
        data_buf[0] = data_buf_size+8;

        if (DBG_CRYPTO)
          log_printhex (data_buf+1, data_buf[0], "ecdh encrypted to:");

        result = gcry_mpi_set_opaque (NULL, data_buf, 8 * (1+data_buf[0]));
        if (!result)
          {
            err = gpg_error_from_syserror ();
            xfree (data_buf);
            log_error ("ecdh failed to create an MPI: %s\n",
                       gpg_strerror (err));
            return err;
          }

        *r_result = result;
      }
    else
      {
        byte *in;
        const void *p;

        p = gcry_mpi_get_opaque (data, &nbits);
        nbytes = (nbits+7)/8;
        if (!p || nbytes > data_buf_size || !nbytes)
          {
            xfree (data_buf);
            return gpg_error (GPG_ERR_BAD_MPI);
          }
        memcpy (data_buf, p, nbytes);
        if (data_buf[0] != nbytes-1)
          {
            log_error ("ecdh inconsistent size\n");
            xfree (data_buf);
            return gpg_error (GPG_ERR_BAD_MPI);
          }
        in = data_buf+data_buf_size;
        data_buf_size = data_buf[0];

        if (DBG_CRYPTO)
          log_printhex (data_buf+1, data_buf_size, "ecdh decrypting :");

        err = gcry_cipher_decrypt (hd, in, data_buf_size, data_buf+1,
                                   data_buf_size);
        gcry_cipher_close (hd);
        if (err)
          {
            log_error ("ecdh failed in gcry_cipher_decrypt: %s\n",
                       gpg_strerror (err));
            xfree (data_buf);
            return err;
          }

        data_buf_size -= 8;

        if (DBG_CRYPTO)
          log_printhex (in, data_buf_size, "ecdh decrypted to :");

        /* Padding is removed later.  */
        /* if (in[data_buf_size-1] > 8 ) */
        /*   { */
        /*     log_error ("ecdh failed at decryption: invalid padding." */
        /*                " 0x%02x > 8\n", in[data_buf_size-1] ); */
        /*     return gpg_error (GPG_ERR_BAD_KEY); */
        /*   } */

        err = gcry_mpi_scan (&result, GCRYMPI_FMT_USG, in, data_buf_size, NULL);
        xfree (data_buf);
        if (err)
          {
            log_error ("ecdh failed to create a plain text MPI: %s\n",
                       gpg_strerror (err));
            return err;
          }

        *r_result = result;
      }
  }

  return err;
}


static gcry_mpi_t
gen_k (unsigned nbits)
{
  gcry_mpi_t k;

  k = gcry_mpi_snew (nbits);
  if (DBG_CRYPTO)
    log_debug ("choosing a random k of %u bits\n", nbits);

  gcry_mpi_randomize (k, nbits-1, GCRY_STRONG_RANDOM);

  if (DBG_CRYPTO)
    {
      unsigned char *buffer;
      if (gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buffer, NULL, k))
        BUG ();
      log_debug ("ephemeral scalar MPI #0: %s\n", buffer);
      gcry_free (buffer);
    }

  return k;
}


/* Generate an ephemeral key for the public ECDH key in PKEY.  On
   success the generated key is stored at R_K; on failure NULL is
   stored at R_K and an error code returned.  */
gpg_error_t
pk_ecdh_generate_ephemeral_key (gcry_mpi_t *pkey, gcry_mpi_t *r_k)
{
  unsigned int nbits;
  gcry_mpi_t k;

  *r_k = NULL;

  nbits = pubkey_nbits (PUBKEY_ALGO_ECDH, pkey);
  if (!nbits)
    return gpg_error (GPG_ERR_TOO_SHORT);
  k = gen_k (nbits);
  if (!k)
    BUG ();

  *r_k = k;
  return 0;
}



/* Perform ECDH decryption.   */
int
pk_ecdh_decrypt (gcry_mpi_t * result, const byte sk_fp[MAX_FINGERPRINT_LEN],
                 gcry_mpi_t data, gcry_mpi_t shared, gcry_mpi_t * skey)
{
  if (!data)
    return gpg_error (GPG_ERR_BAD_MPI);
  return pk_ecdh_encrypt_with_shared_point (0 /*=decryption*/, shared,
                                            sk_fp, data/*encr data as an MPI*/,
                                            skey, result);
}
