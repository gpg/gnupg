/* ecdh.c - ECDH public key operations used in public key glue code
 *	Copyright (C) 2010 Free Software Foundation, Inc.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "gpg.h"
#include "util.h"
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
    { 384, DIGEST_ALGO_SHA384, CIPHER_ALGO_AES256 },

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
  assert (i < DIM (kek_params_table));
  if (DBG_CIPHER)
    log_printhex ("ECDH KEK params are", kek_params, sizeof(kek_params) );
  
  return gcry_mpi_set_opaque (NULL, kek_params, 4 * 8);
}


/* Encrypts/decrypts DATA using a key derived from the ECC shared
   point SHARED_MPI using the FIPS SP 800-56A compliant method
   key_derivation+key_wrapping.  If IS_ENCRYPT is true the function
   encrypts; if false, it decrypts.  On success the result is stored
   at R_RESULT; on failure NULL is stored at R_RESULT and an error
   code returned. 

   FIXME: explain PKEY and PK_FP.
 */
 
/*
   TODO: memory leaks (x_secret).
*/
gpg_error_t
pk_ecdh_encrypt_with_shared_point (int is_encrypt, gcry_mpi_t shared_mpi, 
                                   const byte pk_fp[MAX_FINGERPRINT_LEN],
                                   gcry_mpi_t data, gcry_mpi_t *pkey,
                                   gcry_mpi_t *r_result)
{
  gpg_error_t err;
  byte *secret_x;
  int secret_x_size;
  byte kdf_params[256];
  int kdf_params_size=0;
  int nbits;
  int kdf_hash_algo;
  int kdf_encr_algo;

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

    /* fixme: explain what we are doing.  */
    secret_x_size = (nbits+7)/8; 
    assert (nbytes > secret_x_size);
    memmove (secret_x, secret_x+1, secret_x_size);
    memset (secret_x+secret_x_size, 0, nbytes-secret_x_size);

    if (DBG_CIPHER)
      log_printhex ("ECDH shared secret X is:", secret_x, secret_x_size );
  }

  /*** We have now the shared secret bytes in secret_x. ***/

  /* At this point we are done with PK encryption and the rest of the
   * function uses symmetric key encryption techniques to protect the
   * input DATA.  The following two sections will simply replace
   * current secret_x with a value derived from it.  This will become
   * a KEK.
   */
  {
    IOBUF obuf = iobuf_temp(); 
    err = write_size_body_mpi (obuf, pkey[2]);	/* KEK params */
    
    kdf_params_size = iobuf_temp_to_buffer (obuf,
                                            kdf_params, sizeof(kdf_params));

    if (DBG_CIPHER)
      log_printhex ("ecdh KDF public key params are:",
                    kdf_params, kdf_params_size );

    /* Expect 4 bytes  03 01 hash_alg symm_alg.  */
    if (kdf_params_size != 4 || kdf_params[0] != 3 || kdf_params[1] != 1)	
      return GPG_ERR_BAD_PUBKEY;

    kdf_hash_algo = kdf_params[2];
    kdf_encr_algo = kdf_params[3];

    if (DBG_CIPHER)
      log_debug ("ecdh KDF algorithms %s+%s with aeswrap\n",
                 gcry_md_algo_name (kdf_hash_algo),
                 openpgp_cipher_algo_name (kdf_encr_algo));

    if (kdf_hash_algo != GCRY_MD_SHA256
        && kdf_hash_algo != GCRY_MD_SHA384
        && kdf_hash_algo != GCRY_MD_SHA512)
      return GPG_ERR_BAD_PUBKEY;
    if (kdf_encr_algo != GCRY_CIPHER_AES128
        && kdf_encr_algo != GCRY_CIPHER_AES192
        && kdf_encr_algo != GCRY_CIPHER_AES256)
      return GPG_ERR_BAD_PUBKEY;
  }

  /* Build kdf_params.  */
  {
    IOBUF obuf;

    obuf = iobuf_temp();
    /* variable-length field 1, curve name OID */
    err = write_size_body_mpi (obuf, pkey[0]);
    /* fixed-length field 2 */
    iobuf_put (obuf, PUBKEY_ALGO_ECDH);
    /* variable-length field 3, KDF params */
    err = (err ? err : write_size_body_mpi ( obuf, pkey[2] ));
    /* fixed-length field 4 */
    iobuf_write (obuf, "Anonymous Sender    ", 20);
    /* fixed-length field 5, recipient fp */
    iobuf_write (obuf, pk_fp, 20);	

    kdf_params_size = iobuf_temp_to_buffer (obuf,
                                            kdf_params, sizeof(kdf_params));
    iobuf_close (obuf);
    if (err)
      return err;

    if(DBG_CIPHER)
      log_printhex ("ecdh KDF message params are:",
                    kdf_params, kdf_params_size );
  }

  /* Derive a KEK (key wrapping key) using kdf_params and secret_x. */
  {
    gcry_md_hd_t h;
    int old_size;

    err = gcry_md_open (&h, kdf_hash_algo, 0);
    if(err)
  	log_bug ("gcry_md_open failed for algo %d: %s",
			kdf_hash_algo, gpg_strerror (gcry_error(err)));
    gcry_md_write(h, "\x00\x00\x00\x01", 4);	/* counter = 1 */
    gcry_md_write(h, secret_x, secret_x_size);	/* x of the point X */
    gcry_md_write(h, kdf_params, kdf_params_size);	/* KDF parameters */

    gcry_md_final (h);

    assert( gcry_md_get_algo_dlen (kdf_hash_algo) >= 32 );

    memcpy (secret_x, gcry_md_read (h, kdf_hash_algo),
            gcry_md_get_algo_dlen (kdf_hash_algo));
    gcry_md_close (h);

    old_size = secret_x_size;
    assert( old_size >= gcry_cipher_get_algo_keylen( kdf_encr_algo ) );
    secret_x_size = gcry_cipher_get_algo_keylen( kdf_encr_algo );
    assert( secret_x_size <= gcry_md_get_algo_dlen (kdf_hash_algo) );

    /* We could have allocated more, so clean the tail before returning.  */
    memset( secret_x+secret_x_size, old_size-secret_x_size, 0 );
    if (DBG_CIPHER)
      log_printhex ("ecdh KEK is:", secret_x, secret_x_size );
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
        return err;
      }

    err = gcry_cipher_setkey (hd, secret_x, secret_x_size);
    xfree( secret_x );
    if (err)
      {
        gcry_cipher_close (hd);
        log_error ("ecdh failed in gcry_cipher_setkey: %s\n",
                   gpg_strerror (err));
        return err;
      }

    data_buf_size = (gcry_mpi_get_nbits(data)+7)/8;
    assert ((data_buf_size & 7) == (is_encrypt ? 0 : 1));

    data_buf = xtrymalloc_secure( 1 + 2*data_buf_size + 8);
    if (!data_buf)
      {
        gcry_cipher_close (hd);
        return GPG_ERR_ENOMEM;
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
        
        if (DBG_CIPHER)
          log_printhex ("ecdh encrypting  :", in, data_buf_size );

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

        if (DBG_CIPHER)
         log_printhex ("ecdh encrypted to:", data_buf+1, data_buf[0] );

        err = gcry_mpi_scan (&result, GCRYMPI_FMT_USG,
                            data_buf, 1+data_buf[0], NULL); 
        /* (byte)size + aeswrap of DEK */
        xfree( data_buf );
        if (err)
          {
            log_error ("ecdh failed to create an MPI: %s\n", gpg_strerror (err));
            return err;
          }
        
        *r_result = result;
      }
    else
      {
        byte *in;
        
        err = gcry_mpi_print (GCRYMPI_FMT_USG, data_buf, data_buf_size,
                             &nbytes, data/*in*/);
      if (nbytes != data_buf_size || data_buf[0] != data_buf_size-1)
        {
          log_error ("ecdh inconsistent size\n");
          xfree (data_buf);
          return GPG_ERR_BAD_MPI;
        }
      in = data_buf+data_buf_size;
      data_buf_size = data_buf[0];
      
      if (DBG_CIPHER)
        log_printhex ("ecdh decrypting :", data_buf+1, data_buf_size);
      
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

      if (DBG_CIPHER)
        log_printhex ("ecdh decrypted to :", in, data_buf_size);

      /* Padding is removed later.  */
      /* if (in[data_buf_size-1] > 8 ) */
      /*   { */
      /*     log_error("ecdh failed at decryption: invalid padding. %02x > 8\n", */
      /*               in[data_buf_size-1] ); */
      /*     return GPG_ERR_BAD_KEY; */
      /*   } */
 
      err = gcry_mpi_scan ( &result, GCRYMPI_FMT_USG, in, data_buf_size, NULL);
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
  if (DBG_CIPHER)
    log_debug ("choosing a random k of %u bits\n", nbits);

  gcry_mpi_randomize (k, nbits-1, GCRY_STRONG_RANDOM);

  if (DBG_CIPHER)
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


