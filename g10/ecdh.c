/* ecdh.c - ECDH public key operations used in public key glue code
 *	Copyright (C) 2000, 2003 Free Software Foundation, Inc.
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

gcry_mpi_t
pk_ecdh_default_params_to_mpi( int qbits )  {
  gpg_error_t err;
  gcry_mpi_t result;
  /* Defaults are the strongest possible choices. Performance is not an issue here, only interoperability. */
  byte kek_params[4] = { 
	3	/*size of following field*/, 
	1	/*fixed version for KDF+AESWRAP*/, 
	DIGEST_ALGO_SHA512	/* KEK MD */, 
	CIPHER_ALGO_AES256 	/*KEK AESWRAP alg*/
  };
  int i;

  static const struct {
    int qbits;
    int openpgp_hash_id;
    int openpgp_cipher_id;
  } kek_params_table[] = {
    { 256, DIGEST_ALGO_SHA256, CIPHER_ALGO_AES    },
    { 384, DIGEST_ALGO_SHA384, CIPHER_ALGO_AES256 },
    { 528, DIGEST_ALGO_SHA512, CIPHER_ALGO_AES256 }	// 528 is 521 rounded to the 8 bit boundary
  };

  for( i=0; i<sizeof(kek_params_table)/sizeof(kek_params_table[0]); i++ )  {
    if( kek_params_table[i].qbits >= qbits )  {
      kek_params[2] = kek_params_table[i].openpgp_hash_id;
      kek_params[3] = kek_params_table[i].openpgp_cipher_id;
      break;
    }
  }
  if( DBG_CIPHER )
      log_printhex ("ecdh kek params are", kek_params, sizeof(kek_params) );

  err = gcry_mpi_scan (&result, GCRYMPI_FMT_USG, kek_params, sizeof(kek_params), NULL);
  if (err)
    log_fatal ("mpi_scan failed: %s\n", gpg_strerror (err));

  return result;
}

/* returns allocated (binary) KEK parameters; the size is returned in sizeout. 
 * The caller must free returned value with xfree. 
 * Returns NULL on error 
 */
byte *
pk_ecdh_default_params( int qbits, size_t *sizeout )  {
  gpg_error_t err;
  gcry_mpi_t result;
  /* Defaults are the strongest possible choices. Performance is not an issue here, only interoperability. */
  byte kek_params[4] = { 
	3	/*size of following field*/, 
	1	/*fixed version for KDF+AESWRAP*/, 
	DIGEST_ALGO_SHA512	/* KEK MD */, 
	CIPHER_ALGO_AES256 	/*KEK AESWRAP alg*/
  };
  int i;

  static const struct {
    int qbits;
    int openpgp_hash_id;
    int openpgp_cipher_id;
  } kek_params_table[] = {
    { 256, DIGEST_ALGO_SHA256, CIPHER_ALGO_AES    },
    { 384, DIGEST_ALGO_SHA384, CIPHER_ALGO_AES256 },
    { 528, DIGEST_ALGO_SHA512, CIPHER_ALGO_AES256 }	// 528 is 521 rounded to the 8 bit boundary
  };

  byte *p;

  *sizeout = 0;

  for( i=0; i<sizeof(kek_params_table)/sizeof(kek_params_table[0]); i++ )  {
    if( kek_params_table[i].qbits >= qbits )  {
      kek_params[2] = kek_params_table[i].openpgp_hash_id;
      kek_params[3] = kek_params_table[i].openpgp_cipher_id;
      break;
    }
  }
  if( DBG_CIPHER )
      log_printhex ("ecdh kek params are", kek_params, sizeof(kek_params) );

  p = xtrymalloc( sizeof(kek_params) );
  if( p == NULL )
    return NULL;
  memcpy( p, kek_params, sizeof(kek_params) );
  *sizeout = sizeof(kek_params);
  return p;
}

/* Encrypts/decrypts 'data' with a key derived from shared_mpi ECC point using FIPS SP 800-56A compliant method, which is
 * key derivation + key wrapping. The direction is determined by the first parameter (is_encrypt=1 --> this is encryption).
 * The result is returned in out as a size+value MPI.
 * TODO: memory leaks (x_secret).
 */
static int
pk_ecdh_encrypt_with_shared_point ( int is_encrypt, gcry_mpi_t shared_mpi, 
	const byte pk_fp[MAX_FINGERPRINT_LEN], gcry_mpi_t data, gcry_mpi_t * pkey, gcry_mpi_t *out)
{
  byte *secret_x;
  int secret_x_size;
  byte kdf_params[256];
  int kdf_params_size=0;
  int nbits;
  int kdf_hash_algo;
  int kdf_encr_algo;
  int rc;

  *out = NULL;

  nbits = pubkey_nbits( PUBKEY_ALGO_ECDH, pkey );

  {
    size_t nbytes;
    /* extract x component of the shared point: this is the actual shared secret */
    nbytes = (mpi_get_nbits (pkey[1] /* public point */)+7)/8;
    secret_x = xmalloc_secure( nbytes );
    rc = gcry_mpi_print (GCRYMPI_FMT_USG, secret_x, nbytes, &nbytes, shared_mpi);
    if( rc )  {
      xfree( secret_x );
      log_error ("ec ephemeral export of shared point failed: %s\n", gpg_strerror (rc) );
      return rc;
    }
    secret_x_size = (nbits+7)/8; 
    assert( nbytes > secret_x_size );
    memmove( secret_x, secret_x+1, secret_x_size );
    memset( secret_x+secret_x_size, 0, nbytes-secret_x_size );

    if( DBG_CIPHER )
        log_printhex ("ecdh shared secret X is:", secret_x, secret_x_size );
  }

  /*** We have now the shared secret bytes in secret_x ***/

  /* At this point we are done with PK encryption and the rest of the function uses symmetric 
   *  key encryption techniques to protect the input 'data'. The following two sections will
   *  simply replace current secret_x with a value derived from it. This will become a KEK. 
   */
  {
    IOBUF obuf = iobuf_temp(); 
    rc = iobuf_write_size_body_mpi ( obuf, pkey[2]  );	/* KEK params */

    kdf_params_size = iobuf_temp_to_buffer( obuf, kdf_params, sizeof(kdf_params) );

    if( DBG_CIPHER )
        log_printhex ("ecdh KDF public key params are:", kdf_params, kdf_params_size );

    if( kdf_params_size != 4 || kdf_params[0] != 3 || kdf_params[1] != 1  )	/* expect 4 bytes  03 01 hash_alg symm_alg */
      return GPG_ERR_BAD_PUBKEY;

    kdf_hash_algo = kdf_params[2];
    kdf_encr_algo = kdf_params[3];

    if( DBG_CIPHER )
      log_debug ("ecdh KDF algorithms %s+%s with aeswrap\n", gcry_md_algo_name (kdf_hash_algo), openpgp_cipher_algo_name (kdf_encr_algo) );

    if( kdf_hash_algo != GCRY_MD_SHA256 && kdf_hash_algo != GCRY_MD_SHA384 && kdf_hash_algo != GCRY_MD_SHA512 )
      return GPG_ERR_BAD_PUBKEY;
    if( kdf_encr_algo != GCRY_CIPHER_AES128 && kdf_encr_algo != GCRY_CIPHER_AES192 && kdf_encr_algo != GCRY_CIPHER_AES256 )
      return GPG_ERR_BAD_PUBKEY;
  }

  /* build kdf_params */
  {
    IOBUF obuf;

    obuf = iobuf_temp();
    /* variable-length field 1, curve name OID */
    rc = iobuf_write_size_body_mpi ( obuf, pkey[0] );
    /* fixed-length field 2 */
    iobuf_put (obuf, PUBKEY_ALGO_ECDH);
    /* variable-length field 3, KDF params */
    rc = (rc ? rc : iobuf_write_size_body_mpi ( obuf, pkey[2] ));
    /* fixed-length field 4 */
    iobuf_write (obuf, "Anonymous Sender    ", 20);
    /* fixed-length field 5, recipient fp */
    iobuf_write (obuf, pk_fp, 20);	

    kdf_params_size = iobuf_temp_to_buffer( obuf, kdf_params, sizeof(kdf_params) );
    iobuf_close( obuf );
    if( rc )  {
      return rc;
    }
    if( DBG_CIPHER )
        log_printhex ("ecdh KDF message params are:", kdf_params, kdf_params_size );
  }

  /* Derive a KEK (key wrapping key) using kdf_params and secret_x. */
  {
    gcry_md_hd_t h;
    int old_size;

    rc = gcry_md_open (&h, kdf_hash_algo, 0);
    if(rc)
  	log_bug ("gcry_md_open failed for algo %d: %s",
			kdf_hash_algo, gpg_strerror (gcry_error(rc)));
    gcry_md_write(h, "\x00\x00\x00\x01", 4);	/* counter = 1 */
    gcry_md_write(h, secret_x, secret_x_size);	/* x of the point X */
    gcry_md_write(h, kdf_params, kdf_params_size);	/* KDF parameters */

    gcry_md_final (h);

    assert( gcry_md_get_algo_dlen (kdf_hash_algo) >= 32 );

    memcpy (secret_x, gcry_md_read (h, kdf_hash_algo), gcry_md_get_algo_dlen (kdf_hash_algo));
    gcry_md_close (h);

    old_size = secret_x_size;
    assert( old_size >= gcry_cipher_get_algo_keylen( kdf_encr_algo ) );
    secret_x_size = gcry_cipher_get_algo_keylen( kdf_encr_algo );
    assert( secret_x_size <= gcry_md_get_algo_dlen (kdf_hash_algo) );

    memset( secret_x+secret_x_size, old_size-secret_x_size, 0 );	/* we could have allocated more, so clean the tail before returning */
    if( DBG_CIPHER )
      log_printhex ("ecdh KEK is:", secret_x, secret_x_size );
   }

  /* And, finally, aeswrap with key secret_x */
  {
    gcry_cipher_hd_t hd;
    size_t nbytes;

    byte *data_buf;
    int data_buf_size;

    gcry_mpi_t result;

    rc = gcry_cipher_open (&hd, kdf_encr_algo, GCRY_CIPHER_MODE_AESWRAP, 0);
    if (rc)
    {
      log_error( "ecdh failed to initialize AESWRAP: %s\n", gpg_strerror (rc));
      return rc;
    }

    rc = gcry_cipher_setkey (hd, secret_x, secret_x_size);
    xfree( secret_x );
    if (rc)
    {
      gcry_cipher_close (hd);
      log_error("ecdh failed in gcry_cipher_setkey: %s\n", gpg_strerror (rc));
      return rc;
    }

    data_buf_size = (gcry_mpi_get_nbits(data)+7)/8;
    assert( (data_buf_size & 7) == (is_encrypt ? 0 : 1) );

    data_buf = xmalloc_secure( 1 + 2*data_buf_size + 8 );
    if( !data_buf )  {
      gcry_cipher_close (hd);
      return GPG_ERR_ENOMEM;
    }

    if( is_encrypt )  {
      byte *in = data_buf+1+data_buf_size+8;

      /* write data MPI into the end of data_buf. data_buf is  size aeswrap data */
      rc = gcry_mpi_print (GCRYMPI_FMT_USG, in, data_buf_size, &nbytes, data/*in*/);
      if( rc )   {
        log_error("ecdh failed to export DEK: %s\n", gpg_strerror (rc));
        gcry_cipher_close (hd);
        xfree( data_buf );
        return rc;
      }

      if( DBG_CIPHER )
         log_printhex ("ecdh encrypting  :", in, data_buf_size );

      rc = gcry_cipher_encrypt (hd, data_buf+1, data_buf_size+8, in, data_buf_size);
      memset( in, 0, data_buf_size);
      gcry_cipher_close (hd);
      if(rc)
      {
        log_error("ecdh failed in gcry_cipher_encrypt: %s\n", gpg_strerror (rc));
        xfree( data_buf );
        return rc;
      }
      data_buf[0] = data_buf_size+8;

      if( DBG_CIPHER )
         log_printhex ("ecdh encrypted to:", data_buf+1, data_buf[0] );

      rc = gcry_mpi_scan ( &result, GCRYMPI_FMT_USG, data_buf, 1+data_buf[0], NULL); /* (byte)size + aeswrap of DEK */
      xfree( data_buf );
      if(rc)
      {
        log_error("ecdh failed to create an MPI: %s\n", gpg_strerror (rc));
        return rc;
      }

      *out = result;
    }
    else  {
      byte *in;

      rc = gcry_mpi_print (GCRYMPI_FMT_USG, data_buf, data_buf_size, &nbytes, data/*in*/);
      if( nbytes != data_buf_size || data_buf[0] != data_buf_size-1 )  {
        log_error("ecdh inconsistent size\n");
        xfree( data_buf );
        return GPG_ERR_BAD_MPI;
      }
      in = data_buf+data_buf_size;
      data_buf_size = data_buf[0];

      if( DBG_CIPHER )
         log_printhex ("ecdh decrypting :", data_buf+1, data_buf_size );
      
      rc = gcry_cipher_decrypt (hd, in, data_buf_size, data_buf+1, data_buf_size );
      gcry_cipher_close (hd);
      if(rc)
      {
        log_error("ecdh failed in gcry_cipher_decrypt: %s\n", gpg_strerror (rc));
        xfree( data_buf );
        return rc;
      }

      data_buf_size-=8;

      if( DBG_CIPHER )
         log_printhex ("ecdh decrypted to :", in, data_buf_size );

      /* padding is removed later */
      //if( in[data_buf_size-1] > 8 )  {
      //  log_error("ecdh failed at decryption: invalid padding. %02x > 8\n", in[data_buf_size-1] );
      //  return GPG_ERR_BAD_KEY;
      //}
 
      rc = gcry_mpi_scan ( &result, GCRYMPI_FMT_USG, in, data_buf_size, NULL);
      xfree( data_buf );
      if(rc)
      {
        log_error("ecdh failed to create a plain text MPI: %s\n", gpg_strerror (rc));
        return rc;
      }

      *out = result;
    }
  }

  return rc;
}

/* Perform ECDH encryption, which involves ECDH key generation.
 */
int
pk_ecdh_encrypt (gcry_mpi_t * resarr, const byte pk_fp[MAX_FINGERPRINT_LEN], gcry_mpi_t data, gcry_mpi_t * pkey)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;

  PKT_public_key *pk_eph;
  int nbits;
  int rc;

  nbits = pubkey_nbits( PUBKEY_ALGO_ECDH, pkey );
 
  /*** Generate an ephemeral key ***/

  rc = pk_ecc_keypair_gen( &pk_eph, PUBKEY_ALGO_ECDH, KEYGEN_FLAG_TRANSIENT_KEY | KEYGEN_FLAG_NO_PROTECTION /*this is ephemeral*/, "", nbits );
  if( rc )
    return rc;
  if( DBG_CIPHER )  {
	unsigned char *buffer;
	if (gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buffer, NULL, pk_eph->pkey[1]))
          BUG ();
        log_debug("ephemeral key MPI #0: %s\n", buffer);
	gcry_free( buffer );
  }
  free_public_key (pk_eph);

  /*** Done with ephemeral key generation. 
   * Now use ephemeral secret to get the shared secret. ***/

  rc = gcry_sexp_build (&s_pkey, NULL,
		    "(public-key(ecdh(c%m)(q%m)(p%m)))", pkey[0], pkey[1], pkey[2]);
  if (rc)
    BUG ();
 
  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "%m", pk_eph->pkey[3]))	/* ephemeral scalar goes as data */
    BUG ();

  /* pass it to libgcrypt */
  rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);
  if (rc)
    return rc;

  /* finally, perform encryption */

  {
    gcry_mpi_t shared = mpi_from_sexp (s_ciph, "a");		/* ... and get the shared point */
    gcry_sexp_release (s_ciph);
    resarr[0] = pk_eph->pkey[1];	/* ephemeral public key */

    if( DBG_CIPHER )  {
	unsigned char *buffer;
	if (gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buffer, NULL, resarr[0]))
          BUG ();
        log_debug("ephemeral key MPI: %s\n", buffer);
	gcry_free( buffer );
    }

    rc = pk_ecdh_encrypt_with_shared_point ( 1 /*=encrypton*/, shared, pk_fp, data, pkey, resarr+1 );
    mpi_release( shared );
  }

  return rc;
}

/* Perform ECDH decryption. 
 */
int
pk_ecdh_decrypt (gcry_mpi_t * result, const byte sk_fp[MAX_FINGERPRINT_LEN], gcry_mpi_t *data, gcry_mpi_t * skey)  {
  gcry_sexp_t s_skey, s_data, s_ciph;
  int rc;

  if (!data[0] || !data[1])
    return gpg_error (GPG_ERR_BAD_MPI);

  rc = gcry_sexp_build (&s_skey, NULL,
			    "(public-key(ecdh(c%m)(q%m)(p%m)))",
 			    skey[0]/*curve*/, data[0]/*ephemeral key*/, skey[2]/*KDF params*/);
  if (rc)
    BUG ();

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "%m", skey[3]))	/* static private key (scalar) goes as data */
    BUG ();

  rc = gcry_pk_encrypt (&s_ciph, s_data, s_skey);	/* encrypting ephemeral key with our private scalar yields the shared point */
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_data);
  if (rc)
    return rc;

  {
    gcry_mpi_t shared = mpi_from_sexp (s_ciph, "a");		/* get the shared point */
    gcry_sexp_release (s_ciph);
    rc = pk_ecdh_encrypt_with_shared_point ( 0 /*=decryption*/, shared, sk_fp, data[1]/*encr data as an MPI*/, skey, result );
    mpi_release( shared );
  }

  return rc;
}


