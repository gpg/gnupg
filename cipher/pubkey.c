/* pubkey.c  -	pubkey dispatcher
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "util.h"
#include "errors.h"
#include "mpi.h"
#include "cipher.h"
#include "dynload.h"

/****************
 * Return the number of public key material numbers
 */
int
pubkey_get_npkey( int algo )
{
    if( is_ELGAMAL(algo) )
	return 3;
    if( is_RSA(algo) )
	return 2;
    if( algo == PUBKEY_ALGO_DSA )
	return 4;
    return 0;
}

/****************
 * Return the number of secret key material numbers
 */
int
pubkey_get_nskey( int algo )
{
    if( is_ELGAMAL(algo) )
	return 4;
    if( is_RSA(algo) )
	return 6;
    if( algo == PUBKEY_ALGO_DSA )
	return 5;
    return 0;
}

/****************
 * Return the number of signature material numbers
 */
int
pubkey_get_nsig( int algo )
{
    if( is_ELGAMAL(algo) )
	return 2;
    if( is_RSA(algo) )
	return 1;
    if( algo == PUBKEY_ALGO_DSA )
	return 2;
    return 0;
}

/****************
 * Return the number of encryption material numbers
 */
int
pubkey_get_nenc( int algo )
{
    if( is_ELGAMAL(algo) )
	return 2;
    if( is_RSA(algo) )
	return 1;
    return 0;
}

/****************
 * Get the number of nbits from the public key
 */
unsigned
pubkey_nbits( int algo, MPI *pkey )
{
    if( is_ELGAMAL( algo ) )
	return mpi_get_nbits( pkey[0] );

    if( algo == PUBKEY_ALGO_DSA )
	return mpi_get_nbits( pkey[0] );

    if( is_RSA( algo) )
	return mpi_get_nbits( pkey[0] );

    return 0;
}


int
pubkey_check_secret_key( int algo, MPI *skey )
{
    int rc = 0;

    if( is_ELGAMAL(algo) ) {
	ELG_secret_key sk;
	sk.p = skey[0];
	sk.g = skey[1];
	sk.y = skey[2];
	sk.x = skey[3];
	if( !elg_check_secret_key( &sk ) )
	    rc = G10ERR_BAD_SECKEY;
    }
    else if( algo == PUBKEY_ALGO_DSA ) {
	DSA_secret_key sk;
	sk.p = skey[0];
	sk.q = skey[1];
	sk.g = skey[2];
	sk.y = skey[3];
	sk.x = skey[4];
	if( !dsa_check_secret_key( &sk ) )
	    rc = G10ERR_BAD_SECKEY;
    }
 #ifdef HAVE_RSA_CIPHER
    else if( is_RSA(k->pubkey_algo) ) {
	/* FIXME */
	RSA_secret_key sk;
	assert( ndata == 1 && nskey == 6 );
	sk.n = skey[0];
	sk.e = skey[1];
	sk.d = skey[2];
	sk.p = skey[3];
	sk.q = skey[4];
	sk.u = skey[5];
	plain = mpi_alloc_secure( mpi_get_nlimbs(sk.n) );
	rsa_secret( plain, data[0], &sk );
    }
  #endif
    else
	rc = G10ERR_PUBKEY_ALGO;
    return rc;
}


/****************
 * This is the interface to the public key encryption.
 * Encrypt DATA with PKEY and put it into RESARR which
 * should be an array of MPIs of size PUBKEY_MAX_NENC (or less if the
 * algorithm allows this - check with pubkey_get_nenc() )
 */
int
pubkey_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{
    if( DBG_CIPHER ) {
	int i;
	log_debug("pubkey_encrypt: algo=%d\n", algo );
	for(i=0; i < pubkey_get_npkey(algo); i++ )
	    log_mpidump("  pkey:", pkey[i] );
	log_mpidump("  data:", data );
    }
    /* FIXME: check that data fits into the key */
    if( is_ELGAMAL(algo) ) {
	ELG_public_key pk;
	pk.p = pkey[0];
	pk.g = pkey[1];
	pk.y = pkey[2];
	resarr[0] = mpi_alloc( mpi_get_nlimbs( pk.p ) );
	resarr[1] = mpi_alloc( mpi_get_nlimbs( pk.p ) );
	elg_encrypt( resarr[0], resarr[1], data, &pk );
    }
 #ifdef HAVE_RSA_CIPHER
    else if( algo == PUBKEY_ALGO_RSA || algo == PUBKEY_ALGO_RSA_E ) {
	RSA_public_key pk;
	pk.n = pkey[0];
	pk.e = pkey[1];
	resarr[0] = mpi_alloc( mpi_get_nlimbs( pk.p ) );
	rsa_public( resarr[0], data, &pk );
    }
  #endif
    else
	return G10ERR_PUBKEY_ALGO;

    if( DBG_CIPHER ) {
	int i;
	for(i=0; i < pubkey_get_nenc(algo); i++ )
	    log_mpidump("  encr:", resarr[i] );
    }
    return 0;
}



/****************
 * This is the interface to the public key decryption.
 * ALGO gives the algorithm to use and this implicitly determines
 * the size of the arrays.
 * result is a pointer to a mpi variable which will receive a
 * newly allocated mpi or NULL in case of an error.
 */
int
pubkey_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
    MPI plain = NULL;

    *result = NULL; /* so the caller can always do an mpi_free */
    if( DBG_CIPHER ) {
	int i;
	log_debug("pubkey_decrypt: algo=%d\n", algo );
	for(i=0; i < pubkey_get_nskey(algo); i++ )
	    log_mpidump("  skey:", skey[i] );
	for(i=0; i < pubkey_get_nenc(algo); i++ )
	    log_mpidump("  data:", data[i] );
    }
    if( is_ELGAMAL(algo) ) {
	ELG_secret_key sk;
	sk.p = skey[0];
	sk.g = skey[1];
	sk.y = skey[2];
	sk.x = skey[3];
	plain = mpi_alloc_secure( mpi_get_nlimbs( sk.p ) );
	elg_decrypt( plain, data[0], data[1], &sk );
    }
 #ifdef HAVE_RSA_CIPHER
    else if( algo == PUBKEY_ALGO_RSA || algo == PUBKEY_ALGO_RSA_E ) {
	RSA_secret_key sk;
	sk.n = skey[0];
	sk.e = skey[1];
	sk.d = skey[2];
	sk.p = skey[3];
	sk.q = skey[4];
	sk.u = skey[5];
	plain = mpi_alloc_secure( mpi_get_nlimbs(sk.n) );
	rsa_secret( plain, data[0], &sk );
    }
  #endif
    else
	return G10ERR_PUBKEY_ALGO;

    *result = plain;
    return 0;
}


/****************
 * This is the interface to the public key signing.
 * Sign hash with skey and put the result into resarr which
 * should be an array of MPIs of size PUBKEY_MAX_NSIG (or less if the
 * algorithm allows this - check with pubkey_get_nsig() )
 */
int
pubkey_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{
    if( DBG_CIPHER ) {
	int i;
	log_debug("pubkey_sign: algo=%d\n", algo );
	for(i=0; i < pubkey_get_nskey(algo); i++ )
	    log_mpidump("  skey:", skey[i] );
	log_mpidump("  data:", data );
    }

    if( is_ELGAMAL(algo) ) {
	ELG_secret_key sk;
	sk.p = skey[0];
	sk.g = skey[1];
	sk.y = skey[2];
	sk.x = skey[3];
	resarr[0] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
	resarr[1] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
	elg_sign( resarr[0], resarr[1], data, &sk );
    }
    else if( algo == PUBKEY_ALGO_DSA ) {
	DSA_secret_key sk;
	sk.p = skey[0];
	sk.q = skey[1];
	sk.g = skey[2];
	sk.y = skey[3];
	sk.x = skey[4];
	resarr[0] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
	resarr[1] = mpi_alloc( mpi_get_nlimbs( sk.p ) );
	dsa_sign( resarr[0], resarr[1], data, &sk );
    }
 #ifdef HAVE_RSA_CIPHER
    else if( algo == PUBKEY_ALGO_RSA || algo == PUBKEY_ALGO_RSA_S ) {
	RSA_secret_key sk;
	sk.n = skey[0];
	sk.e = skey[1];
	sk.d = skey[2];
	sk.p = skey[3];
	sk.q = skey[4];
	sk.u = skey[5];
	plain = mpi_alloc_secure( mpi_get_nlimbs(sk.n) );
	rsa_sign( plain, data[0], &sk );
    }
  #endif
    else
	return G10ERR_PUBKEY_ALGO;

    if( DBG_CIPHER ) {
	int i;
	for(i=0; i < pubkey_get_nsig(algo); i++ )
	    log_mpidump("   sig:", resarr[i] );
    }

    return 0;
}

/****************
 * Verify a public key signature.
 * Return 0 if the signature is good
 */
int
pubkey_verify( int algo, MPI hash, MPI *data, MPI *pkey )
{
    int rc = 0;

    if( is_ELGAMAL( algo ) ) {
	ELG_public_key pk;
	pk.p = pkey[0];
	pk.g = pkey[1];
	pk.y = pkey[2];
	if( !elg_verify( data[0], data[1], hash, &pk ) )
	    rc = G10ERR_BAD_SIGN;
    }
    else if( algo == PUBKEY_ALGO_DSA ) {
	DSA_public_key pk;
	pk.p = pkey[0];
	pk.q = pkey[1];
	pk.g = pkey[2];
	pk.y = pkey[3];
	if( !dsa_verify( data[0], data[1], hash, &pk ) )
	    rc = G10ERR_BAD_SIGN;
    }
 #ifdef HAVE_RSA_CIPHER
    else if( algo == PUBKEY_ALGO_RSA || algo == PUBKEY_ALGO_RSA_S ) {
	RSA_public_key pk;
	int i, j, c, old_enc;
	byte *dp;
	const byte *asn;
	size_t mdlen, asnlen;

	pk.e = pkey[0];
	pk.n = pkey[1];
	result = mpi_alloc(40);
	rsa_public( result, data[0], &pk );

	old_enc = 0;
	for(i=j=0; (c=mpi_getbyte(result, i)) != -1; i++ ) {
	    if( !j ) {
		if( !i && c != 1 )
		    break;
		else if( i && c == 0xff )
		    ; /* skip the padding */
		else if( i && !c )
		    j++;
		else
		    break;
	    }
	    else if( ++j == 18 && c != 1 )
		break;
	    else if( j == 19 && c == 0 ) {
		old_enc++;
		break;
	    }
	}
	if( old_enc ) {
	    log_error("old encoding scheme is not supported\n");
	    rc = G10ERR_GENERAL;
	    goto leave;
	}

	if( (rc=check_digest_algo(sig->digest_algo)) )
	    goto leave; /* unsupported algo */
	md_enable( digest, sig->digest_algo );
	asn = md_asn_oid( sig->digest_algo, &asnlen, &mdlen );

	for(i=mdlen,j=asnlen-1; (c=mpi_getbyte(result, i)) != -1 && j >= 0;
							       i++, j-- )
	    if( asn[j] != c )
		break;
	if( j != -1 || mpi_getbyte(result, i) ) { /* ASN is wrong */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}
	for(i++; (c=mpi_getbyte(result, i)) != -1; i++ )
	    if( c != 0xff  )
		break;
	i++;
	if( c != sig->digest_algo || mpi_getbyte(result, i) ) {
	    /* Padding or leading bytes in signature is wrong */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}
	if( mpi_getbyte(result, mdlen-1) != sig->digest_start[0]
	    || mpi_getbyte(result, mdlen-2) != sig->digest_start[1] ) {
	    /* Wrong key used to check the signature */
	    rc = G10ERR_BAD_PUBKEY;
	    goto leave;
	}

	/* complete the digest */
	md_putc( digest, sig->sig_class );
	{   u32 a = sig->timestamp;
	    md_putc( digest, (a >> 24) & 0xff );
	    md_putc( digest, (a >> 16) & 0xff );
	    md_putc( digest, (a >>  8) & 0xff );
	    md_putc( digest,  a        & 0xff );
	}
	md_final( digest );
	dp = md_read( digest, sig->digest_algo );
	for(i=mdlen-1; i >= 0; i--, dp++ ) {
	    if( mpi_getbyte( result, i ) != *dp ) {
		rc = G10ERR_BAD_SIGN;
		break;
	    }
	}
    }
  #endif
    else
	rc = G10ERR_PUBKEY_ALGO;

    return rc;
}

