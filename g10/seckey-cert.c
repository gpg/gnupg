/* seckey-cert.c -  secret key certifucate packet handling
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "mpi.h"
#include "keydb.h"
#include "cipher.h"

#if  BLOWFISH_BLOCKSIZE != 8
  #error unsupportted blocksize
#endif

static u16
checksum_u16( unsigned n )
{
    u16 a;

    a  = (n >> 8) & 0xff;
    a |= n & 0xff;
    return a;
}

static u16
checksum( byte *p, unsigned n )
{
    u16 a;

    for(a=0; n; n-- )
	a += *p++;
    return a;
}



static int
check_elg( PKT_secret_cert *cert )
{
    byte *buffer;
    u16 n, csum=0;
    int res;
    unsigned nbytes;
    u32 keyid[2];
    ELG_secret_key skey;

    if( cert->d.elg.is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	MPI test_x;
	BLOWFISH_context *blowfish_ctx=NULL;

	switch( cert->d.elg.protect_algo ) {
	  case CIPHER_ALGO_NONE: log_bug(NULL); break;
	  case CIPHER_ALGO_BLOWFISH:
	    keyid_from_skc( cert, keyid );
	    dek = get_passphrase_hash( keyid, NULL );
	    blowfish_ctx = m_alloc_secure( sizeof *blowfish_ctx );
	    blowfish_setkey( blowfish_ctx, dek->key, dek->keylen );
	    m_free(dek); /* pw is in secure memory, so m_free() burns it */
	    blowfish_setiv( blowfish_ctx, NULL );
	    blowfish_decode_cfb( blowfish_ctx,
				 cert->d.elg.protect.blowfish.iv,
				 cert->d.elg.protect.blowfish.iv, 8 );
	    buffer = mpi_get_buffer( cert->d.elg.x, &nbytes, NULL );
	    csum = checksum_u16( nbytes*8 );
	    blowfish_decode_cfb( blowfish_ctx, buffer, buffer, nbytes );
	    csum += checksum( buffer, nbytes );
	    test_x = mpi_alloc_secure( mpi_get_nlimbs(cert->d.elg.x) );
	    mpi_set_buffer( test_x, buffer, nbytes, 0 );
	    m_free( buffer );
	    m_free( blowfish_ctx );
	    /* now let's see wether we have used the right passphrase */
	    if( csum != cert->d.elg.csum ) {
		mpi_free(test_x);
		return G10ERR_BAD_PASS;
	    }

	    skey.p = cert->d.elg.p;
	    skey.g = cert->d.elg.g;
	    skey.y = cert->d.elg.y;
	    skey.x = test_x;
	    res = elg_check_secret_key( &skey );
	    memset( &skey, 0, sizeof skey );
	    if( !res ) {
		mpi_free(test_x);
		return G10ERR_BAD_PASS;
	    }
	    mpi_set(cert->d.elg.x, test_x);
	    mpi_free(test_x);
	    cert->d.elg.is_protected = 0;
	    break;

	  default:
	    return G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	}
    }
    else { /* not protected */
	buffer = mpi_get_buffer( cert->d.elg.x, &nbytes, NULL );
	csum = checksum_u16( nbytes*8 );
	csum += checksum( buffer, nbytes );
	m_free( buffer );
	if( csum != cert->d.elg.csum )
	    return G10ERR_CHECKSUM;
    }

    return 0;
}

static int
protect_elg( PKT_secret_cert *cert, DEK *dek )
{
    byte *buffer;
    unsigned nbytes;

    if( !cert->d.elg.is_protected ) { /* add the protection */
	BLOWFISH_context *blowfish_ctx=NULL;

	switch( cert->d.elg.protect_algo ) {
	  case CIPHER_ALGO_NONE: log_bug(NULL); break;
	  case CIPHER_ALGO_BLOWFISH:
	    blowfish_ctx = m_alloc_secure( sizeof *blowfish_ctx );
	    blowfish_setkey( blowfish_ctx, dek->key, dek->keylen );
	    blowfish_setiv( blowfish_ctx, NULL );
	    blowfish_encode_cfb( blowfish_ctx,
				 cert->d.elg.protect.blowfish.iv,
				 cert->d.elg.protect.blowfish.iv, 8 );
	    buffer = mpi_get_buffer( cert->d.elg.x, &nbytes, NULL );
	    blowfish_encode_cfb( blowfish_ctx, buffer, buffer, nbytes );
	    mpi_set_buffer( cert->d.elg.x, buffer, nbytes, 0 );
	    m_free( buffer );
	    m_free( blowfish_ctx );
	    cert->d.elg.is_protected = 1;
	    break;

	  default:
	    return G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	}
    }
    return 0;
}


#ifdef HAVE_RSA_CIPHER
static int
check_rsa( PKT_secret_cert *cert )
{
    byte *buffer;
    u16 n, csum=0;
    int res;
    unsigned nbytes;
    u32 keyid[2];
    RSA_secret_key skey;

    if( cert->d.rsa.is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	BLOWFISH_context *blowfish_ctx=NULL;

	switch( cert->d.rsa.protect_algo ) {
	    /* FIXME: use test variables to check for the correct key */
	  case CIPHER_ALGO_NONE: log_bug(NULL); break;
	  case CIPHER_ALGO_BLOWFISH:
	    keyid_from_skc( cert, keyid );
	    dek = get_passphrase_hash( keyid, NULL );
	    blowfish_ctx = m_alloc_secure( sizeof *blowfish_ctx );
	    blowfish_setkey( blowfish_ctx, dek->key, dek->keylen );
	    m_free(dek); /* pw is in secure memory, so m_free() burns it */
	    blowfish_setiv( blowfish_ctx, NULL );
	    blowfish_decode_cfb( blowfish_ctx,
				 cert->d.rsa.protect.blowfish.iv,
				 cert->d.rsa.protect.blowfish.iv, 8 );
	    csum = 0;
	    #define X(a) do { \
		buffer = mpi_get_buffer( cert->d.rsa.rsa_##a, &nbytes, NULL );\
		csum += checksum_u16( nbytes*8 );			     \
		blowfish_decode_cfb( blowfish_ctx, buffer, buffer, nbytes ); \
		csum += checksum( buffer, nbytes );			     \
		mpi_set_buffer(cert->d.rsa.rsa_##a, buffer, nbytes, 0 );     \
		m_free( buffer );					     \
	       } while(0)
	    X(d);
	    X(p);
	    X(q);
	    X(u);
	    #undef X
	    cert->d.rsa.is_protected = 0;
	    m_free( blowfish_ctx );
	    /* now let's see wether we have used the right passphrase */
	    if( csum != cert->d.rsa.csum )
		return G10ERR_BAD_PASS;

	    skey.d = cert->d.rsa.rsa_d;
	    skey.p = cert->d.rsa.rsa_p;
	    skey.q = cert->d.rsa.rsa_q;
	    skey.u = cert->d.rsa.rsa_u;
	    res = rsa_check_secret_key( &skey );
	    memset( &skey, 0, sizeof skey );
	    if( !res )
		return G10ERR_BAD_PASS;
	    break;

	  default:
	    return G10ERR_CIPHER_ALGO; /* unsupported protection algorithm */
	}
    }
    else { /* not protected */
	csum =0;
	buffer = mpi_get_buffer( cert->d.rsa.rsa_d, &nbytes, NULL );
	csum += checksum_u16( nbytes*8 );
	csum += checksum( buffer, nbytes );
	m_free( buffer );
	buffer = mpi_get_buffer( cert->d.rsa.rsa_p, &nbytes, NULL );
	csum += checksum_u16( nbytes*8 );
	csum += checksum( buffer, nbytes );
	m_free( buffer );
	buffer = mpi_get_buffer( cert->d.rsa.rsa_q, &nbytes, NULL );
	csum += checksum_u16( nbytes*8 );
	csum += checksum( buffer, nbytes );
	m_free( buffer );
	buffer = mpi_get_buffer( cert->d.rsa.rsa_u, &nbytes, NULL );
	csum += checksum_u16( nbytes*8 );
	csum += checksum( buffer, nbytes );
	m_free( buffer );
	if( csum != cert->d.rsa.csum )
	    return G10ERR_CHECKSUM;
    }

    return 0;
}
#endif /*HAVE_RSA_CIPHER*/




/****************
 * Check the secret key certificate
 * Ask up to 3 time for a correct passphrase
 */
int
check_secret_key( PKT_secret_cert *cert )
{
    int rc = G10ERR_BAD_PASS;
    int i;

    for(i=0; i < 3 && rc == G10ERR_BAD_PASS; i++ ) {
	if( i )
	    log_error("Invalid passphrase; please try again ...\n");
	if( cert->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	    rc = check_elg( cert );
      #ifdef HAVE_RSA_CIPHER
	else if( cert->pubkey_algo == PUBKEY_ALGO_RSA )
	    rc = check_rsa( cert );
      #endif
	else
	    rc = G10ERR_PUBKEY_ALGO;
    }
    return rc;
}


/****************
 * Protect the secret key certificate with the passphrase from DEK
 */
int
protect_secret_key( PKT_secret_cert *cert, DEK *dek )
{
    if( !dek )
	return 0;

    if( cert->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	return protect_elg( cert, dek );
  #ifdef 0 /* noy yet implemented */
    else if( cert->pubkey_algo == PUBKEY_ALGO_RSA )
	return protect_rsa( cert, dek );
  #endif
    else
	return G10ERR_PUBKEY_ALGO;
}

