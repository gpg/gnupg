/* seckey-cert.c -  secret key certifucate packet handling
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "mpi.h"
#include "keydb.h"
#include "cipher.h"
#include "main.h"
#include "options.h"


static int
check_elg( PKT_secret_cert *cert )
{
    byte *buffer;
    u16 csum=0;
    int res;
    unsigned nbytes;
    u32 keyid[2];
    ELG_secret_key skey;
    char save_iv[8];

    if( cert->is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	MPI test_x;
	CIPHER_HANDLE cipher_hd=NULL;

	switch( cert->protect.algo ) {
	  case CIPHER_ALGO_NONE: BUG(); break;
	  case CIPHER_ALGO_BLOWFISH:
	  case CIPHER_ALGO_CAST:
	    keyid_from_skc( cert, keyid );
	    if( cert->protect.s2k == 1 || cert->protect.s2k == 3 )
		dek = get_passphrase_hash( keyid, NULL,
						 cert->protect.salt );
	    else
		dek = get_passphrase_hash( keyid, NULL, NULL );

	    cipher_hd = cipher_open( cert->protect.algo,
				     CIPHER_MODE_AUTO_CFB, 1);
	    cipher_setkey( cipher_hd, dek->key, dek->keylen );
	    cipher_setiv( cipher_hd, NULL );
	    m_free(dek); /* pw is in secure memory, so m_free() burns it */
	    memcpy(save_iv, cert->protect.iv, 8 );
	    cipher_decrypt( cipher_hd, cert->protect.iv, cert->protect.iv, 8 );
	    mpi_set_secure(cert->d.elg.x );
	    /*fixme: maybe it is better to set the buffer secure with a
	     * new get_buffer_secure() function */
	    buffer = mpi_get_buffer( cert->d.elg.x, &nbytes, NULL );
	    cipher_decrypt( cipher_hd, buffer, buffer, nbytes );
	    test_x = mpi_alloc_secure( mpi_get_nlimbs(cert->d.elg.x) );
	    mpi_set_buffer( test_x, buffer, nbytes, 0 );
	    csum = checksum_mpi( test_x );
	    m_free( buffer );
	    cipher_close( cipher_hd );
	    /* now let's see wether we have used the right passphrase */
	    if( csum != cert->csum ) {
		/* very bad kludge to work around an early bug */
		csum -= checksum_u16( mpi_get_nbits(test_x) );
		nbytes = mpi_get_nlimbs(test_x) * 4;
		csum += checksum_u16( nbytes*8 );
		if( csum != cert->csum ) {
		    mpi_free(test_x);
		    memcpy( cert->protect.iv, save_iv, 8 );
		    return G10ERR_BAD_PASS;
		}
		if( !opt.batch )
		    log_info("Probably you have an old key - use "
			 "\"--change-passphrase\" to convert.\n");
	    }

	    skey.p = cert->d.elg.p;
	    skey.g = cert->d.elg.g;
	    skey.y = cert->d.elg.y;
	    skey.x = test_x;
	    res = elg_check_secret_key( &skey );
	    memset( &skey, 0, sizeof skey );
	    if( !res ) {
		mpi_free(test_x);
		memcpy( cert->protect.iv, save_iv, 8 );
		return G10ERR_BAD_PASS;
	    }
	    mpi_set(cert->d.elg.x, test_x);
	    mpi_free(test_x);
	    cert->is_protected = 0;
	    break;

	  default:
	    return G10ERR_CIPHER_ALGO; /* unsupported protection algorithm */
	}
    }
    else { /* not protected */
	csum = checksum_mpi( cert->d.elg.x );
	if( csum != cert->csum ) {
	    /* very bad kludge to work around an early bug */
	    csum -= checksum_u16( mpi_get_nbits(cert->d.elg.x) );
	    nbytes = mpi_get_nlimbs(cert->d.elg.x) * 4;
	    csum += checksum_u16( nbytes*8 );
	    if( csum != cert->csum )
		return G10ERR_CHECKSUM;
	    if( !opt.batch )
		 log_info("Probably you have an old key - use "
		     "\"--change-passphrase\" to convert.\n");
	}
    }

    return 0;
}


static int
check_dsa( PKT_secret_cert *cert )
{
    byte *buffer;
    u16 csum=0;
    int res;
    unsigned nbytes;
    u32 keyid[2];
    DSA_secret_key skey;
    char save_iv[8];

    if( cert->is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	MPI test_x;
	CIPHER_HANDLE cipher_hd=NULL;

	switch( cert->protect.algo ) {
	  case CIPHER_ALGO_NONE: BUG(); break;
	  case CIPHER_ALGO_BLOWFISH:
	  case CIPHER_ALGO_CAST:
	    keyid_from_skc( cert, keyid );
	    if( cert->protect.s2k == 1 || cert->protect.s2k == 3 )
		dek = get_passphrase_hash( keyid, NULL,
						 cert->protect.salt );
	    else
		dek = get_passphrase_hash( keyid, NULL, NULL );

	    cipher_hd = cipher_open( cert->protect.algo,
				     CIPHER_MODE_AUTO_CFB, 1);
	    cipher_setkey( cipher_hd, dek->key, dek->keylen );
	    cipher_setiv( cipher_hd, NULL );
	    m_free(dek); /* pw is in secure memory, so m_free() burns it */
	    memcpy(save_iv, cert->protect.iv, 8 );
	    cipher_decrypt( cipher_hd, cert->protect.iv, cert->protect.iv, 8 );
	    mpi_set_secure(cert->d.dsa.x );
	    /*fixme: maybe it is better to set the buffer secure with a
	     * new get_buffer_secure() function */
	    buffer = mpi_get_buffer( cert->d.dsa.x, &nbytes, NULL );
	    cipher_decrypt( cipher_hd, buffer, buffer, nbytes );
	    test_x = mpi_alloc_secure( mpi_get_nlimbs(cert->d.dsa.x) );
	    mpi_set_buffer( test_x, buffer, nbytes, 0 );
	    csum = checksum_mpi( test_x );
	    m_free( buffer );
	    cipher_close( cipher_hd );
	    /* now let's see wether we have used the right passphrase */
	    if( csum != cert->csum ) {
		mpi_free(test_x);
		memcpy( cert->protect.iv, save_iv, 8 );
		return G10ERR_BAD_PASS;
	    }

	    skey.p = cert->d.dsa.p;
	    skey.q = cert->d.dsa.q;
	    skey.g = cert->d.dsa.g;
	    skey.y = cert->d.dsa.y;
	    skey.x = test_x;
	    res = dsa_check_secret_key( &skey );
	    memset( &skey, 0, sizeof skey );
	    if( !res ) {
		mpi_free(test_x);
		memcpy( cert->protect.iv, save_iv, 8 );
		return G10ERR_BAD_PASS;
	    }
	    mpi_set(cert->d.dsa.x, test_x);
	    mpi_free(test_x);
	    cert->is_protected = 0;
	    break;

	  default:
	    return G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	}
    }
    else { /* not protected */
	csum = checksum_mpi( cert->d.dsa.x );
	if( csum != cert->csum )
	    return G10ERR_CHECKSUM;
    }

    return 0;
}



#ifdef HAVE_RSA_CIPHER
/****************
 * FIXME: fix checksum stuff
 */
static int
check_rsa( PKT_secret_cert *cert )
{
    byte *buffer;
    u16 csum=0;
    int res;
    unsigned nbytes;
    u32 keyid[2];
    RSA_secret_key skey;

    if( cert->is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	BLOWFISH_context *blowfish_ctx=NULL;

	switch( cert->protect.algo ) {
	    /* FIXME: use test variables to check for the correct key */
	  case CIPHER_ALGO_NONE: BUG(); break;
	  case CIPHER_ALGO_BLOWFISH:
	    keyid_from_skc( cert, keyid );
	    dek = get_passphrase_hash( keyid, NULL, NULL );
	    blowfish_ctx = m_alloc_secure( sizeof *blowfish_ctx );
	    blowfish_setkey( blowfish_ctx, dek->key, dek->keylen );
	    m_free(dek); /* pw is in secure memory, so m_free() burns it */
	    blowfish_setiv( blowfish_ctx, NULL );
	    blowfish_decode_cfb( blowfish_ctx, cert->protect.iv,
					       cert->protect.iv, 8 );
	    csum = 0;
	    #define X(a) do { \
		mpi_set_secure(cert->d.rsa.rsa_##a); \
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
	    cert->is_protected = 0;
	    m_free( blowfish_ctx );
	    /* now let's see wether we have used the right passphrase */
	    if( csum != cert->csum )
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
	if( csum != cert->csum )
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
	else if( cert->pubkey_algo == PUBKEY_ALGO_DSA )
	    rc = check_dsa( cert );
      #ifdef HAVE_RSA_CIPHER
	else if( cert->pubkey_algo == PUBKEY_ALGO_RSA )
	    rc = check_rsa( cert );
      #endif
	else
	    rc = G10ERR_PUBKEY_ALGO;
	if( get_passphrase_fd() != -1 )
	    break;
    }
    return rc;
}

/****************
 * check wether the secret key is protected.
 * Returns: 0 not protected, -1 on error or the protection algorithm
 */
int
is_secret_key_protected( PKT_secret_cert *cert )
{
    return cert->is_protected? cert->protect.algo : 0;
}


static int
do_protect( void (*fnc)(CIPHER_HANDLE, byte *, byte *, unsigned),
	    CIPHER_HANDLE fnc_hd, PKT_secret_cert *cert )
{
    byte *buffer;
    unsigned nbytes;

    switch( cert->pubkey_algo ) {
      case PUBKEY_ALGO_ELGAMAL:
	/* recalculate the checksum, so that --change-passphrase
	 * can be used to convert from the faulty to the correct one
	 * wk 06.04.98:
	 * fixme: remove this some time in the future.
	 */
	cert->csum = checksum_mpi( cert->d.elg.x );
	buffer = mpi_get_buffer( cert->d.elg.x, &nbytes, NULL );
	(*fnc)( fnc_hd, buffer, buffer, nbytes );
	mpi_set_buffer( cert->d.elg.x, buffer, nbytes, 0 );
	m_free( buffer );
	break;

      case PUBKEY_ALGO_DSA:
	buffer = mpi_get_buffer( cert->d.dsa.x, &nbytes, NULL );
	(*fnc)( fnc_hd, buffer, buffer, nbytes );
	mpi_set_buffer( cert->d.dsa.x, buffer, nbytes, 0 );
	m_free( buffer );
	break;

      default: return G10ERR_PUBKEY_ALGO;
    }
    return 0;
}


/****************
 * Protect the secret key certificate with the passphrase from DEK
 */
int
protect_secret_key( PKT_secret_cert *cert, DEK *dek )
{
    int rc=0;

    if( !dek )
	return 0;

    if( !cert->is_protected ) { /* okay, apply the protection */
	CIPHER_HANDLE cipher_hd=NULL;

	switch( cert->protect.algo ) {
	  case CIPHER_ALGO_NONE: BUG(); break;
	  case CIPHER_ALGO_BLOWFISH:
	  case CIPHER_ALGO_CAST:
	    cipher_hd = cipher_open( cert->protect.algo,
				     CIPHER_MODE_AUTO_CFB, 1 );
	    cipher_setkey( cipher_hd, dek->key, dek->keylen );
	    cipher_setiv( cipher_hd, NULL );
	    cipher_encrypt( cipher_hd, cert->protect.iv, cert->protect.iv, 8 );
	    if( !do_protect( &cipher_encrypt, cipher_hd, cert ) )
		cert->is_protected = 1;
	    cipher_close( cipher_hd );
	    break;

	  default:
	    rc = G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	    break;
	}
    }
    return rc;
}

