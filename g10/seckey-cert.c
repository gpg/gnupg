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
#include "i18n.h"


static int
do_check( PKT_secret_cert *cert )
{
    byte *buffer;
    u16 csum=0;
    int res;
    unsigned nbytes;

    if( cert->is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	u32 keyid[2];
	CIPHER_HANDLE cipher_hd=NULL;
	PKT_secret_cert *save_cert;
	char save_iv[8];

	if( cert->protect.algo == CIPHER_ALGO_NONE )
	    BUG();
	if( check_cipher_algo( cert->protect.algo ) )
	    return G10ERR_CIPHER_ALGO; /* unsupported protection algorithm */
	keyid_from_skc( cert, keyid );
	dek = passphrase_to_dek( keyid, cert->protect.algo,
				 &cert->protect.s2k, 0 );
	cipher_hd = cipher_open( cert->protect.algo,
				 CIPHER_MODE_AUTO_CFB, 1);
	cipher_setkey( cipher_hd, dek->key, dek->keylen );
	cipher_setiv( cipher_hd, NULL );
	m_free(dek); /* pw is in secure memory, so m_free() burns it */
	save_cert = copy_secret_cert( NULL, cert );
	memcpy(save_iv, cert->protect.iv, 8 );
	cipher_decrypt( cipher_hd, cert->protect.iv, cert->protect.iv, 8 );
	switch( cert->pubkey_algo ) {
	  case PUBKEY_ALGO_ELGAMAL:
	  case PUBKEY_ALGO_ELGAMAL_E:
	    /* FIXME: removed ELG knowledge from this function */
	    buffer = mpi_get_secure_buffer( cert->skey[3], &nbytes, NULL );
	    cipher_decrypt( cipher_hd, buffer, buffer, nbytes );
	    mpi_set_buffer( cert->skey[3], buffer, nbytes, 0 );
	    csum = checksum_mpi( cert->skey[3] );
	    m_free( buffer );
	    break;
	  case PUBKEY_ALGO_DSA:
	    buffer = mpi_get_secure_buffer( cert->skey[4], &nbytes, NULL );
	    cipher_decrypt( cipher_hd, buffer, buffer, nbytes );
	    mpi_set_buffer( cert->skey[4], buffer, nbytes, 0 );
	    csum = checksum_mpi( cert->skey[4] );
	    m_free( buffer );
	    break;
	#ifdef HAVE_RSA_CIPHER
	  case PUBKEY_ALGO_RSA:
	  case PUBKEY_ALGO_RSA_E:
	  case PUBKEY_ALGO_RSA_S:
	    csum = 0;
	    #define X(a) do { \
		buffer = mpi_get_secure_buffer( cert->d.rsa.##a,     \
						&nbytes, NULL );     \
		csum += checksum_u16( nbytes*8 );		     \
		cipher_decrypt( cipher_hd, buffer, buffer, nbytes ); \
		csum += checksum( buffer, nbytes );		     \
		mpi_set_buffer(cert->d.rsa.##a, buffer, nbytes, 0 ); \
		m_free( buffer );				     \
	       } while(0)
	    X(d);
	    X(p);
	    X(q);
	    X(u);
	    #undef X
	    break;
	#endif /* HAVE_RSA_CIPHER */

	  default: BUG();
	}
	cipher_close( cipher_hd );
	/* now let's see whether we have used the right passphrase */
	if( csum != cert->csum ) {
	    if( csum != cert->csum ) {
		copy_secret_cert( cert, save_cert );
		free_secret_cert( save_cert );
		memcpy( cert->protect.iv, save_iv, 8 );
		return G10ERR_BAD_PASS;
	    }
	}

	res = pubkey_check_secret_key( cert->pubkey_algo, cert->skey );
	if( res ) {
	    copy_secret_cert( cert, save_cert );
	    free_secret_cert( save_cert );
	    memcpy( cert->protect.iv, save_iv, 8 );
	    return G10ERR_BAD_PASS;
	}
	free_secret_cert( save_cert );
	cert->is_protected = 0;
    }
    else { /* not protected */
	switch( cert->pubkey_algo ) {
	  case PUBKEY_ALGO_ELGAMAL_E:
	  case PUBKEY_ALGO_ELGAMAL:
	    csum = checksum_mpi( cert->skey[3] );
	    break;
	  case PUBKEY_ALGO_DSA:
	    csum = checksum_mpi( cert->skey[4] );
	    break;
	#ifdef HAVE_RSA_CIPHER
	  case PUBKEY_ALGO_RSA_E:
	  case PUBKEY_ALGO_RSA_S:
	  case PUBKEY_ALGO_RSA:
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
	    break;
	#endif
	  default: BUG();
	}
	if( csum != cert->csum )
	    return G10ERR_CHECKSUM;
    }

    return 0;
}



/****************
 * Check the secret key certificate
 * Ask up to 3 times for a correct passphrase
 */
int
check_secret_key( PKT_secret_cert *cert )
{
    int rc = G10ERR_BAD_PASS;
    int i;

    for(i=0; i < 3 && rc == G10ERR_BAD_PASS; i++ ) {
	if( i )
	    log_error(_("Invalid passphrase; please try again ...\n"));
	switch( cert->pubkey_algo ) {
	  case PUBKEY_ALGO_ELGAMAL_E:
	  case PUBKEY_ALGO_ELGAMAL:
	  case PUBKEY_ALGO_DSA:
	    rc = do_check( cert );
	  #if 0 /* set to 1 to enable the workaround */
	    if( rc == G10ERR_BAD_PASS && cert->is_protected
		&& cert->protect.algo == CIPHER_ALGO_BLOWFISH
		&& cert->pubkey_algo != PUBKEY_ALGO_ELGAMAL ) {
		/* Workaround for a bug in 0.2.16 which still used
		 * a 160 bit key for BLOWFISH. */
     log_info("trying workaround for 0.2.16 passphrase bug ...\n");
     log_info("If you don't need this, uncomment it in g10/seckey-cert.c\n\n");
		cert->protect.algo = CIPHER_ALGO_BLOWFISH160;
		rc = do_check( cert );
		if( rc )
		    rc = G10ERR_BAD_PASS;
		cert->protect.algo = CIPHER_ALGO_BLOWFISH;
	    }
	  #endif
	    break;
	#ifdef HAVE_RSA_CIPHER
	  case PUBKEY_ALGO_RSA:
	  case PUBKEY_ALGO_RSA_E:
	  case PUBKEY_ALGO_RSA_S:
	    rc = do_check( cert );
	    break;
	#endif
	  default: rc = G10ERR_PUBKEY_ALGO;
	}
	if( get_passphrase_fd() != -1 )
	    break;
    }

    return rc;
}

/****************
 * check whether the secret key is protected.
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
      case PUBKEY_ALGO_ELGAMAL_E:
      case PUBKEY_ALGO_ELGAMAL:
	buffer = mpi_get_buffer( cert->skey[3], &nbytes, NULL );
	(*fnc)( fnc_hd, buffer, buffer, nbytes );
	mpi_set_buffer( cert->skey[3], buffer, nbytes, 0 );
	m_free( buffer );
	break;

      case PUBKEY_ALGO_DSA:
	buffer = mpi_get_buffer( cert->skey[4], &nbytes, NULL );
	(*fnc)( fnc_hd, buffer, buffer, nbytes );
	mpi_set_buffer( cert->skey[4], buffer, nbytes, 0 );
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

	if( check_cipher_algo( cert->protect.algo ) )
	    rc = G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	else {
	    cipher_hd = cipher_open( cert->protect.algo,
				     CIPHER_MODE_AUTO_CFB, 1 );
	    cipher_setkey( cipher_hd, dek->key, dek->keylen );
	    cipher_setiv( cipher_hd, NULL );
	    cipher_encrypt( cipher_hd, cert->protect.iv, cert->protect.iv, 8 );
	    if( !do_protect( &cipher_encrypt, cipher_hd, cert ) )
		cert->is_protected = 1;
	    cipher_close( cipher_hd );
	}
    }
    return rc;
}

