/* seckey-cert.c -  secret key certificate packet handling
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
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
#include "status.h"


static int
do_check( PKT_secret_key *sk )
{
    byte *buffer;
    u16 csum=0;
    int i, res;
    unsigned nbytes;

    if( sk->is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	u32 keyid[4]; /* 4! because we need two of them */
	CIPHER_HANDLE cipher_hd=NULL;
	PKT_secret_key *save_sk;

	if( sk->protect.s2k.mode == 1001 ) {
	    log_info(_("secret key parts are not available\n"));
	    return G10ERR_GENERAL;
	}
	if( sk->protect.algo == CIPHER_ALGO_NONE )
	    BUG();
	if( check_cipher_algo( sk->protect.algo ) ) {
	    log_info(_("protection algorithm %d is not supported\n"),
			sk->protect.algo );
	    return G10ERR_CIPHER_ALGO;
	}
	keyid_from_sk( sk, keyid );
	keyid[2] = keyid[3] = 0;
	if( !sk->is_primary ) {
            keyid[2] = sk->main_keyid[0];
            keyid[3] = sk->main_keyid[1];
	}
	dek = passphrase_to_dek( keyid, sk->pubkey_algo, sk->protect.algo,
				 &sk->protect.s2k, 0 );
	cipher_hd = cipher_open( sk->protect.algo,
				 CIPHER_MODE_AUTO_CFB, 1);
	cipher_setkey( cipher_hd, dek->key, dek->keylen );
	m_free(dek);
	save_sk = copy_secret_key( NULL, sk );
	cipher_setiv( cipher_hd, sk->protect.iv, sk->protect.ivlen );
	csum = 0;
	if( sk->version >= 4 ) {
	    int ndata;
	    byte *p, *data;
            u16 csumc = 0;

	    i = pubkey_get_npkey(sk->pubkey_algo);
	    assert( mpi_is_opaque( sk->skey[i] ) );
	    p = mpi_get_opaque( sk->skey[i], &ndata );
            if ( ndata > 1 )
                csumc = p[ndata-2] << 8 | p[ndata-1];
	    data = m_alloc_secure( ndata );
	    cipher_decrypt( cipher_hd, data, p, ndata );
	    mpi_free( sk->skey[i] ); sk->skey[i] = NULL ;
	    p = data;
	    if( ndata < 2 ) {
		log_error("not enough bytes for checksum\n");
		sk->csum = 0;
		csum = 1;
	    }
	    else {
		csum = checksum( data, ndata-2);
		sk->csum = data[ndata-2] << 8 | data[ndata-1];
                if ( sk->csum != csum ) {
                    /* This is a PGP 7.0.0 workaround */
                    sk->csum = csumc; /* take the encrypted one */
                }
	    }
            
	    /* must check it here otherwise the mpi_read_xx would fail
	     * because the length may have an arbitrary value */
	    if( sk->csum == csum ) {
		for( ; i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		    nbytes = ndata;
		    sk->skey[i] = mpi_read_from_buffer(p, &nbytes, 1 );
		    ndata -= nbytes;
		    p += nbytes;
		}
                /* at this point ndata should be equal to 2 (the checksum) */
	    }
	    m_free(data);
	}
	else {
	    for(i=pubkey_get_npkey(sk->pubkey_algo);
		    i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		buffer = mpi_get_secure_buffer( sk->skey[i], &nbytes, NULL );
		cipher_sync( cipher_hd );
		assert( mpi_is_protected(sk->skey[i]) );
		cipher_decrypt( cipher_hd, buffer, buffer, nbytes );
		mpi_set_buffer( sk->skey[i], buffer, nbytes, 0 );
		mpi_clear_protect_flag( sk->skey[i] );
		csum += checksum_mpi( sk->skey[i] );
		m_free( buffer );
	    }
	    if( opt.emulate_bugs & EMUBUG_GPGCHKSUM ) {
	       csum = sk->csum;
	    }
	}
	cipher_close( cipher_hd );
	/* now let's see whether we have used the right passphrase */
	if( csum != sk->csum ) {
	    copy_secret_key( sk, save_sk );
            passphrase_clear_cache ( keyid, sk->pubkey_algo );
	    free_secret_key( save_sk );
	    return G10ERR_BAD_PASS;
	}
	/* the checksum may fail, so we also check the key itself */
	res = pubkey_check_secret_key( sk->pubkey_algo, sk->skey );
	if( res ) {
	    copy_secret_key( sk, save_sk );
            passphrase_clear_cache ( keyid, sk->pubkey_algo );
	    free_secret_key( save_sk );
	    return G10ERR_BAD_PASS;
	}
	free_secret_key( save_sk );
	sk->is_protected = 0;
    }
    else { /* not protected, assume it is okay if the checksum is okay */
	csum = 0;
	for(i=pubkey_get_npkey(sk->pubkey_algo);
		i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
	    csum += checksum_mpi( sk->skey[i] );
	}
	if( csum != sk->csum )
	    return G10ERR_CHECKSUM;
    }

    return 0;
}



/****************
 * Check the secret key
 * Ask up to 3 (or n) times for a correct passphrase
 */
int
check_secret_key( PKT_secret_key *sk, int n )
{
    int rc = G10ERR_BAD_PASS;
    int i;

    if( n < 1 )
	n = opt.batch? 1 : 3; /* use the default value */

    for(i=0; i < n && rc == G10ERR_BAD_PASS; i++ ) {
	if( i )
	    log_info(_("Invalid passphrase; please try again ...\n"));
	rc = do_check( sk );
	if( rc == G10ERR_BAD_PASS && is_status_enabled() ) {
	    u32 kid[2];
	    char buf[50];

	    keyid_from_sk( sk, kid );
	    sprintf(buf, "%08lX%08lX", (ulong)kid[0], (ulong)kid[1]);
	    write_status_text( STATUS_BAD_PASSPHRASE, buf );
	}
	if( have_static_passphrase() )
	    break;
    }

    if( !rc )
	write_status( STATUS_GOOD_PASSPHRASE );

    return rc;
}

/****************
 * check whether the secret key is protected.
 * Returns: 0 not protected, -1 on error or the protection algorithm
 */
int
is_secret_key_protected( PKT_secret_key *sk )
{
    return sk->is_protected? sk->protect.algo : 0;
}



/****************
 * Protect the secret key with the passphrase from DEK
 */
int
protect_secret_key( PKT_secret_key *sk, DEK *dek )
{
    int i,j, rc = 0;
    byte *buffer;
    unsigned nbytes;
    u16 csum;

    if( !dek )
	return 0;

    if( !sk->is_protected ) { /* okay, apply the protection */
	CIPHER_HANDLE cipher_hd=NULL;

	if( check_cipher_algo( sk->protect.algo ) )
	    rc = G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	else {
	    print_cipher_algo_note( sk->protect.algo );
	    cipher_hd = cipher_open( sk->protect.algo,
				     CIPHER_MODE_AUTO_CFB, 1 );
	    if( cipher_setkey( cipher_hd, dek->key, dek->keylen ) )
		log_info(_("WARNING: Weak key detected"
			   " - please change passphrase again.\n"));
	    sk->protect.ivlen = cipher_get_blocksize( sk->protect.algo );
	    assert( sk->protect.ivlen <= DIM(sk->protect.iv) );
	    if( sk->protect.ivlen != 8 && sk->protect.ivlen != 16 )
		BUG(); /* yes, we are very careful */
	    randomize_buffer(sk->protect.iv, sk->protect.ivlen, 1);
	    cipher_setiv( cipher_hd, sk->protect.iv, sk->protect.ivlen );
	    if( sk->version >= 4 ) {
                byte *bufarr[PUBKEY_MAX_NSKEY];
		unsigned narr[PUBKEY_MAX_NSKEY];
		unsigned nbits[PUBKEY_MAX_NSKEY];
		int ndata=0;
		byte *p, *data;

		for(j=0, i = pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++, j++ ) {
		    assert( !mpi_is_opaque( sk->skey[i] ) );
		    bufarr[j] = mpi_get_buffer( sk->skey[i], &narr[j], NULL );
		    nbits[j]  = mpi_get_nbits( sk->skey[i] );
		    ndata += narr[j] + 2;
		}
		for( ; j < PUBKEY_MAX_NSKEY; j++ )
		    bufarr[j] = NULL;
		ndata += 2; /* for checksum */

		data = m_alloc_secure( ndata );
		p = data;
		for(j=0; j < PUBKEY_MAX_NSKEY && bufarr[j]; j++ ) {
		    p[0] = nbits[j] >> 8 ;
		    p[1] = nbits[j];
		    p += 2;
		    memcpy(p, bufarr[j], narr[j] );
		    p += narr[j];
		    m_free(bufarr[j]);
		}
		csum = checksum( data, ndata-2);
		sk->csum = csum;
		*p++ =	csum >> 8;
		*p++ =	csum;
		assert( p == data+ndata );
		cipher_encrypt( cipher_hd, data, data, ndata );
		for(i = pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		    mpi_free( sk->skey[i] );
		    sk->skey[i] = NULL;
		}
		i = pubkey_get_npkey(sk->pubkey_algo);
		sk->skey[i] = mpi_set_opaque(NULL, data, ndata );
	    }
	    else {
		/* NOTE: we always recalculate the checksum because there
		 * are some test releases which calculated it wrong */
		csum = 0;
		for(i=pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		    csum += checksum_mpi_counted_nbits( sk->skey[i] );
		    buffer = mpi_get_buffer( sk->skey[i], &nbytes, NULL );
		    cipher_sync( cipher_hd );
		    assert( !mpi_is_protected(sk->skey[i]) );
		    cipher_encrypt( cipher_hd, buffer, buffer, nbytes );
		    mpi_set_buffer( sk->skey[i], buffer, nbytes, 0 );
		    mpi_set_protect_flag( sk->skey[i] );
		    m_free( buffer );
		}
		sk->csum = csum;
	    }
	    sk->is_protected = 1;
	    cipher_close( cipher_hd );
	}
    }
    return rc;
}

