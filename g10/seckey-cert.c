/* seckey-cert.c -  secret key certificate packet handling
 *	Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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

#include <gcrypt.h>
#include "util.h"
#include "packet.h"
#include "keydb.h"
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
	GCRY_CIPHER_HD cipher_hd=NULL;
	PKT_secret_key *save_sk;

	if( sk->protect.algo == GCRY_CIPHER_NONE )
	    BUG();
	if( openpgp_cipher_test_algo( sk->protect.algo ) ) {
	    log_info(_("protection algorithm %d is not supported\n"),
			sk->protect.algo );
	    return G10ERR_CIPHER_ALGO;
	}
	keyid_from_sk( sk, keyid );
	keyid[2] = keyid[3] = 0;
	if( !sk->is_primary ) {
	    PKT_secret_key *sk2 = gcry_xcalloc( 1, sizeof *sk2 );
	    if( !get_primary_seckey( sk2, keyid ) )
		keyid_from_sk( sk2, keyid+2 );
	    free_secret_key( sk2 );
	}
	dek = passphrase_to_dek( keyid, sk->pubkey_algo, sk->protect.algo,
				 &sk->protect.s2k, 0 );
	if( !(cipher_hd = gcry_cipher_open( sk->protect.algo,
				      GCRY_CIPHER_MODE_CFB,
				      GCRY_CIPHER_SECURE
				      | (sk->protect.algo >= 100 ?
					   0 : GCRY_CIPHER_ENABLE_SYNC) ) )
				    ) {
	    BUG();
	}

	if( gcry_cipher_setkey( cipher_hd, dek->key, dek->keylen ) )
	    log_fatal("set key failed: %s\n", gcry_strerror(-1) );
	gcry_free(dek);
	save_sk = copy_secret_key( NULL, sk );
	if( gcry_cipher_setiv( cipher_hd, sk->protect.iv, sk->protect.ivlen ))
	    log_fatal("set IV failed: %s\n", gcry_strerror(-1) );
	csum = 0;
	if( sk->version >= 4 ) {
	    size_t ndata;
	    unsigned int ndatabits;
	    byte *p, *data;

	    i = pubkey_get_npkey(sk->pubkey_algo);
	    assert( gcry_mpi_get_flag( sk->skey[i], GCRYMPI_FLAG_OPAQUE ) );
	    p = gcry_mpi_get_opaque( sk->skey[i], &ndatabits );
	    ndata = (ndatabits+7)/8;
	    data = gcry_xmalloc_secure( ndata );
	    gcry_cipher_decrypt( cipher_hd, data, ndata, p, ndata );
	    mpi_release( sk->skey[i] ); sk->skey[i] = NULL ;
	    p = data;
	    if( ndata < 2 ) {
		log_error("not enough bytes for checksum\n");
		sk->csum = 0;
		csum = 1;
	    }
	    else {
		csum = checksum( data, ndata-2);
		sk->csum = data[ndata-2] << 8 | data[ndata-1];
	    }
	    /* must check it here otherwise the mpi_read_xx would fail
	     * because the length may have an arbitrary value */
	    if( sk->csum == csum ) {
		for( ; i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		    nbytes = ndata;
		    assert( gcry_is_secure( p ) );
		    res = gcry_mpi_scan( &sk->skey[i], GCRYMPI_FMT_PGP,
							     p, &nbytes);
		    if( res )
			log_bug("gcry_mpi_scan failed in do_check: rc=%d\n", res);

		    ndata -= nbytes;
		    p += nbytes;
		}
	    }
	    gcry_free(data);
	}
	else {
	    for(i=pubkey_get_npkey(sk->pubkey_algo);
		    i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		size_t ndata;
		unsigned int ndatabits;
		byte *p, *data;

		assert( gcry_mpi_get_flag( sk->skey[i], GCRYMPI_FLAG_OPAQUE ) );
		p = gcry_mpi_get_opaque( sk->skey[i], &ndatabits );
		ndata = (ndatabits+7)/8;
		data = gcry_xmalloc_secure( ndata );
		gcry_cipher_sync( cipher_hd );
		gcry_cipher_decrypt( cipher_hd, data, ndata, p, ndata );
		mpi_release( sk->skey[i] ); sk->skey[i] = NULL ;

		res = gcry_mpi_scan( &sk->skey[i], GCRYMPI_FMT_USG,
				     data, &ndata );
		if( res )
		    log_bug("gcry_mpi_scan failed in do_check: rc=%d\n", res);

		csum += checksum_mpi( sk->skey[i] );
		gcry_free( buffer );
	    }
	}
	gcry_cipher_close( cipher_hd );
	/* now let's see whether we have used the right passphrase */
	if( csum != sk->csum ) {
	    copy_secret_key( sk, save_sk );
	    free_secret_key( save_sk );
	    return G10ERR_BAD_PASS;
	}
	/* the checksum may fail, so we also check the key itself */
	res = pubkey_check_secret_key( sk->pubkey_algo, sk->skey );
	if( res ) {
	    copy_secret_key( sk, save_sk );
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
	GCRY_CIPHER_HD cipher_hd=NULL;

	if( openpgp_cipher_test_algo( sk->protect.algo ) )
	    rc = G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	else {
	    print_cipher_algo_note( sk->protect.algo );
	    if( !(cipher_hd = gcry_cipher_open( sk->protect.algo,
					  GCRY_CIPHER_MODE_CFB,
					  GCRY_CIPHER_SECURE
					  | (sk->protect.algo >= 100 ?
					      0 : GCRY_CIPHER_ENABLE_SYNC) ))
					 ) {
		BUG();
	    }


	    rc = gcry_cipher_setkey( cipher_hd, dek->key, dek->keylen );
	    if( rc == GCRYERR_WEAK_KEY ) {
		log_info(_("WARNING: Weak key detected"
			   " - please change passphrase again.\n"));
		rc = 0;
	    }
	    else if( rc )
		BUG();

	    /* set the IV length */
	    {	int blocksize = gcry_cipher_get_algo_blklen( sk->protect.algo );
		if( blocksize != 8 && blocksize != 16 )
		    log_fatal("unsupported blocksize %d\n", blocksize );
		sk->protect.ivlen = blocksize;
	    }

	    assert( sk->protect.ivlen <= DIM(sk->protect.iv) );
	    gcry_randomize(sk->protect.iv, sk->protect.ivlen,
							GCRY_STRONG_RANDOM);
	    gcry_cipher_setiv( cipher_hd, sk->protect.iv, sk->protect.ivlen );
	    #warning FIXME: replace set/get buffer
	    if( sk->version >= 4 ) {
	      #define NMPIS (GNUPG_MAX_NSKEY - GNUPG_MAX_NPKEY)
		byte *bufarr[NMPIS];
		unsigned narr[NMPIS];
		unsigned nbits[NMPIS];
		int ndata=0;
		byte *p, *data;

		for(j=0, i = pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++, j++ ) {
		    assert( !gcry_mpi_get_flag( sk->skey[i], GCRYMPI_FLAG_OPAQUE ) );

		    if( gcry_mpi_aprint( GCRYMPI_FMT_USG, (char*)bufarr+j,
							  narr+j, sk->skey[i]))
			BUG();

		    nbits[j]  = gcry_mpi_get_nbits( sk->skey[i] );
		    ndata += narr[j] + 2;
		}
		for( ; j < NMPIS; j++ )
		    bufarr[j] = NULL;
		ndata += 2; /* for checksum */

		data = gcry_xmalloc_secure( ndata );
		p = data;
		for(j=0; j < NMPIS && bufarr[j]; j++ ) {
		    p[0] = nbits[j] >> 8 ;
		    p[1] = nbits[j];
		    p += 2;
		    memcpy(p, bufarr[j], narr[j] );
		    p += narr[j];
		    gcry_free(bufarr[j]);
		}
	      #undef NMPIS
		csum = checksum( data, ndata-2);
		sk->csum = csum;
		*p++ =	csum >> 8;
		*p++ =	csum;
		assert( p == data+ndata );
		gcry_cipher_encrypt( cipher_hd, data, ndata, NULL, 0 );
		for(i = pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		    mpi_release( sk->skey[i] );
		    sk->skey[i] = NULL;
		}
		i = pubkey_get_npkey(sk->pubkey_algo);
		sk->skey[i] = gcry_mpi_set_opaque(NULL, data, ndata*8 );
	    }
	    else {
		/* NOTE: we always recalculate the checksum because there
		 * are some test releases which calculated it wrong */
	       #warning FIXME:	Replace this code
		csum = 0;
		for(i=pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
		    csum += checksum_mpi( sk->skey[i] );

		    if( gcry_mpi_aprint( GCRYMPI_FMT_USG,
					 &buffer, &nbytes, sk->skey[i] ) )
			BUG();

		    gcry_cipher_sync( cipher_hd );
		    assert( !gcry_mpi_get_flag( sk->skey[i], GCRYMPI_FLAG_OPAQUE ) );
		    gcry_cipher_encrypt( cipher_hd, buffer, nbytes, NULL, 0 );
		    gcry_mpi_release( sk->skey[i] );
		    if( gcry_mpi_scan( &sk->skey[i], GCRYMPI_FMT_USG,
				       buffer,&nbytes ) )
			BUG();

		    gcry_free( buffer );
		}
		sk->csum = csum;
	    }
	    sk->is_protected = 1;
	    gcry_cipher_close( cipher_hd );
	}
    }
    return rc;
}

