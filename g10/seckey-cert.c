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
    int i, res;
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
	m_free(dek);
	save_cert = copy_secret_cert( NULL, cert );
	memcpy(save_iv, cert->protect.iv, 8 );
	cipher_decrypt( cipher_hd, cert->protect.iv, cert->protect.iv, 8 );
	csum = 0;
	for(i=pubkey_get_npkey(cert->pubkey_algo);
		i < pubkey_get_nskey(cert->pubkey_algo); i++ ) {
	    buffer = mpi_get_secure_buffer( cert->skey[i], &nbytes, NULL );
	    cipher_sync( cipher_hd );
	    cipher_decrypt( cipher_hd, buffer, buffer, nbytes );
	    mpi_set_buffer( cert->skey[i], buffer, nbytes, 0 );
	    csum += checksum_mpi( cert->skey[i] );
	    m_free( buffer );
	}
	if( opt.emulate_bugs & 1 ) {
	   log_debug("secret key csum is=%04hx should=%04hx algos=%d/%d\n",
		     csum, cert->csum, cert->pubkey_algo,cert->protect.algo );
	   csum = cert->csum;
	}
	cipher_close( cipher_hd );
	/* now let's see whether we have used the right passphrase */
	if( csum != cert->csum ) {
	    copy_secret_cert( cert, save_cert );
	    free_secret_cert( save_cert );
	    memcpy( cert->protect.iv, save_iv, 8 );
	    return G10ERR_BAD_PASS;
	}
	/* the checksum may fail, so we also check the key itself */
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
    else { /* not protected, assume it is okay if the checksum is okay */
	csum = 0;
	for(i=pubkey_get_npkey(cert->pubkey_algo);
		i < pubkey_get_nskey(cert->pubkey_algo); i++ ) {
	    csum += checksum_mpi( cert->skey[i] );
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



/****************
 * Protect the secret key certificate with the passphrase from DEK
 */
int
protect_secret_key( PKT_secret_cert *cert, DEK *dek )
{
    int i, rc = 0;
    byte *buffer;
    unsigned nbytes;
    u16 csum;

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
	    /* NOTE: we always recalculate the checksum because there are some
	     * test releases which calculated it wrong */
	    csum = 0;
	    for(i=pubkey_get_npkey(cert->pubkey_algo);
		    i < pubkey_get_nskey(cert->pubkey_algo); i++ ) {
		csum += checksum_mpi_counted_nbits( cert->skey[i] );
		buffer = mpi_get_buffer( cert->skey[i], &nbytes, NULL );
	   log_debug("protecing i=%d csum=%04hx nbytes=%u\n", i, csum, nbytes );
		cipher_sync( cipher_hd );
		cipher_encrypt( cipher_hd, buffer, buffer, nbytes );
		mpi_set_buffer( cert->skey[i], buffer, nbytes, 0 );
		m_free( buffer );
	    }
	    cert->csum = csum;
	    cert->is_protected = 1;
	    cipher_close( cipher_hd );
	}
    }
    return rc;
}

