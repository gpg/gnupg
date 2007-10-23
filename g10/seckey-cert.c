/* seckey-cert.c -  secret key certificate packet handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
do_check( PKT_secret_key *sk, const char *tryagain_text, int mode,
          int *canceled )
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
	    log_info(_("protection algorithm %d%s is not supported\n"),
			sk->protect.algo,sk->protect.algo==1?" (IDEA)":"" );
	    if (sk->protect.algo==CIPHER_ALGO_IDEA)
              {
                write_status (STATUS_RSA_OR_IDEA);
                idea_cipher_warn (0);
              }
	    return G10ERR_CIPHER_ALGO;
	}
	if(check_digest_algo(sk->protect.s2k.hash_algo))
	  {
	    log_info(_("protection digest %d is not supported\n"),
		     sk->protect.s2k.hash_algo);
	    return G10ERR_DIGEST_ALGO;
	  }
	keyid_from_sk( sk, keyid );
	keyid[2] = keyid[3] = 0;
	if( !sk->is_primary ) {
            keyid[2] = sk->main_keyid[0];
            keyid[3] = sk->main_keyid[1];
	}
	dek = passphrase_to_dek( keyid, sk->pubkey_algo, sk->protect.algo,
				 &sk->protect.s2k, mode,
                                 tryagain_text, canceled );
        if (!dek && canceled && *canceled)
	    return G10ERR_GENERAL;

	cipher_hd = cipher_open( sk->protect.algo,
				 CIPHER_MODE_AUTO_CFB, 1);
	cipher_setkey( cipher_hd, dek->key, dek->keylen );
	xfree(dek);
	save_sk = copy_secret_key( NULL, sk );
	cipher_setiv( cipher_hd, sk->protect.iv, sk->protect.ivlen );
	csum = 0;
	if( sk->version >= 4 ) {
	    unsigned int ndata;
	    byte *p, *data;
            u16 csumc = 0;

	    i = pubkey_get_npkey(sk->pubkey_algo);
	    assert( mpi_is_opaque( sk->skey[i] ) );
	    p = mpi_get_opaque( sk->skey[i], &ndata );
            if ( ndata > 1 )
                csumc = p[ndata-2] << 8 | p[ndata-1];
	    data = xmalloc_secure( ndata );
	    cipher_decrypt( cipher_hd, data, p, ndata );
	    mpi_free( sk->skey[i] ); sk->skey[i] = NULL ;
	    p = data;
            if (sk->protect.sha1chk) {
                /* This is the new SHA1 checksum method to detect
                   tampering with the key as used by the Klima/Rosa
                   attack */
                sk->csum = 0;
                csum = 1;
                if( ndata < 20 ) 
                    log_error("not enough bytes for SHA-1 checksum\n");
                else {
                    MD_HANDLE h = md_open (DIGEST_ALGO_SHA1, 1);
                    if (!h)
                        BUG(); /* algo not available */
                    md_write (h, data, ndata - 20);
                    md_final (h);
                    if (!memcmp (md_read (h, DIGEST_ALGO_SHA1),
                                 data + ndata - 20, 20) ) {
                        /* digest does match.  We have to keep the old
                           style checksum in sk->csum, so that the
                           test used for unprotected keys does work.
                           This test gets used when we are adding new
                           keys. */
                        sk->csum = csum = checksum (data, ndata-20);
                    }
                    md_close (h);
                }
            }
            else {
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
            }

            /* Must check it here otherwise the mpi_read_xx would fail
               because the length may have an arbitrary value */
            if( sk->csum == csum ) {
                for( ; i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
                    nbytes = ndata;
                    sk->skey[i] = mpi_read_from_buffer(p, &nbytes, 1 );
                    if (!sk->skey[i])
                      {
                        /* Checksum was okay, but not correctly
                           decrypted.  */
                        sk->csum = 0;
                        csum = 1;
                        break;
                      }
                    ndata -= nbytes;
                    p += nbytes;
                }
                /* Note: at this point ndata should be 2 for a simple
                   checksum or 20 for the sha1 digest */
            }
	    xfree(data);
	}
	else {
	    for(i=pubkey_get_npkey(sk->pubkey_algo);
		    i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
                byte *p;
                unsigned int ndata;

                assert (mpi_is_opaque (sk->skey[i]));
                p = mpi_get_opaque (sk->skey[i], &ndata);
                assert (ndata >= 2);
                assert (ndata == ((p[0] << 8 | p[1]) + 7)/8 + 2);
                buffer = xmalloc_secure (ndata);
		cipher_sync (cipher_hd);
                buffer[0] = p[0];
                buffer[1] = p[1];
                cipher_decrypt (cipher_hd, buffer+2, p+2, ndata-2);
                csum += checksum (buffer, ndata);
                mpi_free (sk->skey[i]);
                sk->skey[i] = mpi_read_from_buffer (buffer, &ndata, 1);
		xfree (buffer);
                if (!sk->skey[i])
                  {
                    /* Checksum was okay, but not correctly
                       decrypted.  */
                    sk->csum = 0;
                    csum = 1;
                    break;
                  }
/*  		csum += checksum_mpi (sk->skey[i]); */
	    }
	}
	cipher_close( cipher_hd );
	/* now let's see whether we have used the right passphrase */
	if( csum != sk->csum ) {
	    copy_secret_key( sk, save_sk );
            passphrase_clear_cache ( keyid, NULL, sk->pubkey_algo );
	    free_secret_key( save_sk );
	    return G10ERR_BAD_PASS;
	}
	/* the checksum may fail, so we also check the key itself */
	res = pubkey_check_secret_key( sk->pubkey_algo, sk->skey );
	if( res ) {
	    copy_secret_key( sk, save_sk );
            passphrase_clear_cache ( keyid, NULL, sk->pubkey_algo );
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
 * If n is negative, disable the key info prompt and make n=abs(n)
 */
int
check_secret_key( PKT_secret_key *sk, int n )
{
    int rc = G10ERR_BAD_PASS;
    int i,mode;

    if (sk && sk->is_protected && sk->protect.s2k.mode == 1002)
      return 0; /* Let the card support stuff handle this. */

    if(n<0)
      {
	n=abs(n);
	mode=1;
      }
    else
      mode=0;

    if( n < 1 )
	n = (opt.batch && !opt.use_agent)? 1 : 3; /* use the default value */

    for(i=0; i < n && rc == G10ERR_BAD_PASS; i++ ) {
        int canceled = 0;
        const char *tryagain = NULL;
	if (i) {
            tryagain = N_("Invalid passphrase; please try again");
            log_info (_("%s ...\n"), _(tryagain));
        }
	rc = do_check( sk, tryagain, mode, &canceled );
	if( rc == G10ERR_BAD_PASS && is_status_enabled() ) {
	    u32 kid[2];
	    char buf[50];

	    keyid_from_sk( sk, kid );
	    sprintf(buf, "%08lX%08lX", (ulong)kid[0], (ulong)kid[1]);
	    write_status_text( STATUS_BAD_PASSPHRASE, buf );
	}
	if( have_static_passphrase() || canceled)
	    break;
    }

    if( !rc )
	write_status( STATUS_GOOD_PASSPHRASE );

    return rc;
}

/****************
 * check whether the secret key is protected.
 * Returns: 0 not protected, -1 on error or the protection algorithm
 *                           -2 indicates a card stub.
 *                           -3 indicates a not-online stub.
 */
int
is_secret_key_protected( PKT_secret_key *sk )
{
    return sk->is_protected?
               sk->protect.s2k.mode == 1002? -2 :
               sk->protect.s2k.mode == 1001? -3 : sk->protect.algo : 0;
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
		ndata += opt.simple_sk_checksum? 2 : 20; /* for checksum */

		data = xmalloc_secure( ndata );
		p = data;
		for(j=0; j < PUBKEY_MAX_NSKEY && bufarr[j]; j++ ) {
		    p[0] = nbits[j] >> 8 ;
		    p[1] = nbits[j];
		    p += 2;
		    memcpy(p, bufarr[j], narr[j] );
		    p += narr[j];
		    xfree(bufarr[j]);
		}
                
                if (opt.simple_sk_checksum) {
                    log_info (_("generating the deprecated 16-bit checksum"
                              " for secret key protection\n")); 
                    csum = checksum( data, ndata-2);
                    sk->csum = csum;
                    *p++ =	csum >> 8;
                    *p++ =	csum;
                    sk->protect.sha1chk = 0;
                }
                else {
                    MD_HANDLE h = md_open (DIGEST_ALGO_SHA1, 1);
                    if (!h)
                        BUG(); /* algo not available */
                    md_write (h, data, ndata - 20);
                    md_final (h);
                    memcpy (p, md_read (h, DIGEST_ALGO_SHA1), 20);
                    p += 20;
                    md_close (h);
                    sk->csum = csum = 0;
                    sk->protect.sha1chk = 1;
                }
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
		csum = 0;
		for(i=pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
                    byte *data;
		    unsigned int nbits;

		    csum += checksum_mpi (sk->skey[i]);
		    buffer = mpi_get_buffer( sk->skey[i], &nbytes, NULL );
		    cipher_sync (cipher_hd);
		    assert ( !mpi_is_opaque (sk->skey[i]) );
                    data = xmalloc (nbytes+2);
                    nbits  = mpi_get_nbits (sk->skey[i]);
                    assert (nbytes == (nbits + 7)/8);
                    data[0] = nbits >> 8;
                    data[1] = nbits;
		    cipher_encrypt (cipher_hd, data+2, buffer, nbytes);
		    xfree( buffer );
                    
                    mpi_free (sk->skey[i]);
                    sk->skey[i] = mpi_set_opaque (NULL, data, nbytes+2);
		}
		sk->csum = csum;
	    }
	    sk->is_protected = 1;
	    cipher_close( cipher_hd );
	}
    }
    return rc;
}

