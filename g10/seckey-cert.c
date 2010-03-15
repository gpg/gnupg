/* seckey-cert.c -  secret key certificate packet handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2006, 2009 Free Software Foundation, Inc.
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

#include "gpg.h"
#include "util.h"
#include "packet.h"
#include "keydb.h"
#include "cipher.h"
#include "main.h"
#include "options.h"
#include "i18n.h"
#include "status.h"
#include "pkglue.h"

static int
do_check( PKT_secret_key *sk, const char *tryagain_text, int mode,
          int *canceled )
{
    gpg_error_t err;
    byte *buffer;
    u16 csum=0;
    int i, res;
    size_t nbytes;

    if( sk->is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	u32 keyid[4]; /* 4! because we need two of them */
	gcry_cipher_hd_t cipher_hd=NULL;
	PKT_secret_key *save_sk;

	if( sk->protect.s2k.mode == 1001 ) {
	    log_info(_("secret key parts are not available\n"));
	    return G10ERR_UNU_SECKEY;
	}
	if( sk->protect.algo == CIPHER_ALGO_NONE )
	    BUG();
	if( openpgp_cipher_test_algo( sk->protect.algo ) ) {
	    log_info(_("protection algorithm %d%s is not supported\n"),
			sk->protect.algo,sk->protect.algo==1?" (IDEA)":"" );
	    if (sk->protect.algo==CIPHER_ALGO_IDEA)
              {
                write_status (STATUS_RSA_OR_IDEA);
                idea_cipher_warn (0);
              }
	    return G10ERR_CIPHER_ALGO;
	}
	if(gcry_md_test_algo (sk->protect.s2k.hash_algo))
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
	    return GPG_ERR_CANCELED;


	err = openpgp_cipher_open (&cipher_hd, sk->protect.algo,
				   GCRY_CIPHER_MODE_CFB,
				   (GCRY_CIPHER_SECURE
				    | (sk->protect.algo >= 100 ?
				       0 : GCRY_CIPHER_ENABLE_SYNC)));
        if (err)
          log_fatal ("cipher open failed: %s\n", gpg_strerror (err) );

	err = gcry_cipher_setkey (cipher_hd, dek->key, dek->keylen);
        if (err)
          log_fatal ("set key failed: %s\n", gpg_strerror (err) );

	xfree(dek);
	save_sk = copy_secret_key( NULL, sk );

	gcry_cipher_setiv ( cipher_hd, sk->protect.iv, sk->protect.ivlen );

	csum = 0;
	if( sk->version >= 4 ) {
            int ndata;
	    unsigned int ndatabits;
	    byte *p, *data;
            u16 csumc = 0;

	    i = pubkey_get_npkey(sk->pubkey_algo);

            assert ( gcry_mpi_get_flag (sk->skey[i], GCRYMPI_FLAG_OPAQUE ));
            p = gcry_mpi_get_opaque ( sk->skey[i], &ndatabits );
            ndata = (ndatabits+7)/8;

            if ( ndata > 1 )
                csumc = p[ndata-2] << 8 | p[ndata-1];
	    data = xmalloc_secure ( ndata );
	    gcry_cipher_decrypt ( cipher_hd, data, ndata, p, ndata );
	    gcry_mpi_release (sk->skey[i]); sk->skey[i] = NULL ;

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
                    gcry_md_hd_t h;

                    if ( gcry_md_open (&h, DIGEST_ALGO_SHA1, 1))
                        BUG(); /* Algo not available. */
                    gcry_md_write (h, data, ndata - 20);
                    gcry_md_final (h);
                    if (!memcmp (gcry_md_read (h, DIGEST_ALGO_SHA1),
                                 data + ndata - 20, 20) ) 
                      {
                        /* Digest does match.  We have to keep the old
                           style checksum in sk->csum, so that the
                           test used for unprotected keys does work.
                           This test gets used when we are adding new
                           keys. */
                        sk->csum = csum = checksum (data, ndata-20);
                      } 
                    gcry_md_close (h);
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
                    if ( gcry_mpi_scan( &sk->skey[i], GCRYMPI_FMT_PGP,
                                        p, ndata, &nbytes))
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
                size_t ndata;
                unsigned int ndatabits;

                assert (gcry_mpi_get_flag (sk->skey[i], GCRYMPI_FLAG_OPAQUE));
                p = gcry_mpi_get_opaque (sk->skey[i], &ndatabits);
                ndata = (ndatabits+7)/8;
                assert (ndata >= 2);
                assert (ndata == ((p[0] << 8 | p[1]) + 7)/8 + 2);
                buffer = xmalloc_secure (ndata);
		gcry_cipher_sync (cipher_hd);
                buffer[0] = p[0];
                buffer[1] = p[1];
                gcry_cipher_decrypt (cipher_hd, buffer+2, ndata-2,
                                     p+2, ndata-2);
                csum += checksum (buffer, ndata);
                gcry_mpi_release (sk->skey[i]);

		err = gcry_mpi_scan( &sk->skey[i], GCRYMPI_FMT_PGP,
				     buffer, ndata, &ndata );
		xfree (buffer);
                if (err)
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
	gcry_cipher_close ( cipher_hd );

	/* Now let's see whether we have used the correct passphrase. */
	if( csum != sk->csum ) {
	    copy_secret_key( sk, save_sk );
            passphrase_clear_cache ( keyid, NULL, sk->pubkey_algo );
	    free_secret_key( save_sk );
	    return gpg_error (GPG_ERR_BAD_PASSPHRASE);
	}

	/* The checksum may fail, so we also check the key itself. */
	res = pk_check_secret_key ( sk->pubkey_algo, sk->skey );
	if( res ) {
	    copy_secret_key( sk, save_sk );
            passphrase_clear_cache ( keyid, NULL, sk->pubkey_algo );
	    free_secret_key( save_sk );
	    return gpg_error (GPG_ERR_BAD_PASSPHRASE);
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
    int rc = gpg_error (GPG_ERR_BAD_PASSPHRASE);
    int i,mode;

    if (sk && sk->is_protected && sk->protect.s2k.mode == 1002)
      return 0; /* Let the scdaemon handle this. */

    if(n<0)
      {
	n=abs(n);
	mode=1;
      }
    else
      mode=0;

    if( n < 1 )
	n = 3; /* Use the default value */

    for(i=0; i < n && gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE; i++ ) {
        int canceled = 0;
        const char *tryagain = NULL;
	if (i) {
            tryagain = N_("Invalid passphrase; please try again");
            log_info (_("%s ...\n"), _(tryagain));
        }
	rc = do_check( sk, tryagain, mode, &canceled );
	if ( gpg_err_code (rc) == GPG_ERR_BAD_PASSPHRASE
             && is_status_enabled () ) {
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
    size_t nbytes;
    u16 csum;

    if( !dek )
	return 0;

    if( !sk->is_protected ) { /* okay, apply the protection */
	gcry_cipher_hd_t cipher_hd=NULL;

	if ( openpgp_cipher_test_algo ( sk->protect.algo ) ) {
            /* Unsupport protection algorithm. */
            rc = gpg_error (GPG_ERR_CIPHER_ALGO); 
        }
	else {
	    print_cipher_algo_note( sk->protect.algo );
	    
	    if ( openpgp_cipher_open (&cipher_hd, sk->protect.algo,
				      GCRY_CIPHER_MODE_CFB,
				      (GCRY_CIPHER_SECURE
				       | (sk->protect.algo >= 100 ?
					  0 : GCRY_CIPHER_ENABLE_SYNC))) )
              BUG();
	    if ( gcry_cipher_setkey ( cipher_hd, dek->key, dek->keylen ) )
		log_info(_("WARNING: Weak key detected"
			   " - please change passphrase again.\n"));
	    sk->protect.ivlen = openpgp_cipher_get_algo_blklen (sk->protect.algo);
	    assert( sk->protect.ivlen <= DIM(sk->protect.iv) );
	    if( sk->protect.ivlen != 8 && sk->protect.ivlen != 16 )
		BUG(); /* yes, we are very careful */
	    gcry_create_nonce (sk->protect.iv, sk->protect.ivlen);
	    gcry_cipher_setiv (cipher_hd, sk->protect.iv, sk->protect.ivlen);
	    if( sk->version >= 4 ) {
                byte *bufarr[PUBKEY_MAX_NSKEY];
		size_t narr[PUBKEY_MAX_NSKEY];
		unsigned int nbits[PUBKEY_MAX_NSKEY];
		int ndata=0;
		byte *p, *data;

		for (j=0, i = pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++, j++ )
                  {
		    assert (!gcry_mpi_get_flag (sk->skey[i],
                                                GCRYMPI_FLAG_OPAQUE));
		    if (gcry_mpi_aprint (GCRYMPI_FMT_USG, bufarr+j,
                                         narr+j, sk->skey[i]))
                      BUG();
		    nbits[j] = gcry_mpi_get_nbits (sk->skey[i]);
		    ndata += narr[j] + 2;
                  }
		for ( ; j < PUBKEY_MAX_NSKEY; j++ )
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
                    gcry_md_hd_t h;

                    if (gcry_md_open (&h, GCRY_MD_SHA1, 1))
                      BUG(); /* Algo not available. */
                    gcry_md_write (h, data, ndata - 20);
                    gcry_md_final (h);
                    memcpy (p, gcry_md_read (h, DIGEST_ALGO_SHA1), 20);
                    p += 20;
                    gcry_md_close (h);
                    sk->csum = csum = 0;
                    sk->protect.sha1chk = 1;
                }
                assert( p == data+ndata );

		gcry_cipher_encrypt (cipher_hd, data, ndata, NULL, 0);
		for (i = pubkey_get_npkey(sk->pubkey_algo);
                     i < pubkey_get_nskey(sk->pubkey_algo); i++ )
                  {
		    gcry_mpi_release (sk->skey[i]);
		    sk->skey[i] = NULL;
                  }
		i = pubkey_get_npkey(sk->pubkey_algo);
		sk->skey[i] = gcry_mpi_set_opaque (NULL, data, ndata*8 );
	    }
	    else {
		csum = 0;
		for(i=pubkey_get_npkey(sk->pubkey_algo);
			i < pubkey_get_nskey(sk->pubkey_algo); i++ ) {
                    byte *data;
		    unsigned int nbits;

		    csum += checksum_mpi (sk->skey[i]);

		    if (gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer,
                                         &nbytes, sk->skey[i] ))
                      BUG();
		    gcry_cipher_sync (cipher_hd);
		    assert (!gcry_mpi_get_flag (sk->skey[i],
                                                GCRYMPI_FLAG_OPAQUE));

                    data = xmalloc (nbytes+2);  /* fixme: need xtrymalloc. */
                    nbits = gcry_mpi_get_nbits (sk->skey[i]);
                    assert (nbytes == (nbits + 7)/8);
                    data[0] = nbits >> 8;
                    data[1] = nbits;
		    gcry_cipher_encrypt (cipher_hd, data+2, nbytes,
                                         buffer, nbytes);
		    xfree( buffer );
                    
                    gcry_mpi_release (sk->skey[i]);
                    sk->skey[i] = gcry_mpi_set_opaque (NULL,
                                                       data, (nbytes+2)*8 );
		}
		sk->csum = csum;
	    }
	    sk->is_protected = 1;
	    gcry_cipher_close (cipher_hd);
	}
    }
    return rc;
}
