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


static u16
checksum( byte *p )
{
    u16 n, a;

    n = *p++ << 8;
    n |= *p++;
    for(a=0; n; n-- )
	a += *p++;
    return a;
}


/****************
 * Check the secret key certificate
 */
int
check_secret_key( PKT_seckey_cert *cert )
{
    IDEA_context idea_ctx;  /* FIXME: allocate this in secure space ! */
    byte iv[8];
    byte *mpibuf;
    u16 n;
    MPI temp_mpi;
    int res;
    u32 keyid[2];

#if IDEA_BLOCKSIZE != 8 || BLOWFISH_BLOCKSIZE != 8
  #error unsupportted blocksize
#endif

    if( cert->pubkey_algo != PUBKEY_ALGO_RSA )
	return G10ERR_PUBKEY_ALGO; /* unsupport algorithm */

    if( cert->d.rsa.is_protected ) { /* remove the protection */
	DEK *dek = NULL;
	BLOWFISH_context *blowfish_ctx=NULL;

	switch( cert->d.rsa.protect_algo ) {
	  case CIPHER_ALGO_NONE:
	    log_bug("unprotect seckey_cert is flagged protected\n");
	    break;
	  case CIPHER_ALGO_IDEA:
	  case CIPHER_ALGO_BLOWFISH:
	    mpi_get_keyid( cert->d.rsa.rsa_n , keyid );
	    dek = get_passphrase_hash( keyid, NULL );

	  /*  idea_setkey( &idea_ctx, dpw );*/
	    m_free(dek); /* pw is in secure memory, so m_free() burns it */
	    memset( iv, 0, BLOWFISH_BLOCKSIZE );
	    if( cert->d.rsa.protect_algo == CIPHER_ALGO_IDEA ) {
		idea_setiv( &idea_ctx, iv );
		/* fixme: is it save to leave the IV unencrypted in the
		 * certificate or should we move it to secure storage? */
		idea_decode_cfb( &idea_ctx, cert->d.rsa.protect.idea.iv,
					    cert->d.rsa.protect.idea.iv, 8 );
	    }
	    else {
		blowfish_ctx = m_alloc_secure( sizeof *blowfish_ctx );
		blowfish_setiv( blowfish_ctx, iv );
		blowfish_decode_cfb( blowfish_ctx,
				     cert->d.rsa.protect.blowfish.iv,
				     cert->d.rsa.protect.blowfish.iv, 8 );
	    }
	    cert->d.rsa.calc_csum = 0;
	  #define X(a) do {						\
		    mpibuf = (byte*)cert->d.rsa.rsa_##a;		\
		    n = ((mpibuf[0] << 8) | mpibuf[1])-2;		\
		    if( blowfish_ctx )					\
			blowfish_decode_cfb( blowfish_ctx,		\
					     mpibuf+4, mpibuf+4, n );	\
		    else						 \
			idea_decode_cfb( &idea_ctx, mpibuf+4, mpibuf+4, n );\
		    cert->d.rsa.calc_csum += checksum( mpibuf );	\
		    cert->d.rsa.rsa_##a = mpi_decode_buffer( mpibuf );	\
		    m_free( mpibuf );					\
		} while(0)
	    X(d);
	    X(p);
	    X(q);
	    X(u);
	  #undef X
	    m_free( blowfish_ctx );
	    cert->d.rsa.is_protected = 0;
	  #if 0
	    #define X(a) do { printf("\tRSA " #a ": ");                   \
			      mpi_print(stdout, cert->d.rsa.rsa_##a, 1 ); \
			      putchar('\n');                              \
			    } while(0)
	    X(n);
	    X(e);
	    X(d);
	    X(p);
	    X(q);
	    X(u);
	    #undef X
	  #endif
	    /* now let's see wether we have used the right passphrase */
	    if( cert->d.rsa.calc_csum != cert->d.rsa.csum )
		return G10ERR_BAD_PASS;
	    temp_mpi = mpi_alloc(40);
	    mpi_mul(temp_mpi, cert->d.rsa.rsa_p, cert->d.rsa.rsa_q );
	    res = mpi_cmp( temp_mpi, cert->d.rsa.rsa_n );
	    mpi_free(temp_mpi);
	    if( res )
		return G10ERR_BAD_PASS;
	    break;

	  default:
	    return G10ERR_CIPHER_ALGO; /* unsupport protection algorithm */
	}
    }
    /* must check the checksum here, because we didn't do it when
     * parsing an unprotected certificate */
    if( cert->d.rsa.calc_csum != cert->d.rsa.csum ) {
	log_error("checksum in secret key certificate is wrong\n");
	log_debug("stored csum=%04hx calculated csum=%04hx\n",
		   cert->d.rsa.csum, cert->d.rsa.calc_csum );
	return G10ERR_CHECKSUM;
    }
    return 0;
}


