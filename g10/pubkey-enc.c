/* pubkey-enc.c -  public key encoded packet handling
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


/****************
 * Get the session key from a pubkey enc paket and return
 * it in DEK, which should have been allocated in secure memory.
 */
int
get_session_key( PKT_pubkey_enc *k, DEK *dek )
{
    int rc = 0;
    MPI plain_dek  = NULL;
    byte *frame = NULL;
    unsigned n, nframe;
    u16 csum, csum2;
    PKT_secret_cert *skc = m_alloc_clear( sizeof *skc );

    skc->pubkey_algo = k->pubkey_algo;	 /* we want a pubkey with this algo*/
    if( (rc = get_seckey( skc, k->keyid )) )
	goto leave;

    if( k->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	ELG_secret_key skey;

	if( DBG_CIPHER ) {
	    log_mpidump("Encr DEK a:", k->d.elg.a );
	    log_mpidump("     DEK b:", k->d.elg.b );
	}
	skey.p = skc->d.elg.p;
	skey.g = skc->d.elg.g;
	skey.y = skc->d.elg.y;
	skey.x = skc->d.elg.x;
	plain_dek = mpi_alloc_secure( mpi_get_nlimbs(skey.p) );
	elg_decrypt( plain_dek, k->d.elg.a, k->d.elg.b, &skey );
	memset( &skey, 0, sizeof skey );
    }
  #ifdef HAVE_RSA_CIPHER
    else if( k->pubkey_algo == PUBKEY_ALGO_RSA ) {
	RSA_secret_key skey;

	if( DBG_CIPHER )
	    log_mpidump("Encr DEK frame:", k->d.rsa.rsa_integer );

	skey.e = skc->d.rsa.rsa_e;
	skey.n = skc->d.rsa.rsa_n;
	skey.p = skc->d.rsa.rsa_p;
	skey.q = skc->d.rsa.rsa_q;
	skey.d = skc->d.rsa.rsa_d;
	skey.u = skc->d.rsa.rsa_u;
	plain_dek = mpi_alloc_secure( mpi_get_nlimbs(skey.n) );
	rsa_secret( plain_dek, k->d.rsa.rsa_integer, &skey );
	memset( &skey, 0, sizeof skey );
    }
  #endif/*HAVE_RSA_CIPHER*/
    else {
	rc = G10ERR_PUBKEY_ALGO; /* unsupported algorithm */
	goto leave;
    }
    free_secret_cert( skc ); skc = NULL;
    frame = mpi_get_buffer( plain_dek, &nframe, NULL );
    mpi_free( plain_dek ); plain_dek = NULL;

    /* Now get the DEK (data encryption key) from the frame
     *
     * Old versions encode the DEK in in this format (msb is left):
     *
     *	   0  1  DEK(16 bytes)	CSUM(2 bytes)  0  RND(n bytes) 2
     *
     * Later versions encode the DEK like this:
     *
     *	   0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
     *
     * (mpi_get_buffer already removed the leading zero).
     *
     * RND are non-zero randow bytes.
     * A   is the cipher algorithm
     * DEK is the encryption key (session key) with length k
     * CSUM
     */
    if( DBG_CIPHER )
	log_hexdump("DEK frame:", frame, nframe );
    n=0;
    if( n + 7 > nframe )
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }
    if( frame[n] == 1 && frame[nframe-1] == 2 ) {
	log_error("old encoding of DEK is not supported\n");
	rc = G10ERR_CIPHER_ALGO;
	goto leave;
    }
    if( frame[n] != 2 )  /* somethink is wrong */
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }
    for(n++; n < nframe && frame[n]; n++ ) /* skip the random bytes */
	;
    n++; /* and the zero byte */
    if( n + 4 > nframe )
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }

    dek->keylen = nframe - (n+1) - 2;
    dek->algo = frame[n++];
    switch( dek->algo ) {
      case CIPHER_ALGO_IDEA:
	rc = G10ERR_NI_CIPHER;
	goto leave;
      case CIPHER_ALGO_BLOWFISH:
	if( dek->keylen != 20 )
	    { rc = G10ERR_WRONG_SECKEY; goto leave; }
	break;
      case CIPHER_ALGO_BLOWFISH128:
      case CIPHER_ALGO_CAST:
	if( dek->keylen != 16 )
	    { rc = G10ERR_WRONG_SECKEY; goto leave; }
	break;
    #if 0
      case CIPHER_ALGO_CAST:
	if( dek->keylen < 5 || dek->keylen > 16 )
	    { rc = G10ERR_WRONG_SECKEY; goto leave; }
	break;
    #endif
      default:
	dek->algo = 0;
	rc = G10ERR_CIPHER_ALGO;
	goto leave;
    }
    /* copy the key to DEK and compare the checksum */
    csum  = frame[nframe-2] << 8;
    csum |= frame[nframe-1];
    memcpy( dek->key, frame+n, dek->keylen );
    for( csum2=0, n=0; n < dek->keylen; n++ )
	csum2 += dek->key[n];
    if( csum != csum2 ) {
	rc = G10ERR_WRONG_SECKEY;
	goto leave;
    }
    if( DBG_CIPHER )
	log_hexdump("DEK is:", dek->key, dek->keylen );

  leave:
    mpi_free(plain_dek);
    m_free(frame);
    if( skc )
	free_secret_cert( skc );
    return rc;
}


