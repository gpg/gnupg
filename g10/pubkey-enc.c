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
#include "status.h"


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
    PKT_secret_key *sk = m_alloc_clear( sizeof *sk );

    if( is_RSA(k->pubkey_algo) ) /* warn about that */
	write_status(STATUS_RSA_OR_IDEA);
    rc=check_pubkey_algo( k->pubkey_algo );
    if( rc )
	goto leave;

    sk->pubkey_algo = k->pubkey_algo;	/* we want a pubkey with this algo*/
    if( (rc = get_seckey( sk, k->keyid )) )
	goto leave;

    rc = pubkey_decrypt(k->pubkey_algo, &plain_dek, k->data, sk->skey );
    if( rc )
	goto leave;
    free_secret_key( sk ); sk = NULL;
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
    if( dek->algo ==  CIPHER_ALGO_IDEA )
	write_status(STATUS_RSA_OR_IDEA);
    rc = check_cipher_algo( dek->algo );
    if( rc ) {
	dek->algo = 0;
	goto leave;
    }
    if( (dek->keylen*8) != cipher_get_keylen( dek->algo ) ) {
	rc = G10ERR_WRONG_SECKEY;
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
    if( sk )
	free_secret_key( sk );
    return rc;
}


