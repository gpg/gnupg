/* pubkey-enc.c -  public key encoded packet handling
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


/****************
 * Get the session key from a pubkey enc paket and return
 * it in DEK, which should have been allocated in secure memory.
 */
int
get_session_key( PKT_pubkey_enc *k, DEK *dek )
{
    int i, j, c, rc = 0;
    RSA_secret_key  *skey = m_alloc_secure( sizeof *skey );
    MPI dek_frame = mpi_alloc_secure(40);
    u16 csum, csum2;

    if( k->pubkey_algo != PUBKEY_ALGO_RSA ) {
	rc = G10ERR_PUBKEY_ALGO; /* unsupported algorithm */
	goto leave;
    }

    /* get the secret key for the given public key
     * and decode the rsa_integer
     */
    if( (rc = get_seckey( skey, k->keyid )) )
	goto leave;

    if( DBG_CIPHER )
	log_mpidump("Encr DEK frame:", k->d.rsa.rsa_integer );
    rsa_secret( dek_frame, k->d.rsa.rsa_integer, skey );
    /* Now get the DEK (data encryption key) from the dek_frame
     *
     * Old versions encode the DEK in in this format (msb is left):
     *
     *	   0  1  DEK(16 bytes)	CSUM(2 bytes)  0  RND(n bytes) 2
     *
     * Later versions encode the DEK like this:
     *
     *	   0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
     *
     * RND are non-zero randow bytes.
     * A   is the cipher algorithm ( 1 for IDEA, 42 for blowfish  )
     * DEK is the encryption key (session key) with length k
     *	   (16 for idea, 42 for blowfish)
     * CSUM
     */
    if( DBG_CIPHER )
	log_mpidump("DEK frame:", dek_frame );
    for(i=0; mpi_getbyte(dek_frame, i) != -1; i++ )
	;
    for(i--; i >= 0 && !(c=mpi_getbyte(dek_frame, i)); i--)
	; /* Skip leading zeroes */
    if( i < 16 )
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }
    if( c == 1 && mpi_getbyte(dek_frame,0) == 2 ) {
	log_error("old encoding of DEK is not supported\n");
	rc = G10ERR_CIPHER_ALGO;
	goto leave;
    }
    if( c != 2 )  /* somethink is wrong */
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }
    /* look for the zeor byte */
    for(i--; i > 4 ; i-- )
	if( !mpi_getbyte(dek_frame,i) )
	    break;
    if( i <= 4 ) /* zero byte not found */
	{ rc = G10ERR_WRONG_SECKEY; goto leave; }
    /* next byte indicates the used cipher */
    switch( mpi_getbyte(dek_frame, --i ) ) {
      case 1:
	rc = G10ERR_NI_CIPHER;
	goto leave;
      case 42:
	if( i != 22 ) /* length of blowfish is 20 (+2 bytes checksum) */
	    { rc = G10ERR_WRONG_SECKEY; goto leave; }
	dek->algo = CIPHER_ALGO_BLOWFISH;
	break;
      default:
	rc = G10ERR_CIPHER_ALGO;
	goto leave;
    }
    /* copy the key to DEK and compare the checksum */
    csum  = mpi_getbyte(dek_frame, 1) << 8;
    csum |= mpi_getbyte(dek_frame, 0);
    dek->keylen = i - 2;
    for( i--, csum2=0, j=0; i > 1; i-- )
	csum2 += dek->key[j++] = mpi_getbyte(dek_frame, i);
    if( csum != csum2 ) {
	rc = G10ERR_WRONG_SECKEY;
	goto leave;
    }
    if( DBG_CIPHER )
	log_hexdump("DEK is:", dek->key, dek->keylen );

  leave:
    mpi_free(dek_frame);
    m_free(skey);
    return rc;
}


