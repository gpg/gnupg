/* seskey.c -  make sesssion keys
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
#include "cipher.h"
#include "mpi.h"



/****************
 * Make a session key and put it into DEK
 */
void
make_session_key( DEK *dek )
{
    switch( dek->algo ) {
      case CIPHER_ALGO_BLOWFISH:
	dek->keylen = 20;
	randomize_buffer( dek->key, dek->keylen, 1 );
	break;

      default: log_bug("invalid algo %d in make_session_key()\n");
    }
}


/****************
 * Encode the session key. NBITS is the number of bits which should be used
 * for packing teh session key.
 * returns: A mpi with the session key (caller must free)
 */
MPI
encode_session_key( DEK *dek, unsigned nbits )
{
    int nframe = (nbits+7) / 8;
    byte *p;
    MPI frame;
    int i,n,c;
    u16 csum;

    /* the current limitation is, that we can only use a session key
     * which length is a multiple of BITS_PER_MPI_LIMB
     * I think we can live with that.
     */
    if( dek->keylen + 7 > nframe ||  (nbits % BITS_PER_MPI_LIMB) || !nframe )
	log_bug("can't encode a %d bit key in a %d bits frame\n",
		    dek->keylen*8, nbits );

    /* We encode the session key in this way:
     *
     *	   0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
     *
     * RND are non-zero random bytes.
     * A   is the cipher algorithm ( 42 for Blowfish )
     * DEK is the encryption key (session key) length k depends on the
     *	   cipher algorithm (20 is used with blowfish).
     * CSUM is the 16 bit checksum over the DEK
     */
    frame = mpi_alloc_secure( nframe / BYTES_PER_MPI_LIMB );
    csum = 0;
    for( p = dek->key, i=0; i < dek->keylen; i++ )
	csum += *p++;
    mpi_putbyte(frame, 0, csum );
    mpi_putbyte(frame, 1, csum >> 8 );
    for(n=2,i=dek->keylen-1, p = dek->key; i >= 0; i--, n++ )
	mpi_putbyte(frame, n, p[i] );
    mpi_putbyte(frame, n++, dek->algo );
    mpi_putbyte(frame, n++, 0 );
    while( n < nframe-2 ) {
	while( !(c = get_random_byte(1)) )
	    ;
	mpi_putbyte(frame, n++, c );
    }
    mpi_putbyte(frame, n++, 2 );
    mpi_putbyte(frame, n++, 0 );
    assert( n == nframe );
    return frame;
}

