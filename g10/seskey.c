/* seskey.c -  make sesssion keys etc.
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
#include "main.h"



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
     * A   is the cipher algorithm
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

/****************
 * Encode a ripemd160 message digest of LEN bytes into NBITS.
 * returns: A mpi with the session key (caller must free)
 */
MPI
encode_rmd160_value( byte *md, unsigned len, unsigned nbits )
{
    static byte asn[18] = /* FIXME: need other values*/
	  { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,0x48,
	    0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
    int nframe = (nbits+7) / 8;
    byte *p;
    MPI frame;
    int i,n,c;

    if( (nbits % BITS_PER_MPI_LIMB) || nframe < 42 || len != 20 )
	log_bug("can't encode a %d bit MD into a %d bits frame\n",len*8, nbits);

    /* We encode the MD in this way:
     *
     *	   0  A PAD(n bytes)   0  ASN(18 bytes)  MD(20 bytes)
     *
     * PAD consists of FF bytes.
     */
    frame = mpi_alloc_secure( nframe / BYTES_PER_MPI_LIMB );
    n = 0;
    for(i=20-1; i >= 0; i--, n++ )
	mpi_putbyte(frame, n, md[i] );
    for( i=18-1; i >= 0; i--, n++ )
	mpi_putbyte(frame, n, asn[i] );
    mpi_putbyte(frame, n++, 0 );
    while( n < nframe-2 )
	mpi_putbyte(frame, n++, 0xff );
    mpi_putbyte(frame, n++, DIGEST_ALGO_RMD160 );
    mpi_putbyte(frame, n++, 0 );
    assert( n == nframe );
    return frame;
}


/****************
 * Encode a md5 message digest of LEN bytes into NBITS.
 * returns: A mpi with the session key (caller must free)
 */
MPI
encode_md5_value( byte *md, unsigned len, unsigned nbits )
{
    static byte asn[18] =
	  { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,0x48,
	    0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
    int nframe = (nbits+7) / 8;
    byte *p;
    MPI frame;
    int i,n,c;

    if( (nbits % BITS_PER_MPI_LIMB) || nframe < 38 || len != 16 )
	log_bug("can't encode a %d bit MD into a %d bits frame\n",len*8, nbits);

    /* We encode the MD in this way:
     *
     *	   0  A PAD(n bytes)   0  ASN(18 bytes)  MD(16 bytes)
     *
     * PAD consists of FF bytes.
     */
    frame = mpi_alloc_secure( nframe / BYTES_PER_MPI_LIMB );
    n = 0;
    for(i=16-1; i >= 0; i--, n++ )
	mpi_putbyte(frame, n, md[i] );
    for( i=18-1; i >= 0; i--, n++ )
	mpi_putbyte(frame, n, asn[i] );
    mpi_putbyte(frame, n++, 0 );
    while( n < nframe-2 )
	mpi_putbyte(frame, n++, 0xff );
    mpi_putbyte(frame, n++, DIGEST_ALGO_MD5 );
    mpi_putbyte(frame, n++, 0 );
    assert( n == nframe );
    return frame;
}

