/* sha1.c - SHA1 hash function
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * Please see below for more legal informations!
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

/* I took the code for transform() from the Linux kernel
 * (/usr/src/linux/drivers/char/random.c) which has
 *
 * a) This notice:
 * ---------------
 * SHA transform algorithm, taken from code written by Peter Gutman,
 * and apparently in the public domain.
 *
 * b) This copyright notice:
 * -------------------------
 * Version 1.00, last modified 26-May-96
 *
 * Copyright Theodore Ts'o, 1994, 1995, 1996.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.	(This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/*  Test vectors:
 *
 *  "abc"
 *  A999 3E36 4706 816A BA3E  2571 7850 C26C 9CD0 D89D
 *
 *  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *  8498 3E44 1C3B D26E BAAE  4AA1 F951 29E5 E546 70F1
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "sha1.h"


/* The SHA f()-functions.  */
#define f1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )		/* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )			/* Rounds 20-39 */
#define f3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )	/* Rounds 40-59 */
#define f4(x,y,z)   ( x ^ y ^ z )			/* Rounds 60-79 */

/* The SHA Mysterious Constants */
#define K1  0x5A827999L 				/* Rounds  0-19 */
#define K2  0x6ED9EBA1L 				/* Rounds 20-39 */
#define K3  0x8F1BBCDCL 				/* Rounds 40-59 */
#define K4  0xCA62C1D6L 				/* Rounds 60-79 */


#if defined(__GNUC__) && defined(__i386__)
static inline u32
rol(int n, u32 x)
{
	__asm__("roll %%cl,%0"
		:"=r" (x)
		:"0" (x),"c" (n));
	return x;
}
#else
  #define rol(n,x)  ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif





#define expand(W,i) ( W[ i & 15 ] = \
		     rol( 1, ( W[ i & 15 ] ^ W[ (i - 14) & 15 ] ^ \
				W[ (i - 8) & 15 ] ^ W[ (i - 3) & 15 ] ) ) )

#define subRound(a, b, c, d, e, f, k, data) \
    ( e += rol( 5, a ) + f( b, c, d ) + k + data, b = rol( 30, b ) )


void
sha1_init( SHA1_CONTEXT *hd )
{
    hd->h0 = 0x67452301;
    hd->h1 = 0xefcdab89;
    hd->h2 = 0x98badcfe;
    hd->h3 = 0x10325476;
    hd->h4 = 0xc3d2e1f0;
    hd->nblocks = 0;
    hd->count = 0;
}


/****************
 * Transform the message X which consists of 16 32-bit-words
 */
static void
transform( SHA1_CONTEXT *hd, byte *data )
{
    u32 A, B, C, D, E;	   /* Local vars */
    u32 eData[ 16 ];	   /* Expanded data */

    /* Set up first buffer and local data buffer */
    A = hd->h0;
    B = hd->h1;
    C = hd->h2;
    D = hd->h3;
    E = hd->h4;

  #ifdef BIG_ENDIAN_HOST
    memcpy( eData, data, 64 );
  #else
    { int i;
      byte *p2;
      for(i=0, p2=(byte*)eData; i < 16; i++, p2 += 4 ) {
	p2[3] = *data++;
	p2[2] = *data++;
	p2[1] = *data++;
	p2[0] = *data++;
      }
    }
  #endif

    /* Heavy mangling, in 4 sub-rounds of 20 iterations each. */
    subRound( A, B, C, D, E, f1, K1, eData[  0 ] );
    subRound( E, A, B, C, D, f1, K1, eData[  1 ] );
    subRound( D, E, A, B, C, f1, K1, eData[  2 ] );
    subRound( C, D, E, A, B, f1, K1, eData[  3 ] );
    subRound( B, C, D, E, A, f1, K1, eData[  4 ] );
    subRound( A, B, C, D, E, f1, K1, eData[  5 ] );
    subRound( E, A, B, C, D, f1, K1, eData[  6 ] );
    subRound( D, E, A, B, C, f1, K1, eData[  7 ] );
    subRound( C, D, E, A, B, f1, K1, eData[  8 ] );
    subRound( B, C, D, E, A, f1, K1, eData[  9 ] );
    subRound( A, B, C, D, E, f1, K1, eData[ 10 ] );
    subRound( E, A, B, C, D, f1, K1, eData[ 11 ] );
    subRound( D, E, A, B, C, f1, K1, eData[ 12 ] );
    subRound( C, D, E, A, B, f1, K1, eData[ 13 ] );
    subRound( B, C, D, E, A, f1, K1, eData[ 14 ] );
    subRound( A, B, C, D, E, f1, K1, eData[ 15 ] );
    subRound( E, A, B, C, D, f1, K1, expand( eData, 16 ) );
    subRound( D, E, A, B, C, f1, K1, expand( eData, 17 ) );
    subRound( C, D, E, A, B, f1, K1, expand( eData, 18 ) );
    subRound( B, C, D, E, A, f1, K1, expand( eData, 19 ) );

    subRound( A, B, C, D, E, f2, K2, expand( eData, 20 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 21 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 22 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 23 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 24 ) );
    subRound( A, B, C, D, E, f2, K2, expand( eData, 25 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 26 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 27 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 28 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 29 ) );
    subRound( A, B, C, D, E, f2, K2, expand( eData, 30 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 31 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 32 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 33 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 34 ) );
    subRound( A, B, C, D, E, f2, K2, expand( eData, 35 ) );
    subRound( E, A, B, C, D, f2, K2, expand( eData, 36 ) );
    subRound( D, E, A, B, C, f2, K2, expand( eData, 37 ) );
    subRound( C, D, E, A, B, f2, K2, expand( eData, 38 ) );
    subRound( B, C, D, E, A, f2, K2, expand( eData, 39 ) );

    subRound( A, B, C, D, E, f3, K3, expand( eData, 40 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 41 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 42 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 43 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 44 ) );
    subRound( A, B, C, D, E, f3, K3, expand( eData, 45 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 46 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 47 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 48 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 49 ) );
    subRound( A, B, C, D, E, f3, K3, expand( eData, 50 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 51 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 52 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 53 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 54 ) );
    subRound( A, B, C, D, E, f3, K3, expand( eData, 55 ) );
    subRound( E, A, B, C, D, f3, K3, expand( eData, 56 ) );
    subRound( D, E, A, B, C, f3, K3, expand( eData, 57 ) );
    subRound( C, D, E, A, B, f3, K3, expand( eData, 58 ) );
    subRound( B, C, D, E, A, f3, K3, expand( eData, 59 ) );

    subRound( A, B, C, D, E, f4, K4, expand( eData, 60 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 61 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 62 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 63 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 64 ) );
    subRound( A, B, C, D, E, f4, K4, expand( eData, 65 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 66 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 67 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 68 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 69 ) );
    subRound( A, B, C, D, E, f4, K4, expand( eData, 70 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 71 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 72 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 73 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 74 ) );
    subRound( A, B, C, D, E, f4, K4, expand( eData, 75 ) );
    subRound( E, A, B, C, D, f4, K4, expand( eData, 76 ) );
    subRound( D, E, A, B, C, f4, K4, expand( eData, 77 ) );
    subRound( C, D, E, A, B, f4, K4, expand( eData, 78 ) );
    subRound( B, C, D, E, A, f4, K4, expand( eData, 79 ) );

    /* Build message digest */
    hd->h0 += A;
    hd->h1 += B;
    hd->h2 += C;
    hd->h3 += D;
    hd->h4 += E;
}


/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
void
sha1_write( SHA1_CONTEXT *hd, byte *inbuf, size_t inlen)
{
    if( hd->count == 64 ) { /* flush the buffer */
	transform( hd, hd->buf );
	hd->count = 0;
	hd->nblocks++;
    }
    if( !inbuf )
	return;
    if( hd->count ) {
	for( ; inlen && hd->count < 64; inlen-- )
	    hd->buf[hd->count++] = *inbuf++;
	sha1_write( hd, NULL, 0 );
	if( !inlen )
	    return;
    }

    while( inlen >= 64 ) {
	transform( hd, inbuf );
	hd->count = 0;
	hd->nblocks++;
	inlen -= 64;
	inbuf += 64;
    }
    for( ; inlen && hd->count < 64; inlen-- )
	hd->buf[hd->count++] = *inbuf++;
}


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest.
 */

void
sha1_final(SHA1_CONTEXT *hd)
{
    u32 t, msb, lsb;
    byte *p;

    sha1_write(hd, NULL, 0); /* flush */;

    msb = 0;
    t = hd->nblocks;
    if( (lsb = t << 6) < t ) /* multiply by 64 to make a byte count */
	msb++;
    msb += t >> 26;
    t = lsb;
    if( (lsb = t + hd->count) < t ) /* add the count */
	msb++;
    t = lsb;
    if( (lsb = t << 3) < t ) /* multiply by 8 to make a bit count */
	msb++;
    msb += t >> 29;

    if( hd->count < 56 ) { /* enough room */
	hd->buf[hd->count++] = 0x80; /* pad */
	while( hd->count < 56 )
	    hd->buf[hd->count++] = 0;  /* pad */
    }
    else { /* need one extra block */
	hd->buf[hd->count++] = 0x80; /* pad character */
	while( hd->count < 64 )
	    hd->buf[hd->count++] = 0;
	sha1_write(hd, NULL, 0);  /* flush */;
	memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
    }
    /* append the 64 bit count */
    hd->buf[56] = msb >> 24;
    hd->buf[57] = msb >> 16;
    hd->buf[58] = msb >>  8;
    hd->buf[59] = msb	   ;
    hd->buf[60] = lsb >> 24;
    hd->buf[61] = lsb >> 16;
    hd->buf[62] = lsb >>  8;
    hd->buf[63] = lsb	   ;
    transform( hd, hd->buf );

    p = hd->buf;
  #ifdef BIG_ENDIAN_HOST
    #define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0)
  #else /* little endian */
    #define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
		      *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
  #endif
    X(0);
    X(1);
    X(2);
    X(3);
    X(4);
  #undef X

}


