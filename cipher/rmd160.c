/* rmd160.c  -	RIPE-MD160
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
#include "rmd.h"

/*********************************
 * RIPEMD-160 is not patented, see (as of 25.10.97)
 *   http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
 * Note that the code uses Little Endian byteorder, which is good for
 * 386 etc, but we must add some conversion when used on a big endian box.
 *
 *
 * Pseudo-code for RIPEMD-160
 *
 * RIPEMD-160 is an iterative hash function that operates on 32-bit words.
 * The round function takes as input a 5-word chaining variable and a 16-word
 * message block and maps this to a new chaining variable. All operations are
 * defined on 32-bit words. Padding is identical to that of MD4.
 *
 *
 * RIPEMD-160: definitions
 *
 *
 *   nonlinear functions at bit level: exor, mux, -, mux, -
 *
 *   f(j, x, y, z) = x XOR y XOR z		  (0 <= j <= 15)
 *   f(j, x, y, z) = (x AND y) OR (NOT(x) AND z)  (16 <= j <= 31)
 *   f(j, x, y, z) = (x OR NOT(y)) XOR z	  (32 <= j <= 47)
 *   f(j, x, y, z) = (x AND z) OR (y AND NOT(z))  (48 <= j <= 63)
 *   f(j, x, y, z) = x XOR (y OR NOT(z))	  (64 <= j <= 79)
 *
 *
 *   added constants (hexadecimal)
 *
 *   K(j) = 0x00000000	    (0 <= j <= 15)
 *   K(j) = 0x5A827999	   (16 <= j <= 31)	int(2**30 x sqrt(2))
 *   K(j) = 0x6ED9EBA1	   (32 <= j <= 47)	int(2**30 x sqrt(3))
 *   K(j) = 0x8F1BBCDC	   (48 <= j <= 63)	int(2**30 x sqrt(5))
 *   K(j) = 0xA953FD4E	   (64 <= j <= 79)	int(2**30 x sqrt(7))
 *   K'(j) = 0x50A28BE6     (0 <= j <= 15)      int(2**30 x cbrt(2))
 *   K'(j) = 0x5C4DD124    (16 <= j <= 31)      int(2**30 x cbrt(3))
 *   K'(j) = 0x6D703EF3    (32 <= j <= 47)      int(2**30 x cbrt(5))
 *   K'(j) = 0x7A6D76E9    (48 <= j <= 63)      int(2**30 x cbrt(7))
 *   K'(j) = 0x00000000    (64 <= j <= 79)
 *
 *
 *   selection of message word
 *
 *   r(j)      = j		      (0 <= j <= 15)
 *   r(16..31) = 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8
 *   r(32..47) = 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12
 *   r(48..63) = 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
 *   r(64..79) = 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
 *   r0(0..15) = 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12
 *   r0(16..31)= 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2
 *   r0(32..47)= 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13
 *   r0(48..63)= 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
 *   r0(64..79)= 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
 *
 *
 *   amount for rotate left (rol)
 *
 *   s(0..15)  = 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8
 *   s(16..31) = 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12
 *   s(32..47) = 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5
 *   s(48..63) = 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
 *   s(64..79) = 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
 *   s'(0..15) = 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6
 *   s'(16..31)= 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11
 *   s'(32..47)= 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5
 *   s'(48..63)= 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
 *   s'(64..79)= 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
 *
 *
 *   initial value (hexadecimal)
 *
 *   h0 = 0x67452301; h1 = 0xEFCDAB89; h2 = 0x98BADCFE; h3 = 0x10325476;
 *							h4 = 0xC3D2E1F0;
 *
 *
 * RIPEMD-160: pseudo-code
 *
 *   It is assumed that the message after padding consists of t 16-word blocks
 *   that will be denoted with X[i][j], with 0 <= i <= t-1 and 0 <= j <= 15.
 *   The symbol [+] denotes addition modulo 2**32 and rol_s denotes cyclic left
 *   shift (rotate) over s positions.
 *
 *
 *   for i := 0 to t-1 {
 *	 A := h0; B := h1; C := h2; D = h3; E = h4;
 *	 A' := h0; B' := h1; C' := h2; D' = h3; E' = h4;
 *	 for j := 0 to 79 {
 *	     T := rol_s(j)(A [+] f(j, B, C, D) [+] X[i][r(j)] [+] K(j)) [+] E;
 *	     A := E; E := D; D := rol_10(C); C := B; B := T;
 *	     T := rol_s'(j)(A' [+] f(79-j, B', C', D') [+] X[i][r'(j)]
						       [+] K'(j)) [+] E';
 *	     A' := E'; E' := D'; D' := rol_10(C'); C' := B'; B' := T;
 *	 }
 *	 T := h1 [+] C [+] D'; h1 := h2 [+] D [+] E'; h2 := h3 [+] E [+] A';
 *	 h3 := h4 [+] A [+] B'; h4 := h0 [+] B [+] C'; h0 := T;
 *   }
 */

/* Some examples:
 * ""                    9c1185a5c5e9fc54612808977ee8f548b2258d31
 * "a"                   0bdc9d2d256b3ee9daae347be6f4dc835a467ffe
 * "abc"                 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
 * "message digest"      5d0689ef49d2fae572b881b123a85ffa21595f36
 * "a...z"               f71c27109c692c1b56bbdceb5b9d2865b3708dbc
 * "abcdbcde...nopq"     12a053384a9c0c88e405a06c27dcf49ada62eb2b
 * "A...Za...z0...9"     b0e20b6e3116640286ed3a87a5713079b21f5189
 * 8 times "1234567890"  9b752e45573d4b39f4dbd3323cab82bf63326bfb
 * 1 million times "a"   52783243c1697bdbe16d37f97f68f08325dc1528
 */


static void
initialize( RMDHANDLE hd )
{
    hd->h0 = 0x67452301;
    hd->h1 = 0xEFCDAB89;
    hd->h2 = 0x98BADCFE;
    hd->h3 = 0x10325476;
    hd->h4 = 0xC3D2E1F0;
    hd->bufcount = 0;
    hd->nblocks = 0;
}


/****************
 * Transform the message X which consists of 16 32-bit-words
 */
static void
transform( RMDHANDLE hd, u32 *x )
{
    static int r[80] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 };
    static int rr[80] = {
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 };
    static int s[80] = {
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6	};
    static int ss[80] = {
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11	};
    u32 a,b,c,d,e,aa,bb,cc,dd,ee,t;
    int rbits, j;

#define K(a)   ( (a) < 16 ? 0x00000000 :	      \
		 (a) < 32 ? 0x5A827999 :	      \
		 (a) < 48 ? 0x6ED9EBA1 :	      \
		 (a) < 64 ? 0x8F1BBCDC : 0xA953FD4E )
#define KK(a)  ( (a) < 16 ? 0x50A28BE6 :	      \
		 (a) < 32 ? 0x5C4DD124 :	      \
		 (a) < 48 ? 0x6D703EF3 :	      \
		 (a) < 64 ? 0x7A6D76E9 : 0x00000000 )

#define F0(x,y,z)   ( (x) ^ (y) ^ (z) )
#define F1(x,y,z)   ( ((x) & (y)) | (~(x) & (z)) )
#define F2(x,y,z)   ( ((x) | ~(y)) ^ (z) )
#define F3(x,y,z)   ( ((x) & (z)) | ((y) & ~(z)) )
#define F4(x,y,z)   ( (x) ^ ((y) | ~(z)) )
#define F(a,x,y,z)  ( (a) < 16 ? F0((x),(y),(z)) : \
		      (a) < 32 ? F1((x),(y),(z)) : \
		      (a) < 48 ? F2((x),(y),(z)) : \
		      (a) < 64 ? F3((x),(y),(z)) : \
				 F4((x),(y),(z)) )

#define rol(n,x) ( ((x) << (n)) | ((x) >> (32-(n))) )

    a = aa = hd->h0;
    b = bb = hd->h1;
    c = cc = hd->h2;
    d = dd = hd->h3;
    e = ee = hd->h4;

    for(j=0; j < 80; j++ ) {
	t = a + F( j, b, c, d ) + x[ r[j] ] + K(j);
	rbits = s[j];
	a = rol(rbits, t) + e;
	c = rol(10,c);
	t = a; a = e; e = d; d = c; c = b; b = t;

	t = aa + F(79-j, bb, cc, dd ) + x[ rr[j] ] + KK(j);
	rbits = ss[j];
	aa = rol(rbits, t) + ee;
	cc = rol(10,cc);
	t = aa; aa = ee; ee = dd; dd = cc; cc = bb; bb = t;
    }

    t	   = hd->h1 + c + dd;
    hd->h1 = hd->h2 + d + ee;
    hd->h2 = hd->h3 + e + aa;
    hd->h3 = hd->h4 + a + bb;
    hd->h4 = hd->h0 + b + cc;
    hd->h0 = t;
}




RMDHANDLE
rmd160_open( int secure )
{
    RMDHANDLE hd;

    hd = secure? m_alloc_secure( sizeof *hd )
	       : m_alloc( sizeof *hd );
    initialize(hd);
    return hd;
}


RMDHANDLE
rmd160_copy( RMDHANDLE a )
{
    RMDHANDLE b;

    assert(a);
    b = m_is_secure(a)? m_alloc_secure( sizeof *b )
		      : m_alloc( sizeof *b );
    memcpy( b, a, sizeof *a );
    return b;
}

void
rmd160_close(RMDHANDLE hd)
{
    if( hd )
	m_free(hd);
}



/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
void
rmd160_write( RMDHANDLE hd, byte *inbuf, size_t inlen)
{
    if( hd->bufcount == 64 ) { /* flush the buffer */
	transform( hd, (u32*)hd->buffer );
	hd->bufcount = 0;
	hd->nblocks++;
    }
    if( !inbuf )
	return;
    if( hd->bufcount ) {
	for( ; inlen && hd->bufcount < 64; inlen-- )
	    hd->buffer[hd->bufcount++] = *inbuf++;
	rmd160_write( hd, NULL, 0 );
	if( !inlen )
	    return;
    }

    while( inlen >= 64 ) {
	transform( hd, (u32*)inbuf );
	hd->bufcount = 0;
	hd->nblocks++;
	inlen -= 64;
	inbuf += 64;
    }
    for( ; inlen && hd->bufcount < 64; inlen-- )
	hd->buffer[hd->bufcount++] = *inbuf++;
}


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest.
 */

byte *
rmd160_final(RMDHANDLE hd)
{
    u32 t, msb, lsb;
    byte *p;

    rmd160_write(hd, NULL, 0); /* flush */;

    msb = 0;
    t = hd->nblocks;
    if( (lsb = t << 6) < t ) /* multiply by 64 to make a byte count */
	msb++;
    msb += t >> 26;
    t = lsb;
    if( (lsb = t + hd->bufcount) < t ) /* add the bufcount */
	msb++;
    t = lsb;
    if( (lsb = t << 3) < t ) /* multiply by 8 to make a bit count */
	msb++;
    msb += t >> 29;

    if( hd->bufcount < 56 ) { /* enough room */
	hd->buffer[hd->bufcount++] = 0x80; /* pad */
	while( hd->bufcount < 56 )
	    hd->buffer[hd->bufcount++] = 0;  /* pad */
    }
    else { /* need one extra block */
	hd->buffer[hd->bufcount++] = 0x80; /* pad character */
	while( hd->bufcount < 64 )
	    hd->buffer[hd->bufcount++] = 0;
	rmd160_write(hd, NULL, 0);  /* flush */;
	memset(hd->buffer, 0, 56 ); /* fill next block with zeroes */
    }
    /* append the 64 bit count */
    hd->buffer[56] = lsb      ;
    hd->buffer[57] = lsb >>  8;
    hd->buffer[58] = lsb >> 16;
    hd->buffer[59] = lsb >> 24;
    hd->buffer[60] = msb      ;
    hd->buffer[61] = msb >>  8;
    hd->buffer[62] = msb >> 16;
    hd->buffer[63] = msb >> 24;
    transform( hd, (u32*)hd->buffer );

    p = hd->buffer;
  #ifdef HAVE_BIG_ENDIAN
    #define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
			*p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
  #else /* little endian */
    #define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0)
  #endif
    X(0);
    X(1);
    X(2);
    X(3);
    X(4);
  #undef X

    initialize( hd );	/* prepare for next cycle */
    return hd->buffer; /* now contains the digest */
}


