/* gost.c  -  GOST encryption
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * The description of GOST (and the used S-boxes) are taken from:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. .
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
#include "util.h"
#include "types.h"
#include "gost.h"



static u16
mul_inv( u16 x )
{
    u16 t0, t1;
    u16 q, y;

    if( x < 2 )
	return x;
    t1 = 0x10001L / x;
    y =  0x10001L % x;
    if( y == 1 )
	return (1-t1) & 0xffff;

    t0 = 1;
    do {
	q = x / y;
	x = x % y;
	t0 += q * t1;
	if( x == 1 )
	    return t0;
	q = y / x;
	y = y % x;
	t1 += q * t0;
    } while( y != 1 );
    return (1-t1) & 0xffff;
}



static void
expand_key( byte *userkey, u16 *ek )
{
    int i,j;

    for(j=0; j < 8; j++ ) {
	ek[j] = (*userkey << 8) + userkey[1];
	userkey += 2;
    }
    for(i=0; j < GOST_KEYLEN; j++ ) {
	i++;
	ek[i+7] = ek[i&7] << 9 | ek[(i+1)&7] >> 7;
	ek += i & 8;
	i &= 7;
    }
}


static void
invert_key( u16 *ek, u16 dk[GOST_KEYLEN] )
{
    int i;
    u16 t1, t2, t3;
    u16 temp[GOST_KEYLEN];
    u16 *p = temp + GOST_KEYLEN;

    t1 = mul_inv( *ek++ );
    t2 = -*ek++;
    t3 = -*ek++;
    *--p = mul_inv( *ek++ );
    *--p = t3;
    *--p = t2;
    *--p = t1;

    for(i=0; i < GOST_ROUNDS-1; i++ ) {
	t1 = *ek++;
	*--p = *ek++;
	*--p = t1;

	t1 = mul_inv( *ek++ );
	t2 = -*ek++;
	t3 = -*ek++;
	*--p = mul_inv( *ek++ );
	*--p = t3;
	*--p = t2;
	*--p = t1;
    }
    t1 = *ek++;
    *--p = *ek++;
    *--p = t1;

    t1 = mul_inv( *ek++ );
    t2 = -*ek++;
    t3 = -*ek++;
    *--p = mul_inv( *ek++ );
    *--p = t3;
    *--p = t2;
    *--p = t1;
    memcpy(dk, temp, sizeof(temp) );
    memset(temp, 0, sizeof(temp) );  /* burn temp */
}


static void
cipher( byte *inbuf, byte *outbuf, u16 *key )
{
    u16 x1, x2, x3,x4, s2, s3;
    u16 *in, *out;
    int r = GOST_ROUNDS;
  #define MUL(x,y) \
	do {u16 _t16; u32 _t32; 		    \
	    if( (_t16 = (y)) ) {		    \
		if( (x = (x)&0xffff) ) {	    \
		    _t32 = (u32)x * _t16;	    \
		    x = _t32 & 0xffff;		    \
		    _t16 = _t32 >> 16;		    \
		    x = ((x)-_t16) + (x<_t16?1:0);  \
		}				    \
		else {				    \
		    x = 1 - _t16;		    \
		}				    \
	    }					    \
	    else {				    \
		x = 1 - x;			    \
	    }					    \
	} while(0)

    in = (u16*)inbuf;
    x1 = *in++;
    x2 = *in++;
    x3 = *in++;
    x4 = *in;
  #ifdef HAVE_LITTLE_ENDIAN
    x1 = (x1>>8) | (x1<<8);
    x2 = (x2>>8) | (x2<<8);
    x3 = (x3>>8) | (x3<<8);
    x4 = (x4>>8) | (x4<<8);
  #endif
    do {
	MUL(x1, *key++);
	x2 += *key++;
	x3 += *key++;
	MUL(x4, *key++ );

	s3 = x3;
	x3 ^= x1;
	MUL(x3, *key++);
	s2 = x2;
	x2 ^=x4;
	x2 += x3;
	MUL(x2, *key++);
	x3 += x2;

	x1 ^= x2;
	x4 ^= x3;

	x2 ^= s3;
	x3 ^= s2;
    } while( --r );
    MUL(x1, *key++);
    x3 += *key++;
    x2 += *key++;
    MUL(x4, *key);

    out = (u16*)outbuf;
  #ifdef HAVE_LITTLE_ENDIAN
    *out++ = (x1>>8) | (x1<<8);
    *out++ = (x3>>8) | (x3<<8);
    *out++ = (x2>>8) | (x2<<8);
    *out   = (x4>>8) | (x4<<8);
  #else
    *out++ = x1;
    *out++ = x3;
    *out++ = x2;
    *out   = x4;
  #endif
  #undef MUL
}


void
gost_setkey( GOST_context *c, byte *key )
{
    expand_key( key, c->ek );
    invert_key( c->ek, c->dk );
}

void
gost_setiv( GOST_context *c, byte *iv )
{
    memcpy( c->iv, iv, GOST_BLOCKSIZE );
}


void
gost_encode( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	cipher( inbuf, outbuf, c->ek );
	inbuf  += 8;
	outbuf += 8;
    }
}


void
gost_decode( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nblocks )
{
    unsigned n;

    for(n=0; n < nblocks; n++ ) {
	cipher( inbuf, outbuf, c->dk );
	inbuf  += 8;
	outbuf += 8;
    }
}


static void
cfbshift( byte *iv, byte *buf, unsigned count)
{
    unsigned n;

    if( count ) {
	for( n = GOST_BLOCKSIZE - count; n; n--, iv++ )
	    *iv = iv[count];
	for( ; count; count-- )
	    *iv++ = *buf++;
    }
}


/****************
 * FIXME: Make use of bigger chunks
 */
static void
xorblock( byte *out, byte *a, byte *b, unsigned count )
{
    for( ; count ; count--, a++, b++ )
	*out++ = *a ^ *b ;
}


void
gost_encode_cfb( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nbytes)
{
    byte temp[GOST_BLOCKSIZE];

    while( nbytes >= GOST_BLOCKSIZE ) {
	cipher( c->iv, temp, c->ek );
	xorblock( outbuf, inbuf, temp, GOST_BLOCKSIZE);
	cfbshift( c->iv, outbuf, GOST_BLOCKSIZE );
	nbytes -= GOST_BLOCKSIZE;
	inbuf += GOST_BLOCKSIZE;
	outbuf += GOST_BLOCKSIZE;
    }
    if( nbytes ) {
	cipher( c->iv, temp, c->ek );
	xorblock( outbuf, inbuf, temp, nbytes );
	cfbshift( c->iv, outbuf, nbytes );
    }
}


void
gost_decode_cfb( GOST_context *c, byte *outbuf, byte *inbuf, unsigned nbytes)
{
    byte temp[GOST_BLOCKSIZE];

    while( nbytes >= GOST_BLOCKSIZE ) {
	cipher( c->iv, temp, c->ek );
	cfbshift( c->iv, inbuf, GOST_BLOCKSIZE );
	xorblock( outbuf, inbuf, temp, GOST_BLOCKSIZE);
	nbytes -= GOST_BLOCKSIZE;
	inbuf += GOST_BLOCKSIZE;
	outbuf += GOST_BLOCKSIZE;
    }
    if( nbytes ) {
	cipher( c->iv, temp, c->ek );
	cfbshift( c->iv, inbuf, nbytes );
	xorblock( outbuf, inbuf, temp, nbytes );
    }
}

