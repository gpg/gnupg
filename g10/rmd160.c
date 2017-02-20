/* rmd160.c  -	RIPE-MD160
 * Copyright (C) 1998, 1999, 2000, 2001, 2008 Free Software Foundation, Inc.
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/* For historic reasons gpg uses RIPE-MD160 to identify names in
   the trustdb.  It would be better to change that to SHA-1, to take
   advantage of a SHA-1 hardware operation provided by some CPUs.
   This would break trustdb compatibility and thus we don't want to do
   it now.

   We do not use the libgcrypt provided implementation of RMD160
   because that is not available in FIPS mode, thus for the sake of
   gpg internal non-cryptographic, purposes, we use this separate
   implementation.
*/

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/types.h"
#include "rmd160.h"

/*
 * Rotate the 32 bit integer X by N bytes.
 */
#if defined(__GNUC__) && defined(__i386__)
static inline u32
rol (u32 x, int n)
{
  __asm__("roll %%cl,%0"
          :"=r" (x)
          :"0" (x),"c" (n));
  return x;
}
#else
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

/* Structure holding the context for the RIPE-MD160 computation.  */
typedef struct
{
  u32 h0, h1, h2, h3, h4;
  u32 nblocks;
  unsigned char buf[64];
  int  count;
} rmd160_context_t;



static void
rmd160_init (rmd160_context_t *hd)
{
  hd->h0 = 0x67452301;
  hd->h1 = 0xEFCDAB89;
  hd->h2 = 0x98BADCFE;
  hd->h3 = 0x10325476;
  hd->h4 = 0xC3D2E1F0;
  hd->nblocks = 0;
  hd->count = 0;
}



/*
 * Transform the message X which consists of 16 32-bit-words.
 */
static void
transform (rmd160_context_t *hd, const unsigned char *data)
{
  u32 a,b,c,d,e,aa,bb,cc,dd,ee,t;
#ifdef BIG_ENDIAN_HOST
  u32 x[16];
  {
    int i;
    unsigned char *p2, *p1;
    for (i=0, p1=data, p2=(unsigned char*)x; i < 16; i++, p2 += 4 )
      {
        p2[3] = *p1++;
        p2[2] = *p1++;
        p2[1] = *p1++;
	p2[0] = *p1++;
      }
  }
#else
  u32 x[16];
  memcpy (x, data, 64);
#endif


#define K0  0x00000000
#define K1  0x5A827999
#define K2  0x6ED9EBA1
#define K3  0x8F1BBCDC
#define K4  0xA953FD4E
#define KK0 0x50A28BE6
#define KK1 0x5C4DD124
#define KK2 0x6D703EF3
#define KK3 0x7A6D76E9
#define KK4 0x00000000
#define F0(x,y,z)   ( (x) ^ (y) ^ (z) )
#define F1(x,y,z)   ( ((x) & (y)) | (~(x) & (z)) )
#define F2(x,y,z)   ( ((x) | ~(y)) ^ (z) )
#define F3(x,y,z)   ( ((x) & (z)) | ((y) & ~(z)) )
#define F4(x,y,z)   ( (x) ^ ((y) | ~(z)) )
#define R(a,b,c,d,e,f,k,r,s) do { t = a + f(b,c,d) + k + x[r]; \
				  a = rol(t,s) + e;	       \
				  c = rol(c,10);	       \
				} while(0)

  /* Left lane.  */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  R( a, b, c, d, e, F0, K0,  0, 11 );
  R( e, a, b, c, d, F0, K0,  1, 14 );
  R( d, e, a, b, c, F0, K0,  2, 15 );
  R( c, d, e, a, b, F0, K0,  3, 12 );
  R( b, c, d, e, a, F0, K0,  4,  5 );
  R( a, b, c, d, e, F0, K0,  5,  8 );
  R( e, a, b, c, d, F0, K0,  6,  7 );
  R( d, e, a, b, c, F0, K0,  7,  9 );
  R( c, d, e, a, b, F0, K0,  8, 11 );
  R( b, c, d, e, a, F0, K0,  9, 13 );
  R( a, b, c, d, e, F0, K0, 10, 14 );
  R( e, a, b, c, d, F0, K0, 11, 15 );
  R( d, e, a, b, c, F0, K0, 12,  6 );
  R( c, d, e, a, b, F0, K0, 13,  7 );
  R( b, c, d, e, a, F0, K0, 14,  9 );
  R( a, b, c, d, e, F0, K0, 15,  8 );
  R( e, a, b, c, d, F1, K1,  7,  7 );
  R( d, e, a, b, c, F1, K1,  4,  6 );
  R( c, d, e, a, b, F1, K1, 13,  8 );
  R( b, c, d, e, a, F1, K1,  1, 13 );
  R( a, b, c, d, e, F1, K1, 10, 11 );
  R( e, a, b, c, d, F1, K1,  6,  9 );
  R( d, e, a, b, c, F1, K1, 15,  7 );
  R( c, d, e, a, b, F1, K1,  3, 15 );
  R( b, c, d, e, a, F1, K1, 12,  7 );
  R( a, b, c, d, e, F1, K1,  0, 12 );
  R( e, a, b, c, d, F1, K1,  9, 15 );
  R( d, e, a, b, c, F1, K1,  5,  9 );
  R( c, d, e, a, b, F1, K1,  2, 11 );
  R( b, c, d, e, a, F1, K1, 14,  7 );
  R( a, b, c, d, e, F1, K1, 11, 13 );
  R( e, a, b, c, d, F1, K1,  8, 12 );
  R( d, e, a, b, c, F2, K2,  3, 11 );
  R( c, d, e, a, b, F2, K2, 10, 13 );
  R( b, c, d, e, a, F2, K2, 14,  6 );
  R( a, b, c, d, e, F2, K2,  4,  7 );
  R( e, a, b, c, d, F2, K2,  9, 14 );
  R( d, e, a, b, c, F2, K2, 15,  9 );
  R( c, d, e, a, b, F2, K2,  8, 13 );
  R( b, c, d, e, a, F2, K2,  1, 15 );
  R( a, b, c, d, e, F2, K2,  2, 14 );
  R( e, a, b, c, d, F2, K2,  7,  8 );
  R( d, e, a, b, c, F2, K2,  0, 13 );
  R( c, d, e, a, b, F2, K2,  6,  6 );
  R( b, c, d, e, a, F2, K2, 13,  5 );
  R( a, b, c, d, e, F2, K2, 11, 12 );
  R( e, a, b, c, d, F2, K2,  5,  7 );
  R( d, e, a, b, c, F2, K2, 12,  5 );
  R( c, d, e, a, b, F3, K3,  1, 11 );
  R( b, c, d, e, a, F3, K3,  9, 12 );
  R( a, b, c, d, e, F3, K3, 11, 14 );
  R( e, a, b, c, d, F3, K3, 10, 15 );
  R( d, e, a, b, c, F3, K3,  0, 14 );
  R( c, d, e, a, b, F3, K3,  8, 15 );
  R( b, c, d, e, a, F3, K3, 12,  9 );
  R( a, b, c, d, e, F3, K3,  4,  8 );
  R( e, a, b, c, d, F3, K3, 13,  9 );
  R( d, e, a, b, c, F3, K3,  3, 14 );
  R( c, d, e, a, b, F3, K3,  7,  5 );
  R( b, c, d, e, a, F3, K3, 15,  6 );
  R( a, b, c, d, e, F3, K3, 14,  8 );
  R( e, a, b, c, d, F3, K3,  5,  6 );
  R( d, e, a, b, c, F3, K3,  6,  5 );
  R( c, d, e, a, b, F3, K3,  2, 12 );
  R( b, c, d, e, a, F4, K4,  4,  9 );
  R( a, b, c, d, e, F4, K4,  0, 15 );
  R( e, a, b, c, d, F4, K4,  5,  5 );
  R( d, e, a, b, c, F4, K4,  9, 11 );
  R( c, d, e, a, b, F4, K4,  7,  6 );
  R( b, c, d, e, a, F4, K4, 12,  8 );
  R( a, b, c, d, e, F4, K4,  2, 13 );
  R( e, a, b, c, d, F4, K4, 10, 12 );
  R( d, e, a, b, c, F4, K4, 14,  5 );
  R( c, d, e, a, b, F4, K4,  1, 12 );
  R( b, c, d, e, a, F4, K4,  3, 13 );
  R( a, b, c, d, e, F4, K4,  8, 14 );
  R( e, a, b, c, d, F4, K4, 11, 11 );
  R( d, e, a, b, c, F4, K4,  6,  8 );
  R( c, d, e, a, b, F4, K4, 15,  5 );
  R( b, c, d, e, a, F4, K4, 13,  6 );

  aa = a; bb = b; cc = c; dd = d; ee = e;

  /* Right lane.  */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  R( a, b, c, d, e, F4, KK0,	5,  8);
  R( e, a, b, c, d, F4, KK0, 14,  9);
  R( d, e, a, b, c, F4, KK0,	7,  9);
  R( c, d, e, a, b, F4, KK0,	0, 11);
  R( b, c, d, e, a, F4, KK0,	9, 13);
  R( a, b, c, d, e, F4, KK0,	2, 15);
  R( e, a, b, c, d, F4, KK0, 11, 15);
  R( d, e, a, b, c, F4, KK0,	4,  5);
  R( c, d, e, a, b, F4, KK0, 13,  7);
  R( b, c, d, e, a, F4, KK0,	6,  7);
  R( a, b, c, d, e, F4, KK0, 15,  8);
  R( e, a, b, c, d, F4, KK0,	8, 11);
  R( d, e, a, b, c, F4, KK0,	1, 14);
  R( c, d, e, a, b, F4, KK0, 10, 14);
  R( b, c, d, e, a, F4, KK0,	3, 12);
  R( a, b, c, d, e, F4, KK0, 12,  6);
  R( e, a, b, c, d, F3, KK1,	6,  9);
  R( d, e, a, b, c, F3, KK1, 11, 13);
  R( c, d, e, a, b, F3, KK1,	3, 15);
  R( b, c, d, e, a, F3, KK1,	7,  7);
  R( a, b, c, d, e, F3, KK1,	0, 12);
  R( e, a, b, c, d, F3, KK1, 13,  8);
  R( d, e, a, b, c, F3, KK1,	5,  9);
  R( c, d, e, a, b, F3, KK1, 10, 11);
  R( b, c, d, e, a, F3, KK1, 14,  7);
  R( a, b, c, d, e, F3, KK1, 15,  7);
  R( e, a, b, c, d, F3, KK1,	8, 12);
  R( d, e, a, b, c, F3, KK1, 12,  7);
  R( c, d, e, a, b, F3, KK1,	4,  6);
  R( b, c, d, e, a, F3, KK1,	9, 15);
  R( a, b, c, d, e, F3, KK1,	1, 13);
  R( e, a, b, c, d, F3, KK1,	2, 11);
  R( d, e, a, b, c, F2, KK2, 15,  9);
  R( c, d, e, a, b, F2, KK2,	5,  7);
  R( b, c, d, e, a, F2, KK2,	1, 15);
  R( a, b, c, d, e, F2, KK2,	3, 11);
  R( e, a, b, c, d, F2, KK2,	7,  8);
  R( d, e, a, b, c, F2, KK2, 14,  6);
  R( c, d, e, a, b, F2, KK2,	6,  6);
  R( b, c, d, e, a, F2, KK2,	9, 14);
  R( a, b, c, d, e, F2, KK2, 11, 12);
  R( e, a, b, c, d, F2, KK2,	8, 13);
  R( d, e, a, b, c, F2, KK2, 12,  5);
  R( c, d, e, a, b, F2, KK2,	2, 14);
  R( b, c, d, e, a, F2, KK2, 10, 13);
  R( a, b, c, d, e, F2, KK2,	0, 13);
  R( e, a, b, c, d, F2, KK2,	4,  7);
  R( d, e, a, b, c, F2, KK2, 13,  5);
  R( c, d, e, a, b, F1, KK3,	8, 15);
  R( b, c, d, e, a, F1, KK3,	6,  5);
  R( a, b, c, d, e, F1, KK3,	4,  8);
  R( e, a, b, c, d, F1, KK3,	1, 11);
  R( d, e, a, b, c, F1, KK3,	3, 14);
  R( c, d, e, a, b, F1, KK3, 11, 14);
  R( b, c, d, e, a, F1, KK3, 15,  6);
  R( a, b, c, d, e, F1, KK3,	0, 14);
  R( e, a, b, c, d, F1, KK3,	5,  6);
  R( d, e, a, b, c, F1, KK3, 12,  9);
  R( c, d, e, a, b, F1, KK3,	2, 12);
  R( b, c, d, e, a, F1, KK3, 13,  9);
  R( a, b, c, d, e, F1, KK3,	9, 12);
  R( e, a, b, c, d, F1, KK3,	7,  5);
  R( d, e, a, b, c, F1, KK3, 10, 15);
  R( c, d, e, a, b, F1, KK3, 14,  8);
  R( b, c, d, e, a, F0, KK4, 12,  8);
  R( a, b, c, d, e, F0, KK4, 15,  5);
  R( e, a, b, c, d, F0, KK4, 10, 12);
  R( d, e, a, b, c, F0, KK4,	4,  9);
  R( c, d, e, a, b, F0, KK4,	1, 12);
  R( b, c, d, e, a, F0, KK4,	5,  5);
  R( a, b, c, d, e, F0, KK4,	8, 14);
  R( e, a, b, c, d, F0, KK4,	7,  6);
  R( d, e, a, b, c, F0, KK4,	6,  8);
  R( c, d, e, a, b, F0, KK4,	2, 13);
  R( b, c, d, e, a, F0, KK4, 13,  6);
  R( a, b, c, d, e, F0, KK4, 14,  5);
  R( e, a, b, c, d, F0, KK4,	0, 15);
  R( d, e, a, b, c, F0, KK4,	3, 13);
  R( c, d, e, a, b, F0, KK4,	9, 11);
  R( b, c, d, e, a, F0, KK4, 11, 11);


  t	 = hd->h1 + d + cc;
  hd->h1 = hd->h2 + e + dd;
  hd->h2 = hd->h3 + a + ee;
  hd->h3 = hd->h4 + b + aa;
  hd->h4 = hd->h0 + c + bb;
  hd->h0 = t;
}


/* Update the message digest with the content of (INBUF,INLEN).  */
static void
rmd160_write (rmd160_context_t *hd, const unsigned char *inbuf, size_t inlen)
{
  if( hd->count == 64 )
    {
      /* Flush the buffer.  */
      transform (hd, hd->buf);
      hd->count = 0;
      hd->nblocks++;
    }
  if (!inbuf)
    return;

  if (hd->count)
    {
      for (; inlen && hd->count < 64; inlen--)
        hd->buf[hd->count++] = *inbuf++;
      rmd160_write (hd, NULL, 0);
      if (!inlen)
        return;
    }

  while (inlen >= 64)
    {
      transform (hd, inbuf);
      hd->count = 0;
      hd->nblocks++;
      inlen -= 64;
      inbuf += 64;
    }
  for (; inlen && hd->count < 64; inlen--)
    hd->buf[hd->count++] = *inbuf++;
}


/* Complete the message computation.  */
static void
rmd160_final( rmd160_context_t *hd )
{
  u32 t, msb, lsb;
  unsigned char *p;

  rmd160_write (hd, NULL, 0); /* Flush buffer. */

  t = hd->nblocks;
  /* Multiply by 64 to make a byte count. */
  lsb = t << 6;
  msb = t >> 26;
  /* Add the count.  */
  t = lsb;
  if ((lsb += hd->count) < t)
    msb++;
  /* Multiply by 8 to make a bit count.  */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if (hd->count < 56)
    {
      /* Enough room.  */
      hd->buf[hd->count++] = 0x80; /* Pad character. */
      while (hd->count < 56)
        hd->buf[hd->count++] = 0;
    }
  else
    {
      /* Need one extra block.  */
      hd->buf[hd->count++] = 0x80; /* Pad character. */
      while (hd->count < 64)
        hd->buf[hd->count++] = 0;
      rmd160_write (hd, NULL, 0); /* Flush buffer.  */
      memset (hd->buf, 0, 56);    /* Fill next block with zeroes.  */
    }
  /* Append the 64 bit count.  */
  hd->buf[56] = lsb;
  hd->buf[57] = lsb >>  8;
  hd->buf[58] = lsb >> 16;
  hd->buf[59] = lsb >> 24;
  hd->buf[60] = msb;
  hd->buf[61] = msb >>  8;
  hd->buf[62] = msb >> 16;
  hd->buf[63] = msb >> 24;
  transform (hd, hd->buf);

  p = hd->buf;
#define X(a) do { *p++ = hd->h##a;       *p++ = hd->h##a >> 8;	\
                  *p++ = hd->h##a >> 16; *p++ = hd->h##a >> 24; } while(0)
  X(0);
  X(1);
  X(2);
  X(3);
  X(4);
#undef X
}


/*
 * Compines function to put the hash value of the supplied BUFFER into
 * OUTBUF which must have a size of 20 bytes.
 */
void
rmd160_hash_buffer (void *outbuf, const void *buffer, size_t length)
{
  rmd160_context_t hd;

  rmd160_init (&hd);
  rmd160_write (&hd, buffer, length);
  rmd160_final (&hd);
  memcpy (outbuf, hd.buf, 20);
}
