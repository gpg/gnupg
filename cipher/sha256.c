/* sha256.c - SHA224 and SHA256 hash functions
 * Copyright (C) 2003, 2006 Free Software Foundation, Inc.
 *
 * Please see below for more legal information!
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


/*  Test vectors from FIPS-180-2:
 *
 *  "abc"
 * 224:
 *  23097D22 3405D822 8642A477 BDA255B3 2AADBCE4 BDA0B3F7 E36C9DA7
 * 256:
 *  BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD
 *
 *  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 * 224:
 *  75388B16 512776CC 5DBA5DA1 FD890150 B0C6455C B4F58B19 52522525
 * 256:
 *  248D6A61 D20638B8 E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1
 *
 *  "a" x 1000000
 * 224:
 *  20794655 980C91D8 BBB4C1EA 97618A4B F03F4258 1948B2EE 4EE7AD67
 * 256:
 *  CDC76E5C 9914FB92 81A1C7E2 84D73E67 F1809A48 A497200E 046D39CC C7112CD0
 */


#include <config.h>
#include <string.h>
#include "util.h"
#include "algorithms.h"


typedef struct {
    u32  h0,h1,h2,h3,h4,h5,h6,h7;
    u32  nblocks;
    byte buf[64];
    int  count;
} SHA256_CONTEXT;

static void
burn_stack (int bytes)
{
    char buf[128];

    wipememory(buf,sizeof buf);
    bytes -= sizeof buf;
    if (bytes > 0)
        burn_stack (bytes);
}


void
sha256_init( SHA256_CONTEXT *hd )
{
    hd->h0 = 0x6a09e667;
    hd->h1 = 0xbb67ae85;
    hd->h2 = 0x3c6ef372;
    hd->h3 = 0xa54ff53a;
    hd->h4 = 0x510e527f;
    hd->h5 = 0x9b05688c;
    hd->h6 = 0x1f83d9ab;
    hd->h7 = 0x5be0cd19;

    hd->nblocks = 0;
    hd->count = 0;
}

void
sha224_init( SHA256_CONTEXT *hd )
{
    hd->h0 = 0xc1059ed8;
    hd->h1 = 0x367cd507;
    hd->h2 = 0x3070dd17;
    hd->h3 = 0xf70e5939;
    hd->h4 = 0xffc00b31;
    hd->h5 = 0x68581511;
    hd->h6 = 0x64f98fa7;
    hd->h7 = 0xbefa4fa4;

    hd->nblocks = 0;
    hd->count = 0;
}


/****************
 * Transform the message w which consists of 16 32-bit words
 */
static void
transform( SHA256_CONTEXT *hd, byte *data )
{
  u32 a,b,c,d,e,f,g,h;
  u32 w[64];
  int t;
  static const u32 k[]=
    {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

  /* get values from the chaining vars */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  f = hd->h5;
  g = hd->h6;
  h = hd->h7;

#ifdef BIG_ENDIAN_HOST
  memcpy( w, data, 64 );
#else
  {
    int i;
    byte *p2;

    for(i=0, p2=(byte*)w; i < 16; i++, p2 += 4 )
      {
	p2[3] = *data++;
	p2[2] = *data++;
	p2[1] = *data++;
	p2[0] = *data++;
      }
  }
#endif

#define ROTR(x,n) (((x)>>(n)) | ((x)<<(32-(n))))
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sum0(x) (ROTR((x),2) ^ ROTR((x),13) ^ ROTR((x),22))
#define Sum1(x) (ROTR((x),6) ^ ROTR((x),11) ^ ROTR((x),25))
#define S0(x) (ROTR((x),7) ^ ROTR((x),18) ^ ((x)>>3))
#define S1(x) (ROTR((x),17) ^ ROTR((x),19) ^ ((x)>>10))

  for(t=16;t<64;t++)
    w[t] = S1(w[t-2]) + w[t-7] + S0(w[t-15]) + w[t-16];

  for(t=0;t<64;t++)
    {
      u32 t1,t2;

      t1=h+Sum1(e)+Ch(e,f,g)+k[t]+w[t];
      t2=Sum0(a)+Maj(a,b,c);
      h=g;
      g=f;
      f=e;
      e=d+t1;
      d=c;
      c=b;
      b=a;
      a=t1+t2;
      /* printf("t=%d a=%08lX b=%08lX c=%08lX d=%08lX e=%08lX f=%08lX g=%08lX h=%08lX\n",t,a,b,c,d,e,f,g,h); */
    }

  /* update chaining vars */
  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;
  hd->h5 += f;
  hd->h6 += g;
  hd->h7 += h;
}


/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
static void
sha256_write( SHA256_CONTEXT *hd, byte *inbuf, size_t inlen)
{
    if( hd->count == 64 ) { /* flush the buffer */
	transform( hd, hd->buf );
        burn_stack (328);
	hd->count = 0;
	hd->nblocks++;
    }
    if( !inbuf )
	return;
    if( hd->count ) {
	for( ; inlen && hd->count < 64; inlen-- )
	    hd->buf[hd->count++] = *inbuf++;
	sha256_write( hd, NULL, 0 );
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
    burn_stack (328);
    for( ; inlen && hd->count < 64; inlen-- )
	hd->buf[hd->count++] = *inbuf++;
}


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 32 bytes representing the digest.  When used for sha224,
 * we take the leftmost 28 of those bytes.
 */

static void
sha256_final(SHA256_CONTEXT *hd)
{
    u32 t, msb, lsb;
    byte *p;

    sha256_write(hd, NULL, 0); /* flush */;

    t = hd->nblocks;
    /* multiply by 64 to make a byte count */
    lsb = t << 6;
    msb = t >> 26;
    /* add the count */
    t = lsb;
    if( (lsb += hd->count) < t )
	msb++;
    /* multiply by 8 to make a bit count */
    t = lsb;
    lsb <<= 3;
    msb <<= 3;
    msb |= t >> 29;

    if( hd->count < 56 ) { /* enough room */
	hd->buf[hd->count++] = 0x80; /* pad */
	while( hd->count < 56 )
	    hd->buf[hd->count++] = 0;  /* pad */
    }
    else { /* need one extra block */
	hd->buf[hd->count++] = 0x80; /* pad character */
	while( hd->count < 64 )
	    hd->buf[hd->count++] = 0;
	sha256_write(hd, NULL, 0);  /* flush */;
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
    burn_stack (328);

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
    X(5);
    X(6);
    /* Note that this last chunk is included even for SHA224.  We just
       ignore it. */
    X(7);
#undef X
}

static byte *
sha256_read( SHA256_CONTEXT *hd )
{
    return hd->buf;
}

/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 */
const char *
sha256_get_info( int algo, size_t *contextsize,
		 byte **r_asnoid, int *r_asnlen, int *r_mdlen,
		 void (**r_init)( void *c ),
		 void (**r_write)( void *c, byte *buf, size_t nbytes ),
		 void (**r_final)( void *c ),
		 byte *(**r_read)( void *c )
		 )
{
    static byte asn[] = /* Object ID is 2.16.840.1.101.3.4.2.1 */
      { 
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20
      };

    if( algo != 8 )
	return NULL;

    *contextsize = sizeof(SHA256_CONTEXT);
    *r_asnoid = asn;
    *r_asnlen = DIM(asn);
    *r_mdlen = 32;
    *(void  (**)(SHA256_CONTEXT *))r_init 	  	  = sha256_init;
    *(void  (**)(SHA256_CONTEXT *, byte*, size_t))r_write = sha256_write;
    *(void  (**)(SHA256_CONTEXT *))r_final		  = sha256_final;
    *(byte *(**)(SHA256_CONTEXT *))r_read 		  = sha256_read;

    return "SHA256";
}

/* SHA224 is really a truncated SHA256 with a different
   initialization */
const char *
sha224_get_info( int algo, size_t *contextsize,
		 byte **r_asnoid, int *r_asnlen, int *r_mdlen,
		 void (**r_init)( void *c ),
		 void (**r_write)( void *c, byte *buf, size_t nbytes ),
		 void (**r_final)( void *c ),
		 byte *(**r_read)( void *c )
		 )
{
    static byte asn[] = /* Object ID is 2.16.840.1.101.3.4.2.4 */
      { 
	0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	0x00, 0x04, 0x1C
      };

    if( algo != 11 )
	return NULL;

    *contextsize = sizeof(SHA256_CONTEXT);
    *r_asnoid = asn;
    *r_asnlen = DIM(asn);
    *r_mdlen = 28;
    *(void  (**)(SHA256_CONTEXT *))r_init 	  	  = sha224_init;
    *(void  (**)(SHA256_CONTEXT *, byte*, size_t))r_write = sha256_write;
    *(void  (**)(SHA256_CONTEXT *))r_final		  = sha256_final;
    *(byte *(**)(SHA256_CONTEXT *))r_read 		  = sha256_read;

    return "SHA224";
}
