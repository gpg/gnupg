/* md5.c - MD5 Message-Digest Algorithm
 *	Copyright (c) 1994 by Werner Koch (dd9jn)
 *
 *  This is a hacked version from WkLib
 *
 *  This file is part of WkLib.
 *
 *  WkLib is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  WkLib is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 ***********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.  **
 **								      **
 ** License to copy and use this software is granted provided that    **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message-     **
 ** Digest Algorithm" in all material mentioning or referencing this  **
 ** software or this function.					      **
 **								      **
 ** License is also granted to make and use derivative works	      **
 ** provided that such works are identified as "derived from the RSA  **
 ** Data Security, Inc. MD5 Message-Digest Algorithm" in all          **
 ** material mentioning or referencing the derived work.	      **
 **								      **
 ** RSA Data Security, Inc. makes no representations concerning       **
 ** either the merchantability of this software or the suitability    **
 ** of this software for any particular purpose.  It is provided "as  **
 ** is" without express or implied warranty of any kind.              **
 **								      **
 ** These notices must be retained in any copies of any part of this  **
 ** documentation and/or software.				      **
 ***********************************************************************
 *
 * History:
 * 16.01.95 wk	now uses generic base-64 support
 * 24.01.95 wk	changed back to original base-64 coding, because
 *		the generic base-64 support was changed to go conform
 *		with RFC1113 !
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "md5.h"
#include "memory.h"


#if __WATCOMC__ && defined(M_I86)
  /* 16-Bit Compiler breaks Code in Function Transform() */
  /* (at least when compiling for windows) */
  #ifndef __SW_OD
     #error must be compiled without optimizations
  #endif
#endif


static void Init( MD5HANDLE mdContext);
static void Transform(u32 *buf,u32 *in);

static byte PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G, H and I are basic MD5 functions */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (u32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (u32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (u32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (u32)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

/* The routine Init initializes the message-digest context
 * mdContext. All fields are set to zero.
 * mode should be zero is reserved for extensions.
 */

MD5HANDLE
md5_open(int secure)
{
    MD5HANDLE mdContext;

    mdContext = secure? m_alloc_secure( sizeof *mdContext )
		      : m_alloc( sizeof *mdContext );
    Init(mdContext);
    return mdContext;
}


MD5HANDLE
md5_copy( MD5HANDLE a )
{
    MD5HANDLE mdContext;

    assert(a);
    mdContext = m_is_secure(a)? m_alloc_secure( sizeof *mdContext )
			      : m_alloc( sizeof *mdContext );
    memcpy( mdContext, a, sizeof *a );
    return mdContext;
}

void
md5_close(MD5HANDLE hd)
{
    if( hd )
	m_free(hd);
}


static void
Init( MD5HANDLE mdContext)
{
    mdContext->i[0] = mdContext->i[1] = (u32)0;
    /* Load magic initialization constants.
     */
    mdContext->buf[0] = (u32)0x67452301L;
    mdContext->buf[1] = (u32)0xefcdab89L;
    mdContext->buf[2] = (u32)0x98badcfeL;
    mdContext->buf[3] = (u32)0x10325476L;
    mdContext->bufcount = 0;
}

/* The routine Update updates the message-digest context to
 * account for the presence of each of the characters inBuf[0..inLen-1]
 * in the message whose digest is being computed.
 */
void
md5_write( MD5HANDLE mdContext, byte *inBuf, size_t inLen)
{
    register int i, ii;
    int mdi;
    u32 in[16];

    if(mdContext->bufcount) { /* flush the buffer */
	i = mdContext->bufcount;
	mdContext->bufcount = 0;
	md5_write( mdContext, mdContext->digest, i);
    }
    if( !inBuf )
	return;

    /* compute number of bytes mod 64 */
    mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

    /* update number of bits */
    if((mdContext->i[0] + ((u32)inLen << 3)) < mdContext->i[0])
	mdContext->i[1]++;
    mdContext->i[0] += ((u32)inLen << 3);
    mdContext->i[1] += ((u32)inLen >> 29);

    while(inLen--) {
	/* add new character to buffer, increment mdi */
	mdContext->in[mdi++] = *inBuf++;

	/* transform if necessary */
	if( mdi == 0x40 ) {
	    for(i = 0, ii = 0; i < 16; i++, ii += 4)
		in[i] = (((u32)mdContext->in[ii+3]) << 24) |
			(((u32)mdContext->in[ii+2]) << 16) |
			(((u32)mdContext->in[ii+1]) << 8) |
			((u32)mdContext->in[ii]);
	    Transform(mdContext->buf, in);
	    mdi = 0;
	}
    }
}


/****************
 * Process a single character, this character will be buffered to
 * increase performance. The digest-field is used as a buffer.
 */

void
md5_putchar( MD5HANDLE mdContext, int c )
{
    if(mdContext->bufcount == 16)
	md5_write( mdContext, NULL, 0 );
    mdContext->digest[mdContext->bufcount++] = c & 0xff;
}



/* The routine final terminates the message-digest computation and
 * ends with the desired message digest in mdContext->digest[0...15].
 * The handle is prepared for a new MD5 cycle.
 * Returns 16 bytes representing the digest.
 */

void
md5_final(MD5HANDLE mdContext)
{
    u32 in[16];
    int mdi;
    unsigned int i, ii;
    unsigned int padLen;

    if(mdContext->bufcount) /* flush buffer */
	md5_write(mdContext, NULL, 0 );
    /* save number of bits */
    in[14] = mdContext->i[0];
    in[15] = mdContext->i[1];

    /* compute number of bytes mod 64 */
    mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

    /* pad out to 56 mod 64 */
    padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
    md5_write(mdContext, PADDING, padLen);

    /* append length in bits and transform */
    for(i = 0, ii = 0; i < 14; i++, ii += 4)
	in[i] = (((u32)mdContext->in[ii+3]) << 24) |
		(((u32)mdContext->in[ii+2]) << 16) |
		(((u32)mdContext->in[ii+1]) << 8) |
		((u32)mdContext->in[ii]);
    Transform(mdContext->buf, in);

    /* store buffer in digest */
    for(i = 0, ii = 0; i < 4; i++, ii += 4) {
	mdContext->digest[ii]	= (byte)(mdContext->buf[i] & 0xFF);
	mdContext->digest[ii+1] = (byte)((mdContext->buf[i] >> 8) & 0xFF);
	mdContext->digest[ii+2] = (byte)((mdContext->buf[i] >> 16) & 0xFF);
	mdContext->digest[ii+3] = (byte)((mdContext->buf[i] >> 24) & 0xFF);
    }
    Init(mdContext);
}

/**********
 * Returns 16 bytes representing the digest.
 */
byte *
md5_read(MD5HANDLE mdContext)
{
    return mdContext->digest;
}



/****************
 * Converts the result form Read into a printable representation.
 * This should only be used direct after a md5_read(), because it uses
 * In-Place conversion.
 * Returns digest.
 */

char *
md5_tostring( byte *digest )
{
    static byte bintoasc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ."
			     "abcdefghijklmnopqrstuvwxyz_"
			     "0123456789";
    int i;
    byte *d, *s;

    memmove(digest+8,digest, 16); /* make some room */
    d = digest;
    s = digest+8;
    for(i=0; i < 5; i++, s += 3 ) {
	*d++ = bintoasc[(*s >> 2) & 077];
	*d++ = bintoasc[(((*s << 4) & 060) | ((s[1] >> 4) & 017)) & 077];
	*d++ = bintoasc[(((s[1] << 2) & 074) | ((s[2] >> 6) & 03)) & 077];
	*d++ = bintoasc[s[2] & 077];
    }
    *d++ = bintoasc[(*s >> 2) & 077];
    *d++ = bintoasc[((*s << 4) & 060) & 077];
    *d = 0;
    return (char*)digest;
}


/* Basic MD5 step. Transforms buf based on in.	Note that if the Mysterious
 * Constants are arranged backwards in little-endian order and decrypted with
 * the DES they produce OCCULT MESSAGES!
 */
static void
Transform(register u32 *buf,register u32 *in)
{
  register u32 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
  FF ( a, b, c, d, in[ 0], S11, 0xD76AA478L); /* 1 */
  FF ( d, a, b, c, in[ 1], S12, 0xE8C7B756L); /* 2 */
  FF ( c, d, a, b, in[ 2], S13, 0x242070DBL); /* 3 */
  FF ( b, c, d, a, in[ 3], S14, 0xC1BDCEEEL); /* 4 */
  FF ( a, b, c, d, in[ 4], S11, 0xF57C0FAFL); /* 5 */
  FF ( d, a, b, c, in[ 5], S12, 0x4787C62AL); /* 6 */
  FF ( c, d, a, b, in[ 6], S13, 0xA8304613L); /* 7 */
  FF ( b, c, d, a, in[ 7], S14, 0xFD469501L); /* 8 */
  FF ( a, b, c, d, in[ 8], S11, 0x698098D8L); /* 9 */
  FF ( d, a, b, c, in[ 9], S12, 0x8B44F7AFL); /* 10 */
  FF ( c, d, a, b, in[10], S13, 0xFFFF5BB1L); /* 11 */
  FF ( b, c, d, a, in[11], S14, 0x895CD7BEL); /* 12 */
  FF ( a, b, c, d, in[12], S11, 0x6B901122L); /* 13 */
  FF ( d, a, b, c, in[13], S12, 0xFD987193L); /* 14 */
  FF ( c, d, a, b, in[14], S13, 0xA679438EL); /* 15 */
  FF ( b, c, d, a, in[15], S14, 0x49B40821L); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 0xF61E2562L); /* 17 */
  GG ( d, a, b, c, in[ 6], S22, 0xC040B340L); /* 18 */
  GG ( c, d, a, b, in[11], S23, 0x265E5A51L); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 0xE9B6C7AAL); /* 20 */
  GG ( a, b, c, d, in[ 5], S21, 0xD62F105DL); /* 21 */
  GG ( d, a, b, c, in[10], S22, 0x02441453L); /* 22 */
  GG ( c, d, a, b, in[15], S23, 0xD8A1E681L); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 0xE7D3FBC8L); /* 24 */
  GG ( a, b, c, d, in[ 9], S21, 0x21E1CDE6L); /* 25 */
  GG ( d, a, b, c, in[14], S22, 0xC33707D6L); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 0xF4D50D87L); /* 27 */
  GG ( b, c, d, a, in[ 8], S24, 0x455A14EDL); /* 28 */
  GG ( a, b, c, d, in[13], S21, 0xA9E3E905L); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 0xFCEFA3F8L); /* 30 */
  GG ( c, d, a, b, in[ 7], S23, 0x676F02D9L); /* 31 */
  GG ( b, c, d, a, in[12], S24, 0x8D2A4C8AL); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in[ 5], S31, 0xFFFA3942L); /* 33 */
  HH ( d, a, b, c, in[ 8], S32, 0x8771F681L); /* 34 */
  HH ( c, d, a, b, in[11], S33, 0x6D9D6122L); /* 35 */
  HH ( b, c, d, a, in[14], S34, 0xFDE5380CL); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 0xA4BEEA44L); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 0x4BDECFA9L); /* 38 */
  HH ( c, d, a, b, in[ 7], S33, 0xF6BB4B60L); /* 39 */
  HH ( b, c, d, a, in[10], S34, 0xBEBFBC70L); /* 40 */
  HH ( a, b, c, d, in[13], S31, 0x289B7EC6L); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 0xEAA127FAL); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 0xD4EF3085L); /* 43 */
  HH ( b, c, d, a, in[ 6], S34, 0x04881D05L); /* 44 */
  HH ( a, b, c, d, in[ 9], S31, 0xD9D4D039L); /* 45 */
  HH ( d, a, b, c, in[12], S32, 0xE6DB99E5L); /* 46 */
  HH ( c, d, a, b, in[15], S33, 0x1FA27CF8L); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 0xC4AC5665L); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 0xF4292244L); /* 49 */
  II ( d, a, b, c, in[ 7], S42, 0x432AFF97L); /* 50 */
  II ( c, d, a, b, in[14], S43, 0xAB9423A7L); /* 51 */
  II ( b, c, d, a, in[ 5], S44, 0xFC93A039L); /* 52 */
  II ( a, b, c, d, in[12], S41, 0x655B59C3L); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 0x8F0CCC92L); /* 54 */
  II ( c, d, a, b, in[10], S43, 0xFFEFF47DL); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 0x85845DD1L); /* 56 */
  II ( a, b, c, d, in[ 8], S41, 0x6FA87E4FL); /* 57 */
  II ( d, a, b, c, in[15], S42, 0xFE2CE6E0L); /* 58 */
  II ( c, d, a, b, in[ 6], S43, 0xA3014314L); /* 59 */
  II ( b, c, d, a, in[13], S44, 0x4E0811A1L); /* 60 */
  II ( a, b, c, d, in[ 4], S41, 0xF7537E82L); /* 61 */
  II ( d, a, b, c, in[11], S42, 0xBD3AF235L); /* 62 */
  II ( c, d, a, b, in[ 2], S43, 0x2AD7D2BBL); /* 63 */
  II ( b, c, d, a, in[ 9], S44, 0xEB86D391L); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}



/* end of file */
