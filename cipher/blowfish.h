/* blowfish.h
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
#ifndef G10_BLOWFISH_H
#define G10_BLOWFISH_H

#include "types.h"

#define BLOWFISH_BLOCKSIZE 8
#define BLOWFISH_ROUNDS 16

typedef struct {
    u32 s0[256];
    u32 s1[256];
    u32 s2[256];
    u32 s3[256];
    u32 p[BLOWFISH_ROUNDS+2];
    byte iv[BLOWFISH_BLOCKSIZE];
    byte eniv[BLOWFISH_BLOCKSIZE];
    int  count;
} BLOWFISH_context;

void blowfish_setkey( BLOWFISH_context *c, byte *key, unsigned keylen );
void blowfish_setiv( BLOWFISH_context *c, byte *iv );
void blowfish_encode( BLOWFISH_context *c, byte *outbuf, byte *inbuf,
						    unsigned nblocks );
void blowfish_decode( BLOWFISH_context *c, byte *outbuf, byte *inbuf,
						    unsigned nblocks );
void blowfish_encode_cfb( BLOWFISH_context *c, byte *outbuf,
					 byte *inbuf, unsigned nbytes);
void blowfish_decode_cfb( BLOWFISH_context *c, byte *outbuf,
					 byte *inbuf, unsigned nbytes);


#endif /*G10_BLOWFISH_H*/
