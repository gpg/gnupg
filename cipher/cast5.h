/* cast5.h
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
#ifndef G10_CAST5_H
#define G10_CAST5_H

#include "types.h"

#define CAST5_BLOCKSIZE 8

typedef struct {
    u32 s0[256];
    u32 s1[256];
    u32 s2[256];
    u32 s3[256];
    u32 p[16+2];
    byte iv[CAST5_BLOCKSIZE];
    byte eniv[CAST5_BLOCKSIZE];
    int  count;
} CAST5_context;

void cast5_setkey( CAST5_context *c, byte *key, unsigned keylen );
void cast5_setiv( CAST5_context *c, byte *iv );
void cast5_encode( CAST5_context *c, byte *outbuf, byte *inbuf,
						    unsigned nblocks );
void cast5_decode( CAST5_context *c, byte *outbuf, byte *inbuf,
						    unsigned nblocks );
void cast5_encode_cfb( CAST5_context *c, byte *outbuf,
					 byte *inbuf, unsigned nbytes);
void cast5_decode_cfb( CAST5_context *c, byte *outbuf,
					 byte *inbuf, unsigned nbytes);


#endif /*G10_CAST5_H*/
