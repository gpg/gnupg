/* gost.h
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
#ifndef G10_GOST_H
#define G10_GOST_H

#include "types.h"

#define GOST_KEYSIZE 16
#define GOST_BLOCKSIZE 8
#define GOST_ROUNDS 8
#define GOST_KEYLEN (6*GOST_ROUNDS+4)

typedef struct {
    u16 ek[GOST_KEYLEN];
    u16 dk[GOST_KEYLEN];
    byte iv[GOST_BLOCKSIZE];
} GOST_context;

void gost_setkey( GOST_context *c, byte *key );
void gost_setiv( GOST_context *c, byte *iv );
void gost_encode( GOST_context *c, byte *out, byte *in, unsigned nblocks );
void gost_decode( GOST_context *c, byte *out, byte *in, unsigned nblocks );
void gost_encode_cfb( GOST_context *c, byte *outbuf,
				       byte *inbuf, unsigned nbytes);
void gost_decode_cfb( GOST_context *c, byte *outbuf,
				       byte *inbuf, unsigned nbytes);


#endif /*G10_GOST_H*/
