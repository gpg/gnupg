/* idea.h
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * ATTENTION: This code patented and needs a license for any commercial use.
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
#ifndef G10_IDEA_H
#define G10_IDEA_H

#include "types.h"

#define IDEA_KEYSIZE 16
#define IDEA_BLOCKSIZE 8
#define IDEA_ROUNDS 8
#define IDEA_KEYLEN (6*IDEA_ROUNDS+4)

typedef struct {
    u16 ek[IDEA_KEYLEN];
    u16 dk[IDEA_KEYLEN];
    byte iv[IDEA_BLOCKSIZE];
    byte lastcipher[IDEA_BLOCKSIZE];
    int  nleft;
} IDEA_context;

void idea_setkey( IDEA_context *c, byte *key );
void idea_setiv( IDEA_context *c, byte *iv );
void idea_encode( IDEA_context *c, byte *out, byte *in, unsigned nblocks );
void idea_decode( IDEA_context *c, byte *out, byte *in, unsigned nblocks );
void idea_encode_cfb( IDEA_context *c, byte *outbuf,
				       byte *inbuf, unsigned nbytes);
void idea_decode_cfb( IDEA_context *c, byte *outbuf,
				       byte *inbuf, unsigned nbytes);
void idea_sync_cfb( IDEA_context *c );


#endif /*G10_IDEA_H*/
