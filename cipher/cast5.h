/* cast5.h
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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
    u32  Km[16];
    byte Kr[16];
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
void cast5_sync_cfb( CAST5_context *c );


#endif /*G10_CAST5_H*/
