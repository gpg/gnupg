/* blowfish.h
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
} BLOWFISH_context;

void blowfish_setkey( BLOWFISH_context *c, byte *key, unsigned keylen );
void blowfish_encrypt_block( BLOWFISH_context *bc, byte *outbuf, byte *inbuf );
void blowfish_decrypt_block( BLOWFISH_context *bc, byte *outbuf, byte *inbuf );

#endif /*G10_BLOWFISH_H*/
