/* des.h
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
#ifndef G10_DES_H
#define G10_DES_H

#include "types.h"

#define DES_BLOCKSIZE 8
#define DES_ROUNDS 16

typedef struct {
    int tripledes;
} DES_context;

void des_setkey( DES_context *c, byte *key, unsigned keylen );
void des_3des_setkey( DES_context *c, byte *key, unsigned keylen );
void des_encrypt_block( DES_context *bc, byte *outbuf, byte *inbuf );
void des_decrypt_block( DES_context *bc, byte *outbuf, byte *inbuf );

#endif /*G10_DES_H*/
