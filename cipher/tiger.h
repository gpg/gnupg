/* tiger.h  - TIGER hash function
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
#ifndef G10_TIGER_H
#define G10_TIGER_H

#include "types.h"

#ifdef HAVE_U64_TYPEDEF

#define WITH_TIGER_HASH 1

typedef struct {
    u64  a, b, c;
    u32  nblocks;
    byte buf[64];
    int  count;
} TIGER_CONTEXT;


void tiger_init( TIGER_CONTEXT *c );
void tiger_write( TIGER_CONTEXT *hd, byte *inbuf, size_t inlen);
void tiger_final(TIGER_CONTEXT *hd);
#define tiger_read(h) ( (h)->buf )

#endif /* HAVE_TIGER_HASH */

#endif /*G10_TIGER_H*/
