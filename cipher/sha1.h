/* sha1.h - SHA1 hash function
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
#ifndef G10_SHA1_H
#define G10_SHA1_H

#include "types.h"

typedef struct {
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    byte buffer[64];
    int  bufcount;
} *SHA1HANDLE;


/****************
 * Process a single character, this character will be buffered to
 * increase performance.
 */
#define sha1_putchar(h,c)				    \
	    do {					    \
		if( (h)->bufcount == 64 )		    \
		    sha1_write( (h), NULL, 0 ); 	    \
		(h)->buffer[(h)->bufcount++] = (c) & 0xff;  \
	    } while(0)

SHA1HANDLE sha1_open( int secure );
SHA1HANDLE sha1_copy( SHA1HANDLE a );
void	   sha1_close( SHA1HANDLE hd );
void	   sha1_write( SHA1HANDLE hd, byte *inbuf, size_t inlen );
byte *	   sha1_final( SHA1HANDLE hd );

#endif /*G10_SHA1_H*/
