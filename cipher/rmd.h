/* rmd.h - RIPE-MD hash functions
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
#ifndef G10_RMD_H
#define G10_RMD_H

#include "types.h"

typedef struct {
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    byte buffer[64];
    int  bufcount;
} *RMDHANDLE;


/****************
 * Process a single character, this character will be buffered to
 * increase performance.
 */
#define rmd160_putchar(h,c)				    \
	    do {					    \
		if( (h)->bufcount == 64 )		    \
		    rmd160_write( (h), NULL, 0 );	    \
		(h)->buffer[(h)->bufcount++] = (c) & 0xff;  \
	    } while(0)

RMDHANDLE rmd160_open( int secure );
RMDHANDLE rmd160_copy( RMDHANDLE a );
void	  rmd160_close(RMDHANDLE hd);
void	  rmd160_write( RMDHANDLE hd, byte *inbuf, size_t inlen);
byte *	  rmd160_final(RMDHANDLE hd);


#endif /*G10_RMD_H*/
