/* md.h - digest functions
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
#ifndef G10_MD_H
#define G10_MD_H

#include <stdio.h>
#include "types.h"
#include "rmd.h"
#include "sha1.h"
#include "md5.h"

#define MD_BUFFER_SIZE 512

typedef struct {
    int use_rmd160;
    RMD160_CONTEXT rmd160;
    int use_sha1;
    SHA1_CONTEXT sha1;
    int use_md5;
    MD5_CONTEXT md5;
    byte buffer[MD_BUFFER_SIZE]; /* primary buffer */
    int  bufcount;
    int  secure;
    FILE  *debug;
} *MD_HANDLE;


#define md_putc(h,c)					    \
	    do {					    \
		if( (h)->bufcount == MD_BUFFER_SIZE )	    \
		    md_write( (h), NULL, 0 );		    \
		(h)->buffer[(h)->bufcount++] = (c) & 0xff;  \
	    } while(0)

/*-- md.c --*/
MD_HANDLE md_open( int algo, int secure );
void md_enable( MD_HANDLE hd, int algo );
MD_HANDLE md_copy( MD_HANDLE a );
void md_close(MD_HANDLE a);
void md_write( MD_HANDLE a, byte *inbuf, size_t inlen);
void md_final(MD_HANDLE a);
byte *md_read( MD_HANDLE a, int algo );
int md_get_algo( MD_HANDLE a );
const byte *md_asn_oid( int algo, size_t *asnlen, size_t *mdlen );
#define md_is_secure(a) ((a)->secure)

#endif /*G10_MD_H*/
