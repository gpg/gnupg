/* md.c  -  message digest dispatcher
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "util.h"
#include "cipher.h"
#include "errors.h"

int
md_okay( int algo )
{
    switch( algo ) {
      case DIGEST_ALGO_MD5:
      case DIGEST_ALGO_RMD160:
	return 0;
      default:
	return G10ERR_DIGEST_ALGO;
    }
}


MD_HANDLE *
md_open( int algo, int secure )
{
    MD_HANDLE *hd;

    hd = m_alloc( sizeof *hd + 19 );
    hd->algo = algo;
    hd->datalen = 0;
    if( algo == DIGEST_ALGO_MD5 )
	hd->u.md5 = md5_open( secure );
    else if( algo == DIGEST_ALGO_RMD160 )
	hd->u.rmd= rmd160_open( secure );
    else
	return NULL;

    return hd;
}


MD_HANDLE *
md_copy( MD_HANDLE *a )
{
    MD_HANDLE *hd;

    hd = m_alloc( sizeof *hd + 19 );
    hd->algo = a->algo;
    hd->datalen = 0;
    if( a->algo == DIGEST_ALGO_MD5 )
	hd->u.md5 = md5_copy( a->u.md5 );
    else if( a->algo == DIGEST_ALGO_RMD160 )
	hd->u.rmd= rmd160_copy( a->u.rmd );
    else
	log_bug(NULL);
    return hd;
}


/* used for a BAD Kludge in rmd160.c, md5.c  */
MD_HANDLE *
md_makecontainer( int algo )
{
    MD_HANDLE *hd;

    hd = m_alloc( sizeof *hd + 19 );
    hd->algo = algo;
    hd->datalen = 0;
    if( algo == DIGEST_ALGO_MD5 )
	;
    else if( algo == DIGEST_ALGO_RMD160 )
	;
    else
	log_bug(NULL);
    return hd;
}

void
md_close(MD_HANDLE *a)
{
    if( !a )
	return;
    if( a->algo == DIGEST_ALGO_MD5 )
	md5_close( a->u.md5 );
    else if( a->algo == DIGEST_ALGO_RMD160 )
	rmd160_close( a->u.rmd );
    else
	log_bug(NULL);
    m_free(a);
}


void
md_write( MD_HANDLE *a, byte *inbuf, size_t inlen)
{
    if( a->algo == DIGEST_ALGO_MD5 )
	md5_write( a->u.md5, inbuf, inlen );
    else if( a->algo == DIGEST_ALGO_RMD160 )
	rmd160_write( a->u.rmd, inbuf, inlen  );
    else
	log_bug(NULL);
}


void
md_putchar( MD_HANDLE *a, int c )
{
    if( a->algo == DIGEST_ALGO_MD5 )
	md5_putchar( a->u.md5, c );
    else if( a->algo == DIGEST_ALGO_RMD160 )
	rmd160_putchar( a->u.rmd, c );
    else
	log_bug(NULL);
}


byte *
md_final(MD_HANDLE *a)
{
    if( a->algo == DIGEST_ALGO_MD5 ) {
	if( !a->datalen ) {
	    md5_final( a->u.md5 );
	    memcpy(a->data, md5_read( a->u.md5 ), 16);
	    a->datalen = 16;
	}
	return a->data;
    }
    else if( a->algo == DIGEST_ALGO_RMD160 ) {
	if( !a->datalen ) {
	    memcpy(a->data, rmd160_final( a->u.rmd  ), 20 );
	    a->datalen = 20;
	}
	return a->data;
    }
    else
	log_bug(NULL);
}


