/* md.c  -  message digest dispatcher
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "util.h"
#include "cipher.h"
#include "errors.h"

/****************
 * Open a message digest handle for use with algorithm ALGO.
 * More algorithms may be added by md_enable(). The initial algorithm
 * may be 0.
 */
MD_HANDLE
md_open( int algo, int secure )
{
    MD_HANDLE hd;

    hd = secure ? m_alloc_secure_clear( sizeof *hd )
		: m_alloc_clear( sizeof *hd );
    hd->secure = secure;
    if( algo )
	md_enable( hd, algo );
    fast_random_poll();
    return hd;
}

void
md_enable( MD_HANDLE h, int algo )
{
    if( algo == DIGEST_ALGO_MD5 ) {
	if( !h->use_md5 )
	    md5_init( &h->md5 );
	h->use_md5 = 1;
    }
    else if( algo == DIGEST_ALGO_RMD160 ) {
	if( !h->use_rmd160 )
	    rmd160_init( &h->rmd160 );
	h->use_rmd160 = 1;
    }
    else if( algo == DIGEST_ALGO_SHA1 ) {
	if( !h->use_sha1 )
	    sha1_init( &h->sha1 );
	h->use_sha1 = 1;
    }
    else
	log_bug("md_enable(%d)", algo );
}


MD_HANDLE
md_copy( MD_HANDLE a )
{
    MD_HANDLE b;

    b = a->secure ? m_alloc_secure( sizeof *b )
		  : m_alloc( sizeof *b );
    memcpy( b, a, sizeof *a );
    return b;
}


void
md_close(MD_HANDLE a)
{
    if( !a )
	return;
    m_free(a);
}


void
md_write( MD_HANDLE a, byte *inbuf, size_t inlen)
{
    if( a->debug ) {
	if( a->bufcount && fwrite(a->buffer, a->bufcount, 1, a->debug ) != 1 )
	    BUG();
	if( inlen && fwrite(inbuf, inlen, 1, a->debug ) != 1 )
	    BUG();
    }
    if( a->use_rmd160 ) {
	rmd160_write( &a->rmd160, a->buffer, a->bufcount );
	rmd160_write( &a->rmd160, inbuf, inlen	);
    }
    if( a->use_sha1 ) {
	sha1_write( &a->sha1, a->buffer, a->bufcount );
	sha1_write( &a->sha1, inbuf, inlen  );
    }
    if( a->use_md5 ) {
	md5_write( &a->md5, a->buffer, a->bufcount );
	md5_write( &a->md5, inbuf, inlen  );
    }
    a->bufcount = 0;
}



void
md_final(MD_HANDLE a)
{
    if( a->bufcount )
	md_write( a, NULL, 0 );
    if( a->use_rmd160 ) {
	byte *p;
	rmd160_final( &a->rmd160 );
	p = rmd160_read( &a->rmd160 );
    }
    if( a->use_sha1 )
	sha1_final( &a->sha1 );
    if( a->use_md5 )
	md5_final( &a->md5 );
}


/****************
 * if ALGO is null get the digest for the used algo (which should be only one)
 */
byte *
md_read( MD_HANDLE a, int algo )
{
    if( !algo ) {
	if( a->use_rmd160 )
	    return rmd160_read( &a->rmd160 );
	if( a->use_sha1 )
	    return sha1_read( &a->sha1 );
	if( a->use_md5 )
	    return md5_read( &a->md5 );
    }
    else {
	if( algo == DIGEST_ALGO_RMD160 )
	    return rmd160_read( &a->rmd160 );
	if( algo == DIGEST_ALGO_SHA1 )
	    return sha1_read( &a->sha1 );
	if( algo == DIGEST_ALGO_MD5 )
	    return md5_read( &a->md5 );
    }
    BUG();
}

int
md_get_algo( MD_HANDLE a )
{
    if( a->use_rmd160 )
	return DIGEST_ALGO_RMD160;
    if( a->use_sha1 )
	return DIGEST_ALGO_SHA1;
    if( a->use_md5 )
	return DIGEST_ALGO_MD5;
    return 0;
}

/****************
 * Return the length of the digest
 */
int
md_digest_length( int algo )
{
    switch( algo ) {
      case DIGEST_ALGO_RMD160:
      case DIGEST_ALGO_SHA1:
	return 20;
      default:
	return 16;
    }
}


const byte *
md_asn_oid( int algo, size_t *asnlen, size_t *mdlen )
{
    size_t alen, mlen;
    byte *p;

    if( algo == DIGEST_ALGO_MD5 ) {
	static byte asn[18] = /* Object ID is 1.2.840.113549.2.5 */
		    { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,0x48,
		      0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
	mlen = 16; alen = DIM(asn); p = asn;
    }
    else if( algo == DIGEST_ALGO_RMD160 ) {
	static byte asn[15] = /* Object ID is 1.3.36.3.2.1 */
	  { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03,
	    0x02, 0x01, 0x05, 0x00, 0x04, 0x14 };
	mlen = 20; alen = DIM(asn); p = asn;
    }
    else if( algo == DIGEST_ALGO_SHA1 ) {
	static byte asn[15] = /* Objet ID is 1.3.14.3.2.26 */
		    { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
		      0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
	mlen = 20; alen = DIM(asn); p = asn;
    }
    else
	log_bug("md_asn_oid(%d)", algo );

    if( asnlen )
	*asnlen = alen;
    if( mdlen )
	*mdlen = mlen;
    return p;
}


