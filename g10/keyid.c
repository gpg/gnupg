/* keyid.c - jeyid and fingerprint handling
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
#include <time.h>
#include <assert.h>
#include "util.h"
#include "main.h"
#include "packet.h"
#include "options.h"
#include "mpi.h"
#include "keydb.h"


int
pubkey_letter( int algo )
{
    switch( algo ) {
      case PUBKEY_ALGO_RSA:	return 'R' ;
      case PUBKEY_ALGO_RSA_E:	return 'r' ;
      case PUBKEY_ALGO_RSA_S:	return 's' ;
      case PUBKEY_ALGO_ELGAMAL_E:
      case PUBKEY_ALGO_ELGAMAL: return 'G' ;
      case PUBKEY_ALGO_DSA:	return 'D' ;
      default: return '?';
    }
}


static MD_HANDLE
do_fingerprint_md( PKT_public_cert *pkc )
{
    MD_HANDLE md;
    unsigned n;
    unsigned nb[PUBKEY_MAX_NPKEY];
    unsigned nn[PUBKEY_MAX_NPKEY];
    byte *pp[PUBKEY_MAX_NPKEY];
    int i;
    int npkey = pubkey_get_npkey( pkc->pubkey_algo );

    md = md_open( pkc->version < 4 ? DIGEST_ALGO_RMD160 : DIGEST_ALGO_SHA1, 0);
    n = pkc->version < 4 ? 8 : 6;
    for(i=0; i < npkey; i++ ) {
	nb[i] = mpi_get_nbits(pkc->pkey[i]);
	pp[i] = mpi_get_buffer( pkc->pkey[i], nn+i, NULL );
	n += 2 + nn[i];
    }

    md_putc( md, 0x99 );     /* ctb */
    md_putc( md, n >> 8 );   /* 2 byte length header */
    md_putc( md, n );
    if( pkc->version < 4 )
	md_putc( md, 3 );
    else
	md_putc( md, 4 );

    {	u32 a = pkc->timestamp;
	md_putc( md, a >> 24 );
	md_putc( md, a >> 16 );
	md_putc( md, a >>  8 );
	md_putc( md, a	     );
    }
    if( pkc->version < 4 ) {
	u16 a = pkc->valid_days;
	md_putc( md, a >> 8 );
	md_putc( md, a	    );
    }
    md_putc( md, pkc->pubkey_algo );
    for(i=0; i < npkey; i++ ) {
	md_putc( md, nb[i]>>8);
	md_putc( md, nb[i] );
	md_write( md, pp[i], nn[i] );
	m_free(pp[i]);
    }
    md_final( md );

    return md;
}

static MD_HANDLE
do_fingerprint_md_skc( PKT_secret_cert *skc )
{
    PKT_public_cert pkc;
    int npkey = pubkey_get_npkey( skc->pubkey_algo ); /* npkey is correct! */
    int i;

    pkc.pubkey_algo = skc->pubkey_algo;
    pkc.version     = skc->version;
    pkc.timestamp = skc->timestamp;
    pkc.valid_days = skc->valid_days;
    pkc.pubkey_algo = skc->pubkey_algo;
    for( i=0; i < npkey; i++ )
	pkc.pkey[i] = skc->skey[i];
    return do_fingerprint_md( &pkc );
}


/****************
 * Get the keyid from the secret key certificate and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_skc( PKT_secret_cert *skc, u32 *keyid )
{
    u32 lowbits;
    u32 dummy_keyid[2];

    if( !keyid )
	keyid = dummy_keyid;

    if( skc->version < 4 && is_RSA(skc->pubkey_algo) ) {
	lowbits = mpi_get_keyid( skc->skey[0], keyid ); /* take n */
    }
    else {
	const byte *dp;
	MD_HANDLE md;
	md = do_fingerprint_md_skc(skc);
	dp = md_read( md, 0 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	md_close(md);
    }

    return lowbits;
}


/****************
 * Get the keyid from the public key certificate and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_pkc( PKT_public_cert *pkc, u32 *keyid )
{
    u32 lowbits;
    u32 dummy_keyid[2];

    if( !keyid )
	keyid = dummy_keyid;

    if( pkc->version < 4 && is_RSA(pkc->pubkey_algo) ) {
	lowbits = mpi_get_keyid( pkc->pkey[0], keyid ); /* from n */
    }
    else {
	const byte *dp;
	MD_HANDLE md;
	md = do_fingerprint_md(pkc);
	dp = md_read( md, 0 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	md_close(md);
    }

    return lowbits;
}


u32
keyid_from_sig( PKT_signature *sig, u32 *keyid )
{
    if( keyid ) {
	keyid[0] = sig->keyid[0];
	keyid[1] = sig->keyid[1];
    }
    return sig->keyid[1];
}

/****************
 * return the number of bits used in the pkc
 */
unsigned
nbits_from_pkc( PKT_public_cert *pkc )
{
    return pubkey_nbits( pkc->pubkey_algo, pkc->pkey );
}

/****************
 * return the number of bits used in the skc
 */
unsigned
nbits_from_skc( PKT_secret_cert *skc )
{
    return pubkey_nbits( skc->pubkey_algo, skc->skey );
}

/****************
 * return a string with the creation date of the pkc
 * Note: this is alloced in a static buffer.
 *    Format is: yyyy-mm-dd
 */
const char *
datestr_from_pkc( PKT_public_cert *pkc )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime = pkc->timestamp;

    tp = gmtime( &atime );
    sprintf(buffer,"%04d-%02d-%02d", 1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    return buffer;
}

const char *
datestr_from_skc( PKT_secret_cert *skc )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime = skc->timestamp;

    tp = gmtime( &atime );
    sprintf(buffer,"%04d-%02d-%02d", 1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    return buffer;
}

const char *
datestr_from_sig( PKT_signature *sig )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime = sig->timestamp;

    tp = gmtime( &atime );
    sprintf(buffer,"%04d-%02d-%02d", 1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    return buffer;
}


/**************** .
 * Return a byte array with the fingerprint for the given PKC/SKC
 * The length of the array is returned in ret_len. Caller must free
 * the array.
 */



byte *
fingerprint_from_pkc( PKT_public_cert *pkc, size_t *ret_len )
{
    byte *p, *buf, *array;
    const char *dp;
    size_t len;
    unsigned n;

    if( pkc->version < 4 && is_RSA(pkc->pubkey_algo) ) {
	/* RSA in version 3 packets is special */
	MD_HANDLE md;

	md = md_open( DIGEST_ALGO_MD5, 0);
	p = buf = mpi_get_buffer( pkc->pkey[0], &n, NULL );
	md_write( md, p, n );
	m_free(buf);
	p = buf = mpi_get_buffer( pkc->pkey[1], &n, NULL );
	md_write( md, p, n );
	m_free(buf);
	md_final(md);
	array = m_alloc( 16 );
	len = 16;
	memcpy(array, md_read(md, DIGEST_ALGO_MD5), 16 );
	md_close(md);
    }
    else {
	MD_HANDLE md;
	md = do_fingerprint_md(pkc);
	dp = md_read( md, 0 );
	len = md_digest_length( md_get_algo( md ) );
	array = m_alloc( len );
	memcpy(array, dp, len );
	md_close(md);
    }

    *ret_len = len;
    return array;
}

byte *
fingerprint_from_skc( PKT_secret_cert *skc, size_t *ret_len )
{
    byte *p, *buf, *array;
    const char *dp;
    size_t len;
    unsigned n;

    if( skc->version < 4 && is_RSA(skc->pubkey_algo) ) {
	/* RSA in version 3 packets is special */
	MD_HANDLE md;

	md = md_open( DIGEST_ALGO_MD5, 0);
	p = buf = mpi_get_buffer( skc->skey[1], &n, NULL );
	md_write( md, p, n );
	m_free(buf);
	p = buf = mpi_get_buffer( skc->skey[0], &n, NULL );
	md_write( md, p, n );
	m_free(buf);
	md_final(md);
	array = m_alloc( 16 );
	len = 16;
	memcpy(array, md_read(md, DIGEST_ALGO_MD5), 16 );
	md_close(md);
    }
    else {
	MD_HANDLE md;
	md = do_fingerprint_md_skc(skc);
	dp = md_read( md, 0 );
	len = md_digest_length( md_get_algo( md ) );
	array = m_alloc( len );
	memcpy(array, dp, len );
	md_close(md);
    }

    *ret_len = len;
    return array;
}



