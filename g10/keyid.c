/* keyid.c - jeyid and fingerprint handling
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
      case PUBKEY_ALGO_ELGAMAL: return 'G' ;
      case PUBKEY_ALGO_DSA:	return 'D' ;
      default: return '?';
    }
}

/* this is special code for V3 which uses ElGamal and
 * calculates a fingerprint like V4, but with rmd160
 * and a version byte of 3. Returns an md handle, caller must
 * do md_close()
 */

static MD_HANDLE
v3_elg_fingerprint_md( PKT_public_cert *pkc )
{
    MD_HANDLE md;
    byte *buf1, *buf2, *buf3;
    byte *p1, *p2, *p3;
    unsigned n1, n2, n3;
    unsigned n;

    p1 = buf1 = mpi_get_buffer( pkc->d.elg.p, &n1, NULL );
    for( ; !*p1 && n1; p1++, n1-- )  /* skip leading null bytes */
	;
    p2 = buf2 = mpi_get_buffer( pkc->d.elg.g, &n2, NULL );
    for( ; !*p2 && n2; p2++, n2-- )  /* skip leading null bytes */
	;
    p3 = buf3 = mpi_get_buffer( pkc->d.elg.y, &n3, NULL );
    for( ; !*p3 && n3; p3++, n3-- )  /* skip leading null bytes */
	;

    /* calculate length of packet (1+4+2+1+2+n1+2+n2+2+n3) */
    n = 14 + n1 + n2 + n3;
    md = md_open( DIGEST_ALGO_RMD160, 0);

    md_putc( md, 0x99 );     /* ctb */
    md_putc( md, n >> 8 );   /* 2 byte length header */
    md_putc( md, n );
    md_putc( md, 3 );	     /* version */
    {	u32 a = pkc->timestamp;
	md_putc( md, a >> 24 );
	md_putc( md, a >> 16 );
	md_putc( md, a >>  8 );
	md_putc( md, a	     );
    }
    {	u16 a = pkc->valid_days;
	md_putc( md, a >> 8 );
	md_putc( md, a	    );
    }
    md_putc( md, pkc->pubkey_algo );
    md_putc( md, n1>>8); md_putc( md, n1 ); md_write( md, p1, n1 );
    md_putc( md, n2>>8); md_putc( md, n2 ); md_write( md, p2, n2 );
    md_putc( md, n3>>8); md_putc( md, n3 ); md_write( md, p3, n3 );
    m_free(buf1);
    m_free(buf2);
    m_free(buf3);
    md_final( md );

    return md;
}


static MD_HANDLE
v3_elg_fingerprint_md_skc( PKT_secret_cert *skc )
{
    PKT_public_cert pkc;
    byte *p;

    pkc.pubkey_algo = skc->pubkey_algo;
    pkc.timestamp = skc->timestamp;
    pkc.valid_days = skc->valid_days;
    pkc.pubkey_algo = skc->pubkey_algo;
    pkc.d.elg.p = skc->d.elg.p;
    pkc.d.elg.g = skc->d.elg.g;
    pkc.d.elg.y = skc->d.elg.y;
    return v3_elg_fingerprint_md( &pkc );
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

    if( skc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	const byte *dp;
	MD_HANDLE md;
	md = v3_elg_fingerprint_md_skc(skc);
	dp = md_read( md, DIGEST_ALGO_RMD160 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	md_close(md);
    }
    else if( skc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	lowbits = mpi_get_keyid( skc->d.rsa.rsa_n, keyid );
    }
    else {
	keyid[0] = keyid[1] = lowbits = 0;
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

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	const byte *dp;
	MD_HANDLE md;
	md = v3_elg_fingerprint_md(pkc);
	dp = md_read( md, DIGEST_ALGO_RMD160 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	md_close(md);
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	lowbits = mpi_get_keyid( pkc->d.rsa.rsa_n, keyid );
    }
    else {
	keyid[0] = keyid[1] = lowbits = 0;
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
    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	return mpi_get_nbits( pkc->d.elg.p );
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	return mpi_get_nbits( pkc->d.rsa.rsa_n );
    }
    else
	return 0;
}

/****************
 * return the number of bits used in the skc
 */
unsigned
nbits_from_skc( PKT_secret_cert *skc )
{
    if( skc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	return mpi_get_nbits( skc->d.elg.p );
    }
    else if( skc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	return mpi_get_nbits( skc->d.rsa.rsa_n );
    }
    else
	return 0;
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
fingerprint_from_skc( PKT_secret_cert *skc, size_t *ret_len )
{
    PKT_public_cert pkc;
    byte *p;

    pkc.pubkey_algo = skc->pubkey_algo;
    if( pkc.pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	pkc.timestamp = skc->timestamp;
	pkc.valid_days = skc->valid_days;
	pkc.pubkey_algo = skc->pubkey_algo;
	pkc.d.elg.p = skc->d.elg.p;
	pkc.d.elg.g = skc->d.elg.g;
	pkc.d.elg.y = skc->d.elg.y;
    }
    else if( pkc.pubkey_algo == PUBKEY_ALGO_RSA ) {
	pkc.d.rsa.rsa_n = skc->d.rsa.rsa_n;
	pkc.d.rsa.rsa_e = skc->d.rsa.rsa_e;
    }
    p = fingerprint_from_pkc( &pkc, ret_len );
    memset(&pkc, 0, sizeof pkc); /* not really needed */
    return p;
}




byte *
fingerprint_from_pkc( PKT_public_cert *pkc, size_t *ret_len )
{
    byte *p, *buf, *array;
    const char *dp;
    size_t len;
    unsigned n;

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	MD_HANDLE md;
	md = v3_elg_fingerprint_md(pkc);
	dp = md_read( md, DIGEST_ALGO_RMD160 );
	array = m_alloc( 20 );
	len = 20;
	memcpy(array, dp, 20 );
	md_close(md);
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	MD_HANDLE md;

	md = md_open( DIGEST_ALGO_MD5, 0);
	p = buf = mpi_get_buffer( pkc->d.rsa.rsa_n, &n, NULL );
	for( ; !*p && n; p++, n-- )
	    ;
	md_write( md, p, n );
	m_free(buf);
	p = buf = mpi_get_buffer( pkc->d.rsa.rsa_e, &n, NULL );
	for( ; !*p && n; p++, n-- )
	    ;
	md_write( md, p, n );
	m_free(buf);
	md_final(md);
	array = m_alloc( 16 );
	len = 16;
	memcpy(array, md_read(md, DIGEST_ALGO_MD5), 16 );
	md_close(md);
    }
    else {
	array = m_alloc(1);
	len = 0; /* ooops */
    }

    *ret_len = len;
    return array;
}



