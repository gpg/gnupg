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
	lowbits = mpi_get_keyid( skc->d.elg.y, keyid );
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
	lowbits = mpi_get_keyid( pkc->d.elg.y, keyid );
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
    size_t len;
    unsigned n;

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	RMDHANDLE md;
	const char *dp;

	md = rmd160_open(0);

	{   u32 a = pkc->timestamp;
	    rmd160_putchar( md, a >> 24 );
	    rmd160_putchar( md, a >> 16 );
	    rmd160_putchar( md, a >>  8 );
	    rmd160_putchar( md, a	);
	}
	{   u16 a = pkc->valid_days;
	    rmd160_putchar( md, a >> 8 );
	    rmd160_putchar( md, a      );
	}
	rmd160_putchar( md, pkc->pubkey_algo );
	p = buf = mpi_get_buffer( pkc->d.elg.p, &n, NULL );
	for( ; !*p && n; p++, n-- )
	    ;
	rmd160_putchar( md, n>>8); rmd160_putchar( md, n ); rmd160_write( md, p, n );
	m_free(buf);
	p = buf = mpi_get_buffer( pkc->d.elg.g, &n, NULL );
	for( ; !*p && n; p++, n-- )
	    ;
	rmd160_putchar( md, n>>8); rmd160_putchar( md, n ); rmd160_write( md, p, n );
	m_free(buf);
	p = buf = mpi_get_buffer( pkc->d.elg.y, &n, NULL );
	for( ; !*p && n; p++, n-- )
	    ;
	rmd160_putchar( md, n>>8); rmd160_putchar( md, n ); rmd160_write( md, p, n );
	m_free(buf);

	dp = rmd160_final(md);
	array = m_alloc( 20 );
	len = 20;
	memcpy(array, dp, 20 );
	rmd160_close(md);
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	MD5HANDLE md;

	md = md5_open(0);
	p = buf = mpi_get_buffer( pkc->d.rsa.rsa_n, &n, NULL );
	for( ; !*p && n; p++, n-- )
	    ;
	md5_write( md, p, n );
	m_free(buf);
	p = buf = mpi_get_buffer( pkc->d.rsa.rsa_e, &n, NULL );
	for( ; !*p && n; p++, n-- )
	    ;
	md5_write( md, p, n );
	m_free(buf);
	md5_final(md);
	array = m_alloc( 16 );
	len = 16;
	memcpy(array, md5_read(md), 16 );
	md5_close(md);
    }
    else {
	array = m_alloc(1);
	len = 0; /* ooops */
    }

    *ret_len = len;
    return array;
}



