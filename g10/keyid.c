/* keyid.c - jeyid and fingerprint handling
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
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
#include <gcrypt.h>
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
      case GCRY_PK_RSA: return 'R' ;
      case GCRY_PK_RSA_E:	return 'r' ;
      case GCRY_PK_RSA_S:	return 's' ;
      case GCRY_PK_ELG_E: return 'g';
      case GCRY_PK_ELG: return 'G' ;
      case GCRY_PK_DSA: return 'D' ;
      default: return '?';
    }
}


static GCRY_MD_HD
do_fingerprint_md( PKT_public_key *pk )
{
    GCRY_MD_HD md;
    unsigned n;
    unsigned nb[GNUPG_MAX_NPKEY];
    unsigned nn[GNUPG_MAX_NPKEY];
    byte *pp[GNUPG_MAX_NPKEY];
    int i;
    int npkey = pubkey_get_npkey( pk->pubkey_algo );

    md = gcry_md_open( pk->version < 4 ? GCRY_MD_RMD160 : GCRY_MD_SHA1, 0);
    if( !md )
	BUG();
    n = pk->version < 4 ? 8 : 6;
    for(i=0; i < npkey; i++ ) {
	nb[i] = mpi_get_nbits(pk->pkey[i]);
	pp[i] = mpi_get_buffer( pk->pkey[i], nn+i, NULL );
	n += 2 + nn[i];
    }

    gcry_md_putc( md, 0x99 );	  /* ctb */
    gcry_md_putc( md, n >> 8 );   /* 2 byte length header */
    gcry_md_putc( md, n );
    if( pk->version < 4 )
	gcry_md_putc( md, 3 );
    else
	gcry_md_putc( md, 4 );

    {	u32 a = pk->timestamp;
	gcry_md_putc( md, a >> 24 );
	gcry_md_putc( md, a >> 16 );
	gcry_md_putc( md, a >>	8 );
	gcry_md_putc( md, a	  );
    }
    if( pk->version < 4 ) {
	u16 a;

	if( pk->expiredate )
	    a = (u16)((pk->expiredate - pk->timestamp) / 86400L);
	else
	    a = 0;
	gcry_md_putc( md, a >> 8 );
	gcry_md_putc( md, a	 );
    }
    gcry_md_putc( md, pk->pubkey_algo );
    for(i=0; i < npkey; i++ ) {
	gcry_md_putc( md, nb[i]>>8);
	gcry_md_putc( md, nb[i] );
	gcry_md_write( md, pp[i], nn[i] );
	m_free(pp[i]);
    }
    gcry_md_final( md );

    return md;
}

static GCRY_MD_HD
do_fingerprint_md_sk( PKT_secret_key *sk )
{
    PKT_public_key pk;
    int npkey = pubkey_get_npkey( sk->pubkey_algo ); /* npkey is correct! */
    int i;

    pk.pubkey_algo = sk->pubkey_algo;
    pk.version	   = sk->version;
    pk.timestamp = sk->timestamp;
    pk.expiredate = sk->expiredate;
    pk.pubkey_algo = sk->pubkey_algo;
    for( i=0; i < npkey; i++ )
	pk.pkey[i] = sk->skey[i];
    return do_fingerprint_md( &pk );
}


/****************
 * Get the keyid from the secret key and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_sk( PKT_secret_key *sk, u32 *keyid )
{
    u32 lowbits;
    u32 dummy_keyid[2];

    if( !keyid )
	keyid = dummy_keyid;

    if( sk->version < 4 && is_RSA(sk->pubkey_algo) ) {
	lowbits = pubkey_get_npkey(sk->pubkey_algo) ?
		     mpi_get_keyid( sk->skey[0], keyid ) : 0; /* take n */
    }
    else {
	const byte *dp;
	GCRY_MD_HD md;
	md = do_fingerprint_md_sk(sk);
	dp = gcry_md_read( md, 0 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	gcry_md_close(md);
    }

    return lowbits;
}


/****************
 * Get the keyid from the public key and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_pk( PKT_public_key *pk, u32 *keyid )
{
    u32 lowbits;
    u32 dummy_keyid[2];

    if( !keyid )
	keyid = dummy_keyid;

    if( pk->keyid[0] || pk->keyid[1] ) {
	keyid[0] = pk->keyid[0];
	keyid[1] = pk->keyid[1];
	lowbits = keyid[1];
    }
    else if( pk->version < 4 && is_RSA(pk->pubkey_algo) ) {
	lowbits = pubkey_get_npkey(pk->pubkey_algo) ?
		     mpi_get_keyid( pk->pkey[0], keyid ) : 0 ; /* from n */
	pk->keyid[0] = keyid[0];
	pk->keyid[1] = keyid[1];
    }
    else {
	const byte *dp;
	GCRY_MD_HD md;
	md = do_fingerprint_md(pk);
	dp = gcry_md_read( md, 0 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	gcry_md_close(md);
	pk->keyid[0] = keyid[0];
	pk->keyid[1] = keyid[1];
    }

    return lowbits;
}


/****************
 * Get the keyid from the fingerprint.	This function is simple for most
 * keys, but has to do a keylookup for old stayle keys.
 */
u32
keyid_from_fingerprint( const byte *fprint, size_t fprint_len, u32 *keyid )
{
    u32 dummy_keyid[2];

    if( !keyid )
	keyid = dummy_keyid;

    if( fprint_len != 20 ) {
	/* This is special as we have to lookup the key first */
	PKT_public_key pk;
	int rc;

	memset( &pk, 0, sizeof pk );
	rc = get_pubkey_byfprint( &pk, fprint, fprint_len );
	if( rc ) {
	    log_error("Oops: keyid_from_fingerprint: no pubkey\n");
	    keyid[0] = 0;
	    keyid[1] = 0;
	}
	else
	    keyid_from_pk( &pk, keyid );
    }
    else {
	const byte *dp = fprint;
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
    }

    return keyid[1];
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
 * return the number of bits used in the pk
 */
unsigned
nbits_from_pk( PKT_public_key *pk )
{
    return pubkey_nbits( pk->pubkey_algo, pk->pkey );
}

/****************
 * return the number of bits used in the sk
 */
unsigned
nbits_from_sk( PKT_secret_key *sk )
{
    return pubkey_nbits( sk->pubkey_algo, sk->skey );
}

/****************
 * return a string with the creation date of the pk
 * Note: this is alloced in a static buffer.
 *    Format is: yyyy-mm-dd
 */
const char *
datestr_from_pk( PKT_public_key *pk )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime = pk->timestamp;

    tp = gmtime( &atime );
    sprintf(buffer,"%04d-%02d-%02d", 1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    return buffer;
}

const char *
datestr_from_sk( PKT_secret_key *sk )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime = sk->timestamp;

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


const char *
expirestr_from_pk( PKT_public_key *pk )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime;

    if( !pk->expiredate )
	return "never     ";
    atime = pk->expiredate;
    tp = gmtime( &atime );
    sprintf(buffer,"%04d-%02d-%02d", 1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    return buffer;
}

const char *
expirestr_from_sk( PKT_secret_key *sk )
{
    static char buffer[11+5];
    struct tm *tp;
    time_t atime;

    if( !sk->expiredate )
	return "never     ";
    atime = sk->expiredate;
    tp = gmtime( &atime );
    sprintf(buffer,"%04d-%02d-%02d", 1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    return buffer;
}


/**************** .
 * Return a byte array with the fingerprint for the given PK/SK
 * The length of the array is returned in ret_len. Caller must free
 * the array or provide an array of length MAX_FINGERPRINT_LEN.
 */

byte *
fingerprint_from_pk( PKT_public_key *pk, byte *array, size_t *ret_len )
{
    byte *p, *buf;
    const char *dp;
    size_t len;
    unsigned n;

    if( pk->version < 4 && is_RSA(pk->pubkey_algo) ) {
	/* RSA in version 3 packets is special */
	GCRY_MD_HD md;

	md = gcry_md_open( DIGEST_ALGO_MD5, 0);
	if( !md )
	    BUG();
	if( pubkey_get_npkey( pk->pubkey_algo ) > 1 ) {
	    p = buf = mpi_get_buffer( pk->pkey[0], &n, NULL );
	    gcry_md_write( md, p, n );
	    m_free(buf);
	    p = buf = mpi_get_buffer( pk->pkey[1], &n, NULL );
	    gcry_md_write( md, p, n );
	    m_free(buf);
	}
	gcry_md_final(md);
	if( !array )
	    array = m_alloc( 16 );
	len = 16;
	memcpy(array, gcry_md_read(md, DIGEST_ALGO_MD5), 16 );
	gcry_md_close(md);
    }
    else {
	GCRY_MD_HD md;
	md = do_fingerprint_md(pk);
	dp = gcry_md_read( md, 0 );
	len = gcry_md_get_algo_dlen( gcry_md_get_algo( md ) );
	assert( len <= MAX_FINGERPRINT_LEN );
	if( !array )
	    array = m_alloc( len );
	memcpy(array, dp, len );
	gcry_md_close(md);
    }

    *ret_len = len;
    return array;
}

byte *
fingerprint_from_sk( PKT_secret_key *sk, byte *array, size_t *ret_len )
{
    byte *p, *buf;
    const char *dp;
    size_t len;
    unsigned n;

    if( sk->version < 4 && is_RSA(sk->pubkey_algo) ) {
	/* RSA in version 3 packets is special */
	GCRY_MD_HD md;

	md = gcry_md_open( DIGEST_ALGO_MD5, 0);
	if( !md )
	    BUG();
	if( pubkey_get_npkey( sk->pubkey_algo ) > 1 ) {
	    p = buf = mpi_get_buffer( sk->skey[1], &n, NULL );
	    gcry_md_write( md, p, n );
	    m_free(buf);
	    p = buf = mpi_get_buffer( sk->skey[0], &n, NULL );
	    gcry_md_write( md, p, n );
	    m_free(buf);
	}
	gcry_md_final(md);
	if( !array )
	    array = m_alloc( 16 );
	len = 16;
	memcpy(array, gcry_md_read(md, GCRY_MD_MD5), 16 );
	gcry_md_close(md);
    }
    else {
	GCRY_MD_HD md;
	md = do_fingerprint_md_sk(sk);
	dp = gcry_md_read( md, 0 );
	len = gcry_md_get_algo_dlen( gcry_md_get_algo( md ) );
	assert( len <= MAX_FINGERPRINT_LEN );
	if( !array )
	    array = m_alloc( len );
	memcpy(array, dp, len );
	gcry_md_close(md);
    }

    *ret_len = len;
    return array;
}



