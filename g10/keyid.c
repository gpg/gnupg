/* keyid.c - key ID and fingerprint handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
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

#include "gpg.h"
#include "util.h"
#include "main.h"
#include "packet.h"
#include "options.h"
#include "mpi.h"
#include "keydb.h"
#include "i18n.h"


int
pubkey_letter( int algo )
{
    switch( algo ) {
      case PUBKEY_ALGO_RSA:	return 'R' ;
      case PUBKEY_ALGO_RSA_E:	return 'r' ;
      case PUBKEY_ALGO_RSA_S:	return 's' ;
      case PUBKEY_ALGO_ELGAMAL_E: return 'g';
      case PUBKEY_ALGO_ELGAMAL: return 'G' ;
      case PUBKEY_ALGO_DSA:	return 'D' ;
      default: return '?';
    }
}

static gcry_md_hd_t
do_fingerprint_md( PKT_public_key *pk )
{
    gcry_md_hd_t md;
    unsigned int n;
    unsigned int nn[PUBKEY_MAX_NPKEY];
    byte *pp[PUBKEY_MAX_NPKEY];
    int i;
    int npkey = pubkey_get_npkey( pk->pubkey_algo );

    gcry_md_open (&md, pk->version < 4 ? DIGEST_ALGO_RMD160
                                       : DIGEST_ALGO_SHA1, 0);
    n = pk->version < 4 ? 8 : 6;
    for(i=0; i < npkey; i++ ) {
	size_t nbytes;

	if (gcry_mpi_print( GCRYMPI_FMT_PGP, NULL, &nbytes, pk->pkey[i] ))
          BUG ();
	/* fixme: we should try to allocate a buffer on the stack */
	pp[i] = xmalloc(nbytes);
	if (gcry_mpi_print ( GCRYMPI_FMT_PGP, pp[i], &nbytes, pk->pkey[i] ))
          BUG ();
	nn[i] = nbytes;
	n += nn[i];
    }

    gcry_md_putc ( md, 0x99 );     /* ctb */
    gcry_md_putc ( md, n >> 8 );   /* 2 byte length header */
    gcry_md_putc ( md, n );
    if( pk->version < 4 )
	gcry_md_putc ( md, 3 );
    else
	gcry_md_putc ( md, 4 );

    {	u32 a = pk->timestamp;
	gcry_md_putc ( md, a >> 24 );
	gcry_md_putc ( md, a >> 16 );
	gcry_md_putc ( md, a >>  8 );
	gcry_md_putc ( md, a	     );
    }
    if( pk->version < 4 ) {
	u16 a;

	if( pk->expiredate )
	    a = (u16)((pk->expiredate - pk->timestamp) / 86400L);
	else
	    a = 0;
	gcry_md_putc ( md, a >> 8 );
	gcry_md_putc ( md, a	    );
    }
    gcry_md_putc ( md, pk->pubkey_algo );
    for(i=0; i < npkey; i++ ) {
	gcry_md_write( md, pp[i], nn[i] );
	xfree (pp[i]);
    }
    gcry_md_final ( md );

    return md;
}

static gcry_md_hd_t
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


u32
v3_keyid (gcry_mpi_t a, u32 *ki)
{
  byte *buffer;
  size_t nbytes;

  if (gcry_mpi_print (GCRYMPI_FMT_USG, NULL, &nbytes, a ))
    BUG ();
  /* fixme: allocate it on the stack */
  buffer = xmalloc (nbytes);
  if (gcry_mpi_print( GCRYMPI_FMT_USG, buffer, &nbytes, a ))
    BUG ();
  if (nbytes < 8) /* oops */
    ki[0] = ki[1] = 0;
  else 
    {
      memcpy (ki+0, buffer+nbytes-8, 4);
      memcpy (ki+1, buffer+nbytes-4, 4);
    }
  xfree (buffer);
  return ki[1];
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
        keyid[0] = keyid[1] = 0;
	lowbits = pubkey_get_npkey(sk->pubkey_algo) ?
		     v3_keyid (sk->skey[0], keyid) : 0; 
    }
    else {
	const byte *dp;
	gcry_md_hd_t md;
	md = do_fingerprint_md_sk(sk);
	dp = gcry_md_read ( md, 0 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	gcry_md_close (md);
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
        keyid[0] = keyid[1] = 0;
	lowbits = pubkey_get_npkey(pk->pubkey_algo) ?
		     v3_keyid (pk->pkey[0], keyid) : 0 ; 
	pk->keyid[0] = keyid[0];
	pk->keyid[1] = keyid[1];
    }
    else {
	const byte *dp;
	gcry_md_hd_t md;
	md = do_fingerprint_md(pk);
	dp = gcry_md_read ( md, 0 );
	keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	lowbits = keyid[1];
	gcry_md_close (md);
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

byte *
namehash_from_uid(PKT_user_id *uid)
{
  if(uid->namehash==NULL)
    {
      uid->namehash=xmalloc (20);

      if(uid->attrib_data)
        gcry_md_hash_buffer (GCRY_MD_RMD160, uid->namehash,
                             uid->attrib_data,uid->attrib_len);
      else
	gcry_md_hash_buffer (GCRY_MD_RMD160, uid->namehash,
                             uid->name,uid->len);
    }

  return uid->namehash;
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

static const char *
mk_datestr (char *buffer, time_t atime)
{
    struct tm *tp;

    if ( atime < 0 ) /* 32 bit time_t and after 2038-01-19 */
        strcpy (buffer, "????" "-??" "-??"); /* mark this as invalid */
    else {
        tp = gmtime (&atime);
        sprintf (buffer,"%04d-%02d-%02d",
                 1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    }
    return buffer;
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
    time_t atime = pk->timestamp;

    return mk_datestr (buffer, atime);
}

const char *
datestr_from_sk( PKT_secret_key *sk )
{
    static char buffer[11+5];
    time_t atime = sk->timestamp;

    return mk_datestr (buffer, atime);
}

const char *
datestr_from_sig( PKT_signature *sig )
{
    static char buffer[11+5];
    time_t atime = sig->timestamp;

    return mk_datestr (buffer, atime);
}

const char *
expirestr_from_pk( PKT_public_key *pk )
{
    static char buffer[11+5];
    time_t atime;

    if( !pk->expiredate )
	return _("never     ");
    atime = pk->expiredate;
    return mk_datestr (buffer, atime);
}

const char *
expirestr_from_sk( PKT_secret_key *sk )
{
    static char buffer[11+5];
    time_t atime;

    if( !sk->expiredate )
	return _("never     ");
    atime = sk->expiredate;
    return mk_datestr (buffer, atime);
}

const char *
expirestr_from_sig( PKT_signature *sig )
{
    static char buffer[11+5];
    time_t atime;

    if(!sig->expiredate)
      return _("never     ");
    atime=sig->expiredate;
    return mk_datestr (buffer, atime);
}

const char *
colon_strtime (u32 t)
{
    if (!t)
        return "";
    if (opt.fixed_list_mode) {
        static char buf[15];
        sprintf (buf, "%lu", (ulong)t);
        return buf;
    }
    return strtimestamp(t);
}

const char *
colon_datestr_from_pk (PKT_public_key *pk)
{
    if (opt.fixed_list_mode) {
        static char buf[15];
        sprintf (buf, "%lu", (ulong)pk->timestamp);
        return buf;
    }
    return datestr_from_pk (pk);
}

const char *
colon_datestr_from_sk (PKT_secret_key *sk)
{
    if (opt.fixed_list_mode) {
        static char buf[15];
        sprintf (buf, "%lu", (ulong)sk->timestamp);
        return buf;
    }
    return datestr_from_sk (sk);
}

const char *
colon_datestr_from_sig (PKT_signature *sig)
{
    if (opt.fixed_list_mode) {
        static char buf[15];
        sprintf (buf, "%lu", (ulong)sig->timestamp);
        return buf;
    }
    return datestr_from_sig (sig);
}

const char *
colon_expirestr_from_sig (PKT_signature *sig)
{
    if(!sig->expiredate)
        return "";
    if (opt.fixed_list_mode) {
        static char buf[15];
        sprintf (buf, "%lu", (ulong)sig->expiredate);
        return buf;
    }
    return expirestr_from_sig (sig);
}


/**************** .
 * Return a byte array with the fingerprint for the given PK/SK
 * The length of the array is returned in ret_len. Caller must free
 * the array or provide an array of length MAX_FINGERPRINT_LEN.
 */

byte *
fingerprint_from_pk( PKT_public_key *pk, byte *array, size_t *ret_len )
{
    byte *buf;
    const byte *dp;
    size_t len;

    if( pk->version < 4 && is_RSA(pk->pubkey_algo) ) {
	/* RSA in version 3 packets is special */
	gcry_md_hd_t md;

	gcry_md_open (&md, DIGEST_ALGO_MD5, 0);
	if( pubkey_get_npkey( pk->pubkey_algo ) > 1 ) {
	    size_t nbytes;

	    if (gcry_mpi_print( GCRYMPI_FMT_USG, NULL, &nbytes, pk->pkey[0]))
              BUG ();
	    /* fixme: allocate it on the stack */
	    buf = xmalloc(nbytes);
	    if (gcry_mpi_print (GCRYMPI_FMT_USG, buf, &nbytes, pk->pkey[0]))
              BUG ();
	    gcry_md_write (md, buf, nbytes);
	    xfree (buf);
	    if (gcry_mpi_print( GCRYMPI_FMT_USG, NULL, &nbytes, pk->pkey[1]))
              BUG ();
	    /* fixme: allocate it on the stack */
	    buf = xmalloc(nbytes);
	    if (gcry_mpi_print( GCRYMPI_FMT_USG, buf, &nbytes, pk->pkey[1]))
              BUG ();
	    gcry_md_write( md, buf, nbytes );
	    xfree(buf);
	}
	gcry_md_final (md);
	if( !array )
	    array = xmalloc ( 16 );
	len = 16;
	memcpy(array, gcry_md_read (md, DIGEST_ALGO_MD5), 16 );
	gcry_md_close (md);
    }
    else {
	gcry_md_hd_t md;
	md = do_fingerprint_md(pk);
	dp = gcry_md_read ( md, 0 );
	len = gcry_md_get_algo_dlen (gcry_md_get_algo (md));
	assert( len <= MAX_FINGERPRINT_LEN );
	if( !array )
	    array = xmalloc ( len );
	memcpy(array, dp, len );
	pk->keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	pk->keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	gcry_md_close (md);
    }

    *ret_len = len;
    return array;
}

byte *
fingerprint_from_sk( PKT_secret_key *sk, byte *array, size_t *ret_len )
{
    byte  *buf;
    const char *dp;
    size_t len;

    if( sk->version < 4 && is_RSA(sk->pubkey_algo) ) {
	/* RSA in version 3 packets is special */
	gcry_md_hd_t md;

	gcry_md_open (&md, DIGEST_ALGO_MD5, 0);
	if( pubkey_get_npkey( sk->pubkey_algo ) > 1 ) {
	    size_t nbytes;

	    if (gcry_mpi_print( GCRYMPI_FMT_USG, NULL, &nbytes, sk->skey[0]))
              BUG ();
	    /* fixme: allocate it on the stack */
	    buf = xmalloc(nbytes);
	    if (gcry_mpi_print (GCRYMPI_FMT_USG, buf, &nbytes, sk->skey[0]))
              BUG ();
	    gcry_md_write (md, buf, nbytes);
	    xfree (buf);
	    if (gcry_mpi_print( GCRYMPI_FMT_USG, NULL, &nbytes, sk->skey[1]))
              BUG ();
	    /* fixme: allocate it on the stack */
	    buf = xmalloc(nbytes);
	    if (gcry_mpi_print( GCRYMPI_FMT_USG, buf, &nbytes, sk->skey[1]))
              BUG ();
	    gcry_md_write( md, buf, nbytes );
	    xfree(buf);
	}
	gcry_md_final (md);
	if( !array )
	    array = xmalloc ( 16 );
	len = 16;
	memcpy(array, gcry_md_read (md, DIGEST_ALGO_MD5), 16 );
	gcry_md_close (md);
    }
    else {
	gcry_md_hd_t md;

	md = do_fingerprint_md_sk(sk);
	dp = gcry_md_read ( md, 0 );
	len = gcry_md_get_algo_dlen (gcry_md_get_algo (md));
	assert( len <= MAX_FINGERPRINT_LEN );
	if( !array )
	    array = xmalloc ( len );
	memcpy(array, dp, len );
	gcry_md_close (md);
    }

    *ret_len = len;
    return array;
}


/* Create a serialno/fpr string from the serial number and the secret
 * key.  caller must free the returned string.  There is no error
 * return. */
char *
serialno_and_fpr_from_sk (const unsigned char *sn, size_t snlen,
                          PKT_secret_key *sk)
{
  unsigned char fpr[MAX_FINGERPRINT_LEN];
  size_t fprlen;
  char *buffer, *p;
  int i;
  
  fingerprint_from_sk (sk, fpr, &fprlen);
  buffer = p= xmalloc (snlen*2 + 1 + fprlen*2 + 1);
  for (i=0; i < snlen; i++, p+=2)
    sprintf (p, "%02X", sn[i]);
  *p++ = '/';
  for (i=0; i < fprlen; i++, p+=2)
    sprintf (p, "%02X", fpr[i]);
  *p = 0;
  return buffer;
}








