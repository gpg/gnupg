/* keyid.c - key ID and fingerprint handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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

/* This function is useful for v4 fingerprints and v3 or v4 key
   signing. */
void
hash_public_key( MD_HANDLE md, PKT_public_key *pk )
{
  unsigned n=6;
  unsigned nb[PUBKEY_MAX_NPKEY];
  unsigned nn[PUBKEY_MAX_NPKEY];
  byte *pp[PUBKEY_MAX_NPKEY];
  int i;
  int npkey = pubkey_get_npkey( pk->pubkey_algo );

  /* Two extra bytes for the expiration date in v3 */
  if(pk->version<4)
    n+=2;

  if(npkey==0 && pk->pkey[0] && mpi_is_opaque(pk->pkey[0]))
    {
      pp[0]=mpi_get_opaque(pk->pkey[0],&nn[0]);
      n+=nn[0];
    }
  else
    for(i=0; i < npkey; i++ )
      {
	nb[i] = mpi_get_nbits(pk->pkey[i]);
	pp[i] = mpi_get_buffer( pk->pkey[i], nn+i, NULL );
	n += 2 + nn[i];
      }

  md_putc( md, 0x99 );     /* ctb */
  /* What does it mean if n is greater than than 0xFFFF ? */
  md_putc( md, n >> 8 );   /* 2 byte length header */
  md_putc( md, n );
  md_putc( md, pk->version );

  md_putc( md, pk->timestamp >> 24 );
  md_putc( md, pk->timestamp >> 16 );
  md_putc( md, pk->timestamp >>  8 );
  md_putc( md, pk->timestamp       );

  if(pk->version<4)
    {
      u16 days=0;
      if(pk->expiredate)
	days=(u16)((pk->expiredate - pk->timestamp) / 86400L);
 
      md_putc( md, days >> 8 );
      md_putc( md, days );
    }

  md_putc( md, pk->pubkey_algo );

  if(npkey==0 && pk->pkey[0] && mpi_is_opaque(pk->pkey[0]))
    md_write(md,pp[0],nn[0]);
  else
    for(i=0; i < npkey; i++ )
      {
	md_putc( md, nb[i]>>8);
	md_putc( md, nb[i] );
	md_write( md, pp[i], nn[i] );
	xfree(pp[i]);
      }
}

static MD_HANDLE
do_fingerprint_md( PKT_public_key *pk )
{
  MD_HANDLE md;

  md = md_open( DIGEST_ALGO_SHA1, 0);
  hash_public_key(md,pk);
  md_final( md );

  return md;
}

static MD_HANDLE
do_fingerprint_md_sk( PKT_secret_key *sk )
{
    PKT_public_key pk;
    int npkey = pubkey_get_npkey( sk->pubkey_algo ); /* npkey is correct! */
    int i;

    if(npkey==0)
      return NULL;

    pk.pubkey_algo = sk->pubkey_algo;
    pk.version	   = sk->version;
    pk.timestamp = sk->timestamp;
    pk.expiredate = sk->expiredate;
    pk.pubkey_algo = sk->pubkey_algo;
    for( i=0; i < npkey; i++ )
      pk.pkey[i] = sk->skey[i];
    return do_fingerprint_md( &pk );
}

size_t
keystrlen(void)
{
  switch(opt.keyid_format)
    {
    case KF_SHORT:
      return 8;

    case KF_LONG:
      return 16;

    case KF_0xSHORT:
      return 10;

    case KF_0xLONG:
      return 18;

    default:
      BUG();
    }
}

const char *
keystr(u32 *keyid)
{  
  static char keyid_str[19];

  switch(opt.keyid_format)
    {
    case KF_SHORT:
      sprintf(keyid_str,"%08lX",(ulong)keyid[1]);
      break;

    case KF_LONG:
      if(keyid[0])
	sprintf(keyid_str,"%08lX%08lX",(ulong)keyid[0],(ulong)keyid[1]);
      else
	sprintf(keyid_str,"%08lX",(ulong)keyid[1]);
      break;

    case KF_0xSHORT:
      sprintf(keyid_str,"0x%08lX",(ulong)keyid[1]);
      break;

    case KF_0xLONG:
      if(keyid[0])
	sprintf(keyid_str,"0x%08lX%08lX",(ulong)keyid[0],(ulong)keyid[1]);
      else
	sprintf(keyid_str,"0x%08lX",(ulong)keyid[1]);
      break;

    default:
      BUG();
    }

  return keyid_str;
}

const char *
keystr_from_pk(PKT_public_key *pk)
{
  keyid_from_pk(pk,NULL);

  return keystr(pk->keyid);
}

const char *
keystr_from_sk(PKT_secret_key *sk)
{
  keyid_from_sk(sk,NULL);

  return keystr(sk->keyid);
}

const char *
keystr_from_desc(KEYDB_SEARCH_DESC *desc)
{
  switch(desc->mode)
    {
    case KEYDB_SEARCH_MODE_LONG_KID:
    case KEYDB_SEARCH_MODE_SHORT_KID:
      return keystr(desc->u.kid);

    case KEYDB_SEARCH_MODE_FPR20:
      {
	u32 keyid[2];

	keyid[0] = (unsigned char)desc->u.fpr[12] << 24
	  | (unsigned char)desc->u.fpr[13] << 16
	  | (unsigned char)desc->u.fpr[14] << 8
	  | (unsigned char)desc->u.fpr[15] ;
	keyid[1] = (unsigned char)desc->u.fpr[16] << 24
	  | (unsigned char)desc->u.fpr[17] << 16
	  | (unsigned char)desc->u.fpr[18] << 8
	  | (unsigned char)desc->u.fpr[19] ;

	return keystr(keyid);
      }

    case KEYDB_SEARCH_MODE_FPR16:
      return "?v3 fpr?";

    default:
      BUG();
    }
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

  if( sk->keyid[0] || sk->keyid[1] )
    {
      keyid[0] = sk->keyid[0];
      keyid[1] = sk->keyid[1];
      lowbits = keyid[1];
    }
  else if( sk->version < 4 )
    {
      if( is_RSA(sk->pubkey_algo) )
	{
	  lowbits = pubkey_get_npkey(sk->pubkey_algo) ?
	    mpi_get_keyid( sk->skey[0], keyid ) : 0; /* take n */
	  sk->keyid[0]=keyid[0];
	  sk->keyid[1]=keyid[1];
	}
      else
	sk->keyid[0]=sk->keyid[1]=keyid[0]=keyid[1]=lowbits=0xFFFFFFFF;
    }
  else
    {
      const byte *dp;
      MD_HANDLE md;
      md = do_fingerprint_md_sk(sk);
      if(md)
	{
	  dp = md_read( md, 0 );
	  keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	  keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	  lowbits = keyid[1];
	  md_close(md);
	  sk->keyid[0] = keyid[0];
	  sk->keyid[1] = keyid[1];
	}
      else
	sk->keyid[0]=sk->keyid[1]=keyid[0]=keyid[1]=lowbits=0xFFFFFFFF;
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

  if( pk->keyid[0] || pk->keyid[1] )
    {
      keyid[0] = pk->keyid[0];
      keyid[1] = pk->keyid[1];
      lowbits = keyid[1];
    }
  else if( pk->version < 4 )
    {
      if( is_RSA(pk->pubkey_algo) )
	{
	  lowbits = pubkey_get_npkey(pk->pubkey_algo) ?
	    mpi_get_keyid( pk->pkey[0], keyid ) : 0 ; /* from n */
	  pk->keyid[0] = keyid[0];
	  pk->keyid[1] = keyid[1];
	}
      else
	pk->keyid[0]=pk->keyid[1]=keyid[0]=keyid[1]=lowbits=0xFFFFFFFF;
    }
  else
    {
      const byte *dp;
      MD_HANDLE md;
      md = do_fingerprint_md(pk);
      if(md)
	{
	  dp = md_read( md, 0 );
	  keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	  keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	  lowbits = keyid[1];
	  md_close(md);
	  pk->keyid[0] = keyid[0];
	  pk->keyid[1] = keyid[1];
	}
      else
	pk->keyid[0]=pk->keyid[1]=keyid[0]=keyid[1]=lowbits=0xFFFFFFFF;
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
      uid->namehash=xmalloc(20);

      if(uid->attrib_data)
	rmd160_hash_buffer(uid->namehash,uid->attrib_data,uid->attrib_len);
      else
	rmd160_hash_buffer(uid->namehash,uid->name,uid->len);
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
revokestr_from_pk( PKT_public_key *pk )
{
    static char buffer[11+5];
    time_t atime;

    if(!pk->revoked.date)
      return _("never     ");
    atime=pk->revoked.date;
    return mk_datestr (buffer, atime);
}


const char *
usagestr_from_pk( PKT_public_key *pk )
{
  static char buffer[10];
  int i = 0;
  unsigned int use = pk->pubkey_usage;

  if ( use & PUBKEY_USAGE_SIG )
    buffer[i++] = 'S';

  if ( use & PUBKEY_USAGE_CERT )
    buffer[i++] = 'C';

  if ( use & PUBKEY_USAGE_ENC )
    buffer[i++] = 'E';

  if ( (use & PUBKEY_USAGE_AUTH) )
    buffer[i++] = 'A';

  while (i < 4)
    buffer[i++] = ' ';

  buffer[i] = 0;
  return buffer;
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
    byte *p, *buf;
    const byte *dp;
    size_t len;
    unsigned int n;

    if( pk->version < 4 )
      {
	if( is_RSA(pk->pubkey_algo) )
	  {
	    /* RSA in version 3 packets is special */
	    MD_HANDLE md;

	    md = md_open( DIGEST_ALGO_MD5, 0);
	    if( pubkey_get_npkey( pk->pubkey_algo ) > 1 ) {
	      p = buf = mpi_get_buffer( pk->pkey[0], &n, NULL );
	      md_write( md, p, n );
	      xfree(buf);
	      p = buf = mpi_get_buffer( pk->pkey[1], &n, NULL );
	      md_write( md, p, n );
	      xfree(buf);
	    }
	    md_final(md);
	    if( !array )
	      array = xmalloc( 16 );
	    len = 16;
	    memcpy(array, md_read(md, DIGEST_ALGO_MD5), 16 );
	    md_close(md);
	  }
	else
	  {
	    if(!array)
	      array=xmalloc(16);
	    len=16;
	    memset(array,0,16);
	  }
      }
    else {
	MD_HANDLE md;
	md = do_fingerprint_md(pk);
	dp = md_read( md, 0 );
	len = md_digest_length( md_get_algo( md ) );
	assert( len <= MAX_FINGERPRINT_LEN );
	if( !array )
	    array = xmalloc( len );
	memcpy(array, dp, len );
	pk->keyid[0] = dp[12] << 24 | dp[13] << 16 | dp[14] << 8 | dp[15] ;
	pk->keyid[1] = dp[16] << 24 | dp[17] << 16 | dp[18] << 8 | dp[19] ;
	md_close(md);
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

    if( sk->version < 4 )
      {
	if( is_RSA(sk->pubkey_algo) )
	  {
	    /* RSA in version 3 packets is special */
	    MD_HANDLE md;

	    md = md_open( DIGEST_ALGO_MD5, 0);
	    if( pubkey_get_npkey( sk->pubkey_algo ) > 1 ) {
	      p = buf = mpi_get_buffer( sk->skey[0], &n, NULL );
	      md_write( md, p, n );
	      xfree(buf);
	      p = buf = mpi_get_buffer( sk->skey[1], &n, NULL );
	      md_write( md, p, n );
	      xfree(buf);
	    }
	    md_final(md);
	    if( !array )
	      array = xmalloc( 16 );
	    len = 16;
	    memcpy(array, md_read(md, DIGEST_ALGO_MD5), 16 );
	    md_close(md);
	  }
	else
	  {
	    if(!array)
	      array=xmalloc(16);
	    len=16;
	    memset(array,0,16);
	  }
      }
    else {
	MD_HANDLE md;
	md = do_fingerprint_md_sk(sk);
	if(md)
	  {
	    dp = md_read( md, 0 );
	    len = md_digest_length( md_get_algo( md ) );
	    assert( len <= MAX_FINGERPRINT_LEN );
	    if( !array )
	      array = xmalloc( len );
	    memcpy(array, dp, len );
	    md_close(md);
	  }
	else
	  {
	    len=MAX_FINGERPRINT_LEN;
	    if(!array)
	      array=xmalloc(len);
	    memset(array,0,len);
	  }
    }

    *ret_len = len;
    return array;
}
