/* sig-check.c -  Check a signature
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include <assert.h>
#include "util.h"
#include "packet.h"
#include "memory.h"
#include "mpi.h"
#include "keydb.h"
#include "cipher.h"
#include "main.h"
#include "status.h"
#include "i18n.h"
#include "options.h"

struct cmp_help_context_s {
    PKT_signature *sig;
    MD_HANDLE md;
};


static int do_signature_check( PKT_signature *sig, MD_HANDLE digest,
					 u32 *r_expiredate, int *r_expired );
static int do_check( PKT_public_key *pk, PKT_signature *sig,
					 MD_HANDLE digest, int *r_expired );


/****************
 * Check the signature which is contained in SIG.
 * The MD_HANDLE should be currently open, so that this function
 * is able to append some data, before finalizing the digest.
 */
int
signature_check( PKT_signature *sig, MD_HANDLE digest )
{
    u32 dummy;
    int dum2;
    return do_signature_check( sig, digest, &dummy, &dum2 );
}

static int
do_signature_check( PKT_signature *sig, MD_HANDLE digest,
					u32 *r_expiredate, int *r_expired )
{
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    int rc=0;

    *r_expiredate = 0;
    if( get_pubkey( pk, sig->keyid ) )
	rc = G10ERR_NO_PUBKEY;
    else {
	*r_expiredate = pk->expiredate;
	rc = do_check( pk, sig, digest, r_expired );
    }

    free_public_key( pk );

    if( !rc && sig->sig_class < 2 && is_status_enabled() ) {
	/* This signature id works best with DLP algorithms because
	 * they use a random parameter for every signature.  Instead of
	 * this sig-id we could have also used the hash of the document
	 * and the timestamp, but the drawback of this is, that it is
	 * not possible to sign more than one identical document within
	 * one second.	Some remote bacth processing applications might
	 * like this feature here */
	MD_HANDLE md;
	u32 a = sig->timestamp;
	int i, nsig = pubkey_get_nsig( sig->pubkey_algo );
	byte *p, *buffer;

	md = md_open( DIGEST_ALGO_RMD160, 0);
	md_putc( digest, sig->pubkey_algo );
	md_putc( digest, sig->digest_algo );
	md_putc( digest, (a >> 24) & 0xff );
	md_putc( digest, (a >> 16) & 0xff );
	md_putc( digest, (a >>	8) & 0xff );
	md_putc( digest,  a	   & 0xff );
	for(i=0; i < nsig; i++ ) {
	    unsigned n = mpi_get_nbits( sig->data[i]);

	    md_putc( md, n>>8);
	    md_putc( md, n );
	    p = mpi_get_buffer( sig->data[i], &n, NULL );
	    md_write( md, p, n );
	    m_free(p);
	}
	md_final( md );
	p = make_radix64_string( md_read( md, 0 ), 20 );
	buffer = m_alloc( strlen(p) + 60 );
	sprintf( buffer, "%s %s %lu",
		 p, strtimestamp( sig->timestamp ), (ulong)sig->timestamp );
	write_status_text( STATUS_SIG_ID, buffer );
	m_free(buffer);
	m_free(p);
	md_close(md);
    }

    return rc;
}


#if 0 /* not anymore used */
/****************
 * Check the MDC which is contained in SIG.
 * The MD_HANDLE should be currently open, so that this function
 * is able to append some data, before finalizing the digest.
 */
int
mdc_kludge_check( PKT_signature *sig, MD_HANDLE digest )
{
    int rc=0;

    if( (rc=check_digest_algo(sig->digest_algo)) )
	return rc;

    /* make sure the digest algo is enabled (in case of a detached mdc??) */
    md_enable( digest, sig->digest_algo );

    /* complete the digest */
    if( sig->version >= 4 )
	md_putc( digest, sig->version );
    md_putc( digest, sig->sig_class );
    if( sig->version < 4 ) {
	u32 a = sig->timestamp;
	md_putc( digest, (a >> 24) & 0xff );
	md_putc( digest, (a >> 16) & 0xff );
	md_putc( digest, (a >>	8) & 0xff );
	md_putc( digest,  a	   & 0xff );
    }
    else {
	byte buf[6];
	size_t n;
	md_putc( digest, sig->pubkey_algo );
	md_putc( digest, sig->digest_algo );
	if( sig->hashed_data ) {
	    n = (sig->hashed_data[0] << 8) | sig->hashed_data[1];
	    md_write( digest, sig->hashed_data, n+2 );
	    n += 6;
	}
	else
	    n = 6;
	/* add some magic */
	buf[0] = sig->version;
	buf[1] = 0xff;
	buf[2] = n >> 24;
	buf[3] = n >> 16;
	buf[4] = n >>  8;
	buf[5] = n;
	md_write( digest, buf, 6 );
    }
    md_final( digest );

    rc = G10ERR_BAD_SIGN;
    {	const byte *s1 = md_read( digest, sig->digest_algo );
	int s1len = md_digest_length( sig->digest_algo );

	log_hexdump( "MDC calculated", s1, s1len );

	if( !sig->data[0] )
	    log_debug("sig_data[0] is NULL\n");
	else {
	    unsigned s2len;
	    byte *s2;
	    s2 = mpi_get_buffer( sig->data[0], &s2len, NULL );
	    log_hexdump( "MDC stored    ", s2, s2len );

	    if( s2len != s1len )
		log_debug("MDC check: len differ: %d/%d\n", s1len, s2len);
	    else if( memcmp( s1, s2, s1len ) )
		log_debug("MDC check: hashs differ\n");
	    else
		rc = 0;
	    m_free(s2);
	}
    }

    if( !rc && sig->flags.unknown_critical ) {
	log_info(_("assuming bad MDC due to an unknown critical bit\n"));
	rc = G10ERR_BAD_SIGN;
    }
    sig->flags.checked = 1;
    sig->flags.valid = !rc;

    /* FIXME: check that we are actually in an encrypted packet */

    return rc;
}
#endif

/****************
 * This function gets called by pubkey_verify() if the algorithm needs it.
 */
static int
cmp_help( void *opaque, MPI result )
{
  #if 0 /* we do not use this anymore */
    int rc=0, i, j, c, old_enc;
    byte *dp;
    const byte *asn;
    size_t mdlen, asnlen;
    struct cmp_help_context_s *ctx = opaque;
    PKT_signature *sig = ctx->sig;
    MD_HANDLE digest = ctx->md;

    old_enc = 0;
    for(i=j=0; (c=mpi_getbyte(result, i)) != -1; i++ ) {
	if( !j ) {
	    if( !i && c != 1 )
		break;
	    else if( i && c == 0xff )
		; /* skip the padding */
	    else if( i && !c )
		j++;
	    else
		break;
	}
	else if( ++j == 18 && c != 1 )
	    break;
	else if( j == 19 && c == 0 ) {
	    old_enc++;
	    break;
	}
    }
    if( old_enc ) {
	log_error("old encoding scheme is not supported\n");
	return G10ERR_GENERAL;
    }

    if( (rc=check_digest_algo(sig->digest_algo)) )
	return rc; /* unsupported algo */
    asn = md_asn_oid( sig->digest_algo, &asnlen, &mdlen );

    for(i=mdlen,j=asnlen-1; (c=mpi_getbyte(result, i)) != -1 && j >= 0;
							   i++, j-- )
	if( asn[j] != c )
	    break;
    if( j != -1 || mpi_getbyte(result, i) )
	return G10ERR_BAD_PUBKEY;  /* ASN is wrong */
    for(i++; (c=mpi_getbyte(result, i)) != -1; i++ )
	if( c != 0xff  )
	    break;
    i++;
    if( c != sig->digest_algo || mpi_getbyte(result, i) ) {
	/* Padding or leading bytes in signature is wrong */
	return G10ERR_BAD_PUBKEY;
    }
    if( mpi_getbyte(result, mdlen-1) != sig->digest_start[0]
	|| mpi_getbyte(result, mdlen-2) != sig->digest_start[1] ) {
	/* Wrong key used to check the signature */
	return G10ERR_BAD_PUBKEY;
    }

    dp = md_read( digest, sig->digest_algo );
    for(i=mdlen-1; i >= 0; i--, dp++ ) {
	if( mpi_getbyte( result, i ) != *dp )
	    return G10ERR_BAD_SIGN;
    }
    return 0;
  #else
    return -1;
  #endif
}


static int
do_check( PKT_public_key *pk, PKT_signature *sig, MD_HANDLE digest,
						    int *r_expired )
{
    MPI result = NULL;
    int rc=0;
    struct cmp_help_context_s ctx;
    u32 cur_time;

    *r_expired = 0;
    if( pk->version == 4 && pk->pubkey_algo == PUBKEY_ALGO_ELGAMAL_E ) {
	log_info(_("this is a PGP generated "
		  "ElGamal key which is NOT secure for signatures!\n"));
	return G10ERR_PUBKEY_ALGO;
    }

    if( pk->timestamp > sig->timestamp ) {
	ulong d = pk->timestamp - sig->timestamp;
	log_info( d==1
		  ? _("public key is %lu second newer than the signature\n")
		  : _("public key is %lu seconds newer than the signature\n"),
		       d );
	if( !opt.ignore_time_conflict )
	    return G10ERR_TIME_CONFLICT; /* pubkey newer than signature */
    }

    cur_time = make_timestamp();
    if( pk->timestamp > cur_time ) {
	ulong d = pk->timestamp - cur_time;
	log_info( d==1 ? _("key has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key has been created %lu seconds "
			   "in future (time warp or clock problem)\n"), d );
	if( !opt.ignore_time_conflict )
	    return G10ERR_TIME_CONFLICT;
    }

    if( pk->expiredate && pk->expiredate < cur_time ) {
        if (opt.verbose) {
	    u32 tmp_kid[2];

	    keyid_from_pk( pk, tmp_kid );
            log_info(_("NOTE: signature key %08lX expired %s\n"),
                     (ulong)tmp_kid[1], asctimestamp( pk->expiredate ) );
        }
	write_status(STATUS_SIGEXPIRED);
	*r_expired = 1;
    }


    if( (rc=check_digest_algo(sig->digest_algo)) )
	return rc;
    if( (rc=check_pubkey_algo(sig->pubkey_algo)) )
	return rc;

    /* make sure the digest algo is enabled (in case of a detached signature)*/
    md_enable( digest, sig->digest_algo );

    /* complete the digest */
    if( sig->version >= 4 )
	md_putc( digest, sig->version );
    md_putc( digest, sig->sig_class );
    if( sig->version < 4 ) {
	u32 a = sig->timestamp;
	md_putc( digest, (a >> 24) & 0xff );
	md_putc( digest, (a >> 16) & 0xff );
	md_putc( digest, (a >>	8) & 0xff );
	md_putc( digest,  a	   & 0xff );
    }
    else {
	byte buf[6];
	size_t n;
	md_putc( digest, sig->pubkey_algo );
	md_putc( digest, sig->digest_algo );
	if( sig->hashed_data ) {
	    n = (sig->hashed_data[0] << 8) | sig->hashed_data[1];
	    md_write( digest, sig->hashed_data, n+2 );
	    n += 6;
	}
	else
	    n = 6;
	/* add some magic */
	buf[0] = sig->version;
	buf[1] = 0xff;
	buf[2] = n >> 24;
	buf[3] = n >> 16;
	buf[4] = n >>  8;
	buf[5] = n;
	md_write( digest, buf, 6 );
    }
    md_final( digest );

    result = encode_md_value( pk->pubkey_algo, digest, sig->digest_algo,
			      mpi_get_nbits(pk->pkey[0]), 0 );
    ctx.sig = sig;
    ctx.md = digest;
    rc = pubkey_verify( pk->pubkey_algo, result, sig->data, pk->pkey,
			cmp_help, &ctx );
    mpi_free( result );
    if( (opt.emulate_bugs & EMUBUG_MDENCODE)
	&& rc == G10ERR_BAD_SIGN && is_ELGAMAL(pk->pubkey_algo) ) {
	/* In this case we try again because old GnuPG versions didn't encode
	 * the hash right. There is no problem with DSA however  */
	result = encode_md_value( pk->pubkey_algo, digest, sig->digest_algo,
			      mpi_get_nbits(pk->pkey[0]), (sig->version < 5) );
	ctx.sig = sig;
	ctx.md = digest;
	rc = pubkey_verify( pk->pubkey_algo, result, sig->data, pk->pkey,
			    cmp_help, &ctx );
    }

    if( !rc && sig->flags.unknown_critical ) {
	log_info(_("assuming bad signature due to an unknown critical bit\n"));
	rc = G10ERR_BAD_SIGN;
    }
    sig->flags.checked = 1;
    sig->flags.valid = !rc;

    return rc;
}


static void
hash_uid_node( KBNODE unode, MD_HANDLE md, PKT_signature *sig )
{
    PKT_user_id *uid = unode->pkt->pkt.user_id;

    assert( unode->pkt->pkttype == PKT_USER_ID );
    if( uid->photo ) {
	if( sig->version >=4 ) {
	    byte buf[5];
	    buf[0] = 0xd1;		   /* packet of type 17 */
	    buf[1] = uid->photolen >> 24;  /* always use 4 length bytes */
	    buf[2] = uid->photolen >> 16;
	    buf[3] = uid->photolen >>  8;
	    buf[4] = uid->photolen;
	    md_write( md, buf, 5 );
	}
	md_write( md, uid->photo, uid->photolen );
    }
    else {
	if( sig->version >=4 ) {
	    byte buf[5];
	    buf[0] = 0xb4;	      /* indicates a userid packet */
	    buf[1] = uid->len >> 24;  /* always use 4 length bytes */
	    buf[2] = uid->len >> 16;
	    buf[3] = uid->len >>  8;
	    buf[4] = uid->len;
	    md_write( md, buf, 5 );
	}
	md_write( md, uid->name, uid->len );
    }
}

static void
cache_selfsig_result ( PKT_signature *sig, int result )
{
    byte buf[6];

    if ( opt.no_sig_cache )
        return;

    buf[0] = 'G';
    buf[1] = 'P';
    buf[2] = 'G';
    buf[3] = 0;
    if ( !result ) {
        buf[4] = 1; /* mark cache valid */
        buf[5] = 1; /* mark signature valid */
    }
    else if ( result == G10ERR_BAD_SIGN ) {
        buf[4] = 1; /* mark cache valid */
        buf[5] = 0; /* mark signature invalid */
    }
    else {
        buf[4] = 0; /* mark cache invalid */
        buf[5] = 0; 
    }

    build_sig_subpkt (sig, SIGSUBPKT_PRIV_VERIFY_CACHE, buf, 6 );
}

/****************
 * check the signature pointed to by NODE. This is a key signature.
 * If the function detects a self-signature, it uses the PK from
 * ROOT and does not read any public key.
 */
int
check_key_signature( KBNODE root, KBNODE node, int *is_selfsig )
{
    u32 dummy;
    int dum2;
    return check_key_signature2(root, node, is_selfsig, &dummy, &dum2 );
}

int
check_key_signature2( KBNODE root, KBNODE node, int *is_selfsig,
				       u32 *r_expiredate, int *r_expired )
{
    MD_HANDLE md;
    PKT_public_key *pk;
    PKT_signature *sig;
    int algo;
    int rc;

    if( is_selfsig )
	*is_selfsig = 0;
    *r_expiredate = 0;
    *r_expired = 0;
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( root->pkt->pkttype == PKT_PUBLIC_KEY );

    pk = root->pkt->pkt.public_key;
    sig = node->pkt->pkt.signature;
    algo = sig->digest_algo;

  #if 0 /* I am not sure whether this is a good thing to do */
    if( sig->flags.checked )
	log_debug("check_key_signature: already checked: %s\n",
		      sig->flags.valid? "good":"bad" );
  #endif

    /* Check whether we have cached the result of a previous signature check.*/
    if ( !opt.no_sig_cache ) {
        const byte *p;
        size_t len;

        p = parse_sig_subpkt( sig->unhashed_data,
                              SIGSUBPKT_PRIV_VERIFY_CACHE, &len );
        if ( p && len >= 2 && p[0] == 1 ) { /* cache hit */
	    if( is_selfsig ) {	
		u32 keyid[2];	

		keyid_from_pk( pk, keyid );
		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    *is_selfsig = 1;
	    }
            return p[1] == 1? 0 : G10ERR_BAD_SIGN;
        }
    }

    if( (rc=check_digest_algo(algo)) )
	return rc;

    if( sig->sig_class == 0x20 ) { /* key revocation */
	md = md_open( algo, 0 );
	hash_public_key( md, pk );
	rc = do_check( pk, sig, md, r_expired );
        cache_selfsig_result ( sig, rc );
	md_close(md);
    }
    else if( sig->sig_class == 0x28 ) { /* subkey revocation */
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired );
            cache_selfsig_result ( sig, rc );
	    md_close(md);
	}
	else {
	    log_info ("no subkey for subkey revocation packet\n");
	    rc = G10ERR_SIG_CLASS;
	}
    }
    else if( sig->sig_class == 0x18 ) { /* key binding */
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    if( is_selfsig ) {	/* does this make sense????? */
		u32 keyid[2];	/* it should always be a selfsig */

		keyid_from_pk( pk, keyid );
		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    *is_selfsig = 1;
	    }
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md, r_expired );
            cache_selfsig_result ( sig, rc );
	    md_close(md);
	}
	else {
	    log_info ("no subkey for key signature packet\n");
	    rc = G10ERR_SIG_CLASS;
	}
    }
    else if( sig->sig_class == 0x1f ) { /* direct key signature */
	md = md_open( algo, 0 );
	hash_public_key( md, pk );
	rc = do_check( pk, sig, md, r_expired );
        cache_selfsig_result ( sig, rc );
	md_close(md);
    }
    else { /* all other classes */
	KBNODE unode = find_prev_kbnode( root, node, PKT_USER_ID );

	if( unode ) {
	    u32 keyid[2];

	    keyid_from_pk( pk, keyid );
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    hash_uid_node( unode, md, sig );
	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] ) {
		if( is_selfsig )
		    *is_selfsig = 1;
		rc = do_check( pk, sig, md, r_expired );
                cache_selfsig_result ( sig, rc );
	    }
	    else {
		rc = do_signature_check( sig, md, r_expiredate, r_expired );
	    }
	    md_close(md);
	}
	else {
	    log_info ("no user ID for key signature packet of class %02x\n",
                      sig->sig_class );
	    rc = G10ERR_SIG_CLASS;
	}
    }

    return rc;
}


