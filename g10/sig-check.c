/* sig-check.c -  Check a signature
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

struct cmp_help_context_s {
    PKT_signature *sig;
    MD_HANDLE md;
};


static int do_check( PKT_public_key *pk, PKT_signature *sig,
						MD_HANDLE digest );


/****************
 * Check the signature which is contained in SIG.
 * The md5handle should be currently open, so that this function
 * is able to append some data, before finalizing the digest.
 */
int
signature_check( PKT_signature *sig, MD_HANDLE digest )
{
    PKT_public_key *pk = m_alloc_clear( sizeof *pk );
    int rc=0;


    if( is_RSA(sig->pubkey_algo) )
	write_status(STATUS_RSA_OR_IDEA);

    if( get_pubkey( pk, sig->keyid ) )
	rc = G10ERR_NO_PUBKEY;
    else
	rc = do_check( pk, sig, digest );

    free_public_key( pk );
    return rc;
}


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
do_check( PKT_public_key *pk, PKT_signature *sig, MD_HANDLE digest )
{
    MPI result = NULL;
    int rc=0;
    struct cmp_help_context_s ctx;
    u32 cur_time;

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
	return G10ERR_TIME_CONFLICT; /* pubkey newer than signature */
    }

    cur_time = make_timestamp();
    if( pk->timestamp > cur_time ) {
	ulong d = pk->timestamp - cur_time;
	log_info( d==1 ? _("key has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key has been created %lu seconds "
			   "in future (time warp or clock problem)\n"), d );
	return G10ERR_TIME_CONFLICT;
    }

    if( pk->expiredate && pk->expiredate < cur_time ) {
	log_info(_("NOTE: signature key expired %s\n"),
					asctimestamp( pk->expiredate ) );
	write_status(STATUS_SIGEXPIRED);
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
				      mpi_get_nbits(pk->pkey[0]));

    ctx.sig = sig;
    ctx.md = digest;
    rc = pubkey_verify( pk->pubkey_algo, result, sig->data, pk->pkey,
			cmp_help, &ctx );
    mpi_free( result );
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
    if( sig->version >=4 ) {
	byte buf[5];
	buf[0] = 0xb4; /* indicates a userid packet */
	buf[1] = uid->len >> 24;  /* always use 4 length bytes */
	buf[2] = uid->len >> 16;
	buf[3] = uid->len >>  8;
	buf[4] = uid->len;
	md_write( md, buf, 5 );
    }
    md_write( md, uid->name, uid->len );
}

/****************
 * check the signature pointed to by NODE. This is a key signature.
 * If the function detects a self-signature, it uses the PK from
 * ROOT and does not read any public key.
 */
int
check_key_signature( KBNODE root, KBNODE node, int *is_selfsig )
{
    MD_HANDLE md;
    PKT_public_key *pk;
    PKT_signature *sig;
    int algo;
    int rc;

    if( is_selfsig )
	*is_selfsig = 0;
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( root->pkt->pkttype == PKT_PUBLIC_KEY );

    pk = root->pkt->pkt.public_key;
    sig = node->pkt->pkt.signature;
    algo = sig->digest_algo;
    if( (rc=check_digest_algo(algo)) )
	return rc;

    if( sig->sig_class == 0x20 ) {
	md = md_open( algo, 0 );
	hash_public_key( md, pk );
	rc = do_check( pk, sig, md );
	md_close(md);
    }
    else if( sig->sig_class == 0x28 ) { /* subkey revocation */
	KBNODE snode = find_prev_kbnode( root, node, PKT_PUBLIC_SUBKEY );

	if( snode ) {
	    md = md_open( algo, 0 );
	    hash_public_key( md, pk );
	    hash_public_key( md, snode->pkt->pkt.public_key );
	    rc = do_check( pk, sig, md );
	    md_close(md);
	}
	else {
	    log_error("no subkey for subkey revocation packet\n");
	    rc = G10ERR_SIG_CLASS;
	}
    }
    else if( sig->sig_class == 0x18 ) {
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
	    rc = do_check( pk, sig, md );
	    md_close(md);
	}
	else {
	    log_error("no subkey for key signature packet\n");
	    rc = G10ERR_SIG_CLASS;
	}
    }
    else {
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
		rc = do_check( pk, sig, md );
	    }
	    else
		rc = signature_check( sig, md );
	    md_close(md);
	}
	else {
	    log_error("no user id for key signature packet\n");
	    rc = G10ERR_SIG_CLASS;
	}
    }

    return rc;
}


