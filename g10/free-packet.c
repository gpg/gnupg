/* free-packet.c - cleanup stuff for packets
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
#include <assert.h>

#include "packet.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"

void
free_symkey_enc( PKT_symkey_enc *enc )
{
    m_free(enc);
}

void
free_pubkey_enc( PKT_pubkey_enc *enc )
{
    if( enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	mpi_free( enc->d.elg.a );
	mpi_free( enc->d.elg.b );
    }
    else if( enc->pubkey_algo == PUBKEY_ALGO_RSA )
	mpi_free( enc->d.rsa.rsa_integer );
    m_free(enc);
}

void
free_seckey_enc( PKT_signature *sig )
{
    if( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	mpi_free( sig->d.elg.a );
	mpi_free( sig->d.elg.b );
    }
    else if( sig->pubkey_algo == PUBKEY_ALGO_DSA ) {
	mpi_free( sig->d.dsa.r );
	mpi_free( sig->d.dsa.s );
    }
    else if( sig->pubkey_algo == PUBKEY_ALGO_RSA )
	mpi_free( sig->d.rsa.rsa_integer );
    m_free(sig->hashed_data);
    m_free(sig->unhashed_data);
    m_free(sig);
}


/****************
 * Return the digest algorithm from the signature packet.
 * We need this function because the digest algo depends on the
 * used pubkey algorithm.
 */
int
digest_algo_from_sig( PKT_signature *sig )
{
  #if 0 /* not used anymore */
    switch( sig->pubkey_algo ) {
      case PUBKEY_ALGO_ELGAMAL: return sig->d.elg.digest_algo;
      case PUBKEY_ALGO_DSA:	return sig->d.dsa.digest_algo;
      case PUBKEY_ALGO_RSA:	return sig->d.rsa.digest_algo;
      default: return 0;
    }
  #endif
    return sig->digest_algo;
}




void
release_public_cert_parts( PKT_public_cert *cert )
{
    if( cert->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	mpi_free( cert->d.elg.p ); cert->d.elg.p = NULL;
	mpi_free( cert->d.elg.g ); cert->d.elg.g = NULL;
	mpi_free( cert->d.elg.y ); cert->d.elg.y = NULL;
    }
    else if( cert->pubkey_algo == PUBKEY_ALGO_DSA ) {
	mpi_free( cert->d.dsa.p ); cert->d.dsa.p = NULL;
	mpi_free( cert->d.dsa.q ); cert->d.dsa.q = NULL;
	mpi_free( cert->d.dsa.g ); cert->d.dsa.g = NULL;
	mpi_free( cert->d.dsa.y ); cert->d.dsa.y = NULL;
    }
    else if( cert->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_free( cert->d.rsa.n ); cert->d.rsa.n = NULL;
	mpi_free( cert->d.rsa.e ); cert->d.rsa.e = NULL;
    }
}

void
free_public_cert( PKT_public_cert *cert )
{
    release_public_cert_parts( cert );
    m_free(cert);
}

PKT_public_cert *
copy_public_cert( PKT_public_cert *d, PKT_public_cert *s )
{
    if( !d )
	d = m_alloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    if( s->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	d->d.elg.p = mpi_copy( s->d.elg.p );
	d->d.elg.g = mpi_copy( s->d.elg.g );
	d->d.elg.y = mpi_copy( s->d.elg.y );
    }
    else if( s->pubkey_algo == PUBKEY_ALGO_DSA ) {
	d->d.dsa.p = mpi_copy( s->d.dsa.p );
	d->d.dsa.q = mpi_copy( s->d.dsa.q );
	d->d.dsa.g = mpi_copy( s->d.dsa.g );
	d->d.dsa.y = mpi_copy( s->d.dsa.y );
    }
    else if( s->pubkey_algo == PUBKEY_ALGO_RSA ) {
	d->d.rsa.n = mpi_copy( s->d.rsa.n );
	d->d.rsa.e = mpi_copy( s->d.rsa.e );
    }
    return d;
}

void
release_secret_cert_parts( PKT_secret_cert *cert )
{
    if( cert->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	mpi_free( cert->d.elg.p ); cert->d.elg.p = NULL;
	mpi_free( cert->d.elg.g ); cert->d.elg.g = NULL;
	mpi_free( cert->d.elg.y ); cert->d.elg.y = NULL;
	mpi_free( cert->d.elg.x ); cert->d.elg.x = NULL;
    }
    else if( cert->pubkey_algo == PUBKEY_ALGO_DSA ) {
	mpi_free( cert->d.dsa.p ); cert->d.dsa.p = NULL;
	mpi_free( cert->d.dsa.q ); cert->d.dsa.q = NULL;
	mpi_free( cert->d.dsa.g ); cert->d.dsa.g = NULL;
	mpi_free( cert->d.dsa.y ); cert->d.dsa.y = NULL;
	mpi_free( cert->d.dsa.x ); cert->d.dsa.x = NULL;
    }
    else if( cert->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_free( cert->d.rsa.n ); cert->d.rsa.n = NULL;
	mpi_free( cert->d.rsa.e ); cert->d.rsa.e = NULL;
	mpi_free( cert->d.rsa.d ); cert->d.rsa.d = NULL;
	mpi_free( cert->d.rsa.p ); cert->d.rsa.p = NULL;
	mpi_free( cert->d.rsa.q ); cert->d.rsa.q = NULL;
	mpi_free( cert->d.rsa.u ); cert->d.rsa.u = NULL;
    }
}

void
free_secret_cert( PKT_secret_cert *cert )
{
    release_secret_cert_parts( cert );
    m_free(cert);
}

PKT_secret_cert *
copy_secret_cert( PKT_secret_cert *d, PKT_secret_cert *s )
{
    if( !d )
	d = m_alloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    if( s->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	d->d.elg.p = mpi_copy( s->d.elg.p );
	d->d.elg.g = mpi_copy( s->d.elg.g );
	d->d.elg.y = mpi_copy( s->d.elg.y );
	d->d.elg.x = mpi_copy( s->d.elg.x );
    }
    else if( s->pubkey_algo == PUBKEY_ALGO_DSA ) {
	d->d.dsa.p = mpi_copy( s->d.dsa.p );
	d->d.dsa.q = mpi_copy( s->d.dsa.q );
	d->d.dsa.g = mpi_copy( s->d.dsa.g );
	d->d.dsa.y = mpi_copy( s->d.dsa.y );
	d->d.dsa.x = mpi_copy( s->d.dsa.x );
    }
    else if( s->pubkey_algo == PUBKEY_ALGO_RSA ) {
	d->d.rsa.n = mpi_copy( s->d.rsa.n );
	d->d.rsa.e = mpi_copy( s->d.rsa.e );
	d->d.rsa.d = mpi_copy( s->d.rsa.d );
	d->d.rsa.p = mpi_copy( s->d.rsa.p );
	d->d.rsa.q = mpi_copy( s->d.rsa.q );
	d->d.rsa.u = mpi_copy( s->d.rsa.u );
    }
    return d;
}

void
free_comment( PKT_comment *rem )
{
    m_free(rem);
}

void
free_user_id( PKT_user_id *uid )
{
    m_free(uid);
}

void
free_compressed( PKT_compressed *zd )
{
    if( zd->buf ) { /* have to skip some bytes */
	/* don't have any information about the length, so
	 * we assume this is the last packet */
	while( iobuf_get(zd->buf) != -1 )
	    ;
    }
    m_free(zd);
}

void
free_encrypted( PKT_encrypted *ed )
{
    if( ed->buf ) { /* have to skip some bytes */
	if( iobuf_in_block_mode(ed->buf) ) {
	    while( iobuf_get(ed->buf) != -1 )
		;
	    iobuf_set_block_mode(ed->buf, 0);
	}
	else {
	    for( ; ed->len; ed->len-- ) /* skip the packet */
		iobuf_get(ed->buf);
	}
    }
    m_free(ed);
}


void
free_plaintext( PKT_plaintext *pt )
{
    if( pt->buf ) { /* have to skip some bytes */
	if( iobuf_in_block_mode(pt->buf) ) {
	    while( iobuf_get(pt->buf) != -1 )
		;
	    iobuf_set_block_mode(pt->buf, 0);
	}
	else {
	    for( ; pt->len; pt->len-- ) /* skip the packet */
		iobuf_get(pt->buf);
	}
    }
    m_free(pt);
}

/****************
 * Free the packet in pkt.
 */
void
free_packet( PACKET *pkt )
{
    if( !pkt || !pkt->pkt.generic )
	return;

    if( DBG_MEMORY )
	log_debug("free_packet() type=%d\n", pkt->pkttype );

    switch( pkt->pkttype ) {
      case PKT_SIGNATURE:
	free_seckey_enc( pkt->pkt.signature );
	break;
      case PKT_PUBKEY_ENC:
	free_pubkey_enc( pkt->pkt.pubkey_enc );
	break;
      case PKT_SYMKEY_ENC:
	free_symkey_enc( pkt->pkt.symkey_enc );
	break;
      case PKT_PUBLIC_CERT:
	free_public_cert( pkt->pkt.public_cert );
	break;
      case PKT_SECRET_CERT:
	free_secret_cert( pkt->pkt.secret_cert );
	break;
      case PKT_COMMENT:
	free_comment( pkt->pkt.comment );
	break;
      case PKT_USER_ID:
	free_user_id( pkt->pkt.user_id );
	break;
      case PKT_COMPRESSED:
	free_compressed( pkt->pkt.compressed);
	break;
      case PKT_ENCRYPTED:
	free_encrypted( pkt->pkt.encrypted );
	break;
      case PKT_PLAINTEXT:
	free_plaintext( pkt->pkt.plaintext );
	break;
      default:
	m_free( pkt->pkt.generic );
	break;
    }
    pkt->pkt.generic = NULL;
}

/****************
 * Returns 0 if they match.
 */
int
cmp_public_certs( PKT_public_cert *a, PKT_public_cert *b )
{
    if( a->timestamp != b->timestamp )
	return -1;
    if( a->valid_days != b->valid_days )
	return -1;
    if( a->pubkey_algo != b->pubkey_algo )
	return -1;

    if( a->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	if( mpi_cmp( a->d.elg.p , b->d.elg.p ) )
	    return -1;
	if( mpi_cmp( a->d.elg.g , b->d.elg.g ) )
	    return -1;
	if( mpi_cmp( a->d.elg.y , b->d.elg.y ) )
	    return -1;
    }
    else if( a->pubkey_algo == PUBKEY_ALGO_DSA ) {
	if( mpi_cmp( a->d.dsa.p , b->d.dsa.p ) )
	    return -1;
	if( mpi_cmp( a->d.dsa.q , b->d.dsa.q ) )
	    return -1;
	if( mpi_cmp( a->d.dsa.g , b->d.dsa.g ) )
	    return -1;
	if( mpi_cmp( a->d.dsa.y , b->d.dsa.y ) )
	    return -1;
    }
    else if( a->pubkey_algo == PUBKEY_ALGO_RSA ) {
	if( mpi_cmp( a->d.rsa.n , b->d.rsa.n ) )
	    return -1;
	if( mpi_cmp( a->d.rsa.e , b->d.rsa.e ) )
	    return -1;
    }

    return 0;
}

/****************
 * Returns 0 if they match.
 */
int
cmp_public_secret_cert( PKT_public_cert *pkc, PKT_secret_cert *skc )
{
    if( pkc->timestamp != skc->timestamp )
	return -1;
    if( pkc->valid_days != skc->valid_days )
	return -1;
    if( pkc->pubkey_algo != skc->pubkey_algo )
	return -1;

    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	if( mpi_cmp( pkc->d.elg.p , skc->d.elg.p ) )
	    return -1;
	if( mpi_cmp( pkc->d.elg.g , skc->d.elg.g ) )
	    return -1;
	if( mpi_cmp( pkc->d.elg.y , skc->d.elg.y ) )
	    return -1;
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_DSA ) {
	if( mpi_cmp( pkc->d.dsa.p , skc->d.dsa.p ) )
	    return -1;
	if( mpi_cmp( pkc->d.dsa.q , skc->d.dsa.q ) )
	    return -1;
	if( mpi_cmp( pkc->d.dsa.g , skc->d.dsa.g ) )
	    return -1;
	if( mpi_cmp( pkc->d.dsa.y , skc->d.dsa.y ) )
	    return -1;
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	if( mpi_cmp( pkc->d.rsa.n , skc->d.rsa.n ) )
	    return -1;
	if( mpi_cmp( pkc->d.rsa.e , skc->d.rsa.e ) )
	    return -1;
    }

    return 0;
}

int
cmp_user_ids( PKT_user_id *a, PKT_user_id *b )
{
    int res;

    res = a->len - b->len;
    if( !res )
	res = memcmp( a->name, b->name, a->len );
    return res;
}


