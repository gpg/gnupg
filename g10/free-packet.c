/* free-packet.c - cleanup stuff for packets
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

#include "packet.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"
#include "options.h"

void
free_symkey_enc( PKT_symkey_enc *enc )
{
    m_free(enc);
}

void
free_pubkey_enc( PKT_pubkey_enc *enc )
{
    int n, i;
    n = pubkey_get_nenc( enc->pubkey_algo );
    if( !n )
	mpi_free(enc->data[0]);
    for(i=0; i < n; i++ )
	mpi_free( enc->data[i] );
    m_free(enc);
}

void
free_seckey_enc( PKT_signature *sig )
{
    int n, i;
    n = pubkey_get_nsig( sig->pubkey_algo );
    if( !n )
	mpi_free(sig->data[0]);
    for(i=0; i < n; i++ )
	mpi_free( sig->data[i] );
    m_free(sig->hashed_data);
    m_free(sig->unhashed_data);
    m_free(sig);
}



void
release_public_key_parts( PKT_public_key *pk )
{
    int n, i;
    n = pubkey_get_npkey( pk->pubkey_algo );
    if( !n )
	mpi_free(pk->pkey[0]);
    for(i=0; i < n; i++ ) {
	mpi_free( pk->pkey[i] );
	pk->pkey[i] = NULL;
    }
    if( pk->namehash ) {
	m_free(pk->namehash);
	pk->namehash = NULL;
    }
}


void
free_public_key( PKT_public_key *pk )
{
    release_public_key_parts( pk );
    m_free(pk);
}


static void *
cp_data_block( byte *s )
{
    byte *d;
    u16 len;

    if( !s )
	return NULL;
    len = (s[0] << 8) | s[1];
    d = m_alloc( len+2 );
    memcpy(d, s, len+2);
    return d;
}


PKT_public_key *
copy_public_key_new_namehash( PKT_public_key *d, PKT_public_key *s,
			      const byte *namehash )
{
    int n, i;

    if( !d )
	d = m_alloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    if( namehash ) {
	d->namehash = m_alloc( 20 );
	memcpy(d->namehash, namehash, 20 );
    }
    else if( s->namehash ) {
	d->namehash = m_alloc( 20 );
	memcpy(d->namehash, s->namehash, 20 );
    }
    n = pubkey_get_npkey( s->pubkey_algo );
    if( !n )
	d->pkey[0] = mpi_copy(s->pkey[0]);
    else {
	for(i=0; i < n; i++ )
	    d->pkey[i] = mpi_copy( s->pkey[i] );
    }
    return d;
}

PKT_public_key *
copy_public_key( PKT_public_key *d, PKT_public_key *s )
{
   return copy_public_key_new_namehash( d, s, NULL );
}

/****************
 * Replace all common parts of a sk by the one from the public key.
 * This is a hack and a better solution will be to just store the real secret
 * parts somewhere and don't duplicate all the other stuff.
 */
void
copy_public_parts_to_secret_key( PKT_public_key *pk, PKT_secret_key *sk )
{
    sk->expiredate  = pk->expiredate;     
    sk->pubkey_algo = pk->pubkey_algo;    
    sk->pubkey_usage= pk->pubkey_usage;
    sk->req_usage   = pk->req_usage;
    sk->req_algo    = pk->req_algo;
    sk->has_expired = pk->has_expired;    
    sk->is_revoked  = pk->is_revoked;     
    sk->is_valid    = pk->is_valid;    
    sk->main_keyid[0]= pk->main_keyid[0];
    sk->main_keyid[1]= pk->main_keyid[1];
    sk->keyid[0]    = pk->keyid[0];
    sk->keyid[1]    = pk->keyid[1];
}

PKT_signature *
copy_signature( PKT_signature *d, PKT_signature *s )
{
    int n, i;

    if( !d )
	d = m_alloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    n = pubkey_get_nsig( s->pubkey_algo );
    if( !n )
	d->data[0] = mpi_copy(s->data[0]);
    else {
	for(i=0; i < n; i++ )
	    d->data[i] = mpi_copy( s->data[i] );
    }
    d->hashed_data = cp_data_block(s->hashed_data);
    d->unhashed_data = cp_data_block(s->unhashed_data);
    return d;
}


PKT_user_id *
copy_user_id( PKT_user_id *d, PKT_user_id *s )
{
    if( !d )
	d = m_alloc(sizeof *d + s->len - 1 );
    memcpy( d, s, sizeof *d + s->len - 1 );
    return d;
}



void
release_secret_key_parts( PKT_secret_key *sk )
{
    int n, i;

    n = pubkey_get_nskey( sk->pubkey_algo );
    if( !n )
	mpi_free(sk->skey[0]);
    for(i=0; i < n; i++ ) {
	mpi_free( sk->skey[i] );
	sk->skey[i] = NULL;
    }
}

void
free_secret_key( PKT_secret_key *sk )
{
    release_secret_key_parts( sk );
    m_free(sk);
}

PKT_secret_key *
copy_secret_key( PKT_secret_key *d, PKT_secret_key *s )
{
    int n, i;

    if( !d )
	d = m_alloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    n = pubkey_get_nskey( s->pubkey_algo );
    if( !n )
	d->skey[0] = mpi_copy(s->skey[0]);
    else {
	for(i=0; i < n; i++ )
	    d->skey[i] = mpi_copy( s->skey[i] );
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
    if( uid->photo )
	m_free( uid->photo );
    m_free(uid);
}

void
free_compressed( PKT_compressed *zd )
{
    if( zd->buf ) { /* have to skip some bytes */
	/* don't have any information about the length, so
	 * we assume this is the last packet */
	while( iobuf_read( zd->buf, NULL, 1<<30 ) != -1 )
	    ;
    }
    m_free(zd);
}

void
free_encrypted( PKT_encrypted *ed )
{
    if( ed->buf ) { /* have to skip some bytes */
	if( iobuf_in_block_mode(ed->buf) ) {
	    while( iobuf_read( ed->buf, NULL, 1<<30 ) != -1 )
		;
	}
	else {
	   while( ed->len ) { /* skip the packet */
	       int n = iobuf_read( ed->buf, NULL, ed->len );
	       if( n == -1 )
		   ed->len = 0;
	       else
		   ed->len -= n;
	   }
	}
    }
    m_free(ed);
}


void
free_plaintext( PKT_plaintext *pt )
{
    if( pt->buf ) { /* have to skip some bytes */
	if( iobuf_in_block_mode(pt->buf) ) {
	    while( iobuf_read( pt->buf, NULL, 1<<30 ) != -1 )
		;
	}
	else {
	   while( pt->len ) { /* skip the packet */
	       int n = iobuf_read( pt->buf, NULL, pt->len );
	       if( n == -1 )
		   pt->len = 0;
	       else
		   pt->len -= n;
	   }
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
      case PKT_PUBLIC_KEY:
      case PKT_PUBLIC_SUBKEY:
	free_public_key( pkt->pkt.public_key );
	break;
      case PKT_SECRET_KEY:
      case PKT_SECRET_SUBKEY:
	free_secret_key( pkt->pkt.secret_key );
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
 * returns 0 if they match.
 */
int
cmp_public_keys( PKT_public_key *a, PKT_public_key *b )
{
    int n, i;

    if( a->timestamp != b->timestamp )
	return -1;
    if( a->version < 4 && a->expiredate != b->expiredate )
	return -1;
    if( a->pubkey_algo != b->pubkey_algo )
	return -1;

    n = pubkey_get_npkey( b->pubkey_algo );
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( a->pkey[i], b->pkey[i] ) )
	    return -1;
    }

    return 0;
}

/****************
 * Returns 0 if they match.
 * We only compare the public parts.
 */
int
cmp_secret_keys( PKT_secret_key *a, PKT_secret_key *b )
{
    int n, i;

    if( a->timestamp != b->timestamp )
	return -1;
    if( a->version < 4 && a->expiredate != b->expiredate )
	return -1;
    if( a->pubkey_algo != b->pubkey_algo )
	return -1;

    n = pubkey_get_npkey( b->pubkey_algo );
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( a->skey[i], b->skey[i] ) )
	    return -1;
    }

    return 0;
}

/****************
 * Returns 0 if they match.
 */
int
cmp_public_secret_key( PKT_public_key *pk, PKT_secret_key *sk )
{
    int n, i;

    if( pk->timestamp != sk->timestamp )
	return -1;
    if( pk->version < 4 && pk->expiredate != sk->expiredate )
	return -1;
    if( pk->pubkey_algo != sk->pubkey_algo )
	return -1;

    n = pubkey_get_npkey( pk->pubkey_algo );
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( pk->pkey[i] , sk->skey[i] ) )
	    return -1;
    }
    return 0;
}



int
cmp_signatures( PKT_signature *a, PKT_signature *b )
{
    int n, i;

    if( a->keyid[0] != b->keyid[0] )
	return -1;
    if( a->keyid[1] != b->keyid[1] )
	return -1;
    if( a->pubkey_algo != b->pubkey_algo )
	return -1;

    n = pubkey_get_nsig( a->pubkey_algo );
    if( !n )
	return -1; /* can't compare due to unknown algorithm */
    for(i=0; i < n; i++ ) {
	if( mpi_cmp( a->data[i] , b->data[i] ) )
	    return -1;
    }
    return 0;
}



/****************
 * Returns: true if the user ids do not match
 */
int
cmp_user_ids( PKT_user_id *a, PKT_user_id *b )
{
    int res;

    res = a->len - b->len;
    if( !res )
	res = memcmp( a->name, b->name, a->len );
    return res;
}


