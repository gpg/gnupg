/* free-packet.c - cleanup stuff for packets
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
#include <assert.h>

#include "packet.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"


void
free_pubkey_enc( PKT_pubkey_enc *enc )
{
    mpi_free( enc->d.rsa.rsa_integer );
    m_free(enc);
}

void
free_seckey_enc( PKT_signature *enc )
{
    mpi_free( enc->d.rsa.rsa_integer );
    m_free(enc);
}

void
free_pubkey_cert( PKT_pubkey_cert *cert )
{
    mpi_free( cert->d.rsa.rsa_n );
    mpi_free( cert->d.rsa.rsa_e );
    md5_close( cert->mfx.md5 );
    rmd160_close( cert->mfx.rmd160 );
    m_free(cert);
}

PKT_pubkey_cert *
copy_pubkey_cert( PKT_pubkey_cert *d, PKT_pubkey_cert *s )
{
    if( !d )
	d = m_alloc(sizeof *d);
    memcpy( d, s, sizeof *d );
    d->d.rsa.rsa_n = mpi_copy( s->d.rsa.rsa_n );
    d->d.rsa.rsa_e = mpi_copy( s->d.rsa.rsa_e );
    d->mfx.md5 = NULL;
    d->mfx.rmd160 =NULL;
    return d;
}

void
free_seckey_cert( PKT_seckey_cert *cert )
{
    mpi_free( cert->d.rsa.rsa_n );
    mpi_free( cert->d.rsa.rsa_e );
    if( cert->d.rsa.is_protected ) {
	m_free( cert->d.rsa.rsa_d );
	m_free( cert->d.rsa.rsa_p );
	m_free( cert->d.rsa.rsa_q );
	m_free( cert->d.rsa.rsa_u );
    }
    else {
	mpi_free( cert->d.rsa.rsa_d );
	mpi_free( cert->d.rsa.rsa_p );
	mpi_free( cert->d.rsa.rsa_q );
	mpi_free( cert->d.rsa.rsa_u );
    }
    m_free(cert);
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
	/* don't have any informations about the length, so
	 * we assume this is the last packet */
	while( iobuf_get(zd->buf) != -1 )
	    ;
    }
    m_free(zd);
}

void
free_encr_data( PKT_encr_data *ed )
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
      case PKT_PUBKEY_CERT:
	free_pubkey_cert( pkt->pkt.pubkey_cert );
	break;
      case PKT_SECKEY_CERT:
	free_seckey_cert( pkt->pkt.seckey_cert );
	break;
      case PKT_COMMENT:
	free_comment( pkt->pkt.comment );
	break;
      case PKT_USER_ID:
	free_user_id( pkt->pkt.user_id );
	break;
      case PKT_COMPR_DATA:
	free_compressed( pkt->pkt.compressed);
	break;
      case PKT_ENCR_DATA:
	free_encr_data( pkt->pkt.encr_data );
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


