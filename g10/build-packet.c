/* build-packet.c - assemble packets and write them
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
#include "errors.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"
#include "options.h"


static int do_comment( IOBUF out, int ctb, PKT_comment *rem );
static int do_user_id( IOBUF out, int ctb, PKT_user_id *uid );
static int do_pubkey_cert( IOBUF out, int ctb, PKT_pubkey_cert *pk );
static int do_seckey_cert( IOBUF out, int ctb, PKT_seckey_cert *pk );
static int do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc );
static u32 calc_plaintext( PKT_plaintext *pt );
static int do_plaintext( IOBUF out, int ctb, PKT_plaintext *pt );
static int do_encr_data( IOBUF out, int ctb, PKT_encr_data *ed );

static int calc_header_length( u32 len );
static int write_16(IOBUF inp, u16 a);
static int write_32(IOBUF inp, u32 a);
static int write_header( IOBUF out, int ctb, u32 len );
static int write_version( IOBUF out, int ctb );

/****************
 * Build a packet and write it to INP
 * Returns: 0 := okay
 *	   >0 := error
 * Note: Caller must free the packet
 */
int
build_packet( IOBUF out, PACKET *pkt )
{
    int rc=0, ctb;

    if( DBG_PACKET )
	log_debug("build_packet() type=%d\n", pkt->pkttype );
    assert( pkt->pkt.generic );
    ctb = 0x80 | ((pkt->pkttype & 15)<<2);
    switch( pkt->pkttype ) {
      case PKT_USER_ID:
	rc = do_user_id( out, ctb, pkt->pkt.user_id );
	break;
      case PKT_COMMENT:
	rc = do_comment( out, ctb, pkt->pkt.comment );
	break;
      case PKT_PUBKEY_CERT:
	rc = do_pubkey_cert( out, ctb, pkt->pkt.pubkey_cert );
	break;
      case PKT_SECKEY_CERT:
	rc = do_seckey_cert( out, ctb, pkt->pkt.seckey_cert );
	break;
      case PKT_PUBKEY_ENC:
	rc = do_pubkey_enc( out, ctb, pkt->pkt.pubkey_enc );
	break;
      case PKT_PLAINTEXT:
	rc = do_plaintext( out, ctb, pkt->pkt.plaintext );
	break;
      case PKT_ENCR_DATA:
	rc = do_encr_data( out, ctb, pkt->pkt.encr_data );
	break;
      case PKT_SIGNATURE:
      case PKT_RING_TRUST:
      case PKT_COMPR_DATA:
      default:
	log_bug("invalid packet type in build_packet()");
	break;
    }

    return rc;
}

/****************
 * calculate the length of a packet described by PKT
 */
u32
calc_packet_length( PACKET *pkt )
{
    u32 n=0;

    assert( pkt->pkt.generic );
    switch( pkt->pkttype ) {
      case PKT_PLAINTEXT:
	n = calc_plaintext( pkt->pkt.plaintext );
	break;
      case PKT_USER_ID:
      case PKT_COMMENT:
      case PKT_PUBKEY_CERT:
      case PKT_SECKEY_CERT:
      case PKT_PUBKEY_ENC:
      case PKT_ENCR_DATA:
      case PKT_SIGNATURE:
      case PKT_RING_TRUST:
      case PKT_COMPR_DATA:
      default:
	log_bug("invalid packet type in calc_packet_length()");
	break;
    }
    n += calc_header_length(n);
    return n;
}


static int
do_comment( IOBUF out, int ctb, PKT_comment *rem )
{
    write_header(out, ctb, rem->len);
    if( iobuf_write( out, rem->data, rem->len ) )
	return G10ERR_WRITE_FILE;
    return 0;
}

static int
do_user_id( IOBUF out, int ctb, PKT_user_id *uid )
{
    write_header(out, ctb, uid->len);
    if( iobuf_write( out, uid->name, uid->len ) )
	return G10ERR_WRITE_FILE;
    return 0;
}

static int
do_pubkey_cert( IOBUF out, int ctb, PKT_pubkey_cert *pkc )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    write_version( a, ctb );
    write_32(a, pkc->timestamp );
    write_16(a, pkc->valid_days );
    iobuf_put(a, pkc->pubkey_algo );
    if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_encode(a, pkc->d.rsa.rsa_n );
	mpi_encode(a, pkc->d.rsa.rsa_e );
    }
    else {
	rc = G10ERR_PUBKEY_ALGO;
	goto leave;
    }

    write_header(out, ctb, iobuf_get_temp_length(a) );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

  leave:
    iobuf_close(a);
    return rc;
}

static int
do_seckey_cert( IOBUF out, int ctb, PKT_seckey_cert *skc )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    write_version( a, ctb );
    write_32(a, skc->timestamp );
    write_16(a, skc->valid_days );
    iobuf_put(a, skc->pubkey_algo );
    if( skc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_encode(a, skc->d.rsa.rsa_n );
	mpi_encode(a, skc->d.rsa.rsa_e );
	iobuf_put(a, skc->d.rsa.protect_algo );
	skc->d.rsa.calc_csum = 0;
	if( skc->d.rsa.protect_algo ) {
	    assert( skc->d.rsa.is_protected == 1 );
	    assert( skc->d.rsa.protect_algo == CIPHER_ALGO_BLOWFISH );
	    iobuf_write(a, skc->d.rsa.protect.blowfish.iv, 8 );

	    mpi_write_csum(a, (byte*)skc->d.rsa.rsa_d, &skc->d.rsa.calc_csum );
	    mpi_write_csum(a, (byte*)skc->d.rsa.rsa_p, &skc->d.rsa.calc_csum );
	    mpi_write_csum(a, (byte*)skc->d.rsa.rsa_q, &skc->d.rsa.calc_csum );
	    mpi_write_csum(a, (byte*)skc->d.rsa.rsa_u, &skc->d.rsa.calc_csum );
	}
	else {	/* Not protected: You fool you! */
	    assert( !skc->d.rsa.is_protected );
	    mpi_encode_csum(a, skc->d.rsa.rsa_d, &skc->d.rsa.calc_csum );
	    mpi_encode_csum(a, skc->d.rsa.rsa_p, &skc->d.rsa.calc_csum );
	    mpi_encode_csum(a, skc->d.rsa.rsa_q, &skc->d.rsa.calc_csum );
	    mpi_encode_csum(a, skc->d.rsa.rsa_u, &skc->d.rsa.calc_csum );
	}

	write_16(a, skc->d.rsa.calc_csum );
    }
    else {
	rc = G10ERR_PUBKEY_ALGO;
	goto leave;
    }

    write_header(out, ctb, iobuf_get_temp_length(a) );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

  leave:
    iobuf_close(a);
    return rc;
}

static int
do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    write_version( a, ctb );
    write_32(a, enc->keyid[0] );
    write_32(a, enc->keyid[1] );
    iobuf_put(a,enc->pubkey_algo );
    if( enc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_encode(a, enc->d.rsa.rsa_integer );
    }
    else {
	rc = G10ERR_PUBKEY_ALGO;
	goto leave;
    }

    write_header(out, ctb, iobuf_get_temp_length(a) );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

  leave:
    iobuf_close(a);
    return rc;
}


static u32
calc_plaintext( PKT_plaintext *pt )
{
    return pt->len? (1 + 1 + pt->namelen + 4 + pt->len) : 0;
}

static int
do_plaintext( IOBUF out, int ctb, PKT_plaintext *pt )
{
    int c, i, rc = 0;
    u32 n;

    write_header(out, ctb, calc_plaintext( pt ) );
    iobuf_put(out, pt->mode );
    iobuf_put(out, pt->namelen );
    for(i=0; i < pt->namelen; i++ )
	iobuf_put(out, pt->name[i] );
    if( write_32(out, pt->timestamp ) )
	rc = G10ERR_WRITE_FILE;

    n = 0;
    while( (c=iobuf_get(pt->buf)) != -1 ) {
	if( iobuf_put(out, c) ) {
	    rc = G10ERR_WRITE_FILE;
	    break;
	}
	n++;
    }
    if( !pt->len )
	iobuf_set_block_mode(out, 0 ); /* write end marker */
    else if( n != pt->len )
	log_error("do_plaintext(): wrote %lu bytes but expected %lu bytes\n",
			(ulong)n, (ulong)pt->len );

    return rc;
}



static int
do_encr_data( IOBUF out, int ctb, PKT_encr_data *ed )
{
    int rc = 0;
    u32 n;

    n = ed->len ? (ed->len + 10) : 0;
    write_header(out, ctb, n );

    /* This is all. The caller has to write the real data */

    return rc;
}




static int
write_16(IOBUF out, u16 a)
{
    iobuf_put(out, a>>8);
    if( iobuf_put(out,a) )
	return -1;
    return 0;
}

static int
write_32(IOBUF out, u32 a)
{
    iobuf_put(out, a>> 24);
    iobuf_put(out, a>> 16);
    iobuf_put(out, a>> 8);
    if( iobuf_put(out, a) )
	return -1;
    return 0;
}


/****************
 * calculate the length of a header
 */
static int
calc_header_length( u32 len )
{
    if( !len )
	return 1; /* only the ctb */
    else if( len < 256 )
	return 2;
    else if( len < 65536 )
	return 3;
    else
	return 5;
}

/****************
 * Write the CTB and the packet length
 */
static int
write_header( IOBUF out, int ctb, u32 len )
{
    if( !len )
	ctb |= 3;
    else if( len < 256 )
	;
    else if( len < 65536 )
	ctb |= 1;
    else
	ctb |= 2;
    if( iobuf_put(out, ctb ) )
	return -1;
    if( !len ) {
	iobuf_set_block_mode(out, 5 /*8196*/ );
    }
    else {
	if( ctb & 2 ) {
	    iobuf_put(out, len >> 24 );
	    iobuf_put(out, len >> 16 );
	}
	if( ctb & 3 )
	    iobuf_put(out, len >> 8 );
	if( iobuf_put(out, len ) )
	    return -1;
    }
    return 0;
}

static int
write_version( IOBUF out, int ctb )
{
    if( iobuf_put( out, 3 ) )
	return -1;
    return 0;
}

