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
static int do_public_cert( IOBUF out, int ctb, PKT_public_cert *pk );
static int do_secret_cert( IOBUF out, int ctb, PKT_secret_cert *pk );
static int do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc );
static u32 calc_plaintext( PKT_plaintext *pt );
static int do_plaintext( IOBUF out, int ctb, PKT_plaintext *pt );
static int do_encrypted( IOBUF out, int ctb, PKT_encrypted *ed );
static int do_compressed( IOBUF out, int ctb, PKT_compressed *cd );
static int do_signature( IOBUF out, int ctb, PKT_signature *sig );
static int do_onepass_sig( IOBUF out, int ctb, PKT_onepass_sig *ops );

static int calc_header_length( u32 len );
static int write_16(IOBUF inp, u16 a);
static int write_32(IOBUF inp, u32 a);
static int write_header( IOBUF out, int ctb, u32 len );
static int write_header2( IOBUF out, int ctb, u32 len, int hdrlen, int blkmode );
static int write_new_header( IOBUF out, int ctb, u32 len, int hdrlen );
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
    if( pkt->pkttype > 15 ) /* new format */
	ctb = 0xc0 | (pkt->pkttype & 0x3f);
    else
	ctb = 0x80 | ((pkt->pkttype & 15)<<2);
    switch( pkt->pkttype ) {
      case PKT_USER_ID:
	rc = do_user_id( out, ctb, pkt->pkt.user_id );
	break;
      case PKT_COMMENT:
	rc = do_comment( out, ctb, pkt->pkt.comment );
	break;
      case PKT_PUBLIC_CERT:
	rc = do_public_cert( out, ctb, pkt->pkt.public_cert );
	break;
      case PKT_SECRET_CERT:
	rc = do_secret_cert( out, ctb, pkt->pkt.secret_cert );
	break;
      case PKT_PUBKEY_ENC:
	rc = do_pubkey_enc( out, ctb, pkt->pkt.pubkey_enc );
	break;
      case PKT_PLAINTEXT:
	rc = do_plaintext( out, ctb, pkt->pkt.plaintext );
	break;
      case PKT_ENCRYPTED:
	rc = do_encrypted( out, ctb, pkt->pkt.encrypted );
	break;
      case PKT_COMPRESSED:
	rc = do_compressed( out, ctb, pkt->pkt.compressed );
	break;
      case PKT_SIGNATURE:
	rc = do_signature( out, ctb, pkt->pkt.signature );
	break;
      case PKT_ONEPASS_SIG:
	rc = do_onepass_sig( out, ctb, pkt->pkt.onepass_sig );
	break;
      case PKT_RING_TRUST:
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
      case PKT_PUBLIC_CERT:
      case PKT_SECRET_CERT:
      case PKT_PUBKEY_ENC:
      case PKT_ENCRYPTED:
      case PKT_SIGNATURE:
      case PKT_ONEPASS_SIG:
      case PKT_RING_TRUST:
      case PKT_COMPRESSED:
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
    if( !opt.no_comment ) {
	write_header(out, ctb, rem->len);
	if( iobuf_write( out, rem->data, rem->len ) )
	    return G10ERR_WRITE_FILE;
    }
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
do_public_cert( IOBUF out, int ctb, PKT_public_cert *pkc )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    if( !pkc->version )
	iobuf_put( a, 3 );
    else
	iobuf_put( a, pkc->version );
    write_32(a, pkc->timestamp );
    write_16(a, pkc->valid_days );
    iobuf_put(a, pkc->pubkey_algo );
    if( pkc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	mpi_write(a, pkc->d.elg.p );
	mpi_write(a, pkc->d.elg.g );
	mpi_write(a, pkc->d.elg.y );
    }
    else if( pkc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_write(a, pkc->d.rsa.rsa_n );
	mpi_write(a, pkc->d.rsa.rsa_e );
    }
    else {
	rc = G10ERR_PUBKEY_ALGO;
	goto leave;
    }

    write_header2(out, ctb, iobuf_get_temp_length(a), pkc->hdrbytes, 1 );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

  leave:
    iobuf_close(a);
    return rc;
}


/****************
 * Make a hash value from the public key certificate
 */
void
hash_public_cert( MD_HANDLE md, PKT_public_cert *pkc )
{
    PACKET pkt;
    int rc = 0;
    int c;
    IOBUF a = iobuf_temp();
   /* FILE *fp = fopen("dump.pkc", "a");*/

    /* build the packet */
    init_packet(&pkt);
    pkt.pkttype = PKT_PUBLIC_CERT;
    pkt.pkt.public_cert = pkc;
    if( (rc = build_packet( a, &pkt )) )
	log_fatal("build public_cert for hashing failed: %s\n", g10_errstr(rc));
    while( (c=iobuf_get(a)) != -1 ) {
	/* putc( c, fp);*/
	md_putc( md, c );
    }
    /*fclose(fp);*/
    iobuf_cancel(a);
}


static int
do_secret_cert( IOBUF out, int ctb, PKT_secret_cert *skc )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    if( !skc->version )
	iobuf_put( a, 3 );
    else
	iobuf_put( a, skc->version );
    write_32(a, skc->timestamp );
    write_16(a, skc->valid_days );
    iobuf_put(a, skc->pubkey_algo );
    if( skc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	mpi_write(a, skc->d.elg.p );
	mpi_write(a, skc->d.elg.g );
	mpi_write(a, skc->d.elg.y );
	if( skc->d.elg.is_protected ) {
	    assert( skc->d.elg.protect_algo == CIPHER_ALGO_BLOWFISH );
	    iobuf_put(a, skc->d.elg.protect_algo );
	    iobuf_write(a, skc->d.elg.protect.blowfish.iv, 8 );
	}
	else
	    iobuf_put(a, 0 );

	mpi_write(a, skc->d.elg.x );
	write_16(a, skc->d.elg.csum );
    }
    else if( skc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_write(a, skc->d.rsa.rsa_n );
	mpi_write(a, skc->d.rsa.rsa_e );
	if( skc->d.rsa.is_protected ) {
	    assert( skc->d.rsa.protect_algo == CIPHER_ALGO_BLOWFISH );
	    iobuf_put(a, skc->d.rsa.protect_algo );
	    iobuf_write(a, skc->d.rsa.protect.blowfish.iv, 8 );
	}
	else
	    iobuf_put(a, 0 );
	mpi_write(a, skc->d.rsa.rsa_d );
	mpi_write(a, skc->d.rsa.rsa_p );
	mpi_write(a, skc->d.rsa.rsa_q );
	mpi_write(a, skc->d.rsa.rsa_u );
	write_16(a, skc->d.rsa.csum );
    }
    else {
	rc = G10ERR_PUBKEY_ALGO;
	goto leave;
    }

    write_header2(out, ctb, iobuf_get_temp_length(a), skc->hdrbytes, 1 );
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
    if( enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	mpi_write(a, enc->d.elg.a );
	mpi_write(a, enc->d.elg.b );
    }
    else if( enc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	mpi_write(a, enc->d.rsa.rsa_integer );
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
do_encrypted( IOBUF out, int ctb, PKT_encrypted *ed )
{
    int rc = 0;
    u32 n;

    n = ed->len ? (ed->len + 10) : 0;
    write_header(out, ctb, n );

    /* This is all. The caller has to write the real data */

    return rc;
}

static int
do_compressed( IOBUF out, int ctb, PKT_compressed *cd )
{
    int rc = 0;

    /* we must use the old convention and don't use blockmode */
    write_header2(out, ctb, 0, 0, 0 );
    iobuf_put(out, cd->algorithm );

    /* This is all. The caller has to write the real data */

    return rc;
}


static int
do_signature( IOBUF out, int ctb, PKT_signature *sig )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    write_version( a, ctb );
    iobuf_put(a, 5 ); /* constant */
    iobuf_put(a, sig->sig_class );
    write_32(a, sig->timestamp );
    write_32(a, sig->keyid[0] );
    write_32(a, sig->keyid[1] );
    iobuf_put(a, sig->pubkey_algo );
    if( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	iobuf_put(a, sig->d.elg.digest_algo );
	iobuf_put(a, sig->d.elg.digest_start[0] );
	iobuf_put(a, sig->d.elg.digest_start[1] );
	mpi_write(a, sig->d.elg.a );
	mpi_write(a, sig->d.elg.b );
    }
    else if( sig->pubkey_algo == PUBKEY_ALGO_RSA ) {
	iobuf_put(a, sig->d.rsa.digest_algo );
	iobuf_put(a, sig->d.rsa.digest_start[0] );
	iobuf_put(a, sig->d.rsa.digest_start[1] );
	mpi_write(a, sig->d.rsa.rsa_integer );
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
do_onepass_sig( IOBUF out, int ctb, PKT_onepass_sig *ops )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    write_version( a, ctb );
    iobuf_put(a, ops->sig_class );
    iobuf_put(a, ops->digest_algo );
    iobuf_put(a, ops->pubkey_algo );
    write_32(a, ops->keyid[0] );
    write_32(a, ops->keyid[1] );
    iobuf_put(a, ops->last );

    write_header(out, ctb, iobuf_get_temp_length(a) );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

    iobuf_close(a);
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
    return write_header2( out, ctb, len, 0, 1 );
}

/****************
 * if HDRLEN is > 0, try to build a header of this length.
 * we need this, so hat we can hash packets without reading them again.
 */
static int
write_header2( IOBUF out, int ctb, u32 len, int hdrlen, int blkmode )
{
    if( ctb & 0x40 )
	return write_new_header( out, ctb, len, hdrlen );

    if( hdrlen ) {
	if( !len )
	    ctb |= 3;
	else if( hdrlen == 2 && len < 256 )
	    ;
	else if( hdrlen == 3 && len < 65536 )
	    ctb |= 1;
	else
	    ctb |= 2;
    }
    else {
	if( !len )
	    ctb |= 3;
	else if( len < 256 )
	    ;
	else if( len < 65536 )
	    ctb |= 1;
	else
	    ctb |= 2;
    }
    if( iobuf_put(out, ctb ) )
	return -1;
    if( !len ) {
	if( blkmode )
	    iobuf_set_block_mode(out, 8196 );
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
write_new_header( IOBUF out, int ctb, u32 len, int hdrlen )
{
    if( hdrlen )
	log_bug("can't cope with hdrlen yet\n");

    if( iobuf_put(out, ctb ) )
	return -1;
    if( !len ) {
	log_bug("can't write partial headers yet\n");
    }
    else {
	if( len < 192 ) {
	    if( iobuf_put(out, len ) )
		return -1;
	}
	else if( len < 8384 ) {
	    len -= 192;
	    if( iobuf_put( out, (len / 256) + 192) )
		return -1;
	    if( iobuf_put( out, (len % 256) )  )
		return -1;
	}
	else
	    log_bug("need a partial header to code a length %lu\n", (ulong)len);
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

