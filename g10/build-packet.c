/* build-packet.c - assemble packets and write them
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
#include "errors.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"
#include "options.h"


static int do_comment( IOBUF out, int ctb, PKT_comment *rem );
static int do_user_id( IOBUF out, int ctb, PKT_user_id *uid );
static int do_public_key( IOBUF out, int ctb, PKT_public_key *pk );
static int do_secret_key( IOBUF out, int ctb, PKT_secret_key *pk );
static int do_symkey_enc( IOBUF out, int ctb, PKT_symkey_enc *enc );
static int do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc );
static u32 calc_plaintext( PKT_plaintext *pt );
static int do_plaintext( IOBUF out, int ctb, PKT_plaintext *pt );
static int do_encrypted( IOBUF out, int ctb, PKT_encrypted *ed );
static int do_encrypted_mdc( IOBUF out, int ctb, PKT_encrypted *ed );
static int do_mdc( IOBUF out, PKT_mdc *mdc );
static int do_compressed( IOBUF out, int ctb, PKT_compressed *cd );
static int do_signature( IOBUF out, int ctb, PKT_signature *sig );
static int do_onepass_sig( IOBUF out, int ctb, PKT_onepass_sig *ops );

static int calc_header_length( u32 len, int new_ctb );
static int write_16(IOBUF inp, u16 a);
static int write_32(IOBUF inp, u32 a);
static int write_header( IOBUF out, int ctb, u32 len );
static int write_sign_packet_header( IOBUF out, int ctb, u32 len );
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
    int new_ctb=0, rc=0, ctb;
    int pkttype;

    if( DBG_PACKET )
	log_debug("build_packet() type=%d\n", pkt->pkttype );
    assert( pkt->pkt.generic );

    switch( (pkttype = pkt->pkttype) ) {
      case PKT_OLD_COMMENT: pkttype = pkt->pkttype = PKT_COMMENT; break;
      case PKT_PLAINTEXT: new_ctb = pkt->pkt.plaintext->new_ctb; break;
      case PKT_ENCRYPTED:
      case PKT_ENCRYPTED_MDC: new_ctb = pkt->pkt.encrypted->new_ctb; break;
      case PKT_COMPRESSED:new_ctb = pkt->pkt.compressed->new_ctb; break;
      case PKT_USER_ID:
	    if( pkt->pkt.user_id->photo )
		pkttype = PKT_PHOTO_ID;
	    break;
      default: break;
    }

    if( new_ctb || pkttype > 15 ) /* new format */
	ctb = 0xc0 | (pkttype & 0x3f);
    else
	ctb = 0x80 | ((pkttype & 15)<<2);
    switch( pkttype ) {
      case PKT_PHOTO_ID:
      case PKT_USER_ID:
	rc = do_user_id( out, ctb, pkt->pkt.user_id );
	break;
      case PKT_COMMENT:
	rc = do_comment( out, ctb, pkt->pkt.comment );
	break;
      case PKT_PUBLIC_SUBKEY:
      case PKT_PUBLIC_KEY:
	rc = do_public_key( out, ctb, pkt->pkt.public_key );
	break;
      case PKT_SECRET_SUBKEY:
      case PKT_SECRET_KEY:
	rc = do_secret_key( out, ctb, pkt->pkt.secret_key );
	break;
      case PKT_SYMKEY_ENC:
	rc = do_symkey_enc( out, ctb, pkt->pkt.symkey_enc );
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
      case PKT_ENCRYPTED_MDC:
	rc = do_encrypted_mdc( out, ctb, pkt->pkt.encrypted );
	break;
      case PKT_MDC:
	rc = do_mdc( out, pkt->pkt.mdc );
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
	break; /* ignore it */
      default:
	log_bug("invalid packet type in build_packet()\n");
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
    int new_ctb = 0;

    assert( pkt->pkt.generic );
    switch( pkt->pkttype ) {
      case PKT_PLAINTEXT:
	n = calc_plaintext( pkt->pkt.plaintext );
	new_ctb = pkt->pkt.plaintext->new_ctb;
	break;
      case PKT_PHOTO_ID:
      case PKT_USER_ID:
      case PKT_COMMENT:
      case PKT_PUBLIC_KEY:
      case PKT_SECRET_KEY:
      case PKT_SYMKEY_ENC:
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

    n += calc_header_length(n, new_ctb);
    return n;
}

static void
write_fake_data( IOBUF out, MPI a )
{
    if( a ) {
	int i;
	void *p;

	p = mpi_get_opaque( a, &i );
	iobuf_write( out, p, i );
    }
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
    if( uid->photo ) {
	write_header(out, ctb, uid->photolen);
	if( iobuf_write( out, uid->photo, uid->photolen ) )
	    return G10ERR_WRITE_FILE;
    }
    else {
	write_header(out, ctb, uid->len);
	if( iobuf_write( out, uid->name, uid->len ) )
	    return G10ERR_WRITE_FILE;
    }
    return 0;
}

static int
do_public_key( IOBUF out, int ctb, PKT_public_key *pk )
{
    int rc = 0;
    int n, i;
    IOBUF a = iobuf_temp();

    if( !pk->version )
	iobuf_put( a, 3 );
    else
	iobuf_put( a, pk->version );
    write_32(a, pk->timestamp );
    if( pk->version < 4 ) {
	u16 ndays;
	if( pk->expiredate )
	    ndays = (u16)((pk->expiredate - pk->timestamp) / 86400L);
	else
	    ndays = 0;
	write_16(a, ndays );
    }
    iobuf_put(a, pk->pubkey_algo );
    n = pubkey_get_npkey( pk->pubkey_algo );
    if( !n )
	write_fake_data( a, pk->pkey[0] );
    for(i=0; i < n; i++ )
	mpi_write(a, pk->pkey[i] );

    write_header2(out, ctb, iobuf_get_temp_length(a), pk->hdrbytes, 1 );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

    iobuf_close(a);
    return rc;
}


/****************
 * Make a hash value from the public key certificate
 */
void
hash_public_key( MD_HANDLE md, PKT_public_key *pk )
{
    PACKET pkt;
    int rc = 0;
    int ctb;
    ulong pktlen;
    int c;
    IOBUF a = iobuf_temp();
  #if 0
    FILE *fp = fopen("dump.pk", "a");
    int i=0;

    fprintf(fp, "\nHashing PK (v%d):\n", pk->version);
  #endif

    /* build the packet */
    init_packet(&pkt);
    pkt.pkttype = PKT_PUBLIC_KEY;
    pkt.pkt.public_key = pk;
    if( (rc = build_packet( a, &pkt )) )
	log_fatal("build public_key for hashing failed: %s\n", g10_errstr(rc));

    if( !(pk->version == 3 && pk->pubkey_algo == 16) ) {
	/* skip the constructed header but don't do this for our very old
	 * v3 ElG keys */
	ctb = iobuf_get_noeof(a);
	pktlen = 0;
	if( (ctb & 0x40) ) {
	    c = iobuf_get_noeof(a);
	    if( c < 192 )
		pktlen = c;
	    else if( c < 224 ) {
		pktlen = (c - 192) * 256;
		c = iobuf_get_noeof(a);
		pktlen += c + 192;
	    }
	    else if( c == 255 ) {
		pktlen	= iobuf_get_noeof(a) << 24;
		pktlen |= iobuf_get_noeof(a) << 16;
		pktlen |= iobuf_get_noeof(a) << 8;
		pktlen |= iobuf_get_noeof(a);
	    }
	}
	else {
	    int lenbytes = ((ctb&3)==3)? 0 : (1<<(ctb & 3));
	    for( ; lenbytes; lenbytes-- ) {
		pktlen <<= 8;
		pktlen |= iobuf_get_noeof(a);
	    }
	}
	/* hash a header */
	md_putc( md, 0x99 );
	pktlen &= 0xffff; /* can't handle longer packets */
	md_putc( md, pktlen >> 8 );
	md_putc( md, pktlen & 0xff );
    }
    /* hash the packet body */
    while( (c=iobuf_get(a)) != -1 ) {
      #if 0
	fprintf( fp," %02x", c );
	if( (++i == 24) ) {
	    putc('\n', fp);
	    i=0;
	}
      #endif
	md_putc( md, c );
    }
  #if 0
    putc('\n', fp);
    fclose(fp);
  #endif
    iobuf_cancel(a);
}


static int
do_secret_key( IOBUF out, int ctb, PKT_secret_key *sk )
{
    int rc = 0;
    int i, nskey, npkey;
    IOBUF a = iobuf_temp();

    if( !sk->version )
	iobuf_put( a, 3 );
    else
	iobuf_put( a, sk->version );
    write_32(a, sk->timestamp );
    if( sk->version < 4 ) {
	u16 ndays;
	if( sk->expiredate )
	    ndays = (u16)((sk->expiredate - sk->timestamp) / 86400L);
	else
	    ndays = 0;
	write_16(a, ndays);
    }
    iobuf_put(a, sk->pubkey_algo );
    nskey = pubkey_get_nskey( sk->pubkey_algo );
    npkey = pubkey_get_npkey( sk->pubkey_algo );
    if( !npkey ) {
	write_fake_data( a, sk->skey[0] );
	goto leave;
    }
    assert( npkey < nskey );

    for(i=0; i < npkey; i++ )
	mpi_write(a, sk->skey[i] );
    if( sk->is_protected ) {
	if( is_RSA(sk->pubkey_algo) && sk->version < 4
				    && !sk->protect.s2k.mode ) {
	    iobuf_put(a, sk->protect.algo );
	    iobuf_write(a, sk->protect.iv, sk->protect.ivlen );
	}
	else {
	    iobuf_put(a, 0xff );
	    iobuf_put(a, sk->protect.algo );
	    if( sk->protect.s2k.mode >= 1000 ) {
		iobuf_put(a, 101 );
		iobuf_put(a, sk->protect.s2k.hash_algo );
		iobuf_write(a, "GNU", 3 );
		iobuf_put(a, sk->protect.s2k.mode - 1000 );
	    }
	    else {
		iobuf_put(a, sk->protect.s2k.mode );
		iobuf_put(a, sk->protect.s2k.hash_algo );
	    }
	    if( sk->protect.s2k.mode == 1
		|| sk->protect.s2k.mode == 3 )
		iobuf_write(a, sk->protect.s2k.salt, 8 );
	    if( sk->protect.s2k.mode == 3 )
		iobuf_put(a, sk->protect.s2k.count );
	    if( sk->protect.s2k.mode != 1001 )
		iobuf_write(a, sk->protect.iv, sk->protect.ivlen );
	}
    }
    else
	iobuf_put(a, 0 );
    if( sk->protect.s2k.mode == 1001 )
	;
    else if( sk->is_protected && sk->version >= 4 ) {
	byte *p;
	assert( mpi_is_opaque( sk->skey[npkey] ) );
	p = mpi_get_opaque( sk->skey[npkey], &i );
	iobuf_write(a, p, i );
    }
    else {
	for(   ; i < nskey; i++ )
	    mpi_write(a, sk->skey[i] );
	write_16(a, sk->csum );
    }

  leave:
    write_header2(out, ctb, iobuf_get_temp_length(a), sk->hdrbytes, 1 );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

    iobuf_close(a);
    return rc;
}

static int
do_symkey_enc( IOBUF out, int ctb, PKT_symkey_enc *enc )
{
    int rc = 0;
    IOBUF a = iobuf_temp();

    assert( enc->version == 4 );
    switch( enc->s2k.mode ) {
      case 0: case 1: case 3: break;
      default: log_bug("do_symkey_enc: s2k=%d\n", enc->s2k.mode );
    }
    iobuf_put( a, enc->version );
    iobuf_put( a, enc->cipher_algo );
    iobuf_put( a, enc->s2k.mode );
    iobuf_put( a, enc->s2k.hash_algo );
    if( enc->s2k.mode == 1 || enc->s2k.mode == 3 ) {
	iobuf_write(a, enc->s2k.salt, 8 );
	if( enc->s2k.mode == 3 )
	    iobuf_put(a, enc->s2k.count);
    }
    if( enc->seskeylen )
	iobuf_write(a, enc->seskey, enc->seskeylen );

    write_header(out, ctb, iobuf_get_temp_length(a) );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

    iobuf_close(a);
    return rc;
}




static int
do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc )
{
    int rc = 0;
    int n, i;
    IOBUF a = iobuf_temp();

    write_version( a, ctb );
    if( enc->throw_keyid ) {
	write_32(a, 0 );  /* don't tell Eve who can decrypt the message */
	write_32(a, 0 );
    }
    else {
	write_32(a, enc->keyid[0] );
	write_32(a, enc->keyid[1] );
    }
    iobuf_put(a,enc->pubkey_algo );
    n = pubkey_get_nenc( enc->pubkey_algo );
    if( !n )
	write_fake_data( a, enc->data[0] );
    for(i=0; i < n; i++ )
	mpi_write(a, enc->data[i] );

    write_header(out, ctb, iobuf_get_temp_length(a) );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

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
    int i, rc = 0;
    u32 n;
    byte buf[1000]; /* this buffer has the plaintext! */
    int nbytes;

    write_header(out, ctb, calc_plaintext( pt ) );
    iobuf_put(out, pt->mode );
    iobuf_put(out, pt->namelen );
    for(i=0; i < pt->namelen; i++ )
	iobuf_put(out, pt->name[i] );
    if( write_32(out, pt->timestamp ) )
	rc = G10ERR_WRITE_FILE;

    n = 0;
    while( (nbytes=iobuf_read(pt->buf, buf, 1000)) != -1 ) {
	if( iobuf_write(out, buf, nbytes) == -1 ) {
	    rc = G10ERR_WRITE_FILE;
	    break;
	}
	n += nbytes;
    }
    memset(buf,0,1000); /* at least burn the buffer */
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

    n = ed->len ? (ed->len + ed->extralen) : 0;
    write_header(out, ctb, n );

    /* This is all. The caller has to write the real data */

    return rc;
}

static int
do_encrypted_mdc( IOBUF out, int ctb, PKT_encrypted *ed )
{
    int rc = 0;
    u32 n;

    assert( ed->mdc_method );

    n = ed->len ? (ed->len + ed->extralen) : 0;
    write_header(out, ctb, n );
    iobuf_put(out, 1 );  /* version */

    /* This is all. The caller has to write the real data */

    return rc;
}


static int
do_mdc( IOBUF out, PKT_mdc *mdc )
{
    /* This packet requires a fixed header encoding */
    iobuf_put( out, 0xd3 ); /* packet ID and 1 byte length */
    iobuf_put( out, 0x14 ); /* length = 20 */
    if( iobuf_write( out, mdc->hash, sizeof(mdc->hash) ) )
	return G10ERR_WRITE_FILE;
    return 0;
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



/****************
 * Find a subpacket of type REQTYPE in BUFFER and a return a pointer
 * to the first byte of that subpacket data.
 * And return the length of the packet in RET_N and the number of
 * header bytes in RET_HLEN (length header and type byte).
 */
byte *
find_subpkt( byte *buffer, sigsubpkttype_t reqtype,
	     size_t *ret_hlen, size_t *ret_n )
{
    int buflen;
    sigsubpkttype_t type;
    byte *bufstart;
    size_t n;

    if( !buffer )
	return NULL;
    buflen = (*buffer << 8) | buffer[1];
    buffer += 2;
    for(;;) {
	if( !buflen )
	    return NULL; /* end of packets; not found */
	bufstart = buffer;
	n = *buffer++; buflen--;
	if( n == 255 ) {
	    if( buflen < 4 )
		break;
	    n = (buffer[0] << 24) | (buffer[1] << 16)
				  | (buffer[2] << 8) | buffer[3];
	    buffer += 4;
	    buflen -= 4;
	}
	else if( n >= 192 ) {
	    if( buflen < 2 )
		break;
	    n = (( n - 192 ) << 8) + *buffer + 192;
	    buffer++;
	    buflen--;
	}
	if( buflen < n )
	    break;
	type = *buffer & 0x7f;
	if( type == reqtype ) {
	    buffer++;
	    n--;
	    if( n > buflen )
		break;
	    if( ret_hlen )
		*ret_hlen = buffer - bufstart;
	    if( ret_n )
		*ret_n = n;
	    return buffer;
	}
	buffer += n; buflen -=n;
    }

    log_error("find_subpkt: buffer shorter than subpacket\n");
    return NULL;
}

/****************
 * Delete all subpackets of type REQTYPE and return the number of bytes
 * which are now unused at the end of the buffer.
 */
size_t
delete_sig_subpkt( byte *buffer, sigsubpkttype_t reqtype )
{
    int buflen, orig_buflen;
    sigsubpkttype_t type;
    byte *bufstart, *orig_buffer;
    size_t n;
    size_t unused = 0;
    int okay = 0;

    if( !buffer )
	return 0;
    orig_buffer = buffer;
    buflen = (*buffer << 8) | buffer[1];
    buffer += 2;
    orig_buflen = buflen;
    for(;;) {
	if( !buflen ) {
            okay = 1;
            break;
        }
	bufstart = buffer;
	n = *buffer++; buflen--;
	if( n == 255 ) {
	    if( buflen < 4 )
		break;
	    n = (buffer[0] << 24) | (buffer[1] << 16)
				  | (buffer[2] << 8) | buffer[3];
	    buffer += 4;
	    buflen -= 4;
	}
	else if( n >= 192 ) {
	    if( buflen < 2 )
		break;
	    n = (( n - 192 ) << 8) + *buffer + 192;
	    buffer++;
	    buflen--;
	}
	if( buflen < n )
	    break;
	type = *buffer & 0x7f;
	if( type == reqtype ) {
	    buffer++;
            buflen--;
	    n--;
	    if( n > buflen )
		break;
            memmove (bufstart, buffer + n, n + (buffer-bufstart)); /* shift */
            unused += n + (buffer-bufstart);
            buffer = bufstart;
            buflen -= n;
	}
        else {
            buffer += n; buflen -=n;
        }
    }

    if (!okay)
        log_error("delete_subpkt: buffer shorter than subpacket\n");
    assert (unused <= orig_buflen);
    orig_buflen -= unused;
    orig_buffer[0] = (orig_buflen >> 8) & 0xff;
    orig_buffer[1] = orig_buflen & 0xff;
    return unused;
}


/****************
 * Create or update a signature subpacket for SIG of TYPE.
 * This functions knows where to put the data (hashed or unhashed).
 * The function may move data from the unhashed part to the hashed one.
 * Note: All pointers into sig->[un]hashed are not valid after a call
 * to this function.  The data to put into the subpaket should be
 * in buffer with a length of buflen.
 */
void
build_sig_subpkt( PKT_signature *sig, sigsubpkttype_t type,
		  const byte *buffer, size_t buflen )
{
    byte *data;
    size_t hlen, dlen, nlen;
    int found=0;
    int critical, hashed, realloced;
    size_t n, n0;
    size_t unused = 0;

    critical = (type & SIGSUBPKT_FLAG_CRITICAL);
    type &= ~SIGSUBPKT_FLAG_CRITICAL;

    if( type == SIGSUBPKT_NOTATION )
	; /* we allow multiple packets */
    else if( (data = find_subpkt( sig->hashed_data, type, &hlen, &dlen )) )
	found = 1;
    else if( (data = find_subpkt( sig->unhashed_data, type, &hlen, &dlen )))
	found = 2;

    if (found==2 && type == SIGSUBPKT_PRIV_VERIFY_CACHE) {
        unused = delete_sig_subpkt (sig->unhashed_data, type);
        assert (unused);
        found = 0;
    }

    if( found )
	log_bug("build_sig_packet: update nyi\n");
    if( (buflen+1) >= 8384 )
	nlen = 5;
    else if( (buflen+1) >= 192 )
	nlen = 2;
    else
	nlen = 1;

    switch( type ) {
      case SIGSUBPKT_SIG_CREATED:
      case SIGSUBPKT_PREF_SYM:
      case SIGSUBPKT_PREF_HASH:
      case SIGSUBPKT_PREF_COMPR:
      case SIGSUBPKT_KS_FLAGS:
      case SIGSUBPKT_KEY_EXPIRE:
      case SIGSUBPKT_NOTATION:
      case SIGSUBPKT_POLICY:
      case SIGSUBPKT_REVOC_REASON:
	       hashed = 1; break;
      default: hashed = 0; break;
    }

    if( hashed ) {
	n0 = sig->hashed_data ? ((*sig->hashed_data << 8)
				    | sig->hashed_data[1]) : 0;
	n = n0 + nlen + 1 + buflen; /* length, type, buffer */
	realloced = !!sig->hashed_data;
	data = sig->hashed_data ? m_realloc( sig->hashed_data, n+2 )
				: m_alloc( n+2 );
    }
    else {
	n0 = sig->unhashed_data ? ((*sig->unhashed_data << 8)
				      | sig->unhashed_data[1]) : 0;
	n = n0 + nlen + 1 + buflen; /* length, type, buffer */
        if ( sig->unhashed_data && (nlen + 1 + buflen) <= unused ) {
            /* does fit into the freed area */
            data = sig->unhashed_data;
            realloced = 1;
            log_debug ("updating area of type %d\n", type );
        }
        else {
            realloced = !!sig->unhashed_data;
            data = sig->unhashed_data ? m_realloc( sig->unhashed_data, n+2 )
                                      : m_alloc( n+2 );
        }
    }

    if( critical )
	type |= SIGSUBPKT_FLAG_CRITICAL;

    data[0] = (n >> 8) & 0xff;
    data[1] = n & 0xff;
    if( nlen == 5 ) {
	data[n0+2] = 255;
	data[n0+3] = (buflen+1) >> 24;
	data[n0+4] = (buflen+1) >> 16;
	data[n0+5] = (buflen+1) >>  8;
	data[n0+6] = (buflen+1);
	data[n0+7] = type;
	memcpy(data+n0+8, buffer, buflen );
    }
    else if( nlen == 2 ) {
	data[n0+2] = (buflen+1-192) / 256 + 192;
	data[n0+3] = (buflen+1-192) % 256;
	data[n0+4] = type;
	memcpy(data+n0+5, buffer, buflen );
    }
    else {
	data[n0+2] = buflen+1;
	data[n0+3] = type;
	memcpy(data+n0+4, buffer, buflen );
    }

    if( hashed ) {
	if( !realloced )
	    m_free(sig->hashed_data);
	sig->hashed_data = data;
    }
    else {
	if( !realloced )
	    m_free(sig->unhashed_data);
	sig->unhashed_data = data;
    }
}

/****************
 * Put all the required stuff from SIG into subpackets of sig.
 */
void
build_sig_subpkt_from_sig( PKT_signature *sig )
{
    u32  u;
    byte buf[8];

    u = sig->keyid[0];
    buf[0] = (u >> 24) & 0xff;
    buf[1] = (u >> 16) & 0xff;
    buf[2] = (u >>  8) & 0xff;
    buf[3] = u & 0xff;
    u = sig->keyid[1];
    buf[4] = (u >> 24) & 0xff;
    buf[5] = (u >> 16) & 0xff;
    buf[6] = (u >>  8) & 0xff;
    buf[7] = u & 0xff;
    build_sig_subpkt( sig, SIGSUBPKT_ISSUER, buf, 8 );

    u = sig->timestamp;
    buf[0] = (u >> 24) & 0xff;
    buf[1] = (u >> 16) & 0xff;
    buf[2] = (u >>  8) & 0xff;
    buf[3] = u & 0xff;
    build_sig_subpkt( sig, SIGSUBPKT_SIG_CREATED, buf, 4 );
}


static int
do_signature( IOBUF out, int ctb, PKT_signature *sig )
{
    int rc = 0;
    int n, i;
    IOBUF a = iobuf_temp();

    if( !sig->version )
	iobuf_put( a, 3 );
    else
	iobuf_put( a, sig->version );
    if( sig->version < 4 )
	iobuf_put(a, 5 ); /* constant */
    iobuf_put(a, sig->sig_class );
    if( sig->version < 4 ) {
	write_32(a, sig->timestamp );
	write_32(a, sig->keyid[0] );
	write_32(a, sig->keyid[1] );
    }
    iobuf_put(a, sig->pubkey_algo );
    iobuf_put(a, sig->digest_algo );
    if( sig->version >= 4 ) {
	size_t nn;
	/* timestamp and keyid must have been packed into the
	 * subpackets prior to the call of this function, because
	 * these subpackets are hashed */
	nn = sig->hashed_data?((sig->hashed_data[0]<<8)
				|sig->hashed_data[1])	:0;
	write_16(a, nn);
	if( nn )
	    iobuf_write( a, sig->hashed_data+2, nn );
	nn = sig->unhashed_data?((sig->unhashed_data[0]<<8)
				  |sig->unhashed_data[1])   :0;
	write_16(a, nn);
	if( nn )
	    iobuf_write( a, sig->unhashed_data+2, nn );
    }
    iobuf_put(a, sig->digest_start[0] );
    iobuf_put(a, sig->digest_start[1] );
    n = pubkey_get_nsig( sig->pubkey_algo );
    if( !n )
	write_fake_data( a, sig->data[0] );
    for(i=0; i < n; i++ )
	mpi_write(a, sig->data[i] );

    if( is_RSA(sig->pubkey_algo) && sig->version < 4 )
	write_sign_packet_header(out, ctb, iobuf_get_temp_length(a) );
    else
	write_header(out, ctb, iobuf_get_temp_length(a) );
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

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
calc_header_length( u32 len, int new_ctb )
{
    if( !len )
	return 1; /* only the ctb */

    if( new_ctb ) {
	if( len < 192 )
	    return 2;
	if( len < 8384 )
	    return 3;
	else
	    return 6;
    }
    if( len < 256 )
	return 2;
    if( len < 65536 )
	return 3;

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


static int
write_sign_packet_header( IOBUF out, int ctb, u32 len )
{
    /* work around a bug in the pgp read function for signature packets,
     * which are not correctly coded and silently assume at some
     * point 2 byte length headers.*/
    iobuf_put(out, 0x89 );
    iobuf_put(out, len >> 8 );
    return iobuf_put(out, len ) == -1 ? -1:0;
}

/****************
 * if HDRLEN is > 0, try to build a header of this length.
 * we need this, so that we can hash packets without reading them again.
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
	iobuf_set_partial_block_mode(out, 512 );
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
	else {
	    if( iobuf_put( out, 0xff ) )
		return -1;
	    if( iobuf_put( out, (len >> 24)&0xff ) )
		return -1;
	    if( iobuf_put( out, (len >> 16)&0xff ) )
		return -1;
	    if( iobuf_put( out, (len >> 8)&0xff )  )
		return -1;
	    if( iobuf_put( out, len & 0xff ) )
		return -1;
	}
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

