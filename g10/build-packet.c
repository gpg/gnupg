/* build-packet.c - assemble packets and write them
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 *               2006 Free Software Foundation, Inc.
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
#include <assert.h>
#include <ctype.h>

#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"
#include "i18n.h"
#include "options.h"

static int do_user_id( IOBUF out, int ctb, PKT_user_id *uid );
static int do_public_key( IOBUF out, int ctb, PKT_public_key *pk );
static int do_secret_key( IOBUF out, int ctb, PKT_secret_key *pk );
static int do_symkey_enc( IOBUF out, int ctb, PKT_symkey_enc *enc );
static int do_pubkey_enc( IOBUF out, int ctb, PKT_pubkey_enc *enc );
static u32 calc_plaintext( PKT_plaintext *pt );
static int do_plaintext( IOBUF out, int ctb, PKT_plaintext *pt );
static int do_encrypted( IOBUF out, int ctb, PKT_encrypted *ed );
static int do_encrypted_mdc( IOBUF out, int ctb, PKT_encrypted *ed );
static int do_compressed( IOBUF out, int ctb, PKT_compressed *cd );
static int do_signature( IOBUF out, int ctb, PKT_signature *sig );
static int do_onepass_sig( IOBUF out, int ctb, PKT_onepass_sig *ops );

static int calc_header_length( u32 len, int new_ctb );
static int write_16(IOBUF inp, u16 a);
static int write_32(IOBUF inp, u32 a);
static int write_header( IOBUF out, int ctb, u32 len );
static int write_sign_packet_header( IOBUF out, int ctb, u32 len );
static int write_header2( IOBUF out, int ctb, u32 len, int hdrlen );
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

    switch( (pkttype = pkt->pkttype) )
      {
      case PKT_PLAINTEXT: new_ctb = pkt->pkt.plaintext->new_ctb; break;
      case PKT_ENCRYPTED:
      case PKT_ENCRYPTED_MDC: new_ctb = pkt->pkt.encrypted->new_ctb; break;
      case PKT_COMPRESSED:new_ctb = pkt->pkt.compressed->new_ctb; break;
      case PKT_USER_ID:
	if( pkt->pkt.user_id->attrib_data )
	  pkttype = PKT_ATTRIBUTE;
	break;
      default: break;
      }

    if( new_ctb || pkttype > 15 ) /* new format */
	ctb = 0xc0 | (pkttype & 0x3f);
    else
	ctb = 0x80 | ((pkttype & 15)<<2);
    switch( pkttype )
      {
      case PKT_ATTRIBUTE:
      case PKT_USER_ID:
	rc = do_user_id( out, ctb, pkt->pkt.user_id );
	break;
      case PKT_OLD_COMMENT:
      case PKT_COMMENT:
	/*
	  Ignore these.  Theoretically, this will never be called as
	  we have no way to output comment packets any longer, but
	  just in case there is some code path that would end up
	  outputting a comment that was written before comments were
	  dropped (in the public key?) this is a no-op.
	*/
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
	break; /* ignore it (keyring.c does write it directly)*/
      case PKT_MDC: /* we write it directly, so we should never see it here. */
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
      case PKT_ATTRIBUTE:
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
        unsigned int i;
	void *p;

	p = mpi_get_opaque( a, &i );
	iobuf_write( out, p, i );
    }
}

static int
do_user_id( IOBUF out, int ctb, PKT_user_id *uid )
{
    if( uid->attrib_data )
      {
	write_header(out, ctb, uid->attrib_len);
	if( iobuf_write( out, uid->attrib_data, uid->attrib_len ) )
	  return G10ERR_WRITE_FILE;
      }
    else
      {
        write_header2( out, ctb, uid->len, 2 );
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

    write_header2(out, ctb, iobuf_get_temp_length(a), pk->hdrbytes);
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

    iobuf_close(a);
    return rc;
}


static int
do_secret_key( IOBUF out, int ctb, PKT_secret_key *sk )
{
    int rc = 0;
    int i, nskey, npkey;
    IOBUF a = iobuf_temp(); /* build in a self-enlarging buffer */

    /* Write the version number - if none is specified, use 3 */
    if( !sk->version )
	iobuf_put( a, 3 );
    else
	iobuf_put( a, sk->version );
    write_32(a, sk->timestamp );

    /* v3  needs the expiration time */
    if( sk->version < 4 ) {
	u16 ndays;
	if( sk->expiredate )
	    ndays = (u16)((sk->expiredate - sk->timestamp) / 86400L);
	else
	    ndays = 0;
	write_16(a, ndays);
    }

    iobuf_put(a, sk->pubkey_algo );

    /* get number of secret and public parameters.  They are held in
       one array first the public ones, then the secret ones */
    nskey = pubkey_get_nskey( sk->pubkey_algo );
    npkey = pubkey_get_npkey( sk->pubkey_algo );

    /* If we don't have any public parameters - which is the case if
       we don't know the algorithm used - the parameters are stored as
       one blob in a faked (opaque) MPI */
    if( !npkey ) {
	write_fake_data( a, sk->skey[0] );
	goto leave;
    }
    assert( npkey < nskey );

    /* Writing the public parameters is easy */
    for(i=0; i < npkey; i++ )
	mpi_write(a, sk->skey[i] );

    /* build the header for protected (encrypted) secret parameters */
    if( sk->is_protected ) {
	if( is_RSA(sk->pubkey_algo) && sk->version < 4
				    && !sk->protect.s2k.mode ) {
            /* the simple rfc1991 (v3) way */
	    iobuf_put(a, sk->protect.algo );
	    iobuf_write(a, sk->protect.iv, sk->protect.ivlen );
	}
	else {
          /* OpenPGP protection according to rfc2440 */
	    iobuf_put(a, sk->protect.sha1chk? 0xfe : 0xff );
	    iobuf_put(a, sk->protect.algo );
	    if( sk->protect.s2k.mode >= 1000 ) {
                /* These modes are not possible in OpenPGP, we use them
                   to implement our extensions, 101 can be seen as a
                   private/experimental extension (this is not
                   specified in rfc2440 but the same scheme is used
                   for all other algorithm identifiers) */
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

            /* For out special modes 1001, 1002 we do not need an IV */
	    if( sk->protect.s2k.mode != 1001 
              && sk->protect.s2k.mode != 1002 )
		iobuf_write(a, sk->protect.iv, sk->protect.ivlen );
	}
    }
    else
	iobuf_put(a, 0 );

    if( sk->protect.s2k.mode == 1001 )
        ; /* GnuPG extension - don't write a secret key at all */ 
    else if( sk->protect.s2k.mode == 1002 )
      {  /* GnuPG extension - divert to OpenPGP smartcard. */ 
	iobuf_put(a, sk->protect.ivlen ); /* length of the serial
                                             number or 0 for no serial
                                             number. */
        /* The serial number gets stored in the IV field. */
        iobuf_write(a, sk->protect.iv, sk->protect.ivlen);
      }
    else if( sk->is_protected && sk->version >= 4 ) {
        /* The secret key is protected - write it out as it is */
	byte *p;
	unsigned int ndata;

	assert( mpi_is_opaque( sk->skey[npkey] ) );
	p = mpi_get_opaque( sk->skey[npkey], &ndata );
	iobuf_write(a, p, ndata );
    }
    else if( sk->is_protected ) {
        /* The secret key is protected te old v4 way. */
	for(   ; i < nskey; i++ ) {
            byte *p;
            unsigned int ndata;

            assert (mpi_is_opaque (sk->skey[i]));
            p = mpi_get_opaque (sk->skey[i], &ndata);
            iobuf_write (a, p, ndata);
        }
	write_16(a, sk->csum );
    }
    else {
        /* non-protected key */
	for(   ; i < nskey; i++ )
	    mpi_write(a, sk->skey[i] );
	write_16(a, sk->csum );
    }

  leave:
    /* Build the header of the packet - which we must do after writing all
       the other stuff, so that we know the length of the packet */
    write_header2(out, ctb, iobuf_get_temp_length(a), sk->hdrbytes);
    /* And finally write it out the real stream */
    if( iobuf_write_temp( out, a ) )
	rc = G10ERR_WRITE_FILE;

    iobuf_close(a); /* close the remporary buffer */
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
  /* Truncate namelen to the maximum 255 characters.  Note this means
     that a function that calls build_packet with an illegal literal
     packet will get it back legalized. */

  if(pt->namelen>255)
    pt->namelen=255;

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
    wipememory(buf,1000); /* burn the buffer */
    if( (ctb&0x40) && !pt->len )
      iobuf_set_partial_block_mode(out, 0 ); /* turn off partial */
    if( pt->len && n != pt->len )
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

    /* Take version number and the following MDC packet in account. */
    n = ed->len ? (ed->len + ed->extralen + 1 + 22) : 0;
    write_header(out, ctb, n );
    iobuf_put(out, 1 );  /* version */

    /* This is all. The caller has to write the real data */

    return rc;
}


static int
do_compressed( IOBUF out, int ctb, PKT_compressed *cd )
{
    int rc = 0;

    /* We must use the old convention and don't use blockmode for tyhe
       sake of PGP 2 compatibility.  However if the new_ctb flag was
       set, CTB is already formatted as new style and write_header2
       does create a partial length encoding using new the new
       style. */
    write_header2(out, ctb, 0, 0);
    iobuf_put(out, cd->algorithm );

    /* This is all. The caller has to write the real data */

    return rc;
}


/****************
 * Delete all subpackets of type REQTYPE and return a bool whether a packet
 * was deleted.
 */
int
delete_sig_subpkt (subpktarea_t *area, sigsubpkttype_t reqtype )
{
    int buflen;
    sigsubpkttype_t type;
    byte *buffer, *bufstart;
    size_t n;
    size_t unused = 0;
    int okay = 0;

    if( !area )
	return 0;
    buflen = area->len;
    buffer = area->data;
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
            buffer += n; /* point to next subpkt */
            buflen -= n;
            memmove (bufstart, buffer, buflen); /* shift */
            unused +=  buffer - bufstart;
            buffer = bufstart;
	}
        else {
            buffer += n; buflen -=n;
        }
    }

    if (!okay)
        log_error ("delete_subpkt: buffer shorter than subpacket\n");
    assert (unused <= area->len);
    area->len -= unused;
    return !!unused;
}


/****************
 * Create or update a signature subpacket for SIG of TYPE.  This
 * functions knows where to put the data (hashed or unhashed).  The
 * function may move data from the unhashed part to the hashed one.
 * Note: All pointers into sig->[un]hashed (e.g. returned by
 * parse_sig_subpkt) are not valid after a call to this function.  The
 * data to put into the subpaket should be in a buffer with a length
 * of buflen. 
 */
void
build_sig_subpkt (PKT_signature *sig, sigsubpkttype_t type,
		  const byte *buffer, size_t buflen )
{
    byte *p;
    int critical, hashed;
    subpktarea_t *oldarea, *newarea;
    size_t nlen, n, n0;

    critical = (type & SIGSUBPKT_FLAG_CRITICAL);
    type &= ~SIGSUBPKT_FLAG_CRITICAL;

    /* Sanity check buffer sizes */
    if(parse_one_sig_subpkt(buffer,buflen,type)<0)
      BUG();

    switch(type)
      {
      case SIGSUBPKT_NOTATION:
      case SIGSUBPKT_POLICY:
      case SIGSUBPKT_REV_KEY:
      case SIGSUBPKT_SIGNATURE:
	/* we do allow multiple subpackets */
	break;

      default:
	/* we don't allow multiple subpackets */
	delete_sig_subpkt(sig->hashed,type);
	delete_sig_subpkt(sig->unhashed,type);
	break;
      }

    /* Any special magic that needs to be done for this type so the
       packet doesn't need to be reparsed? */
    switch(type)
      {
      case SIGSUBPKT_NOTATION:
	sig->flags.notation=1;
	break;

      case SIGSUBPKT_POLICY:
	sig->flags.policy_url=1;
	break;

      case SIGSUBPKT_PREF_KS:
	sig->flags.pref_ks=1;
	break;

      case SIGSUBPKT_EXPORTABLE:
	if(buffer[0])
	  sig->flags.exportable=1;
	else
	  sig->flags.exportable=0;
	break;

      case SIGSUBPKT_REVOCABLE:
	if(buffer[0])
	  sig->flags.revocable=1;
	else
	  sig->flags.revocable=0;
	break;

      case SIGSUBPKT_TRUST:
	sig->trust_depth=buffer[0];
	sig->trust_value=buffer[1];
	break;

      case SIGSUBPKT_REGEXP:
	sig->trust_regexp=buffer;
	break;

	/* This should never happen since we don't currently allow
	   creating such a subpacket, but just in case... */
      case SIGSUBPKT_SIG_EXPIRE:
	if(buffer_to_u32(buffer)+sig->timestamp<=make_timestamp())
	  sig->flags.expired=1;
	else
	  sig->flags.expired=0;
	break;

      default:
	break;
      }

    if( (buflen+1) >= 8384 )
	nlen = 5; /* write 5 byte length header */
    else if( (buflen+1) >= 192 )
	nlen = 2; /* write 2 byte length header */
    else
	nlen = 1; /* just a 1 byte length header */

    switch( type )
      {
	/* The issuer being unhashed is a historical oddity.  It
	   should work equally as well hashed.  Of course, if even an
	   unhashed issuer is tampered with, it makes it awfully hard
	   to verify the sig... */
      case SIGSUBPKT_ISSUER:
      case SIGSUBPKT_SIGNATURE:
        hashed = 0;
        break;
      default: 
        hashed = 1;
        break;
      }

    if( critical )
	type |= SIGSUBPKT_FLAG_CRITICAL;

    oldarea = hashed? sig->hashed : sig->unhashed;

    /* Calculate new size of the area and allocate */
    n0 = oldarea? oldarea->len : 0;
    n = n0 + nlen + 1 + buflen; /* length, type, buffer */
    if (oldarea && n <= oldarea->size) { /* fits into the unused space */
        newarea = oldarea;
        /*log_debug ("updating area for type %d\n", type );*/
    }
    else if (oldarea) {
        newarea = xrealloc (oldarea, sizeof (*newarea) + n - 1);
        newarea->size = n;
        /*log_debug ("reallocating area for type %d\n", type );*/
    }
    else {
        newarea = xmalloc (sizeof (*newarea) + n - 1);
        newarea->size = n;
        /*log_debug ("allocating area for type %d\n", type );*/
    }
    newarea->len = n;

    p = newarea->data + n0;
    if (nlen == 5) {
	*p++ = 255;
	*p++ = (buflen+1) >> 24;
	*p++ = (buflen+1) >> 16;
	*p++ = (buflen+1) >>  8;
	*p++ = (buflen+1);
	*p++ = type;
	memcpy (p, buffer, buflen);
    }
    else if (nlen == 2) {
	*p++ = (buflen+1-192) / 256 + 192;
	*p++ = (buflen+1-192) % 256;
	*p++ = type;
	memcpy (p, buffer, buflen);
    }
    else {
	*p++ = buflen+1;
	*p++ = type;
	memcpy (p, buffer, buflen);
    }

    if (hashed) 
	sig->hashed = newarea;
    else
	sig->unhashed = newarea;
}

/****************
 * Put all the required stuff from SIG into subpackets of sig.
 * Hmmm, should we delete those subpackets which are in a wrong area?
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

    if(sig->expiredate)
      {
	if(sig->expiredate>sig->timestamp)
	  u=sig->expiredate-sig->timestamp;
	else
	  u=1; /* A 1-second expiration time is the shortest one
		  OpenPGP has */

	buf[0] = (u >> 24) & 0xff;
	buf[1] = (u >> 16) & 0xff;
	buf[2] = (u >>  8) & 0xff;
	buf[3] = u & 0xff;

	/* Mark this CRITICAL, so if any implementation doesn't
           understand sigs that can expire, it'll just disregard this
           sig altogether. */

	build_sig_subpkt( sig, SIGSUBPKT_SIG_EXPIRE | SIGSUBPKT_FLAG_CRITICAL,
			  buf, 4 );
      }
}

void
build_attribute_subpkt(PKT_user_id *uid,byte type,
		       const void *buf,u32 buflen,
		       const void *header,u32 headerlen)
{
  byte *attrib;
  int idx;

  if(1+headerlen+buflen>8383)
    idx=5;
  else if(1+headerlen+buflen>191)
    idx=2;
  else
    idx=1;

  /* realloc uid->attrib_data to the right size */

  uid->attrib_data=xrealloc(uid->attrib_data,
			     uid->attrib_len+idx+1+headerlen+buflen);

  attrib=&uid->attrib_data[uid->attrib_len];

  if(idx==5)
    {
      attrib[0]=255;
      attrib[1]=(1+headerlen+buflen) >> 24;
      attrib[2]=(1+headerlen+buflen) >> 16;
      attrib[3]=(1+headerlen+buflen) >> 8;
      attrib[4]=1+headerlen+buflen;
    }
  else if(idx==2)
    {
      attrib[0]=(1+headerlen+buflen-192) / 256 + 192;
      attrib[1]=(1+headerlen+buflen-192) % 256;
    }
  else
    attrib[0]=1+headerlen+buflen; /* Good luck finding a JPEG this small! */

  attrib[idx++]=type;

  /* Tack on our data at the end */

  if(headerlen>0)
    memcpy(&attrib[idx],header,headerlen);
  memcpy(&attrib[idx+headerlen],buf,buflen);
  uid->attrib_len+=idx+headerlen+buflen;
}

struct notation *
string_to_notation(const char *string,int is_utf8)
{
  const char *s;
  int saw_at=0;
  struct notation *notation;

  notation=xmalloc_clear(sizeof(*notation));

  if(*string=='-')
    {
      notation->flags.ignore=1;
      string++;
    }

  if(*string=='!')
    {
      notation->flags.critical=1;
      string++;
    }

  /* If and when the IETF assigns some official name tags, we'll have
     to add them here. */

  for( s=string ; *s != '='; s++ )
    {
      if( *s=='@')
	saw_at++;

      /* -notationname is legal without an = sign */
      if(!*s && notation->flags.ignore)
	break;

      if( !*s || !isascii (*s) || (!isgraph(*s) && !isspace(*s)) )
	{
	  log_error(_("a notation name must have only printable characters"
		      " or spaces, and end with an '='\n") );
	  goto fail;
	}
    }

  notation->name=xmalloc((s-string)+1);
  strncpy(notation->name,string,s-string);
  notation->name[s-string]='\0';

  if(!saw_at && !opt.expert)
    {
      log_error(_("a user notation name must contain the '@' character\n"));
      goto fail;
    }

  if (saw_at > 1)
    {
      log_error(_("a notation name must not contain more than"
		  " one '@' character\n"));
      goto fail;
    }

  if(*s)
    {
      const char *i=s+1;
      int highbit=0;

      /* we only support printable text - therefore we enforce the use
	 of only printable characters (an empty value is valid) */
      for(s++; *s ; s++ )
	{
	  if ( !isascii (*s) )
	    highbit=1;
	  else if (iscntrl(*s))
	    {
	      log_error(_("a notation value must not use any"
			  " control characters\n"));
	      goto fail;
	    }
	}

      if(!highbit || is_utf8)
	notation->value=xstrdup(i);
      else
	notation->value=native_to_utf8(i);
    }

  return notation;

 fail:
  free_notation(notation);
  return NULL;
}

struct notation *
sig_to_notation(PKT_signature *sig)
{
  const byte *p;
  size_t len;
  int seq=0,crit;
  struct notation *list=NULL;

  while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION,&len,&seq,&crit)))
    {
      int n1,n2;
      struct notation *n=NULL;

      if(len<8)
	{
	  log_info(_("WARNING: invalid notation data found\n"));
	  continue;
	}

      n1=(p[4]<<8)|p[5];
      n2=(p[6]<<8)|p[7];

      if(8+n1+n2!=len)
	{
	  log_info(_("WARNING: invalid notation data found\n"));
	  continue;
	}

      n=xmalloc_clear(sizeof(*n));
      n->name=xmalloc(n1+1);

      memcpy(n->name,&p[8],n1);
      n->name[n1]='\0';

      if(p[0]&0x80)
	{
	  n->value=xmalloc(n2+1);
	  memcpy(n->value,&p[8+n1],n2);
	  n->value[n2]='\0';
	}
      else
	{
	  n->bdat=xmalloc(n2);
	  n->blen=n2;
	  memcpy(n->bdat,&p[8+n1],n2);

	  n->value=xmalloc(2+strlen(_("not human readable"))+2+1);
	  strcpy(n->value,"[ ");
	  strcat(n->value,_("not human readable"));
	  strcat(n->value," ]");
	}

      n->flags.critical=crit;

      n->next=list;
      list=n;
    }

  return list;
}

void
free_notation(struct notation *notation)
{
  while(notation)
    {
      struct notation *n=notation;

      xfree(n->name);
      xfree(n->value);
      xfree(n->altvalue);
      xfree(n->bdat);
      notation=n->next;
      xfree(n);
    }
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
	nn = sig->hashed? sig->hashed->len : 0;
	write_16(a, nn);
	if( nn )
	    iobuf_write( a, sig->hashed->data, nn );
	nn = sig->unhashed? sig->unhashed->len : 0;
	write_16(a, nn);
	if( nn )
	    iobuf_write( a, sig->unhashed->data, nn );
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
    return write_header2( out, ctb, len, 0 );
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
 * If HDRLEN is > 0, try to build a header of this length.  We need
 * this so that we can hash packets without reading them again.  If
 * len is 0, write a partial or indeterminate length header, unless
 * hdrlen is specified in which case write an actual zero length
 * (using the specified hdrlen).
 */
static int
write_header2( IOBUF out, int ctb, u32 len, int hdrlen )
{
  if( ctb & 0x40 )
    return write_new_header( out, ctb, len, hdrlen );

  if( hdrlen )
    {
      if( hdrlen == 2 && len < 256 )
	;
      else if( hdrlen == 3 && len < 65536 )
	ctb |= 1;
      else
	ctb |= 2;
    }
  else
    {
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

  if( len || hdrlen )
    {
      if( ctb & 2 )
	{
	  if(iobuf_put(out, len >> 24 ))
	    return -1;
	  if(iobuf_put(out, len >> 16 ))
	    return -1;
	}

      if( ctb & 3 )
	if(iobuf_put(out, len >> 8 ))
	  return -1;

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
