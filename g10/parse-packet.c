/* parse-packet.c  - read packets
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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

#include "packet.h"
#include "iobuf.h"
#include "mpi.h"
#include "util.h"
#include "cipher.h"
#include "memory.h"
#include "filter.h"
#include "photoid.h"
#include "options.h"
#include "main.h"
#include "i18n.h"

#ifndef MAX_EXTERN_MPI_BITS
#define MAX_EXTERN_MPI_BITS 16384
#endif


static int mpi_print_mode;
static int list_mode;
static FILE *listfp;

static int  parse( IOBUF inp, PACKET *pkt, int onlykeypkts,
                  off_t *retpos, int *skip, IOBUF out, int do_skip
#ifdef DEBUG_PARSE_PACKET
		   ,const char *dbg_w, const char *dbg_f, int dbg_l
#endif
		 );
static int  copy_packet( IOBUF inp, IOBUF out, int pkttype,
			 unsigned long pktlen, int partial );
static void skip_packet( IOBUF inp, int pkttype,
			 unsigned long pktlen, int partial );
static void *read_rest( IOBUF inp, size_t pktlen, int partial );
static int  parse_marker( IOBUF inp, int pkttype, unsigned long pktlen );
static int  parse_symkeyenc( IOBUF inp, int pkttype, unsigned long pktlen,
							     PACKET *packet );
static int  parse_pubkeyenc( IOBUF inp, int pkttype, unsigned long pktlen,
							     PACKET *packet );
static int  parse_onepass_sig( IOBUF inp, int pkttype, unsigned long pktlen,
							PKT_onepass_sig *ops );
static int  parse_key( IOBUF inp, int pkttype, unsigned long pktlen,
				      byte *hdr, int hdrlen, PACKET *packet );
static int  parse_user_id( IOBUF inp, int pkttype, unsigned long pktlen,
							   PACKET *packet );
static int  parse_attribute( IOBUF inp, int pkttype, unsigned long pktlen,
							   PACKET *packet );
static int  parse_comment( IOBUF inp, int pkttype, unsigned long pktlen,
							   PACKET *packet );
static void parse_trust( IOBUF inp, int pkttype, unsigned long pktlen,
							   PACKET *packet );
static int  parse_plaintext( IOBUF inp, int pkttype, unsigned long pktlen,
			     PACKET *packet, int new_ctb, int partial);
static int  parse_compressed( IOBUF inp, int pkttype, unsigned long pktlen,
					       PACKET *packet, int new_ctb );
static int  parse_encrypted( IOBUF inp, int pkttype, unsigned long pktlen,
			     PACKET *packet, int new_ctb, int partial);
static int  parse_mdc( IOBUF inp, int pkttype, unsigned long pktlen,
					       PACKET *packet, int new_ctb);
static int  parse_gpg_control( IOBUF inp, int pkttype, unsigned long pktlen,
                               PACKET *packet, int partial );

static unsigned short
read_16(IOBUF inp)
{
    unsigned short a;
    a = iobuf_get_noeof(inp) << 8;
    a |= iobuf_get_noeof(inp);
    return a;
}

static unsigned long
read_32(IOBUF inp)
{
    unsigned long a;
    a =  iobuf_get_noeof(inp) << 24;
    a |= iobuf_get_noeof(inp) << 16;
    a |= iobuf_get_noeof(inp) << 8;
    a |= iobuf_get_noeof(inp);
    return a;
}


int
set_packet_list_mode( int mode )
{
    int old = list_mode;
    list_mode = mode;
    mpi_print_mode = DBG_MPI;
    /* We use stdout print only if invoked by the --list-packets
       command but switch to stderr in all otehr cases.  This breaks
       the previous behaviour but that seems to be more of a bug than
       intentional.  I don't believe that any application makes use of
       this long standing annoying way of printing to stdout except
       when doing a --list-packets. If this assumption fails, it will
       be easy to add an option for the listing stream.  Note that we
       initialize it only once; mainly because some code may switch
       the option value later back to 1 and we want to have all output
       to the same stream.  

       Using stderr is not actually very clean because it bypasses the
       logging code but it is a special thing anyay.  I am not sure
       whether using log_stream() would be better.  Perhaps we should
       enable the list mdoe only with a special option. */
    if (!listfp)
        listfp = opt.list_packets == 2 ? stdout : stderr;
    return old;
}

static void
unknown_pubkey_warning( int algo )
{
    static byte unknown_pubkey_algos[256];

    algo &= 0xff;
    if( !unknown_pubkey_algos[algo] ) {
	if( opt.verbose )
	    log_info(_("can't handle public key algorithm %d\n"), algo );
	unknown_pubkey_algos[algo] = 1;
    }
}

/****************
 * Parse a Packet and return it in packet
 * Returns: 0 := valid packet in pkt
 *	   -1 := no more packets
 *	   >0 := error
 * Note: The function may return an error and a partly valid packet;
 * caller must free this packet.
 */
#ifdef DEBUG_PARSE_PACKET
int
dbg_parse_packet( IOBUF inp, PACKET *pkt, const char *dbg_f, int dbg_l )
{
    int skip, rc;

    do {
	rc = parse( inp, pkt, 0, NULL, &skip, NULL, 0, "parse", dbg_f, dbg_l );
    } while( skip );
    return rc;
}
#else
int
parse_packet( IOBUF inp, PACKET *pkt )
{
    int skip, rc;

    do {
	rc = parse( inp, pkt, 0, NULL, &skip, NULL, 0 );
    } while( skip );
    return rc;
}
#endif

/****************
 * Like parse packet, but only return secret or public (sub)key packets.
 */
#ifdef DEBUG_PARSE_PACKET
int
dbg_search_packet( IOBUF inp, PACKET *pkt, off_t *retpos, int with_uid,
		   const char *dbg_f, int dbg_l )
{
    int skip, rc;

    do {
	rc = parse( inp, pkt, with_uid?2:1, retpos, &skip, NULL, 0, "search", dbg_f, dbg_l );
    } while( skip );
    return rc;
}
#else
int
search_packet( IOBUF inp, PACKET *pkt, off_t *retpos, int with_uid )
{
    int skip, rc;

    do {
	rc = parse( inp, pkt, with_uid?2:1, retpos, &skip, NULL, 0 );
    } while( skip );
    return rc;
}
#endif

/****************
 * Copy all packets from INP to OUT, thereby removing unused spaces.
 */
#ifdef DEBUG_PARSE_PACKET
int
dbg_copy_all_packets( IOBUF inp, IOBUF out,
		   const char *dbg_f, int dbg_l )
{
    PACKET pkt;
    int skip, rc=0;
    do {
	init_packet(&pkt);
    } while( !(rc = parse( inp, &pkt, 0, NULL, &skip, out, 0, "copy", dbg_f, dbg_l )));
    return rc;
}
#else
int
copy_all_packets( IOBUF inp, IOBUF out )
{
    PACKET pkt;
    int skip, rc=0;
    do {
	init_packet(&pkt);
    } while( !(rc = parse( inp, &pkt, 0, NULL, &skip, out, 0 )));
    return rc;
}
#endif

/****************
 * Copy some packets from INP to OUT, thereby removing unused spaces.
 * Stop at offset STOPoff (i.e. don't copy packets at this or later offsets)
 */
#ifdef DEBUG_PARSE_PACKET
int
dbg_copy_some_packets( IOBUF inp, IOBUF out, off_t stopoff,
		   const char *dbg_f, int dbg_l )
{
    PACKET pkt;
    int skip, rc=0;
    do {
	if( iobuf_tell(inp) >= stopoff )
	    return 0;
	init_packet(&pkt);
    } while( !(rc = parse( inp, &pkt, 0, NULL, &skip, out, 0,
				     "some", dbg_f, dbg_l )) );
    return rc;
}
#else
int
copy_some_packets( IOBUF inp, IOBUF out, off_t stopoff )
{
    PACKET pkt;
    int skip, rc=0;
    do {
	if( iobuf_tell(inp) >= stopoff )
	    return 0;
	init_packet(&pkt);
    } while( !(rc = parse( inp, &pkt, 0, NULL, &skip, out, 0 )) );
    return rc;
}
#endif

/****************
 * Skip over N packets
 */
#ifdef DEBUG_PARSE_PACKET
int
dbg_skip_some_packets( IOBUF inp, unsigned n,
		   const char *dbg_f, int dbg_l )
{
    int skip, rc=0;
    PACKET pkt;

    for( ;n && !rc; n--) {
	init_packet(&pkt);
	rc = parse( inp, &pkt, 0, NULL, &skip, NULL, 1, "skip", dbg_f, dbg_l );
    }
    return rc;
}
#else
int
skip_some_packets( IOBUF inp, unsigned n )
{
    int skip, rc=0;
    PACKET pkt;

    for( ;n && !rc; n--) {
	init_packet(&pkt);
	rc = parse( inp, &pkt, 0, NULL, &skip, NULL, 1 );
    }
    return rc;
}
#endif


/****************
 * Parse packet. Set the variable skip points to 1 if the packet
 * should be skipped; this is the case if either ONLYKEYPKTS is set
 * and the parsed packet isn't one or the
 * packet-type is 0, indicating deleted stuff.
 * if OUT is not NULL, a special copymode is used.
 */
static int
parse( IOBUF inp, PACKET *pkt, int onlykeypkts, off_t *retpos,
       int *skip, IOBUF out, int do_skip
#ifdef DEBUG_PARSE_PACKET
       ,const char *dbg_w, const char *dbg_f, int dbg_l
#endif
     )
{
    int rc=0, c, ctb, pkttype, lenbytes;
    unsigned long pktlen;
    byte hdr[8];
    int hdrlen;
    int new_ctb = 0, partial=0;
    int with_uid = (onlykeypkts == 2);

    *skip = 0;
    assert( !pkt->pkt.generic );
    if( retpos )
	*retpos = iobuf_tell(inp);

    if( (ctb = iobuf_get(inp)) == -1 ) {
	rc = -1;
	goto leave;
    }
    hdrlen=0;
    hdr[hdrlen++] = ctb;
    if( !(ctb & 0x80) ) {
        log_error("%s: invalid packet (ctb=%02x)\n", iobuf_where(inp), ctb );
	rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    pktlen = 0;
    new_ctb = !!(ctb & 0x40);
    if( new_ctb ) {
        pkttype = ctb & 0x3f;
	if( (c = iobuf_get(inp)) == -1 ) {
	    log_error("%s: 1st length byte missing\n", iobuf_where(inp) );
	    rc = G10ERR_INVALID_PACKET;
	    goto leave;
	}
        if (pkttype == PKT_COMPRESSED) {
             iobuf_set_partial_block_mode(inp, c & 0xff);
             pktlen = 0;/* to indicate partial length */
	     partial=1;
        }
        else {
             hdr[hdrlen++] = c;
             if( c < 192 )
	       pktlen = c;
             else if( c < 224 )
	       {
		 pktlen = (c - 192) * 256;
		 if( (c = iobuf_get(inp)) == -1 )
		   {
		     log_error("%s: 2nd length byte missing\n",
			       iobuf_where(inp) );
		     rc = G10ERR_INVALID_PACKET;
		     goto leave;
		   }
		 hdr[hdrlen++] = c;
		 pktlen += c + 192;
	       }
             else if( c == 255 )
	       {
		 pktlen  = (hdr[hdrlen++] = iobuf_get_noeof(inp)) << 24;
		 pktlen |= (hdr[hdrlen++] = iobuf_get_noeof(inp)) << 16;
		 pktlen |= (hdr[hdrlen++] = iobuf_get_noeof(inp)) << 8;
		 if( (c = iobuf_get(inp)) == -1 )
		   {
		     log_error("%s: 4 byte length invalid\n",
			       iobuf_where(inp) );
		     rc = G10ERR_INVALID_PACKET;
		     goto leave;
		   }
		 pktlen |= (hdr[hdrlen++] = c );
	       }
             else
	       {
		 /* Partial body length.  Note that we handled
		    PKT_COMPRESSED earlier. */
		 if(pkttype==PKT_PLAINTEXT || pkttype==PKT_ENCRYPTED
		    || pkttype==PKT_ENCRYPTED_MDC)
		   {
		     iobuf_set_partial_block_mode(inp, c & 0xff);
		     pktlen = 0;/* to indicate partial length */
		     partial=1;
		   }
		 else
		   {
		     log_error("%s: partial length for invalid"
			       " packet type %d\n",iobuf_where(inp),pkttype);
		     rc=G10ERR_INVALID_PACKET;
		     goto leave;
		   }
	       }
	}
    }
    else
      {
	pkttype = (ctb>>2)&0xf;
	lenbytes = ((ctb&3)==3)? 0 : (1<<(ctb & 3));
	if( !lenbytes )
	  {
	    pktlen = 0; /* don't know the value */
	    /* This isn't really partial, but we can treat it the same
	       in a "read until the end" sort of way. */
	    partial=1;
	    if(pkttype!=PKT_ENCRYPTED && pkttype!=PKT_PLAINTEXT
	       && pkttype!=PKT_COMPRESSED)
	      {
		log_error ("%s: indeterminate length for invalid"
			   " packet type %d\n", iobuf_where(inp), pkttype );
		rc = G10ERR_INVALID_PACKET;
		goto leave;
	      }
	  }
	else
	  {
	    for( ; lenbytes; lenbytes-- )
	      {
		pktlen <<= 8;
		pktlen |= hdr[hdrlen++] = iobuf_get_noeof(inp);
	      }
	  }
      }

    if (pktlen == 0xffffffff) {
        /* with a some probability this is caused by a problem in the
         * the uncompressing layer - in some error cases it just loops
         * and spits out 0xff bytes. */
        log_error ("%s: garbled packet detected\n", iobuf_where(inp) );
	g10_exit (2);
    }

    if( out && pkttype	) {
	if( iobuf_write( out, hdr, hdrlen ) == -1 )
	    rc = G10ERR_WRITE_FILE;
	else
	    rc = copy_packet(inp, out, pkttype, pktlen, partial );
	goto leave;
    }

    if (with_uid && pkttype == PKT_USER_ID)
        ;
    else if( do_skip 
        || !pkttype
        || (onlykeypkts && pkttype != PKT_PUBLIC_SUBKEY
                        && pkttype != PKT_PUBLIC_KEY
                        && pkttype != PKT_SECRET_SUBKEY
                        && pkttype != PKT_SECRET_KEY  ) ) {
	iobuf_skip_rest(inp, pktlen, partial);
	*skip = 1;
	rc = 0;
	goto leave;
    }

    if( DBG_PACKET ) {
#ifdef DEBUG_PARSE_PACKET
	log_debug("parse_packet(iob=%d): type=%d length=%lu%s (%s.%s.%d)\n",
		   iobuf_id(inp), pkttype, pktlen, new_ctb?" (new_ctb)":"",
		    dbg_w, dbg_f, dbg_l );
#else
	log_debug("parse_packet(iob=%d): type=%d length=%lu%s\n",
		   iobuf_id(inp), pkttype, pktlen, new_ctb?" (new_ctb)":"" );
#endif
    }
    pkt->pkttype = pkttype;
    rc = G10ERR_UNKNOWN_PACKET; /* default error */
    switch( pkttype ) {
      case PKT_PUBLIC_KEY:
      case PKT_PUBLIC_SUBKEY:
	pkt->pkt.public_key = xmalloc_clear(sizeof *pkt->pkt.public_key );
	rc = parse_key(inp, pkttype, pktlen, hdr, hdrlen, pkt );
	break;
      case PKT_SECRET_KEY:
      case PKT_SECRET_SUBKEY:
	pkt->pkt.secret_key = xmalloc_clear(sizeof *pkt->pkt.secret_key );
	rc = parse_key(inp, pkttype, pktlen, hdr, hdrlen, pkt );
	break;
      case PKT_SYMKEY_ENC:
	rc = parse_symkeyenc( inp, pkttype, pktlen, pkt );
	break;
      case PKT_PUBKEY_ENC:
	rc = parse_pubkeyenc(inp, pkttype, pktlen, pkt );
	break;
      case PKT_SIGNATURE:
	pkt->pkt.signature = xmalloc_clear(sizeof *pkt->pkt.signature );
	rc = parse_signature(inp, pkttype, pktlen, pkt->pkt.signature );
	break;
      case PKT_ONEPASS_SIG:
	pkt->pkt.onepass_sig = xmalloc_clear(sizeof *pkt->pkt.onepass_sig );
	rc = parse_onepass_sig(inp, pkttype, pktlen, pkt->pkt.onepass_sig );
	break;
      case PKT_USER_ID:
	rc = parse_user_id(inp, pkttype, pktlen, pkt );
	break;
      case PKT_ATTRIBUTE:
	pkt->pkttype = pkttype = PKT_USER_ID;  /* we store it in the userID */
	rc = parse_attribute(inp, pkttype, pktlen, pkt);
	break;
      case PKT_OLD_COMMENT:
      case PKT_COMMENT:
	rc = parse_comment(inp, pkttype, pktlen, pkt);
	break;
      case PKT_RING_TRUST:
	parse_trust(inp, pkttype, pktlen, pkt);
	rc = 0;
	break;
      case PKT_PLAINTEXT:
	rc = parse_plaintext(inp, pkttype, pktlen, pkt, new_ctb, partial );
	break;
      case PKT_COMPRESSED:
	rc = parse_compressed(inp, pkttype, pktlen, pkt, new_ctb );
	break;
      case PKT_ENCRYPTED:
      case PKT_ENCRYPTED_MDC:
	rc = parse_encrypted(inp, pkttype, pktlen, pkt, new_ctb, partial );
	break;
      case PKT_MDC:
	rc = parse_mdc(inp, pkttype, pktlen, pkt, new_ctb );
	break;
      case PKT_GPG_CONTROL:
        rc = parse_gpg_control(inp, pkttype, pktlen, pkt, partial );
        break;
    case PKT_MARKER:
        rc = parse_marker(inp,pkttype,pktlen);
	break;
      default:
	skip_packet(inp, pkttype, pktlen, partial);
	break;
    }

  leave:
    if( !rc && iobuf_error(inp) )
	rc = G10ERR_INV_KEYRING;
    return rc;
}

static void
dump_hex_line( int c, int *i )
{
    if( *i && !(*i%8) ) {
	if( *i && !(*i%24) )
	    fprintf (listfp, "\n%4d:", *i );
	else
	    putc (' ', listfp);
    }
    if( c == -1 )
	fprintf (listfp, " EOF" );
    else
	fprintf (listfp, " %02x", c );
    ++*i;
}


static int
copy_packet( IOBUF inp, IOBUF out, int pkttype,
	     unsigned long pktlen, int partial )
{
    int n;
    char buf[100];

    if( partial ) {
	while( (n = iobuf_read( inp, buf, 100 )) != -1 )
	    if( iobuf_write(out, buf, n ) )
		return G10ERR_WRITE_FILE; /* write error */
    }
    else if( !pktlen && pkttype == PKT_COMPRESSED ) {
	log_debug("copy_packet: compressed!\n");
	/* compressed packet, copy till EOF */
	while( (n = iobuf_read( inp, buf, 100 )) != -1 )
	    if( iobuf_write(out, buf, n ) )
		return G10ERR_WRITE_FILE; /* write error */
    }
    else {
	for( ; pktlen; pktlen -= n ) {
	    n = pktlen > 100 ? 100 : pktlen;
	    n = iobuf_read( inp, buf, n );
	    if( n == -1 )
		return G10ERR_READ_FILE;
	    if( iobuf_write(out, buf, n ) )
		return G10ERR_WRITE_FILE; /* write error */
	}
    }
    return 0;
}


static void
skip_packet( IOBUF inp, int pkttype, unsigned long pktlen, int partial )
{
  if( list_mode )
    {
      fprintf (listfp, ":unknown packet: type %2d, length %lu\n",
	       pkttype, pktlen);
      if( pkttype )
	{
	  int c, i=0 ;
	  fputs("dump:", listfp );
	  if( partial )
	    {
	      while( (c=iobuf_get(inp)) != -1 )
		dump_hex_line(c, &i);
	    }
	  else
	    {
	      for( ; pktlen; pktlen-- )
		dump_hex_line(iobuf_get(inp), &i);
	    }
	  putc ('\n', listfp);
	  return;
	}
    }
  iobuf_skip_rest(inp,pktlen,partial);
}

static void *
read_rest( IOBUF inp, size_t pktlen, int partial )
{
    byte *p;
    int i;

    if( partial ) {
	log_error("read_rest: can't store stream data\n");
	p = NULL;
    }
    else {
	p = xmalloc( pktlen );
	for(i=0; pktlen; pktlen--, i++ )
	    p[i] = iobuf_get(inp);
    }
    return p;
}

static int
parse_marker( IOBUF inp, int pkttype, unsigned long pktlen )
{
  if(pktlen!=3)
    goto fail;

  if(iobuf_get(inp)!='P')
    {
      pktlen--;
      goto fail;
    }

  if(iobuf_get(inp)!='G')
    {
      pktlen--;
      goto fail;
    }

  if(iobuf_get(inp)!='P')
    {
      pktlen--;
      goto fail;
    }

  if(list_mode)
    fputs(":marker packet: PGP\n", listfp );

  return 0;

 fail:
  log_error("invalid marker packet\n");
  iobuf_skip_rest(inp,pktlen,0);
  return G10ERR_INVALID_PACKET;
}

static int
parse_symkeyenc( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *packet )
{
    PKT_symkey_enc *k;
    int rc = 0;
    int i, version, s2kmode, cipher_algo, hash_algo, seskeylen, minlen;

    if( pktlen < 4 ) {
	log_error("packet(%d) too short\n", pkttype);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    version = iobuf_get_noeof(inp); pktlen--;
    if( version != 4 ) {
	log_error("packet(%d) with unknown version %d\n", pkttype, version);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    if( pktlen > 200 ) { /* (we encode the seskeylen in a byte) */
	log_error("packet(%d) too large\n", pkttype);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    cipher_algo = iobuf_get_noeof(inp); pktlen--;
    s2kmode = iobuf_get_noeof(inp); pktlen--;
    hash_algo = iobuf_get_noeof(inp); pktlen--;
    switch( s2kmode ) {
      case 0:  /* simple s2k */
	minlen = 0;
	break;
      case 1:  /* salted s2k */
	minlen = 8;
	break;
      case 3:  /* iterated+salted s2k */
	minlen = 9;
	break;
      default:
	log_error("unknown S2K %d\n", s2kmode );
	goto leave;
    }
    if( minlen > pktlen ) {
	log_error("packet with S2K %d too short\n", s2kmode );
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    seskeylen = pktlen - minlen;
    k = packet->pkt.symkey_enc = xmalloc_clear( sizeof *packet->pkt.symkey_enc
						+ seskeylen - 1 );
    k->version = version;
    k->cipher_algo = cipher_algo;
    k->s2k.mode = s2kmode;
    k->s2k.hash_algo = hash_algo;
    if( s2kmode == 1 || s2kmode == 3 ) {
	for(i=0; i < 8 && pktlen; i++, pktlen-- )
	    k->s2k.salt[i] = iobuf_get_noeof(inp);
    }
    if( s2kmode == 3 ) {
	k->s2k.count = iobuf_get(inp); pktlen--;
    }
    k->seskeylen = seskeylen;
    if(k->seskeylen)
      {
	for(i=0; i < seskeylen && pktlen; i++, pktlen-- )
	  k->seskey[i] = iobuf_get_noeof(inp);

	/* What we're watching out for here is a session key decryptor
	   with no salt.  The RFC says that using salt for this is a
	   MUST. */
	if(s2kmode!=1 && s2kmode!=3)
	  log_info(_("WARNING: potentially insecure symmetrically"
		     " encrypted session key\n"));
      }
    assert( !pktlen );

    if( list_mode ) {
	fprintf (listfp, ":symkey enc packet: version %d, cipher %d, s2k %d, hash %d",
	       version, cipher_algo, s2kmode, hash_algo);
	if(seskeylen)
	  fprintf (listfp, ", seskey %d bits",(seskeylen-1)*8);
	fprintf (listfp, "\n");
	if( s2kmode == 1 || s2kmode == 3 ) {
	    fprintf (listfp, "\tsalt ");
	    for(i=0; i < 8; i++ )
		fprintf (listfp, "%02x", k->s2k.salt[i]);
	    if( s2kmode == 3 )
		fprintf (listfp, ", count %lu (%lu)",
			 S2K_DECODE_COUNT((ulong)k->s2k.count),
			 (ulong)k->s2k.count );
	    fprintf (listfp, "\n");
	}
    }

  leave:
    iobuf_skip_rest(inp, pktlen, 0);
    return rc;
}

static int
parse_pubkeyenc( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *packet )
{
    unsigned int n;
    int rc = 0;
    int i, ndata;
    PKT_pubkey_enc *k;

    k = packet->pkt.pubkey_enc = xmalloc_clear(sizeof *packet->pkt.pubkey_enc);
    if( pktlen < 12 ) {
	log_error("packet(%d) too short\n", pkttype);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    k->version = iobuf_get_noeof(inp); pktlen--;
    if( k->version != 2 && k->version != 3 ) {
	log_error("packet(%d) with unknown version %d\n", pkttype, k->version);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    k->keyid[0] = read_32(inp); pktlen -= 4;
    k->keyid[1] = read_32(inp); pktlen -= 4;
    k->pubkey_algo = iobuf_get_noeof(inp); pktlen--;
    k->throw_keyid = 0; /* only used as flag for build_packet */
    if( list_mode )
	fprintf (listfp, ":pubkey enc packet: version %d, algo %d, keyid %08lX%08lX\n",
	  k->version, k->pubkey_algo, (ulong)k->keyid[0], (ulong)k->keyid[1]);

    ndata = pubkey_get_nenc(k->pubkey_algo);
    if( !ndata ) {
	if( list_mode )
	    fprintf (listfp, "\tunsupported algorithm %d\n", k->pubkey_algo );
	unknown_pubkey_warning( k->pubkey_algo );
	k->data[0] = NULL;  /* no need to store the encrypted data */
    }
    else {
	for( i=0; i < ndata; i++ ) {
	    n = pktlen;
	    k->data[i] = mpi_read(inp, &n, 0); pktlen -=n;
	    if( list_mode ) {
		fprintf (listfp, "\tdata: ");
		mpi_print(listfp, k->data[i], mpi_print_mode );
		putc ('\n', listfp);
	    }
            if (!k->data[i])
                rc = G10ERR_INVALID_PACKET;
	}
    }

  leave:
    iobuf_skip_rest(inp, pktlen, 0);
    return rc;
}


static void
dump_sig_subpkt( int hashed, int type, int critical,
		 const byte *buffer, size_t buflen, size_t length )
{
    const char *p=NULL;
    int i;

    /* The CERT has warning out with explains how to use GNUPG to
     * detect the ARRs - we print our old message here when it is a faked
     * ARR and add an additional notice */
    if ( type == SIGSUBPKT_ARR && !hashed ) {
        fprintf (listfp,
                 "\tsubpkt %d len %u (additional recipient request)\n"
                 "WARNING: PGP versions > 5.0 and < 6.5.8 will automagically "
                 "encrypt to this key and thereby reveal the plaintext to "
                 "the owner of this ARR key. Detailed info follows:\n",
                 type, (unsigned)length );
    }
    
    buffer++;
    length--;
   
    fprintf (listfp, "\t%s%ssubpkt %d len %u (", /*)*/
	      critical ? "critical ":"",
	      hashed ? "hashed ":"", type, (unsigned)length );
    if( length > buflen ) {
	fprintf (listfp, "too short: buffer is only %u)\n", (unsigned)buflen );
	return;
    }
    switch( type ) {
      case SIGSUBPKT_SIG_CREATED:
	if( length >= 4 )
	    fprintf (listfp, "sig created %s", strtimestamp( buffer_to_u32(buffer) ) );
	break;
      case SIGSUBPKT_SIG_EXPIRE:
	if( length >= 4 )
	  {
	    if(buffer_to_u32(buffer))
	      fprintf (listfp, "sig expires after %s",
		       strtimevalue( buffer_to_u32(buffer) ) );
	    else
	      fprintf (listfp, "sig does not expire");
	  }
	break;
      case SIGSUBPKT_EXPORTABLE:
	if( length )
	    fprintf (listfp, "%sexportable", *buffer? "":"not ");
	break;
      case SIGSUBPKT_TRUST:
	if(length!=2)
	  p="[invalid trust subpacket]";
	else
	  fprintf (listfp, "trust signature of depth %d, value %d",buffer[0],buffer[1]);
	break;
      case SIGSUBPKT_REGEXP:
	if(!length)
	  p="[invalid regexp subpacket]";
	else
	  fprintf (listfp, "regular expression: \"%s\"",buffer);
	break;
      case SIGSUBPKT_REVOCABLE:
	if( length )
	    fprintf (listfp, "%srevocable", *buffer? "":"not ");
	break;
      case SIGSUBPKT_KEY_EXPIRE:
	if( length >= 4 )
	  {
	    if(buffer_to_u32(buffer))
	      fprintf (listfp, "key expires after %s",
		       strtimevalue( buffer_to_u32(buffer) ) );
	    else
	      fprintf (listfp, "key does not expire");
	  }
	break;
      case SIGSUBPKT_PREF_SYM:
	fputs("pref-sym-algos:", listfp );
	for( i=0; i < length; i++ )
	    fprintf (listfp, " %d", buffer[i] );
	break;
      case SIGSUBPKT_REV_KEY:
	fputs("revocation key: ", listfp );
	if( length < 22 )
	    p = "[too short]";
	else {
	    fprintf (listfp, "c=%02x a=%d f=", buffer[0], buffer[1] );
	    for( i=2; i < length; i++ )
		fprintf (listfp, "%02X", buffer[i] );
	}
	break;
      case SIGSUBPKT_ISSUER:
	if( length >= 8 )
	    fprintf (listfp, "issuer key ID %08lX%08lX",
		      (ulong)buffer_to_u32(buffer),
		      (ulong)buffer_to_u32(buffer+4) );
	break;
      case SIGSUBPKT_NOTATION:
	{
	    fputs("notation: ", listfp );
	    if( length < 8 )
		p = "[too short]";
	    else {
		const byte *s = buffer;
		size_t n1, n2;

		n1 = (s[4] << 8) | s[5];
		n2 = (s[6] << 8) | s[7];
		s += 8;
		if( 8+n1+n2 != length )
		    p = "[error]";
		else {
		    print_string( listfp, s, n1, ')' );
		    putc( '=', listfp );

		    if( *buffer & 0x80 )
		      print_string( listfp, s+n1, n2, ')' );
		    else
		      p = "[not human readable]";
		}
	    }
	}
	break;
      case SIGSUBPKT_PREF_HASH:
	fputs("pref-hash-algos:", listfp );
	for( i=0; i < length; i++ )
	    fprintf (listfp, " %d", buffer[i] );
	break;
      case SIGSUBPKT_PREF_COMPR:
	fputs("pref-zip-algos:", listfp );
	for( i=0; i < length; i++ )
	    fprintf (listfp, " %d", buffer[i] );
	break;
      case SIGSUBPKT_KS_FLAGS:
	fputs("key server preferences:",listfp);
	for(i=0;i<length;i++)
	  fprintf (listfp, " %02X", buffer[i]);
	break;
      case SIGSUBPKT_PREF_KS:
	fputs("preferred key server: ", listfp );
	print_string( listfp, buffer, length, ')' );
	break;
      case SIGSUBPKT_PRIMARY_UID:
	p = "primary user ID";
	break;
      case SIGSUBPKT_POLICY:
	fputs("policy: ", listfp );
	print_string( listfp, buffer, length, ')' );
	break;
      case SIGSUBPKT_KEY_FLAGS:
        fputs ( "key flags:", listfp );
        for( i=0; i < length; i++ )
            fprintf (listfp, " %02X", buffer[i] );
	break;
      case SIGSUBPKT_SIGNERS_UID:
	p = "signer's user ID";
	break;
      case SIGSUBPKT_REVOC_REASON:
        if( length ) {
	    fprintf (listfp, "revocation reason 0x%02x (", *buffer );
	    print_string( listfp, buffer+1, length-1, ')' );
	    p = ")";
	}
	break;
      case SIGSUBPKT_ARR:
        fputs("Big Brother's key (ignored): ", listfp );
	if( length < 22 )
	    p = "[too short]";
	else {
	    fprintf (listfp, "c=%02x a=%d f=", buffer[0], buffer[1] );
	    for( i=2; i < length; i++ )
		fprintf (listfp, "%02X", buffer[i] );
	}
        break;
      case SIGSUBPKT_FEATURES:
        fputs ( "features:", listfp );
        for( i=0; i < length; i++ )
            fprintf (listfp, " %02x", buffer[i] );
	break;
      case SIGSUBPKT_SIGNATURE:
	fputs("signature: ",listfp);
	if(length<17)
	  p="[too short]";
	else
	  fprintf (listfp, "v%d, class 0x%02X, algo %d, digest algo %d",
		 buffer[0],
		 buffer[0]==3?buffer[2]:buffer[1],
		 buffer[0]==3?buffer[15]:buffer[2],
		 buffer[0]==3?buffer[16]:buffer[3]);
	break;
      default:
	if(type>=100 && type<=110)
	  p="experimental / private subpacket";
	else
	  p = "?";
	break;
    }

    fprintf (listfp, "%s)\n", p? p: "");
}

/****************
 * Returns: >= 0 use this offset into buffer
 *	    -1 explicitly reject returning this type
 *	    -2 subpacket too short
 */
int
parse_one_sig_subpkt( const byte *buffer, size_t n, int type )
{
  switch( type )
    {
    case SIGSUBPKT_REV_KEY:
      if(n < 22)
	break;
      return 0;
    case SIGSUBPKT_SIG_CREATED:
    case SIGSUBPKT_SIG_EXPIRE:
    case SIGSUBPKT_KEY_EXPIRE:
      if( n < 4 )
	break;
      return 0;
    case SIGSUBPKT_KEY_FLAGS:
    case SIGSUBPKT_KS_FLAGS:
    case SIGSUBPKT_PREF_SYM:
    case SIGSUBPKT_PREF_HASH:
    case SIGSUBPKT_PREF_COMPR:
    case SIGSUBPKT_POLICY:
    case SIGSUBPKT_PREF_KS:
    case SIGSUBPKT_FEATURES:
    case SIGSUBPKT_REGEXP:
      return 0;
    case SIGSUBPKT_SIGNATURE:
    case SIGSUBPKT_EXPORTABLE:
    case SIGSUBPKT_REVOCABLE:
    case SIGSUBPKT_REVOC_REASON:
      if( !n )
	break;
      return 0;
    case SIGSUBPKT_ISSUER: /* issuer key ID */
      if( n < 8 )
	break;
      return 0;
    case SIGSUBPKT_NOTATION:
      /* minimum length needed, and the subpacket must be well-formed
	 where the name length and value length all fit inside the
	 packet. */
      if(n<8 || 8+((buffer[4]<<8)|buffer[5])+((buffer[6]<<8)|buffer[7]) != n)
	break;
      return 0;
    case SIGSUBPKT_PRIMARY_UID:
      if ( n != 1 )
	break;
      return 0;
    case SIGSUBPKT_TRUST:
      if ( n != 2 )
	break;
      return 0;
    default: return 0;
    }
  return -2;
}

/* Not many critical notations we understand yet... */
static int
can_handle_critical_notation(const byte *name,size_t len)
{
  if(len==32 && memcmp(name,"preferred-email-encoding@pgp.com",32)==0)
    return 1;
  if(len==21 && memcmp(name,"pka-address@gnupg.org",21)==0)
    return 1;

  return 0;
}

static int
can_handle_critical( const byte *buffer, size_t n, int type )
{
  switch( type )
    {
    case SIGSUBPKT_NOTATION:
      if(n>=8)
	return can_handle_critical_notation(buffer+8,(buffer[4]<<8)|buffer[5]);
      else
	return 0;
    case SIGSUBPKT_SIGNATURE:
    case SIGSUBPKT_SIG_CREATED:
    case SIGSUBPKT_SIG_EXPIRE:
    case SIGSUBPKT_KEY_EXPIRE:
    case SIGSUBPKT_EXPORTABLE:
    case SIGSUBPKT_REVOCABLE:
    case SIGSUBPKT_REV_KEY:
    case SIGSUBPKT_ISSUER:/* issuer key ID */
    case SIGSUBPKT_PREF_SYM:
    case SIGSUBPKT_PREF_HASH:
    case SIGSUBPKT_PREF_COMPR:
    case SIGSUBPKT_KEY_FLAGS:
    case SIGSUBPKT_PRIMARY_UID:
    case SIGSUBPKT_FEATURES:
    case SIGSUBPKT_TRUST:
    case SIGSUBPKT_REGEXP:
      /* Is it enough to show the policy or keyserver? */
    case SIGSUBPKT_POLICY:
    case SIGSUBPKT_PREF_KS:
      return 1;

    default:
      return 0;
    }
}


const byte *
enum_sig_subpkt( const subpktarea_t *pktbuf, sigsubpkttype_t reqtype,
		 size_t *ret_n, int *start, int *critical )
{
    const byte *buffer;
    int buflen;
    int type;
    int critical_dummy;
    int offset;
    size_t n;
    int seq = 0;
    int reqseq = start? *start: 0;

    if(!critical)
      critical=&critical_dummy;

    if( !pktbuf || reqseq == -1 ) {
	/* return some value different from NULL to indicate that
	 * there is no critical bit we do not understand.  The caller
	 * will never use the value.  Yes I know, it is an ugly hack */
	return reqtype == SIGSUBPKT_TEST_CRITICAL? (const byte*)&pktbuf : NULL;
    }
    buffer = pktbuf->data;
    buflen = pktbuf->len;
    while( buflen ) {
	n = *buffer++; buflen--;
	if( n == 255 ) { /* 4 byte length header */
	    if( buflen < 4 )
		goto too_short;
	    n = (buffer[0] << 24) | (buffer[1] << 16)
                | (buffer[2] << 8) | buffer[3];
	    buffer += 4;
	    buflen -= 4;
	}
	else if( n >= 192 ) { /* 2 byte special encoded length header */
	    if( buflen < 2 )
		goto too_short;
	    n = (( n - 192 ) << 8) + *buffer + 192;
	    buffer++;
	    buflen--;
	}
	if( buflen < n )
	    goto too_short;
	type = *buffer;
	if( type & 0x80 ) {
	    type &= 0x7f;
	    *critical = 1;
	}
	else
	    *critical = 0;
	if( !(++seq > reqseq) )
	    ;
	else if( reqtype == SIGSUBPKT_TEST_CRITICAL ) {
	    if( *critical ) {
		if( n-1 > buflen+1 )
		    goto too_short;
		if( !can_handle_critical(buffer+1, n-1, type ) )
		  {
		    if(opt.verbose)
		      log_info(_("subpacket of type %d has "
				 "critical bit set\n"),type);
		    if( start )
		      *start = seq;
		    return NULL; /* this is an error */
		  }
	    }
	}
	else if( reqtype < 0 ) /* list packets */
	    dump_sig_subpkt( reqtype == SIGSUBPKT_LIST_HASHED,
				    type, *critical, buffer, buflen, n );
	else if( type == reqtype ) { /* found */
	    buffer++;
	    n--;
	    if( n > buflen )
		goto too_short;
	    if( ret_n )
		*ret_n = n;
	    offset = parse_one_sig_subpkt(buffer, n, type );
	    switch( offset ) {
	      case -2:
		log_error("subpacket of type %d too short\n", type);
		return NULL;
	      case -1:
		return NULL;
	      default:
		break;
	    }
	    if( start )
		*start = seq;
	    return buffer+offset;
	}
	buffer += n; buflen -=n;
    }
    if( reqtype == SIGSUBPKT_TEST_CRITICAL )
	return buffer; /* as value true to indicate that there is no */
		       /* critical bit we don't understand */
    if( start )
	*start = -1;
    return NULL; /* end of packets; not found */

  too_short:
    if(opt.verbose)
      log_info("buffer shorter than subpacket\n");
    if( start )
	*start = -1;
    return NULL;
}


const byte *
parse_sig_subpkt (const subpktarea_t *buffer, sigsubpkttype_t reqtype,
                  size_t *ret_n)
{
    return enum_sig_subpkt( buffer, reqtype, ret_n, NULL, NULL );
}

const byte *
parse_sig_subpkt2 (PKT_signature *sig, sigsubpkttype_t reqtype,
                   size_t *ret_n )
{
    const byte *p;

    p = parse_sig_subpkt (sig->hashed, reqtype, ret_n );
    if( !p )
	p = parse_sig_subpkt (sig->unhashed, reqtype, ret_n );
    return p;
}

/* Find all revocation keys. Look in hashed area only. */
void parse_revkeys(PKT_signature *sig)
{
  struct revocation_key *revkey;
  int seq=0;
  size_t len;

  if(sig->sig_class!=0x1F)
    return;

  while((revkey=
	 (struct revocation_key *)enum_sig_subpkt(sig->hashed,
						  SIGSUBPKT_REV_KEY,
						  &len,&seq,NULL)))
    {
      if(len==sizeof(struct revocation_key) &&
	 (revkey->class&0x80)) /* 0x80 bit must be set */
	{
	  sig->revkey=xrealloc(sig->revkey,
			  sizeof(struct revocation_key *)*(sig->numrevkeys+1));
	  sig->revkey[sig->numrevkeys]=revkey;
	  sig->numrevkeys++;
	}
    }
}

int
parse_signature( IOBUF inp, int pkttype, unsigned long pktlen,
					  PKT_signature *sig )
{
    int md5_len=0;
    unsigned n;
    int is_v4=0;
    int rc=0;
    int i, ndata;

    if( pktlen < 16 ) {
	log_error("packet(%d) too short\n", pkttype);
	goto leave;
    }
    sig->version = iobuf_get_noeof(inp); pktlen--;
    if( sig->version == 4 )
	is_v4=1;
    else if( sig->version != 2 && sig->version != 3 ) {
	log_error("packet(%d) with unknown version %d\n", pkttype, sig->version);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }

    if( !is_v4 ) {
	md5_len = iobuf_get_noeof(inp); pktlen--;
    }
    sig->sig_class = iobuf_get_noeof(inp); pktlen--;
    if( !is_v4 ) {
	sig->timestamp = read_32(inp); pktlen -= 4;
	sig->keyid[0] = read_32(inp); pktlen -= 4;
	sig->keyid[1] = read_32(inp); pktlen -= 4;
    }
    sig->pubkey_algo = iobuf_get_noeof(inp); pktlen--;
    sig->digest_algo = iobuf_get_noeof(inp); pktlen--;
    sig->flags.exportable=1;
    sig->flags.revocable=1;
    if( is_v4 ) { /* read subpackets */
	n = read_16(inp); pktlen -= 2; /* length of hashed data */
	if( n > 10000 ) {
	    log_error("signature packet: hashed data too long\n");
	    rc = G10ERR_INVALID_PACKET;
	    goto leave;
	}
	if( n ) {
	    sig->hashed = xmalloc (sizeof (*sig->hashed) + n - 1 );
            sig->hashed->size = n;
	    sig->hashed->len = n;
	    if( iobuf_read (inp, sig->hashed->data, n ) != n ) {
		log_error ("premature eof while reading "
                           "hashed signature data\n");
		rc = -1;
		goto leave;
	    }
	    pktlen -= n;
	}
	n = read_16(inp); pktlen -= 2; /* length of unhashed data */
	if( n > 10000 ) {
	    log_error("signature packet: unhashed data too long\n");
	    rc = G10ERR_INVALID_PACKET;
	    goto leave;
	}
	if( n ) {
	    sig->unhashed = xmalloc (sizeof(*sig->unhashed) + n - 1 );
            sig->unhashed->size = n;
	    sig->unhashed->len = n;
	    if( iobuf_read(inp, sig->unhashed->data, n ) != n ) {
		log_error("premature eof while reading "
                          "unhashed signature data\n");
		rc = -1;
		goto leave;
	    }
	    pktlen -= n;
	}
    }

    if( pktlen < 5 ) { /* sanity check */
	log_error("packet(%d) too short\n", pkttype);
	rc = G10ERR_INVALID_PACKET;
	goto leave;
    }

    sig->digest_start[0] = iobuf_get_noeof(inp); pktlen--;
    sig->digest_start[1] = iobuf_get_noeof(inp); pktlen--;

    if( is_v4 && sig->pubkey_algo )
      { /*extract required information */
	const byte *p;
	size_t len;

	/* set sig->flags.unknown_critical if there is a
	 * critical bit set for packets which we do not understand */
	if( !parse_sig_subpkt (sig->hashed, SIGSUBPKT_TEST_CRITICAL, NULL)
	    || !parse_sig_subpkt (sig->unhashed, SIGSUBPKT_TEST_CRITICAL,
				  NULL) )
	  sig->flags.unknown_critical = 1;

	p = parse_sig_subpkt (sig->hashed, SIGSUBPKT_SIG_CREATED, NULL );
	if(p)
	  sig->timestamp = buffer_to_u32(p);
	else if(!(sig->pubkey_algo>=100 && sig->pubkey_algo<=110)
		&& opt.verbose)
	  log_info ("signature packet without timestamp\n");

	p = parse_sig_subpkt2( sig, SIGSUBPKT_ISSUER, NULL );
	if(p)
	  {
	    sig->keyid[0] = buffer_to_u32(p);
	    sig->keyid[1] = buffer_to_u32(p+4);
	  }
	else if(!(sig->pubkey_algo>=100 && sig->pubkey_algo<=110)
		&& opt.verbose)
	  log_info ("signature packet without keyid\n");

	p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_SIG_EXPIRE,NULL);
	if(p && buffer_to_u32(p))
	  sig->expiredate=sig->timestamp+buffer_to_u32(p);
	if(sig->expiredate && sig->expiredate<=make_timestamp())
	  sig->flags.expired=1;

	p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_POLICY,NULL);
	if(p)
	  sig->flags.policy_url=1;

	p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_PREF_KS,NULL);
	if(p)
	  sig->flags.pref_ks=1;

	p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION,NULL);
	if(p)
	  sig->flags.notation=1;

	p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_REVOCABLE,NULL);
	if(p && *p==0)
	  sig->flags.revocable=0;

	p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_TRUST,&len);
	if(p && len==2)
	  {
	    sig->trust_depth=p[0];
	    sig->trust_value=p[1];

	    /* Only look for a regexp if there is also a trust
	       subpacket. */
	    sig->trust_regexp=
	      parse_sig_subpkt(sig->hashed,SIGSUBPKT_REGEXP,&len);

	    /* If the regular expression is of 0 length, there is no
	       regular expression. */
	    if(len==0)
	      sig->trust_regexp=NULL;
	  }

	/* We accept the exportable subpacket from either the hashed
	   or unhashed areas as older versions of gpg put it in the
	   unhashed area.  In theory, anyway, we should never see this
	   packet off of a local keyring. */

	p=parse_sig_subpkt2(sig,SIGSUBPKT_EXPORTABLE,NULL);
	if(p && *p==0)
	  sig->flags.exportable=0;

	/* Find all revocation keys. */
	if(sig->sig_class==0x1F)
	  parse_revkeys(sig);
      }

    if( list_mode ) {
	fprintf (listfp, ":signature packet: algo %d, keyid %08lX%08lX\n"
	       "\tversion %d, created %lu, md5len %d, sigclass 0x%02x\n"
	       "\tdigest algo %d, begin of digest %02x %02x\n",
		sig->pubkey_algo,
		(ulong)sig->keyid[0], (ulong)sig->keyid[1],
		sig->version, (ulong)sig->timestamp, md5_len, sig->sig_class,
		sig->digest_algo,
		sig->digest_start[0], sig->digest_start[1] );
	if( is_v4 ) {
	    parse_sig_subpkt (sig->hashed,   SIGSUBPKT_LIST_HASHED, NULL );
	    parse_sig_subpkt (sig->unhashed, SIGSUBPKT_LIST_UNHASHED, NULL);
	}
    }

    ndata = pubkey_get_nsig(sig->pubkey_algo);
    if( !ndata ) {
	if( list_mode )
	    fprintf (listfp, "\tunknown algorithm %d\n", sig->pubkey_algo );
	unknown_pubkey_warning( sig->pubkey_algo );
	/* We store the plain material in data[0], so that we are able
	 * to write it back with build_packet() */
        if (pktlen > (5 * MAX_EXTERN_MPI_BITS/8))
          {
            /* However we include a limit to avoid too trivial DoS
               attacks by having gpg allocate too much memory.  */
	    log_error ("signature packet: too much data\n");
	    rc = G10ERR_INVALID_PACKET;
          }
        else
          {
            sig->data[0]= mpi_set_opaque (NULL, read_rest(inp, pktlen, 0),
                                          pktlen );
            pktlen = 0;
          }
    }
    else {
	for( i=0; i < ndata; i++ ) {
	    n = pktlen;
	    sig->data[i] = mpi_read(inp, &n, 0 );
	    pktlen -=n;
	    if( list_mode ) {
		fprintf (listfp, "\tdata: ");
		mpi_print(listfp, sig->data[i], mpi_print_mode );
		putc ('\n', listfp);
	    }
            if (!sig->data[i])
                rc = G10ERR_INVALID_PACKET;
	}
    }

  leave:
    iobuf_skip_rest(inp, pktlen, 0);
    return rc;
}


static int
parse_onepass_sig( IOBUF inp, int pkttype, unsigned long pktlen,
					     PKT_onepass_sig *ops )
{
    int version;
    int rc = 0;

    if( pktlen < 13 ) {
	log_error("packet(%d) too short\n", pkttype);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    version = iobuf_get_noeof(inp); pktlen--;
    if( version != 3 ) {
	log_error("onepass_sig with unknown version %d\n", version);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    ops->sig_class = iobuf_get_noeof(inp); pktlen--;
    ops->digest_algo = iobuf_get_noeof(inp); pktlen--;
    ops->pubkey_algo = iobuf_get_noeof(inp); pktlen--;
    ops->keyid[0] = read_32(inp); pktlen -= 4;
    ops->keyid[1] = read_32(inp); pktlen -= 4;
    ops->last = iobuf_get_noeof(inp); pktlen--;
    if( list_mode )
	fprintf (listfp, ":onepass_sig packet: keyid %08lX%08lX\n"
	      "\tversion %d, sigclass 0x%02x, digest %d, pubkey %d, last=%d\n",
		(ulong)ops->keyid[0], (ulong)ops->keyid[1],
		version, ops->sig_class,
		ops->digest_algo, ops->pubkey_algo, ops->last );


  leave:
    iobuf_skip_rest(inp, pktlen, 0);
    return rc;
}


static MPI
read_protected_v3_mpi (IOBUF inp, unsigned long *length)
{
  int c;
  unsigned int nbits, nbytes;
  unsigned char *buf, *p;
  MPI val;

  if (*length < 2)
    {
      log_error ("mpi too small\n");
      return NULL;
    }

  if ((c=iobuf_get (inp)) == -1)
    return NULL;
  --*length;
  nbits = c << 8;
  if ((c=iobuf_get(inp)) == -1)
    return NULL;
  --*length;
  nbits |= c;

  if (nbits > 16384)
    {
      log_error ("mpi too large (%u bits)\n", nbits);
      return NULL;
    }
  nbytes = (nbits+7) / 8;
  buf = p = xmalloc (2 + nbytes);
  *p++ = nbits >> 8;
  *p++ = nbits;
  for (; nbytes && *length; nbytes--, --*length)
    *p++ = iobuf_get (inp);
  if (nbytes)
    {
      log_error ("packet shorter tham mpi\n");
      xfree (buf);
      return NULL;
    }

  /* convert buffer into an opaque MPI */
  val = mpi_set_opaque (NULL, buf, p-buf); 
  return val;
}


static int
parse_key( IOBUF inp, int pkttype, unsigned long pktlen,
			      byte *hdr, int hdrlen, PACKET *pkt )
{
    int i, version, algorithm;
    unsigned n;
    unsigned long timestamp, expiredate, max_expiredate;
    int npkey, nskey;
    int is_v4=0;
    int rc=0;

    version = iobuf_get_noeof(inp); pktlen--;
    if( pkttype == PKT_PUBLIC_SUBKEY && version == '#' ) {
	/* early versions of G10 use old PGP comments packets;
	 * luckily all those comments are started by a hash */
	if( list_mode ) {
	    fprintf (listfp, ":rfc1991 comment packet: \"" );
	    for( ; pktlen; pktlen-- ) {
		int c;
		c = iobuf_get_noeof(inp);
		if( c >= ' ' && c <= 'z' )
		    putc (c, listfp);
		else
		    fprintf (listfp, "\\x%02x", c );
	    }
	    fprintf (listfp, "\"\n");
	}
	iobuf_skip_rest(inp, pktlen, 0);
	return 0;
    }
    else if( version == 4 )
	is_v4=1;
    else if( version != 2 && version != 3 ) {
	log_error("packet(%d) with unknown version %d\n", pkttype, version);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }

    if( pktlen < 11 ) {
	log_error("packet(%d) too short\n", pkttype);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }

    timestamp = read_32(inp); pktlen -= 4;
    if( is_v4 ) {
	expiredate = 0; /* have to get it from the selfsignature */
	max_expiredate = 0;
    }
    else {
	unsigned short ndays;
	ndays = read_16(inp); pktlen -= 2;
	if( ndays )
	    expiredate = timestamp + ndays * 86400L;
	else
	    expiredate = 0;

	max_expiredate=expiredate;
    }
    algorithm = iobuf_get_noeof(inp); pktlen--;
    if( list_mode )
	fprintf (listfp, ":%s key packet:\n"
	       "\tversion %d, algo %d, created %lu, expires %lu\n",
		pkttype == PKT_PUBLIC_KEY? "public" :
		pkttype == PKT_SECRET_KEY? "secret" :
		pkttype == PKT_PUBLIC_SUBKEY? "public sub" :
		pkttype == PKT_SECRET_SUBKEY? "secret sub" : "??",
		version, algorithm, timestamp, expiredate );

    if( pkttype == PKT_SECRET_KEY || pkttype == PKT_SECRET_SUBKEY )  {
	PKT_secret_key *sk = pkt->pkt.secret_key;

	sk->timestamp = timestamp;
	sk->expiredate = expiredate;
	sk->max_expiredate = max_expiredate;
	sk->hdrbytes = hdrlen;
	sk->version = version;
	sk->is_primary = pkttype == PKT_SECRET_KEY;
	sk->pubkey_algo = algorithm;
	sk->req_usage = 0; 
	sk->pubkey_usage = 0; /* not yet used */
    }
    else {
	PKT_public_key *pk = pkt->pkt.public_key;

	pk->timestamp = timestamp;
	pk->expiredate = expiredate;
	pk->max_expiredate = max_expiredate;
	pk->hdrbytes	= hdrlen;
	pk->version	= version;
	pk->is_primary = pkttype == PKT_PUBLIC_KEY;
	pk->pubkey_algo = algorithm;
	pk->req_usage = 0; 
	pk->pubkey_usage = 0; /* not yet used */
        pk->is_revoked = 0;
	pk->is_disabled = 0;
	pk->keyid[0] = 0;
	pk->keyid[1] = 0;
    }
    nskey = pubkey_get_nskey( algorithm );
    npkey = pubkey_get_npkey( algorithm );
    if( !npkey ) {
	if( list_mode )
	    fprintf (listfp, "\tunknown algorithm %d\n", algorithm );
	unknown_pubkey_warning( algorithm );
    }


    if( pkttype == PKT_SECRET_KEY || pkttype == PKT_SECRET_SUBKEY ) {
	PKT_secret_key *sk = pkt->pkt.secret_key;
	byte temp[16];
        size_t snlen = 0;

	if( !npkey ) {
	    sk->skey[0] = mpi_set_opaque( NULL,
					  read_rest(inp, pktlen, 0), pktlen );
	    pktlen = 0;
	    goto leave;
	}

	for(i=0; i < npkey; i++ ) {
	    n = pktlen; sk->skey[i] = mpi_read(inp, &n, 0 ); pktlen -=n;
	    if( list_mode ) {
		fprintf (listfp,   "\tskey[%d]: ", i);
		mpi_print(listfp, sk->skey[i], mpi_print_mode  );
		putc ('\n', listfp);
	    }
            if (!sk->skey[i])
                rc = G10ERR_INVALID_PACKET;
	}
        if (rc) /* one of the MPIs were bad */
            goto leave;
	sk->protect.algo = iobuf_get_noeof(inp); pktlen--;
        sk->protect.sha1chk = 0;
	if( sk->protect.algo ) {
	    sk->is_protected = 1;
	    sk->protect.s2k.count = 0;
	    if( sk->protect.algo == 254 || sk->protect.algo == 255 ) {
		if( pktlen < 3 ) {
		    rc = G10ERR_INVALID_PACKET;
		    goto leave;
		}
                sk->protect.sha1chk = (sk->protect.algo == 254);
		sk->protect.algo = iobuf_get_noeof(inp); pktlen--;
		/* Note that a sk->protect.algo > 110 is illegal, but
		   I'm not erroring on it here as otherwise there
		   would be no way to delete such a key. */
		sk->protect.s2k.mode  = iobuf_get_noeof(inp); pktlen--;
		sk->protect.s2k.hash_algo = iobuf_get_noeof(inp); pktlen--;
		/* check for the special GNU extension */
		if( is_v4 && sk->protect.s2k.mode == 101 ) {
		    for(i=0; i < 4 && pktlen; i++, pktlen-- )
			temp[i] = iobuf_get_noeof(inp);
		    if( i < 4 || memcmp( temp, "GNU", 3 ) ) {
			if( list_mode )
			    fprintf (listfp,   "\tunknown S2K %d\n",
						sk->protect.s2k.mode );
			rc = G10ERR_INVALID_PACKET;
			goto leave;
		    }
		    /* here we know that it is a gnu extension
		     * What follows is the GNU protection mode:
		     * All values have special meanings
		     * and they are mapped in the mode with a base of 1000.
		     */
		    sk->protect.s2k.mode = 1000 + temp[3];
		}
		switch( sk->protect.s2k.mode ) {
		  case 1:
		  case 3:
		    for(i=0; i < 8 && pktlen; i++, pktlen-- )
			temp[i] = iobuf_get_noeof(inp);
		    memcpy(sk->protect.s2k.salt, temp, 8 );
		    break;
		}
		switch( sk->protect.s2k.mode ) {
		  case 0: if( list_mode ) fprintf (listfp, "\tsimple S2K" );
		    break;
		  case 1: if( list_mode ) fprintf (listfp, "\tsalted S2K" );
		    break;
		  case 3: if( list_mode ) fprintf (listfp, "\titer+salt S2K" );
		    break;
		  case 1001: if( list_mode ) fprintf (listfp,
                                                      "\tgnu-dummy S2K" );
		    break;
		  case 1002: if (list_mode) fprintf (listfp,
                                                  "\tgnu-divert-to-card S2K");
		    break;
		  default:
		    if( list_mode )
			fprintf (listfp,   "\tunknown %sS2K %d\n",
				 sk->protect.s2k.mode < 1000? "":"GNU ",
						   sk->protect.s2k.mode );
		    rc = G10ERR_INVALID_PACKET;
		    goto leave;
		}

		if( list_mode ) {
		    fprintf (listfp, ", algo: %d,%s hash: %d",
				     sk->protect.algo,
                                     sk->protect.sha1chk?" SHA1 protection,"
                                                        :" simple checksum,",
				     sk->protect.s2k.hash_algo );
		    if( sk->protect.s2k.mode == 1
			|| sk->protect.s2k.mode == 3 ) {
			fprintf (listfp, ", salt: ");
			for(i=0; i < 8; i++ )
			    fprintf (listfp, "%02x", sk->protect.s2k.salt[i]);
		    }
		    putc ('\n', listfp);
		}

		if( sk->protect.s2k.mode == 3 ) {
		    if( pktlen < 1 ) {
			rc = G10ERR_INVALID_PACKET;
			goto leave;
		    }
		    sk->protect.s2k.count = iobuf_get(inp);
		    pktlen--;
		    if( list_mode )
			fprintf (listfp, "\tprotect count: %lu\n",
					    (ulong)sk->protect.s2k.count);
		}
		else if( sk->protect.s2k.mode == 1002 ) {
                    /* Read the serial number. */
                    if (pktlen < 1) {
                      rc = G10ERR_INVALID_PACKET;
			goto leave;
		    }
		    snlen = iobuf_get (inp);
		    pktlen--;
                    if (pktlen < snlen || snlen == -1) {
			rc = G10ERR_INVALID_PACKET;
			goto leave;
                    }
		}
	    }
	    /* Note that a sk->protect.algo > 110 is illegal, but I'm
	       not erroring on it here as otherwise there would be no
	       way to delete such a key. */
	    else { /* old version; no S2K, so we set mode to 0, hash MD5 */
		sk->protect.s2k.mode = 0;
		sk->protect.s2k.hash_algo = DIGEST_ALGO_MD5;
		if( list_mode )
		    fprintf (listfp,   "\tprotect algo: %d  (hash algo: %d)\n",
			 sk->protect.algo, sk->protect.s2k.hash_algo );
	    }
	    /* It is really ugly that we don't know the size
	     * of the IV here in cases we are not aware of the algorithm.
	     * so a
	     *	 sk->protect.ivlen = cipher_get_blocksize(sk->protect.algo);
	     * won't work.  The only solution I see is to hardwire it here.
	     * NOTE: if you change the ivlen above 16, don't forget to
	     * enlarge temp.
	     */
	    switch( sk->protect.algo ) {
	      case 7: case 8: case 9: /* AES */
	      case 10: /* Twofish */
	      case 11: case 12: /* Camellia */
		sk->protect.ivlen = 16;
		break;
	      default:
		sk->protect.ivlen = 8;
	    }
	    if( sk->protect.s2k.mode == 1001 )
		sk->protect.ivlen = 0;
	    else if( sk->protect.s2k.mode == 1002 )
		sk->protect.ivlen = snlen < 16? snlen : 16;

	    if( pktlen < sk->protect.ivlen ) {
		rc = G10ERR_INVALID_PACKET;
		goto leave;
	    }
	    for(i=0; i < sk->protect.ivlen && pktlen; i++, pktlen-- )
		temp[i] = iobuf_get_noeof(inp);
	    if( list_mode ) {
		fprintf (listfp,
                         sk->protect.s2k.mode == 1002? "\tserial-number: "
                                                     : "\tprotect IV: ");
		for(i=0; i < sk->protect.ivlen; i++ )
		    fprintf (listfp, " %02x", temp[i] );
		putc ('\n', listfp);
	    }
	    memcpy(sk->protect.iv, temp, sk->protect.ivlen );
	}
	else
	    sk->is_protected = 0;
	/* It does not make sense to read it into secure memory.
	 * If the user is so careless, not to protect his secret key,
	 * we can assume, that he operates an open system :=(.
	 * So we put the key into secure memory when we unprotect it. */
	if( sk->protect.s2k.mode == 1001 
            || sk->protect.s2k.mode == 1002 ) {
	    /* better set some dummy stuff here */
	    sk->skey[npkey] = mpi_set_opaque(NULL, xstrdup("dummydata"), 10);
	    pktlen = 0;
	}
	else if( is_v4 && sk->is_protected ) {
	    /* ugly; the length is encrypted too, so we read all
	     * stuff up to the end of the packet into the first
	     * skey element */
	    sk->skey[npkey] = mpi_set_opaque(NULL,
					     read_rest(inp, pktlen, 0),pktlen);
	    pktlen = 0;
	    if( list_mode ) {
		fprintf (listfp, "\tencrypted stuff follows\n");
	    }
	}
	else { /* v3 method: the mpi length is not encrypted */
	    for(i=npkey; i < nskey; i++ ) {
                if ( sk->is_protected ) {
                    sk->skey[i] = read_protected_v3_mpi (inp, &pktlen);
                    if( list_mode ) 
                        fprintf (listfp,   "\tskey[%d]: [encrypted]\n", i);
                }
                else {
                    n = pktlen;
                    sk->skey[i] = mpi_read(inp, &n, 0 );
                    pktlen -=n;
                    if( list_mode ) {
                        fprintf (listfp,   "\tskey[%d]: ", i);
                        mpi_print(listfp, sk->skey[i], mpi_print_mode  );
                        putc ('\n', listfp);
                    }
                }

                if (!sk->skey[i])
                    rc = G10ERR_INVALID_PACKET;
	    }
            if (rc)
                goto leave;

	    sk->csum = read_16(inp); pktlen -= 2;
	    if( list_mode ) {
		fprintf (listfp, "\tchecksum: %04hx\n", sk->csum);
	    }
	}
    }
    else {
	PKT_public_key *pk = pkt->pkt.public_key;

	if( !npkey ) {
	    pk->pkey[0] = mpi_set_opaque( NULL,
					  read_rest(inp, pktlen, 0), pktlen );
	    pktlen = 0;
	    goto leave;
	}

	for(i=0; i < npkey; i++ ) {
	    n = pktlen; pk->pkey[i] = mpi_read(inp, &n, 0 ); pktlen -=n;
	    if( list_mode ) {
		fprintf (listfp,   "\tpkey[%d]: ", i);
		mpi_print(listfp, pk->pkey[i], mpi_print_mode  );
		putc ('\n', listfp);
	    }
            if (!pk->pkey[i])
                rc = G10ERR_INVALID_PACKET;
	}
        if (rc)
            goto leave;
    }

  leave:
    iobuf_skip_rest(inp, pktlen, 0);
    return rc;
}

/* Attribute subpackets have the same format as v4 signature
   subpackets.  This is not part of OpenPGP, but is done in several
   versions of PGP nevertheless. */
int
parse_attribute_subpkts(PKT_user_id *uid)
{
  size_t n;
  int count=0;
  struct user_attribute *attribs=NULL;
  const byte *buffer=uid->attrib_data;
  int buflen=uid->attrib_len;
  byte type;

  xfree(uid->attribs);

  while(buflen)
    {
      n = *buffer++; buflen--;
      if( n == 255 ) { /* 4 byte length header */
	if( buflen < 4 )
	  goto too_short;
	n = (buffer[0] << 24) | (buffer[1] << 16)
	  | (buffer[2] << 8) | buffer[3];
	buffer += 4;
	buflen -= 4;
      }
      else if( n >= 192 ) { /* 2 byte special encoded length header */
	if( buflen < 2 )
	  goto too_short;
	n = (( n - 192 ) << 8) + *buffer + 192;
	buffer++;
	buflen--;
      }
      if( buflen < n )
	goto too_short;

      attribs=xrealloc(attribs,(count+1)*sizeof(struct user_attribute));
      memset(&attribs[count],0,sizeof(struct user_attribute));

      type=*buffer;
      buffer++;
      buflen--;
      n--;

      attribs[count].type=type;
      attribs[count].data=buffer;
      attribs[count].len=n;
      buffer+=n;
      buflen-=n;
      count++;
    }

  uid->attribs=attribs;
  uid->numattribs=count;
  return count;

 too_short:
  if(opt.verbose)
    log_info("buffer shorter than attribute subpacket\n");
  uid->attribs=attribs;
  uid->numattribs=count;
  return count;
}


static int
parse_user_id( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *packet )
{
    byte *p;

    /* Cap the size of a user ID at 2k: a value absurdly large enough
       that there is no sane user ID string (which is printable text
       as of RFC2440bis) that won't fit in it, but yet small enough to
       avoid allocation problems.  A large pktlen may not be
       allocatable, and a very large pktlen could actually cause our
       allocation to wrap around in xmalloc to a small number. */

    if(pktlen>2048)
      {
	log_error("packet(%d) too large\n", pkttype);
	iobuf_skip_rest(inp, pktlen, 0);
	return G10ERR_INVALID_PACKET;
      }

    packet->pkt.user_id = xmalloc_clear(sizeof *packet->pkt.user_id + pktlen);
    packet->pkt.user_id->len = pktlen;
    packet->pkt.user_id->ref=1;

    p = packet->pkt.user_id->name;
    for( ; pktlen; pktlen--, p++ )
	*p = iobuf_get_noeof(inp);
    *p = 0;

    if( list_mode ) {
	int n = packet->pkt.user_id->len;
	fprintf (listfp, ":user ID packet: \"");
	/* fixme: Hey why don't we replace this with print_string?? */
	for(p=packet->pkt.user_id->name; n; p++, n-- ) {
	    if( *p >= ' ' && *p <= 'z' )
		putc (*p, listfp);
	    else
		fprintf (listfp, "\\x%02x", *p );
	}
	fprintf (listfp, "\"\n");
    }
    return 0;
}


void
make_attribute_uidname(PKT_user_id *uid, size_t max_namelen)
{
  assert ( max_namelen > 70 );
  if(uid->numattribs<=0)
    sprintf(uid->name,"[bad attribute packet of size %lu]",uid->attrib_len);
  else if(uid->numattribs>1)
    sprintf(uid->name,"[%d attributes of size %lu]",
	    uid->numattribs,uid->attrib_len);
  else
    {
      /* Only one attribute, so list it as the "user id" */

      if(uid->attribs->type==ATTRIB_IMAGE)
	{
	  u32 len;
	  byte type;

	  if(parse_image_header(uid->attribs,&type,&len))
	    sprintf(uid->name,"[%.20s image of size %lu]",
		    image_type_to_string(type,1),(ulong)len);
	  else
	    sprintf(uid->name,"[invalid image]");
	}
      else
	sprintf(uid->name,"[unknown attribute of size %lu]",
		(ulong)uid->attribs->len);
    }

  uid->len = strlen(uid->name);
}

static int
parse_attribute( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *packet )
{
    byte *p;

#define EXTRA_UID_NAME_SPACE 71
    packet->pkt.user_id = xmalloc_clear(sizeof *packet->pkt.user_id
					+ EXTRA_UID_NAME_SPACE);
    packet->pkt.user_id->ref=1;
    packet->pkt.user_id->attrib_data = xmalloc(pktlen);
    packet->pkt.user_id->attrib_len = pktlen;

    p = packet->pkt.user_id->attrib_data;
    for( ; pktlen; pktlen--, p++ )
	*p = iobuf_get_noeof(inp);

    /* Now parse out the individual attribute subpackets.  This is
       somewhat pointless since there is only one currently defined
       attribute type (jpeg), but it is correct by the spec. */
    parse_attribute_subpkts(packet->pkt.user_id);

    make_attribute_uidname(packet->pkt.user_id, EXTRA_UID_NAME_SPACE);

    if( list_mode ) {
	fprintf (listfp, ":attribute packet: %s\n", packet->pkt.user_id->name );
    }
    return 0;
}


static int
parse_comment( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *packet )
{
    byte *p;

    /* Cap comment packet at a reasonable value to avoid an integer
       overflow in the malloc below.  Comment packets are actually not
       anymore define my OpenPGP and we even stopped to use our
       private comment packet. */
    if (pktlen>65536)
      {
	log_error ("packet(%d) too large\n", pkttype);
	iobuf_skip_rest (inp, pktlen, 0);
	return G10ERR_INVALID_PACKET;
      }
    packet->pkt.comment = xmalloc(sizeof *packet->pkt.comment + pktlen - 1);
    packet->pkt.comment->len = pktlen;
    p = packet->pkt.comment->data;
    for( ; pktlen; pktlen--, p++ )
	*p = iobuf_get_noeof(inp);

    if( list_mode ) {
	int n = packet->pkt.comment->len;
	fprintf (listfp, ":%scomment packet: \"", pkttype == PKT_OLD_COMMENT?
					 "OpenPGP draft " : "GnuPG " );
	for(p=packet->pkt.comment->data; n; p++, n-- ) {
	    if( *p >= ' ' && *p <= 'z' )
		putc (*p, listfp);
	    else
		fprintf (listfp, "\\x%02x", *p );
	}
	fprintf (listfp, "\"\n");
    }
    return 0;
}


static void
parse_trust( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *pkt )
{
  int c;

  if (pktlen)
    {
      c = iobuf_get_noeof(inp);
      pktlen--;
      pkt->pkt.ring_trust = xmalloc( sizeof *pkt->pkt.ring_trust );
      pkt->pkt.ring_trust->trustval = c;
      pkt->pkt.ring_trust->sigcache = 0;
      if (!c && pktlen==1)
        {
          c = iobuf_get_noeof (inp);
          pktlen--;
          /* we require that bit 7 of the sigcache is 0 (easier eof handling)*/
          if ( !(c & 0x80) )
            pkt->pkt.ring_trust->sigcache = c;
        }
      if( list_mode )
	fprintf (listfp, ":trust packet: flag=%02x sigcache=%02x\n",
               pkt->pkt.ring_trust->trustval,
               pkt->pkt.ring_trust->sigcache);
    }
  else
    {
      if( list_mode )
	fprintf (listfp, ":trust packet: empty\n");
    }
  iobuf_skip_rest (inp, pktlen, 0);
}


static int
parse_plaintext( IOBUF inp, int pkttype, unsigned long pktlen,
		 PACKET *pkt, int new_ctb, int partial )
{
    int rc = 0;
    int mode, namelen;
    PKT_plaintext *pt;
    byte *p;
    int c, i;

    if( !partial && pktlen < 6 ) {
	log_error("packet(%d) too short (%lu)\n", pkttype, (ulong)pktlen);
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    mode = iobuf_get_noeof(inp); if( pktlen ) pktlen--;
    namelen = iobuf_get_noeof(inp); if( pktlen ) pktlen--;
    /* Note that namelen will never exceeds 255 byte. */
    pt = pkt->pkt.plaintext = xmalloc(sizeof *pkt->pkt.plaintext + namelen -1);
    pt->new_ctb = new_ctb;
    pt->mode = mode;
    pt->namelen = namelen;
    pt->is_partial = partial;
    if( pktlen ) {
	for( i=0; pktlen > 4 && i < namelen; pktlen--, i++ )
	    pt->name[i] = iobuf_get_noeof(inp);
    }
    else {
	for( i=0; i < namelen; i++ )
	    if( (c=iobuf_get(inp)) == -1 )
		break;
	    else
		pt->name[i] = c;
    }
    pt->timestamp = read_32(inp); if( pktlen) pktlen -= 4;
    pt->len = pktlen;
    pt->buf = inp;
    pktlen = 0;

    if( list_mode ) {
	fprintf (listfp, ":literal data packet:\n"
	       "\tmode %c (%X), created %lu, name=\"",
	            mode >= ' ' && mode <'z'? mode : '?', mode,
		    (ulong)pt->timestamp );
	for(p=pt->name,i=0; i < namelen; p++, i++ ) {
	    if( *p >= ' ' && *p <= 'z' )
		putc (*p, listfp);
	    else
		fprintf (listfp, "\\x%02x", *p );
	}
	fprintf (listfp, "\",\n\traw data: ");
	if(partial)
	  fprintf (listfp, "unknown length\n");
	else
	  fprintf (listfp, "%lu bytes\n", (ulong)pt->len );
    }

  leave:
    return rc;
}


static int
parse_compressed( IOBUF inp, int pkttype, unsigned long pktlen,
		  PACKET *pkt, int new_ctb )
{
    PKT_compressed *zd;

    /* pktlen is here 0, but data follows
     * (this should be the last object in a file or
     *	the compress algorithm should know the length)
     */
    zd = pkt->pkt.compressed =	xmalloc(sizeof *pkt->pkt.compressed );
    zd->algorithm = iobuf_get_noeof(inp);
    zd->len = 0; /* not used */ 
    zd->new_ctb = new_ctb;
    zd->buf = inp;
    if( list_mode )
	fprintf (listfp, ":compressed packet: algo=%d\n", zd->algorithm);
    return 0;
}


static int
parse_encrypted( IOBUF inp, int pkttype, unsigned long pktlen,
		 PACKET *pkt, int new_ctb, int partial )
{
    int rc = 0;
    PKT_encrypted *ed;
    unsigned long orig_pktlen = pktlen;

    ed = pkt->pkt.encrypted =  xmalloc(sizeof *pkt->pkt.encrypted );
    ed->len = pktlen;
    /* we don't know the extralen which is (cipher_blocksize+2)
       because the algorithm ist not specified in this packet.
       However, it is only important to know this for some sanity
       checks on the packet length - it doesn't matter that we can't
       do it */
    ed->extralen = 0;
    ed->buf = NULL;
    ed->new_ctb = new_ctb;
    ed->is_partial = partial;
    ed->mdc_method = 0;
    if( pkttype == PKT_ENCRYPTED_MDC ) {
	/* fixme: add some pktlen sanity checks */
	int version;

	version = iobuf_get_noeof(inp); 
        if (orig_pktlen)
            pktlen--;
	if( version != 1 ) {
	    log_error("encrypted_mdc packet with unknown version %d\n",
								version);
            /*skip_rest(inp, pktlen); should we really do this? */
            rc = G10ERR_INVALID_PACKET;
	    goto leave;
	}
	ed->mdc_method = DIGEST_ALGO_SHA1;
    }
    if( orig_pktlen && pktlen < 10 ) { /* actually this is blocksize+2 */
	log_error("packet(%d) too short\n", pkttype);
        rc = G10ERR_INVALID_PACKET;
	iobuf_skip_rest(inp, pktlen, partial);
	goto leave;
    }
    if( list_mode ) {
	if( orig_pktlen )
	    fprintf (listfp, ":encrypted data packet:\n\tlength: %lu\n",
                     orig_pktlen);
	else
	    fprintf (listfp, ":encrypted data packet:\n\tlength: unknown\n");
	if( ed->mdc_method )
	    fprintf (listfp, "\tmdc_method: %d\n", ed->mdc_method );
    }

    ed->buf = inp;

  leave:
    return rc;
}


static int
parse_mdc( IOBUF inp, int pkttype, unsigned long pktlen,
				   PACKET *pkt, int new_ctb )
{
    int rc = 0;
    PKT_mdc *mdc;
    byte *p;

    mdc = pkt->pkt.mdc=  xmalloc(sizeof *pkt->pkt.mdc );
    if( list_mode )
	fprintf (listfp, ":mdc packet: length=%lu\n", pktlen);
    if( !new_ctb || pktlen != 20 ) {
	log_error("mdc_packet with invalid encoding\n");
        rc = G10ERR_INVALID_PACKET;
	goto leave;
    }
    p = mdc->hash;
    for( ; pktlen; pktlen--, p++ )
	*p = iobuf_get_noeof(inp);

  leave:
    return rc;
}


/*
 * This packet is internally generated by GPG (by armor.c) to
 * transfer some information to the lower layer.  To make sure that
 * this packet is really a GPG faked one and not one comming from outside,
 * we first check that there is a unique tag in it.
 * The format of such a control packet is:
 *   n byte  session marker
 *   1 byte  control type CTRLPKT_xxxxx
 *   m byte  control data
 */

static int
parse_gpg_control( IOBUF inp, int pkttype,
		   unsigned long pktlen, PACKET *packet, int partial )
{
    byte *p;
    const byte *sesmark;
    size_t sesmarklen;
    int i;

    if ( list_mode )
        fprintf (listfp, ":packet 63: length %lu ",  pktlen);

    sesmark = get_session_marker ( &sesmarklen );
    if ( pktlen < sesmarklen+1 ) /* 1 is for the control bytes */
        goto skipit;
    for( i=0; i < sesmarklen; i++, pktlen-- ) {
	if ( sesmark[i] != iobuf_get_noeof(inp) )
            goto skipit;
    }
    if (pktlen > 4096)
      goto skipit; /* Definitely too large.  We skip it to avoid an
                      overflow in the malloc. */
    if ( list_mode )
        puts ("- gpg control packet");

    packet->pkt.gpg_control = xmalloc(sizeof *packet->pkt.gpg_control
                                      + pktlen - 1);
    packet->pkt.gpg_control->control = iobuf_get_noeof(inp); pktlen--;
    packet->pkt.gpg_control->datalen = pktlen;
    p = packet->pkt.gpg_control->data;
    for( ; pktlen; pktlen--, p++ )
	*p = iobuf_get_noeof(inp);

    return 0;

 skipit:
    if ( list_mode ) {
        int c;

        i=0;
        fprintf (listfp, "- private (rest length %lu)\n",  pktlen);
        if( partial ) {
            while( (c=iobuf_get(inp)) != -1 )
                dump_hex_line(c, &i);
        }
        else {
            for( ; pktlen; pktlen-- )
                dump_hex_line(iobuf_get(inp), &i);
        }
        putc ('\n', listfp);
    }
    iobuf_skip_rest(inp,pktlen, 0);
    return G10ERR_INVALID_PACKET;
}

/* create a gpg control packet to be used internally as a placeholder */
PACKET *
create_gpg_control( ctrlpkttype_t type, const byte *data, size_t datalen )
{
    PACKET *packet;
    byte *p;

    packet = xmalloc( sizeof *packet );
    init_packet(packet);
    packet->pkttype = PKT_GPG_CONTROL;
    packet->pkt.gpg_control = xmalloc(sizeof *packet->pkt.gpg_control
                                      + datalen - 1);
    packet->pkt.gpg_control->control = type;
    packet->pkt.gpg_control->datalen = datalen;
    p = packet->pkt.gpg_control->data;
    for( ; datalen; datalen--, p++ )
	*p = *data++;

    return packet;
}
