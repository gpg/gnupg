/* parse-packet.c  - read packets
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
#include "filter.h"
#include "options.h"

static mpi_print_mode = 0;
static list_mode = 0;

static void skip_packet( IOBUF inp, int pkttype, unsigned long pktlen );
static void skip_rest( IOBUF inp, unsigned long pktlen );
static int  parse_publickey( IOBUF inp, int pkttype, unsigned long pktlen,
							     PACKET *packet );
static int  parse_signature( IOBUF inp, int pkttype, unsigned long pktlen,
							 PKT_signature *sig );
static int  parse_certificate( IOBUF inp, int pkttype, unsigned long pktlen,
				      byte *hdr, int hdrlen, PACKET *packet );
static int  parse_user_id( IOBUF inp, int pkttype, unsigned long pktlen,
							   PACKET *packet );
static void parse_comment( IOBUF inp, int pkttype, unsigned long pktlen );
static void parse_trust( IOBUF inp, int pkttype, unsigned long pktlen );
static int  parse_plaintext( IOBUF inp, int pkttype, unsigned long pktlen,
								PACKET *pkt );
static int  parse_compressed( IOBUF inp, int pkttype, unsigned long pktlen,
							   PACKET *packet );
static int  parse_encrypted( IOBUF inp, int pkttype, unsigned long pktlen,
							   PACKET *packet );

static u16
checksum( byte *p )
{
    u16 n, a;

    n = *p++ << 8;
    n |= *p++;
    for(a=0; n; n-- )
	a += *p++;
    return a;
}

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
    return old;
}

/****************
 * Parse a Packet and return it in packet
 * Returns: 0 := valid packet in pkt
 *	   -1 := no more packets
 *	   >0 := error
 * Note: The function may return an error and a partly valid packet;
 * caller must free this packet.
 */
int
parse_packet( IOBUF inp, PACKET *pkt )
{
    int rc, ctb, pkttype, lenbytes;
    unsigned long pktlen;
    byte hdr[5];
    int hdrlen;

    assert( !pkt->pkt.generic );
    if( (ctb = iobuf_get(inp)) == -1 )
	return -1;
    hdrlen=0;
    hdr[hdrlen++] = ctb;
    if( !(ctb & 0x80) ) {
	log_error("invalid packet at '%s'\n", iobuf_where(inp) );
	return G10ERR_INVALID_PACKET;
    }
    /* we handle the pgp 3 extensions here, so that we can skip such packets*/
    pkttype =  ctb & 0x40 ? (ctb & 0x3f) : ((ctb>>2)&0xf);
    lenbytes = (ctb & 0x40) || ((ctb&3)==3)? 0 : (1<<(ctb & 3));
    pktlen = 0;
    if( !lenbytes ) {
	pktlen = 0; /* don't know the value */
	iobuf_set_block_mode(inp, 1);
    }
    else {
	for( ; lenbytes; lenbytes-- ) {
	    pktlen <<= 8;
	    pktlen |= hdr[hdrlen++] = iobuf_get_noeof(inp);
	}
    }

    if( DBG_PACKET )
	log_debug("parse_packet(iob=%d): type=%d length=%lu\n",
					    iobuf_id(inp), pkttype, pktlen );
    pkt->pkttype = pkttype;
    rc = G10ERR_UNKNOWN_PACKET; /* default to no error */
    switch( pkttype ) {
      case PKT_PUBKEY_CERT:
	pkt->pkt.pubkey_cert = m_alloc_clear(sizeof *pkt->pkt.pubkey_cert );
	rc = parse_certificate(inp, pkttype, pktlen, hdr, hdrlen, pkt );
	break;
      case PKT_SECKEY_CERT:
	pkt->pkt.seckey_cert = m_alloc_clear(sizeof *pkt->pkt.seckey_cert );
	rc = parse_certificate(inp, pkttype, pktlen, hdr, hdrlen, pkt );
	break;
      case PKT_PUBKEY_ENC:
	rc = parse_publickey(inp, pkttype, pktlen, pkt );
	break;
      case PKT_SIGNATURE:
	pkt->pkt.signature = m_alloc_clear(sizeof *pkt->pkt.signature );
	rc = parse_signature(inp, pkttype, pktlen, pkt->pkt.signature );
	m_check(pkt->pkt.signature);
	break;
      case PKT_USER_ID:
	rc = parse_user_id(inp, pkttype, pktlen, pkt );
	break;
      case PKT_COMMENT:
	parse_comment(inp, pkttype, pktlen);
	break;
      case PKT_RING_TRUST:
	parse_trust(inp, pkttype, pktlen);
	break;
      case PKT_PLAINTEXT:
	rc = parse_plaintext(inp, pkttype, pktlen, pkt );
	break;
      case PKT_COMPR_DATA:
	rc = parse_compressed(inp, pkttype, pktlen, pkt );
	break;
      case PKT_ENCR_DATA:
	rc = parse_encrypted(inp, pkttype, pktlen, pkt );
	break;
      default:
	skip_packet(inp, pkttype, pktlen);
	break;
    }

    return rc;
}


static void
skip_packet( IOBUF inp, int pkttype, unsigned long pktlen )
{
    if( list_mode )
	printf(":unknown packet: type %2d, length %lu\n", pkttype, pktlen );
    skip_rest(inp,pktlen);
}

static void
skip_rest( IOBUF inp, unsigned long pktlen )
{
    if( iobuf_in_block_mode(inp) ) {
	while( iobuf_get(inp) != -1 )
		;
    }
    else {
	for( ; pktlen; pktlen-- )
	    iobuf_get(inp);
    }
}


static int
parse_publickey( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *packet )
{
    int version;
    unsigned n;
    PKT_pubkey_enc *k;

    k = packet->pkt.pubkey_enc = m_alloc(sizeof *packet->pkt.pubkey_enc );
    if( pktlen < 12 ) {
	log_error("packet(%d) too short\n", pkttype);
	goto leave;
    }
    version = iobuf_get_noeof(inp); pktlen--;
    if( version != 2 && version != 3 ) {
	log_error("packet(%d) with unknown version %d\n", pkttype, version);
	goto leave;
    }
    k->keyid[0] = read_32(inp); pktlen -= 4;
    k->keyid[1] = read_32(inp); pktlen -= 4;
    k->pubkey_algo = iobuf_get_noeof(inp); pktlen--;
    if( list_mode )
	printf(":public key packet: keyid %08lX%08lX\n",
					k->keyid[0], k->keyid[1]);
    if( k->pubkey_algo == PUBKEY_ALGO_RSA ) {
	n = pktlen;
	k->d.rsa.rsa_integer = mpi_decode(inp, &n ); pktlen -=n;
	if( list_mode ) {
	    printf("\trsa integer: ");
	    mpi_print(stdout, k->d.rsa.rsa_integer, mpi_print_mode );
	    putchar('\n');
	}
    }
    else if( list_mode )
	printf("\tunknown algorithm %d\n", k->pubkey_algo );


  leave:
    skip_rest(inp, pktlen);
    return 0;
}


static int
parse_signature( IOBUF inp, int pkttype, unsigned long pktlen,
					  PKT_signature *sig )
{
    int version, md5_len;
    unsigned n;

    if( pktlen < 16 ) {
	log_error("packet(%d) too short\n", pkttype);
	goto leave;
    }
    version = iobuf_get_noeof(inp); pktlen--;
    if( version != 2 && version != 3 ) {
	log_error("packet(%d) with unknown version %d\n", pkttype, version);
	goto leave;
    }
    m_check(sig);
    md5_len = iobuf_get_noeof(inp); pktlen--;
    sig->sig_class = iobuf_get_noeof(inp); pktlen--;
    sig->timestamp = read_32(inp); pktlen -= 4;
    sig->keyid[0] = read_32(inp); pktlen -= 4;
    sig->keyid[1] = read_32(inp); pktlen -= 4;
    sig->pubkey_algo = iobuf_get_noeof(inp); pktlen--;
    m_check(sig);
    if( list_mode )
	printf(":signature packet: keyid %08lX%08lX\n"
	       "\tversion %d, created %lu, md5len %d, sigclass %02x\n",
		sig->keyid[0], sig->keyid[1],
		version, sig->timestamp, md5_len, sig->sig_class );
    if( sig->pubkey_algo == PUBKEY_ALGO_RSA ) {
	if( pktlen < 5 ) {
	    log_error("packet(%d) too short\n", pkttype);
	    goto leave;
	}
    m_check(sig);
	sig->d.rsa.digest_algo = iobuf_get_noeof(inp); pktlen--;
	sig->d.rsa.digest_start[0] = iobuf_get_noeof(inp); pktlen--;
	sig->d.rsa.digest_start[1] = iobuf_get_noeof(inp); pktlen--;
    m_check(sig);
	n = pktlen;
	sig->d.rsa.rsa_integer = mpi_decode(inp, &n ); pktlen -=n;
	if( list_mode ) {
	    printf("\tdigest algo %d, begin of digest %02x %02x\n",
		    sig->d.rsa.digest_algo,
		    sig->d.rsa.digest_start[0], sig->d.rsa.digest_start[1] );
	    printf("\trsa integer: ");
	    mpi_print(stdout, sig->d.rsa.rsa_integer, mpi_print_mode );
	    putchar('\n');
	}
    }
    else if( list_mode )
	printf("\tunknown algorithm %d\n", sig->pubkey_algo );
    m_check(sig);


  leave:
    skip_rest(inp, pktlen);
    return 0;
}




static int
parse_certificate( IOBUF inp, int pkttype, unsigned long pktlen,
			      byte *hdr, int hdrlen, PACKET *pkt )
{
    int i, version, algorithm;
    unsigned n;
    unsigned long timestamp;
    unsigned short valid_period;
    MPI rsa_pub_mod, rsa_pub_exp;

    if( pkttype == PKT_PUBKEY_CERT ) {
	pkt->pkt.pubkey_cert->mfx.md5 = md5_open(0);
	pkt->pkt.pubkey_cert->mfx.rmd160 = rmd160_open(0);
	pkt->pkt.pubkey_cert->mfx.maxbuf_size = 1;
	md5_write(pkt->pkt.pubkey_cert->mfx.md5, hdr, hdrlen);
	rmd160_write(pkt->pkt.pubkey_cert->mfx.rmd160, hdr, hdrlen);
	iobuf_push_filter( inp, md_filter, &pkt->pkt.pubkey_cert->mfx );
    }

    if( pktlen < 12 ) {
	log_error("packet(%d) too short\n", pkttype);
	goto leave;
    }
    version = iobuf_get_noeof(inp); pktlen--;
    if( version != 2 && version != 3 ) {
	log_error("packet(%d) with unknown version %d\n", pkttype, version);
	goto leave;
    }

    timestamp = read_32(inp); pktlen -= 4;
    valid_period = read_16(inp); pktlen -= 2;
    algorithm = iobuf_get_noeof(inp); pktlen--;
    if( list_mode )
	printf(":%s key certification packet:\n"
	       "\tversion %d, created %lu, valid for %hu days\n",
		pkttype == PKT_PUBKEY_CERT? "public": "secret",
		version, timestamp, valid_period );
    if( pkttype == PKT_SECKEY_CERT )  {
	pkt->pkt.seckey_cert->timestamp = timestamp;
	pkt->pkt.seckey_cert->valid_days = valid_period;
	pkt->pkt.seckey_cert->pubkey_algo = algorithm;
    }
    else {
	pkt->pkt.pubkey_cert->timestamp = timestamp;
	pkt->pkt.pubkey_cert->valid_days = valid_period;
	pkt->pkt.pubkey_cert->pubkey_algo = algorithm;
    }

    if( algorithm == PUBKEY_ALGO_RSA ) {
	n = pktlen; rsa_pub_mod = mpi_decode(inp, &n ); pktlen -=n;
	n = pktlen; rsa_pub_exp = mpi_decode(inp, &n ); pktlen -=n;
	if( list_mode ) {
	    printf(  "\tpublic modulus  n:  ");
	    mpi_print(stdout, rsa_pub_mod, mpi_print_mode  );
	    printf("\n\tpublic exponent e: ");
	    mpi_print(stdout, rsa_pub_exp, mpi_print_mode  );
	    putchar('\n');
	}
	if( pkttype == PKT_PUBKEY_CERT ) {
	    pkt->pkt.pubkey_cert->d.rsa.rsa_n = rsa_pub_mod;
	    pkt->pkt.pubkey_cert->d.rsa.rsa_e = rsa_pub_exp;
	}
	else {
	    PKT_seckey_cert *cert = pkt->pkt.seckey_cert;
	    byte temp[8];
	    byte *mpibuf;

	    pkt->pkt.seckey_cert->d.rsa.rsa_n = rsa_pub_mod;
	    pkt->pkt.seckey_cert->d.rsa.rsa_e = rsa_pub_exp;
	    cert->d.rsa.protect_algo = iobuf_get_noeof(inp); pktlen--;
	    if( list_mode )
		printf(  "\tprotect algo: %d\n", cert->d.rsa.protect_algo);
	    if( cert->d.rsa.protect_algo ) {
		cert->d.rsa.is_protected = 1;
		for(i=0; i < 8 && pktlen; i++, pktlen-- )
		    temp[i] = iobuf_get_noeof(inp);
		if( list_mode ) {
		    printf(  "\tprotect IV: ");
		    for(i=0; i < 8; i++ )
			printf(" %02x", temp[i] );
		    putchar('\n');
		}
		if( cert->d.rsa.protect_algo == CIPHER_ALGO_IDEA )
		    memcpy(cert->d.rsa.protect.idea.iv, temp, 8 );
		else if( cert->d.rsa.protect_algo == CIPHER_ALGO_BLOWFISH )
		    memcpy(cert->d.rsa.protect.blowfish.iv, temp, 8 );
	    }
	    else
		cert->d.rsa.is_protected = 0;

	    n = pktlen; mpibuf = mpi_read(inp, &n ); pktlen -=n; assert(n>=2);
	    cert->d.rsa.rsa_d = (MPI)mpibuf;

	    n = pktlen; mpibuf = mpi_read(inp, &n ); pktlen -=n; assert(n>=2);
	    cert->d.rsa.rsa_p = (MPI)mpibuf;

	    n = pktlen; mpibuf = mpi_read(inp, &n ); pktlen -=n; assert(n>=2);
	    cert->d.rsa.rsa_q = (MPI)mpibuf;

	    n = pktlen; mpibuf = mpi_read(inp, &n ); pktlen -=n; assert(n>=2);
	    cert->d.rsa.rsa_u = (MPI)mpibuf;

	    cert->d.rsa.csum = read_16(inp); pktlen -= 2;
	    cert->d.rsa.calc_csum = 0;
	    if( list_mode ) {
		printf("\t[secret values d,p,q,u are not shown]\n"
		       "\tchecksum: %04hx\n", cert->d.rsa.csum);
	    }
	    if( !cert->d.rsa.is_protected ) { /* convert buffer to MPIs */
	      #define X(a) do { 					\
		    mpibuf = (byte*)cert->d.rsa.rsa_##a;		\
		    cert->d.rsa.calc_csum += checksum( mpibuf );	\
		    cert->d.rsa.rsa_##a = mpi_decode_buffer( mpibuf );	\
		    m_free( mpibuf );					\
		} while(0)
		X(d);
		X(p);
		X(q);
		X(u);
	      #undef X
	     /* log_mpidump("rsa n=", cert->d.rsa.rsa_n );
		log_mpidump("rsa e=", cert->d.rsa.rsa_e );
		log_mpidump("rsa d=", cert->d.rsa.rsa_d );
		log_mpidump("rsa p=", cert->d.rsa.rsa_p );
		log_mpidump("rsa q=", cert->d.rsa.rsa_q );
		log_mpidump("rsa u=", cert->d.rsa.rsa_u ); */
	    }
	}
    }
    else if( list_mode )
	printf("\tunknown algorithm %d\n", algorithm );


  leave:
    if( pkttype == PKT_PUBKEY_CERT )
	iobuf_pop_filter( inp, md_filter, &pkt->pkt.pubkey_cert->mfx );
    skip_rest(inp, pktlen);
    return 0;
}


static int
parse_user_id( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *packet )
{
    byte *p;

    packet->pkt.user_id = m_alloc(sizeof *packet->pkt.user_id  + pktlen - 1);
    packet->pkt.user_id->len = pktlen;
    p = packet->pkt.user_id->name;
    for( ; pktlen; pktlen--, p++ )
	*p = iobuf_get_noeof(inp);

    if( list_mode ) {
	int n = packet->pkt.user_id->len;
	printf(":user id packet: \"");
	for(p=packet->pkt.user_id->name; n; p++, n-- ) {
	    if( *p >= ' ' && *p <= 'z' )
		putchar(*p);
	    else
		printf("\\x%02x", *p );
	}
	printf("\"\n");
    }
    return 0;
}

static void
parse_comment( IOBUF inp, int pkttype, unsigned long pktlen )
{
    if( list_mode ) {
	printf(":comment packet: \"" );
	for( ; pktlen; pktlen-- ) {
	    int c;
	    c = iobuf_get_noeof(inp);
	    if( c >= ' ' && c <= 'z' )
		putchar(c);
	    else
		printf("\\x%02x", c );
	}
	printf("\"\n");
    }
    skip_rest(inp, pktlen);
}


static void
parse_trust( IOBUF inp, int pkttype, unsigned long pktlen )
{
    int c;

    c = iobuf_get_noeof(inp);
    if( list_mode )
	printf(":trust packet: flag=%02x\n", c );
  #if 0 /* fixme: depending on the context we have different interpretations*/
    if( prev_packet_is_a_key_packet ) {
	int ot = c & 7;   /* ownertrust bits (for the key owner) */

	    !ot ? "undefined" :
	ot == 1 ? "unknown"   : /* we don't know the owner of this key */
	ot == 2 ? "no"        : /* usually we do not trust this key owner */
				/* to sign other keys */
	ot == 5 ? "usually"   : /* usually we trust this key owner to sign */
	ot == 6 ? "always"    : /* always trust this key owner to sign */
	ot == 7 ? "ultimate"  : /* also present in the secret keyring */
	      ""                /* reserved value */
	if( c & (1<<5) )
	    "key is disabled"
	if( c & (1<<7) )
	    "buckstop"
    else if( prev_packet_is_user_is_packet ) {
	    int kl = c & 3; /* keylegit bits */
	0 = "unknown, undefined, or uninitialized trust"
	1 = "we do not trust this key's ownership"
	2 = "we have marginal confidence of this key's ownership"
	3 = "we completely trust this key's ownership."
	 /* This one (3) requires either:
	  * - 1 ultimately trusted signature (SIGTRUST=7)
	  * - COMPLETES_NEEDED completely trusted signatures (SIGTRUST=6)
	  * - MARGINALS_NEEDED marginally trusted signatures (SIGTRUST=5)
	  */
	if( c & 0x80 )
	    "warnonly"
    else if( prev_packet_is_a_signature ) {
	 Bits 0-2 - SIGTRUST bits - Trust bits for this signature.  Value is
		    copied directly from OWNERTRUST bits of signer:
	      000 - undefined, or uninitialized trust.
	      001 - unknown
	      010 - We do not trust this signature.
	      011 - reserved
	      100 - reserved
	      101 - We reasonably trust this signature.
	      110 - We completely trust this signature.
	      111 - ultimately trusted signature (from the owner of the ring)
	  Bit 6 - CHECKED bit - This means that the key checking pass (pgp -kc,
		  also invoked automatically whenever keys are added to the
		  keyring) has tested this signature and found it good.  If
		  this bit is not set, the maintenance pass considers this
		  signature untrustworthy.
	  Bit 7 - CONTIG bit - Means this signature leads up a contiguous trusted
		  certification path all the way back to the ultimately-
		  trusted keyring owner, where the buck stops.	This bit is derived
		  from other trust packets.  It is currently not used for anything
		  in PGP.
    }
  #endif
}


static int
parse_plaintext( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *pkt )
{
    int mode, namelen;
    PKT_plaintext *pt;
    byte *p;
    int c, i;

    if( pktlen && pktlen < 6 ) {
	log_error("packet(%d) too short (%lu)\n", pkttype, (ulong)pktlen);
	goto leave;
    }
    mode = iobuf_get_noeof(inp); if( pktlen ) pktlen--;
    namelen = iobuf_get_noeof(inp); if( pktlen ) pktlen--;
    pt = pkt->pkt.plaintext = m_alloc(sizeof *pkt->pkt.plaintext + namelen -1);
    pt->mode = mode;
    pt->namelen = namelen;
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
	printf(":literal data packet:\n"
	       "\tmode %c, created %lu, name=\"",
		    mode >= ' ' && mode <'z'? mode : '?',
		    pt->timestamp );
	for(p=pt->name,i=0; i < namelen; p++, i++ ) {
	    if( *p >= ' ' && *p <= 'z' )
		putchar(*p);
	    else
		printf("\\x%02x", *p );
	}
	printf("\",\n\traw data: %lu bytes\n", pt->len );
    }

  leave:
    return 0;
}


static int
parse_compressed( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *pkt )
{
    PKT_compressed *zd;
    int algorithm;

    /* pktlen is here 0, but data follows
     * (this should be the last object in a file or
     *	the compress algorithm should know the length)
     */
    zd = pkt->pkt.compressed =	m_alloc(sizeof *pkt->pkt.compressed );
    zd->len = 0; /* not yet used */
    zd->algorithm = iobuf_get_noeof(inp);
    zd->buf = inp;
    algorithm = iobuf_get_noeof(inp);
    if( list_mode )
	printf(":compressed packet: algo=%d\n", zd->algorithm);
    return 0;
}


static int
parse_encrypted( IOBUF inp, int pkttype, unsigned long pktlen, PACKET *pkt )
{
    PKT_encr_data *ed;

    ed = pkt->pkt.encr_data =  m_alloc(sizeof *pkt->pkt.encr_data );
    ed->len = pktlen;
    ed->buf = NULL;
    if( pktlen && pktlen < 10 ) {
	log_error("packet(%d) too short\n", pkttype);
	skip_rest(inp, pktlen);
	goto leave;
    }
    if( list_mode )
	if( pktlen )
	    printf(":encrypted data packet:\n\tlength: %lu\n", pktlen-10);
	else
	    printf(":encrypted data packet:\n\tlength: unknown\n");

    ed->buf = inp;
    pktlen = 0;

  leave:
    return 0;
}


