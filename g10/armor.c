/* armor.c - Armor filter
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
#include <errno.h>
#include <assert.h>

#include "errors.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "filter.h"
#include "packet.h"
#include "options.h"




#define CRCINIT 0xB704CE
#define CRCPOLY 0X864CFB
#define CRCUPDATE(a,c) do {						    \
			a = ((a) << 8) ^ crc_table[((a)&0xff >> 16) ^ (c)]; \
			a &= 0x00ffffff;				    \
		    } while(0)
static u32 crc_table[256];
static byte bintoasc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			 "abcdefghijklmnopqrstuvwxyz"
			 "0123456789+/";
static byte asctobin[256]; /* runtime initialized */
static int is_initialized;

typedef enum {
    fhdrINIT=0,
    fhdrLF,
    fhdrWAIT,
    fhdrWAITINFO,
    fhdrWAITCLEARSIG,
    fhdrDASH,
    fhdrHEAD,
    fhdrDASH2,
    fhdrINFO
} fhdr_state_t;

struct fhdr_struct {
    fhdr_state_t state;
    int count;
    int hdr_line; /* number of the header line */
    char buf[256];
};


/* if we encounter this armor string with this index, go
 * into a mode, which fakes packets and wait for the next armor */
#define BEGIN_SIGNED_MSG_IDX 3
static char *head_strings[] = {
    "BEGIN PGP MESSAGE",
    "BEGIN PGP PUBLIC KEY BLOCK",
    "BEGIN PGP SIGNATURE",
    "BEGIN PGP SIGNED MESSAGE",
    NULL
};
static char *tail_strings[] = {
    "END PGP MESSAGE",
    "END PGP PUBLIC KEY BLOCK",
    "END PGP SIGNATURE",
    NULL
};


static void
initialize(void)
{
    int i, j;
    u32 t;
    byte *s;

    /* init the crc lookup table */
    crc_table[0] = 0;
    for(i=j=0; j < 128; j++ ) {
	t = crc_table[j];
	if( t & 0x00800000 ) {
	    t <<= 1;
	    crc_table[i++] = t ^ CRCPOLY;
	    crc_table[i++] = t;
	}
	else {
	    t <<= 1;
	    crc_table[i++] = t;
	    crc_table[i++] = t ^ CRCPOLY;
	}
    }
    /* build the helptable for radix64 to bin conversion */
    for(i=0; i < 256; i++ )
	asctobin[i] = 255; /* used to detect invalid characters */
    for(s=bintoasc,i=0; *s; s++,i++ )
	asctobin[*s] = i;

    is_initialized=1;
}

/****************
 * Check wether this is a armored file or not
 * See also parse-packet.c for details on this code
 * Returns: True if it seems to be armored
 */
static int
is_armored( byte *buf, size_t len )
{
    int ctb, pkttype;

    if( len < 28 )
	return 0; /* not even enough space for the "---BEGIN"... */

    ctb = *buf;
    if( !(ctb & 0x80) )
	return 1; /* invalid packet: assume it is armored */
    pkttype =  ctb & 0x40 ? (ctb & 0x3f) : ((ctb>>2)&0xf);
    /*lenbytes = (ctb & 0x40) || ((ctb&3)==3)? 0 : (1<<(ctb & 3));*/
    switch( pkttype ) {
      case PKT_PUBLIC_CERT:
      case PKT_SECRET_CERT:
      case PKT_PUBKEY_ENC:
      case PKT_SIGNATURE:
      case PKT_COMMENT:
      case PKT_PLAINTEXT:
      case PKT_COMPRESSED:
      case PKT_ENCRYPTED:
	return 0; /* seems to be a regular packet: not armored */
    }

    return 1;
}




static int
find_header( struct fhdr_struct *fhdr, int c )
{
    int i;
    const char *s;

    if( c == '\n' ) {
	switch( fhdr->state ) {
	  case fhdrINFO:
	    if( !fhdr->count )
		return 1;   /* blank line: data starts with the next line */
	    fhdr->buf[fhdr->count] = 0;
	    log_debug("armor line: '%s'\n", fhdr->buf );
	    /* fall through */
	  case fhdrWAITINFO:
	    fhdr->state = fhdrINFO;
	    fhdr->count = 0;
	    break;
	  case fhdrWAITCLEARSIG:
	    if( fhdr->count++ == 1 ) /* skip the empty line */
		return 1; /* clear signed text follows */
	    else if( fhdr->count > 1 )
		fhdr->state = fhdrWAIT; /* was not valid */
	    break;
	  default:
	    fhdr->state = fhdrLF;
	    break;
	}
    }
    else {
	switch( fhdr->state ) {
	  case fhdrINIT:
	  case fhdrLF:
	    if( c == '-' ) {
		fhdr->state = fhdrDASH;
		fhdr->count = 1;
	    }
	    else
		fhdr->state = fhdrWAIT;
	    break;
	  case fhdrWAIT:
	  case fhdrWAITINFO:
	  case fhdrWAITCLEARSIG:
	    break;
	  case fhdrDASH:
	    if( c == '-' ) {
		if( ++fhdr->count == 5 ) {
		    fhdr->state = fhdrHEAD;
		    fhdr->count = 0;
		}
	    }
	    else
		fhdr->state = fhdrWAIT;
	    break;
	  case fhdrHEAD:
	    if( c != '-' ) {
		if( fhdr->count < DIM(fhdr->buf)-1 )
		    fhdr->buf[fhdr->count++] = c;
	    }
	    else {
		fhdr->buf[fhdr->count] = 0;
		for(i=0; (s=head_strings[i]); i++ )
		    if( !strcmp(s,fhdr->buf) )
			break;
		if( s ) { /* found string; wait for trailing dashes */
		    fhdr->hdr_line = i;
		    fhdr->state = fhdrDASH2;
		    fhdr->count = 1;
		}
		else
		    fhdr->state = fhdrWAIT;
	    }
	    break;

	  case fhdrDASH2:
	    if( c == '-' ) {
		if( ++fhdr->count == 5 ) {
		    fhdr->state = fhdrWAITINFO;
		    log_debug("armor head: '%s'\n",
					head_strings[fhdr->hdr_line]);
		    fhdr->state = fhdr->hdr_line == BEGIN_SIGNED_MSG_IDX
				   ? fhdrWAITCLEARSIG : fhdrWAITINFO;
		    if( fhdr->state == fhdrWAITCLEARSIG )
			fhdr->count = 0;
		}
	    }
	    else
		fhdr->state = fhdrWAIT;
	    break;

	  case fhdrINFO:
	    if( fhdr->count < DIM(fhdr->buf)-1 )
		fhdr->buf[fhdr->count++] = c;
	    break;

	  default: abort();
	}
    }
    return 0;
}

/****************
 * check wether the trailer is okay.
 * Returns: 0 := still in trailer
 *	    -1 := Okay
 *	    1 := Error in trailer
 */
static int
check_trailer( struct fhdr_struct *fhdr, int c )
{
    return -1;
    /* FIXME: implement this ! */
}


/* figure out wether the data is armored or not */
static int
check_input( armor_filter_context_t *afx, IOBUF a )
{
    int rc = 0;
    int c;
    size_t n = 0, nn=0;
    struct fhdr_struct fhdr;

    assert( DIM(afx->helpbuf) >= 50 );
    memset( &fhdr, 0, sizeof(fhdr) );

    /* read a couple of bytes */
    for( n=0; n < DIM(afx->helpbuf); n++ ) {
	if( (c=iobuf_get(a)) == -1 )
	    break;
	afx->helpbuf[n] = c & 0xff;
    }

    if( !n )
	rc = -1;
    else if( is_armored( afx->helpbuf, n ) ) {
	for(nn=0; nn < n; nn++ )
	    if( find_header( &fhdr, afx->helpbuf[nn] ) )
		break;
	if( nn == n ) { /* continue read */
	    while( (c=iobuf_get(a)) != -1 )
		if( find_header( &fhdr, c ) )
		    break;
	    if( c == -1 )
		rc = -1; /* eof */
	}
	if( !rc && fhdr.hdr_line == BEGIN_SIGNED_MSG_IDX ) {
	    /* start fake package mode (for clear signatures) */
	    nn++;
	    afx->helplen = n;
	    afx->helpidx = nn;
	    afx->templen = 0;
	    afx->tempidx = 0;
	    afx->fake = m_alloc_clear( sizeof(struct fhdr_struct) );
	}
	else if( !rc ) {
	    /* next byte to read or helpbuf[nn+1]
	     * is the first rad64 byte */
	    nn++;
	    afx->inp_checked = 1;
	    afx->crc = CRCINIT;
	    afx->idx = 0;
	    afx->radbuf[0] = 0;
	    afx->helplen = n;
	    afx->helpidx = nn;
	}
    }
    else {
	afx->inp_checked = 1;
	afx->inp_bypass = 1;
    }

    return rc;
}



/* fake a literal data packet and wait for an armor line */
static int
fake_packet( armor_filter_context_t *afx, IOBUF a,
	     size_t *retn, byte *buf, size_t size  )
{
    int rc = 0;
    int c;
    size_t n = 0;
    struct fhdr_struct *fhdr = afx->fake;
    byte *helpbuf = afx->helpbuf;
    int helpidx = afx->helpidx;
    int helplen = afx->helplen;
    byte *tempbuf = afx->tempbuf;
    int tempidx = afx->tempidx;
    int templen = afx->templen;

    /* FIXME: have to read one ahead or do some other mimic to
     * get rid of the lf before the "begin signed message"
     */
    size = 100; /* FIXME: only used for testing (remove it)  */
    n = 2; /* reserve 2 bytes for the length header */
    while( n < size-2 ) { /* and 2 for the term header */
	if( templen && (fhdr->state == fhdrWAIT || fhdr->state == fhdrLF) ) {
	    if( tempidx < templen ) {
		buf[n++] = tempbuf[tempidx++];
		continue;
	    }
	    tempidx = templen = 0;
	}

	if( helpidx < helplen )
	    c = helpbuf[helpidx++];
	else if( (c=iobuf_get(a)) == -1 )
	    break;
	if( find_header( fhdr, c ) ) {
	    m_free(afx->fake);
	    afx->fake = NULL;
	    afx->inp_checked = 1;
	    afx->crc = CRCINIT;
	    afx->idx = 0;
	    afx->radbuf[0] = 0;
	    /* we don't need to care about the tempbuf */
	    break;
	}
	if( fhdr->state == fhdrWAIT || fhdr->state == fhdrLF ) {
	    if( templen ) {
		tempidx = 0;
		continue;
	    }
	    buf[n++] = c;
	}
	else if( fhdr->state == fhdrWAITINFO
		|| fhdr->state == fhdrINFO )
	    ;
	else { /* store it in another temp. buf */
	    assert( templen < DIM(afx->tempbuf) );
	    tempbuf[templen++] = c;
	}
    }
    buf[0] = (n-2) >> 8;
    buf[1] = (n-2);
    if( !afx->fake ) { /* write last (ending) length header */
	buf[n++] = 0;
	buf[n++] = 0;
    }

    afx->helpidx = helpidx;
    afx->helplen = helplen;
    afx->tempidx = tempidx;
    afx->templen = templen;
    *retn = n;
    return rc;
}



static int
radix64_read( armor_filter_context_t *afx, IOBUF a, size_t *retn,
	      byte *buf, size_t size )
{
    byte val;
    int c, c2;
    int checkcrc=0;
    int rc = 0;
    size_t n = 0;
    int  idx, i;
    u32 crc;

    crc = afx->crc;
    idx = afx->idx;
    val = afx->radbuf[0];
    for( n=0; n < size; ) {
	if( afx->helpidx < afx->helplen )
	    c = afx->helpbuf[afx->helpidx++];
	else if( (c=iobuf_get(a)) == -1 )
	    break;
	if( c == '\n' || c == ' ' || c == '\r' || c == '\t' )
	    continue;
	else if( c == '=' ) { /* pad character: stop */
	    if( idx == 1 )
		buf[n++] = val;
	    checkcrc++;
	    break;
	}
	else if( (c = asctobin[(c2=c)]) == 255 ) {
	    log_error("invalid radix64 character %02x skipped\n", c2);
	    continue;
	}
	switch(idx) {
	  case 0: val =  c << 2; break;
	  case 1: val |= (c>>4)&3; buf[n++]=val;val=(c<<4)&0xf0;break;
	  case 2: val |= (c>>2)&15; buf[n++]=val;val=(c<<6)&0xc0;break;
	  case 3: val |= c&0x3f; buf[n++] = val; break;
	}
	idx = (idx+1) % 4;
    }
    for(i=0; i < n; i++ )
	crc = (crc << 8) ^ crc_table[((crc >> 16)&0xff) ^ buf[i]];
    crc &= 0x00ffffff;
    afx->crc = crc;
    afx->idx = idx;
    afx->radbuf[0] = val;
    if( checkcrc ) {
	afx->inp_eof = 1; /*assume eof */
	for(;;) { /* skip lf and pad characters */
	    if( afx->helpidx < afx->helplen )
		c = afx->helpbuf[afx->helpidx++];
	    else if( (c=iobuf_get(a)) == -1 )
		break;
	    if( c == '\n' || c == ' ' || c == '\r'
		|| c == '\t' || c == '=' )
		continue;
	    break;
	}
	if( c == -1 )
	    log_error("premature eof (no CRC)\n");
	else {
	    u32 mycrc = 0;
	    idx = 0;
	    do {
		if( (c = asctobin[c]) == 255 )
		    break;
		switch(idx) {
		  case 0: val =  c << 2; break;
		  case 1: val |= (c>>4)&3; mycrc |= val << 16;val=(c<<4)&0xf0;break;
		  case 2: val |= (c>>2)&15; mycrc |= val << 8;val=(c<<6)&0xc0;break;
		  case 3: val |= c&0x3f; mycrc |= val; break;
		}
		if( afx->helpidx < afx->helplen )
		    c = afx->helpbuf[afx->helpidx++];
		else if( (c=iobuf_get(a)) == -1 )
		    break;
	    } while( ++idx < 4 );
	    if( c == -1 )
		log_error("premature eof (in CRC)\n");
	    else if( idx != 4 )
		log_error("malformed CRC\n");
	    else if( mycrc != afx->crc )
		log_error("CRC error; %06lx - %06lx\n",
				    (ulong)afx->crc, (ulong)mycrc);
	    else {
		struct fhdr_struct fhdr;

		memset( &fhdr, 0, sizeof(fhdr) );
		for(rc=0;!rc;) {
		    rc = check_trailer( &fhdr, c );
		    if( !rc ) {
			if( afx->helpidx < afx->helplen )
			    c = afx->helpbuf[afx->helpidx++];
			else if( (c=iobuf_get(a)) == -1 )
			    rc = 2;
		    }
		}
		if( rc == -1 )
		    rc = 0;
		else if( rc == 2 )
		    log_error("premature eof (in Trailer)\n");
		else
		    log_error("error in trailer line\n");
	    }
	}
    }

    if( !n )
	rc = -1;

    *retn = n;
    return rc;
}


/****************
 * The filter is used to handle the armor stuff
 */
int
armor_filter( void *opaque, int control,
	     IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    armor_filter_context_t *afx = opaque;
    int rc=0, i, c;
    byte radbuf[3];
    int  idx, idx2;
    size_t n=0;
    u32 crc;

    if( DBG_FILTER )
	log_debug("armor-filter: control: %d\n", control );
    if( control == IOBUFCTRL_UNDERFLOW && afx->inp_bypass ) {
	for( n=0; n < size; n++ ) {
	    if( (c=iobuf_get(a)) == -1 )
		break;
	    buf[n] = c & 0xff;
	}
	if( !n )
	    rc = -1;
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_UNDERFLOW ) {
	if( size < 20 )
	    BUG(); /* supplied buffer maybe too short */

	if( afx->inp_eof ) {
	    *ret_len = 0;
	    if( DBG_FILTER )
		log_debug("armor-filter: eof due to inp_eof flag\n" );
	    return -1;
	}

	if( afx->fake )
	    rc = fake_packet( afx, a, &n, buf, size );
	else if( !afx->inp_checked ) {
	    rc = check_input( afx, a );
	    if( afx->inp_bypass )
		;
	    else if( afx->fake ) {
		/* the buffer is at least 20 bytes long, so it
		 * is easy to construct a packet */
		buf[0] = 0xaf; /* old packet format, type 11, var length */
		buf[1] = 0;    /* set the length header */
		buf[2] = 6;
		buf[3] = 't';  /* canonical text */
		buf[4] = 0;    /* namelength */
		buf[5] = buf[6] = buf[7] = buf[8] = 0; /* timestamp */
		n = 9;
	    }
	    else if( !rc )
		rc = radix64_read( afx, a, &n, buf, size );
	}
	else
	    rc = radix64_read( afx, a, &n, buf, size );

	*ret_len = n;
    }
    else if( control == IOBUFCTRL_FLUSH ) {
	if( !afx->status ) { /* write the header line */
	    if( afx->what >= DIM(head_strings) )
		log_bug("afx->what=%d", afx->what);
	    iobuf_writestr(a, "-----");
	    iobuf_writestr(a, head_strings[afx->what] );
	    iobuf_writestr(a, "-----\n");
	    iobuf_writestr(a, "Version: G10 pre-release "  VERSION "\n");
	    iobuf_writestr(a, "Comment: This is a alpha test version!\n\n");
	    afx->status++;
	    afx->idx = 0;
	    afx->idx2 = 0;
	    afx->crc = CRCINIT;
	}
	crc = afx->crc;
	idx = afx->idx;
	idx2 = afx->idx2;
	for(i=0; i < idx; i++ )
	    radbuf[i] = afx->radbuf[i];

	for(i=0; i < size; i++ )
	    crc = (crc << 8) ^ crc_table[((crc >> 16)&0xff) ^ buf[i]];
	crc &= 0x00ffffff;

	for( ; size; buf++, size-- ) {
	    radbuf[idx++] = *buf;
	    if( idx > 2 ) {
		idx = 0;
		c = bintoasc[(*radbuf >> 2) & 077];
		iobuf_put(a, c);
		c = bintoasc[(((*radbuf<<4)&060)|((radbuf[1] >> 4)&017))&077];
		iobuf_put(a, c);
		c = bintoasc[(((radbuf[1]<<2)&074)|((radbuf[2]>>6)&03))&077];
		iobuf_put(a, c);
		c = bintoasc[radbuf[2]&077];
		iobuf_put(a, c);
		if( ++idx2 > (72/4) ) {
		    iobuf_put(a, '\n');
		    idx2=0;
		}
	    }
	}
	for(i=0; i < idx; i++ )
	    afx->radbuf[i] = radbuf[i];
	afx->idx = idx;
	afx->idx2 = idx2;
	afx->crc  = crc;
    }
    else if( control == IOBUFCTRL_INIT ) {
	if( !is_initialized )
	    initialize();
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( afx->status ) { /* pad, write cecksum, and bottom line */
	    crc = afx->crc;
	    idx = afx->idx;
	    idx2 = afx->idx2;
	    for(i=0; i < idx; i++ )
		radbuf[i] = afx->radbuf[i];
	    if( idx ) {
		c = bintoasc[(*radbuf>>2)&077];
		iobuf_put(a, c);
		if( idx == 1 ) {
		    c = bintoasc[((*radbuf << 4) & 060) & 077];
		    iobuf_put(a, c);
		    iobuf_put(a, '=');
		    iobuf_put(a, '=');
		}
		else { /* 2 */
		    c = bintoasc[(((*radbuf<<4)&060)|((radbuf[1]>>4)&017))&077];
		    iobuf_put(a, c);
		    c = bintoasc[((radbuf[1] << 2) & 074) & 077];
		    iobuf_put(a, c);
		    iobuf_put(a, '=');
		}
		++idx2;
	    }
	    /* may need a linefeed */
	    if( idx2 < (72/4) )
		iobuf_put(a, '\n');
	    /* write the CRC */
	    iobuf_put(a, '=');
	    radbuf[0] = crc >>16;
	    radbuf[1] = crc >> 8;
	    radbuf[2] = crc;
	    c = bintoasc[(*radbuf >> 2) & 077];
	    iobuf_put(a, c);
	    c = bintoasc[(((*radbuf<<4)&060)|((radbuf[1] >> 4)&017))&077];
	    iobuf_put(a, c);
	    c = bintoasc[(((radbuf[1]<<2)&074)|((radbuf[2]>>6)&03))&077];
	    iobuf_put(a, c);
	    c = bintoasc[radbuf[2]&077];
	    iobuf_put(a, c);
	    iobuf_put(a, '\n');
	    /* and the the trailer */
	    if( afx->what >= DIM(tail_strings) )
		log_bug("afx->what=%d", afx->what);
	    iobuf_writestr(a, "-----");
	    iobuf_writestr(a, tail_strings[afx->what] );
	    iobuf_writestr(a, "-----\n");
	}
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "armor_filter";
    return rc;
}

