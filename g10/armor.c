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
    fhdrHASArmor,
    fhdrNOArmor,
    fhdrINIT,
    fhdrINITCont,
    fhdrINITSkip,
    fhdrCHECKBegin,
    fhdrWAITHeader,
    fhdrWAITClearsig,
    fhdrSKIPHeader,
    fhdrCLEARSIG,
    fhdrREADClearsig,
    fhdrEMPTYClearsig,
    fhdrCHECKClearsig,
    fhdrCHECKClearsig2,
    fhdrREADClearsigNext,
    fhdrENDClearsig,
    fhdrTEXT,
    fhdrERROR,
    fhdrERRORShow,
    fhdrEOF
} fhdr_state_t;


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


static fhdr_state_t find_header( fhdr_state_t state,
			  byte *buf, size_t *r_buflen, IOBUF a, size_t n);


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
is_armored( byte *buf )
{
    int ctb, pkttype;

    ctb = *buf;
    if( !(ctb & 0x80) )
	return 1; /* invalid packet: assume it is armored */
    pkttype =  ctb & 0x40 ? (ctb & 0x3f) : ((ctb>>2)&0xf);
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


/****************
 * parse an ascii armor.
 * Returns: the state,
 *	    the remaining bytes in BUF are returned in RBUFLEN.
 */
static fhdr_state_t
find_header( fhdr_state_t state, byte *buf, size_t *r_buflen, IOBUF a, size_t n)
{
    int c, i;
    const char *s;
    char *p;
    size_t buflen;
    int cont;
    int clearsig=0;
    int hdr_line=0;

    buflen = *r_buflen;
    assert(buflen >= 100 );
    buflen--;

    do {
	switch( state ) {
	  case fhdrHASArmor:
	    /* read 28 bytes, which is the bare minimum for a BEGIN...
	     * and check wether this has a Armor. */
	    c = 0;
	    for(n=0; n < 28 && (c=iobuf_get(a)) != -1 && c != '\n'; )
		buf[n++] = c;
	    if( n < 28 || c == -1 )
		state = fhdrNOArmor; /* too short */
	    else if( !is_armored( buf ) )
		state = fhdrNOArmor;
	    else
		state = fhdrINITCont;
	    break;

	  case fhdrINIT: /* read some stuff into buffer */
	    n = 0;
	  case fhdrINITCont: /* read more stuff into buffer */
	    c = 0;
	    for(; n < buflen && (c=iobuf_get(a)) != -1 && c != '\n'; )
		buf[n++] = c;
	    state = c == '\n' ? fhdrCHECKBegin :
		     c == -1  ? fhdrEOF : fhdrINITSkip;
	    break;

	  case fhdrINITSkip:
	    while( (c=iobuf_get(a)) != -1 && c != '\n' )
		;
	    state =  c == -1? fhdrEOF : fhdrINIT;
	    break;

	  case fhdrSKIPHeader:
	    while( (c=iobuf_get(a)) != -1 && c != '\n' )
		;
	    state =  c == -1? fhdrEOF : fhdrWAITHeader;
	    break;

	  case fhdrWAITHeader: /* wait for Header lines */
	    c = 0;
	    for(n=0; n < buflen && (c=iobuf_get(a)) != -1 && c != '\n'; )
		buf[n++] = c;
	    buf[n] = 0;
	    if( n < buflen || c == '\n' ) {
		if( n && buf[0] != '\r') { /* maybe a header */
		    if( strchr( buf, ':') ) { /* yes */
			log_debug("armor header: ");
			print_string( stderr, buf, n );
			putc('\n', stderr);
			state = fhdrWAITHeader;
		    }
		    else
			state = fhdrTEXT;
		}
		else if( !n || (buf[0] == '\r' && !buf[1]) ) { /* empty line */
		    if( clearsig )
			state = fhdrWAITClearsig;
		    else {
			/* this is not really correct: if we do not have
			 * a clearsig and not armor lines we are not allowed
			 * to have an empty line */
			n = 0;
			state = fhdrTEXT;
		    }
		}
		else {
		    log_debug("invalid armor header: ");
		    print_string( stderr, buf, n );
		    putc('\n', stderr);
		    state = fhdrERROR;
		}
	    }
	    else if( c != -1 ) {
		if( strchr( buf, ':') ) { /* buffer to short, but this is okay*/
		    log_debug("armor header: ");
		    print_string( stderr, buf, n );
		    fputs("[...]\n", stderr);  /* indicate it is truncated */
		    state = fhdrSKIPHeader;  /* skip rest of line */
		}
		else /* line too long */
		    state = fhdrERROR;
	    }
	    else
		state = fhdrEOF;
	    break;

	  case fhdrWAITClearsig: /* skip all empty lines (for clearsig) */
	    c = 0;
	    for(n=0; n < buflen && (c=iobuf_get(a)) != -1 && c != '\n'; )
		buf[n++] = c;
	    if( n < buflen || c == '\n' ) {
		buf[n] = 0;
		if( !n || (buf[0]=='\r' && !buf[1]) ) /* empty line */
		    ;
		else
		    state = fhdrTEXT;
	    }
	    else
		state = fhdrEOF;
	    break;

	  case fhdrENDClearsig:
	  case fhdrCHECKBegin:
	    state = state == fhdrCHECKBegin ? fhdrINITSkip : fhdrERRORShow;
	    if( n < 15 )
		break;	/* too short */
	    if( memcmp( buf, "-----", 5 ) )
		break;
	    buf[n] = 0;
	    p = strstr(buf+5, "-----");
	    if( !p )
		break;
	    *p = 0;
	    p += 5;
	    if( *p == '\r' )
		p++;
	    if( *p )
		break; /* garbage after dashes */
	    p = buf+5;
	    for(i=0; (s=head_strings[i]); i++ )
		if( !strcmp(s, p) )
		    break;
	    if( !s )
		break; /* unknown begin line */
	    /* found the begin line */
	    hdr_line = i;
	    state = fhdrWAITHeader;
	    if( hdr_line == BEGIN_SIGNED_MSG_IDX )
		clearsig = 1;
	    log_debug("armor: %s\n", head_strings[hdr_line]);
	    break;

	  case fhdrCLEARSIG:
	  case fhdrEMPTYClearsig:
	  case fhdrREADClearsig:
	    /* we are at the start of a line: read a clearsig into the buffer
	     * we have to look for a the header line or dashd escaped text*/
	    n = 0;
	    c = 0;
	    for(; n < buflen && (c=iobuf_get(a)) != -1 && c != '\n'; )
		buf[n++] = c;
	    buf[n] = 0;
	    if( c == -1 )
		state = fhdrEOF;
	    else if( !n || ( buf[0]=='\r' && !buf[1] ) ) {
		state = fhdrEMPTYClearsig;
		/* FIXME: handle it */
	    }
	    else if( c == '\n' )
		state = fhdrCHECKClearsig2;
	    else
		state = fhdrCHECKClearsig;
	    break;

	  case fhdrCHECKClearsig:
	  case fhdrCHECKClearsig2:
	    /* check the clearsig line */
	    if( n > 15 && !memcmp(buf, "-----", 5 ) )
		state = fhdrENDClearsig;
	    else if( buf[0] == '-' && buf[1] == ' ' ) {
		/* dash escaped line */
		if( buf[2] == '-' || ( n > 6 && !memcmp(buf+2, "From ", 5))) {
		    for(i=2; i < n; i++ )
			buf[i-2] = buf[i];
		    n -= 2;
		    buf[n] = 0; /* not really needed */
		    state = state == fhdrCHECKClearsig2 ?
				     fhdrREADClearsig : fhdrREADClearsigNext;
		    /* FIXME: add the lf to the buffer */
		}
		else {
		    log_debug("invalid dash escaped line: ");
		    print_string( stderr, buf, n );
		    putc('\n', stderr);
		    state = fhdrERROR;
		}
	    }
	    else {
		state = state == fhdrCHECKClearsig2 ?
				  fhdrREADClearsig : fhdrREADClearsigNext;
		/* FIXME: add the lf to the buffer */
	    }
	    break;

	  case fhdrREADClearsigNext:
	    /* Read to the end of the line, do not care about checking
	     * for dashed escaped text of headers */
	    break;

	  case fhdrERRORShow:
	    log_debug("invalid clear text header: ");
	    print_string( stderr, buf, n );
	    putc('\n', stderr);
	    state = fhdrERROR;
	    break;

	  default: BUG();
	}
	switch( state ) {
	  case fhdrINIT:
	  case fhdrINITCont:
	  case fhdrINITSkip:
	  case fhdrCHECKBegin:
	  case fhdrWAITHeader:
	  case fhdrWAITClearsig:
	  case fhdrSKIPHeader:
	  case fhdrEMPTYClearsig:
	  case fhdrCHECKClearsig:
	  case fhdrCHECKClearsig2:
	  case fhdrERRORShow:
	    cont = 1;
	    break;
	  default: cont = 0;
	}
    } while( cont );

    if( clearsig && state == fhdrTEXT )
	state = fhdrCLEARSIG;
    *r_buflen = n;
    return state;
}


/* figure out wether the data is armored or not */
static int
check_input( armor_filter_context_t *afx, IOBUF a )
{
    int rc = 0;
    size_t n;
    fhdr_state_t state = afx->parse_state;

    if( state != fhdrENDClearsig )
	state = fhdrHASArmor;

    n = DIM(afx->helpbuf);
    state = find_header( state, afx->helpbuf, &n, a, afx->helplen );
    switch( state ) {
      case fhdrNOArmor:
	afx->inp_checked = 1;
	afx->inp_bypass = 1;
	afx->helplen = n;
	break;

      case fhdrERROR:
      case fhdrEOF:
	rc = -1;
	break;

      case fhdrCLEARSIG: /* start fake package mode (for clear signatures) */
	afx->helplen = n;
	afx->helpidx = 0;
	afx->faked = 1;
	break;

      case fhdrTEXT:
	afx->helplen = n;
	afx->helpidx = 0;
	afx->inp_checked = 1;
	afx->crc = CRCINIT;
	afx->idx = 0;
	afx->radbuf[0] = 0;
	break;

      default: BUG();
    }

    afx->parse_state = state;
    return rc;
}



/* fake a literal data packet and wait for an armor line */
static int
fake_packet( armor_filter_context_t *afx, IOBUF a,
	     size_t *retn, byte *buf, size_t size  )
{
    int rc = 0;
    size_t len = 0;
    size_t n, nn;
    fhdr_state_t state = afx->parse_state;

    size = 100; /* FIXME: only used for testing (remove it)  */

    len = 2;	/* reserve 2 bytes for the length header */
    size -= 2;	/* and 2 for the term header */
    while( !rc && len < size ) {
	if( afx->helpidx < afx->helplen ) { /* flush the last buffer */
	    n = afx->helplen;
	    for(nn=afx->helpidx; len < size && nn < n ; nn++ )
		buf[len++] = afx->helpbuf[nn];
	    afx->helpidx = nn;
	    continue;
	}
	if( state == fhdrEOF ) {
	    rc = -1;
	    continue;
	}
	/* read a new one */
	n = DIM(afx->helpbuf);
	afx->helpidx = 0;
	state = find_header( state, afx->helpbuf, &n, a, 0 );
	switch( state) {
	  case fhdrERROR:
	  case fhdrEOF:
	    rc = -1;
	    break;

	  case fhdrCLEARSIG:
	  case fhdrREADClearsig:
	  case fhdrREADClearsigNext:
	    afx->helplen = n;
	    break;

	  case fhdrENDClearsig:
	    afx->helplen = n;
	    afx->faked = 0;
	    rc = -1;
	    break;

	  default: BUG();
	}
    }
    buf[0] = (len-2) >> 8;
    buf[1] = (len-2);
    if( state == fhdrENDClearsig ) { /* write last (ending) length header */
	buf[len++] = 0;
	buf[len++] = 0;
	rc = 0;
    }

    afx->parse_state = state;
    *retn = len;
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
		for(rc=0;!rc;) {
		    rc = 0 /*check_trailer( &fhdr, c )*/;
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

	if( afx->faked )
	    rc = fake_packet( afx, a, &n, buf, size );
	else if( !afx->inp_checked ) {
	    rc = check_input( afx, a );
	    if( afx->inp_bypass )
		;
	    else if( afx->faked ) {
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

