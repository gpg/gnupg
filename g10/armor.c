/* armor.c - Armor flter
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
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include "errors.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "filter.h"
#include "packet.h"
#include "options.h"
#include "main.h"
#include "status.h"
#include "i18n.h"

#define MAX_LINELEN 20000

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
    fhdrHASArmor = 0,
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
    fhdrNullClearsig,
    fhdrEMPTYClearsig,
    fhdrCHECKClearsig,
    fhdrCHECKClearsig2,
    fhdrCHECKDashEscaped,
    fhdrCHECKDashEscaped2,
    fhdrCHECKDashEscaped3,
    fhdrREADClearsigNext,
    fhdrENDClearsig,
    fhdrENDClearsigHelp,
    fhdrTESTSpaces,
    fhdrCLEARSIGSimple,
    fhdrCLEARSIGSimpleNext,
    fhdrTEXT,
    fhdrTEXTSimple,
    fhdrERROR,
    fhdrERRORShow,
    fhdrEOF
} fhdr_state_t;


/* if we encounter this armor string with this index, go
 * into a mode which fakes packets and wait for the next armor */
#define BEGIN_SIGNATURE 2
#define BEGIN_SIGNED_MSG_IDX 3
static char *head_strings[] = {
    "BEGIN PGP MESSAGE",
    "BEGIN PGP PUBLIC KEY BLOCK",
    "BEGIN PGP SIGNATURE",
    "BEGIN PGP SIGNED MESSAGE",
    "BEGIN PGP ARMORED FILE",       /* gnupg extension */
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PGP SECRET KEY BLOCK",   /* only used by pgp2 */
    NULL
};
static char *tail_strings[] = {
    "END PGP MESSAGE",
    "END PGP PUBLIC KEY BLOCK",
    "END PGP SIGNATURE",
    "END dummy",
    "END PGP ARMORED FILE",
    "END PGP PRIVATE KEY BLOCK",
    "END PGP SECRET KEY BLOCK",
    NULL
};


/* Create a new context for armor filters.  */
armor_filter_context_t *
new_armor_context (void)
{
  armor_filter_context_t *afx;

  afx = xcalloc (1, sizeof *afx);
  afx->refcount = 1;

  return afx;
}

/* Release an armor filter context.  Passing NULL is explicitly
   allowed and a no-op.  */
void
release_armor_context (armor_filter_context_t *afx)
{
  if (!afx)
    return;

  /* In contrast to 2.0, we use in 1.4 heap based contexts only in a
     very few places and in general keep the stack based contexts.  A
     REFCOUNT of 0 indicates a stack based context and thus we don't
     do anything in this case. */
  if (!afx->refcount)
    return;

  if ( --afx->refcount )
    return;
  xfree (afx);
}

/* Push the armor filter onto the iobuf stream IOBUF.  */
int
push_armor_filter (armor_filter_context_t *afx, iobuf_t iobuf)
{
  int rc; 

  if (!afx->refcount)
    return iobuf_push_filter (iobuf, armor_filter, afx);
    
  afx->refcount++;
  rc = iobuf_push_filter (iobuf, armor_filter, afx);
  if (rc)
    afx->refcount--;
  return rc;
}





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
 * Check whether this is an armored file or not See also
 * parse-packet.c for details on this code For unknown historic
 * reasons we use a string here but only the first byte will be used.
 * Returns: True if it seems to be armored
 */
static int
is_armored( const byte *buf )
{
    int ctb, pkttype;

    ctb = *buf;
    if( !(ctb & 0x80) )
	return 1; /* invalid packet: assume it is armored */
    pkttype =  ctb & 0x40 ? (ctb & 0x3f) : ((ctb>>2)&0xf);
    switch( pkttype ) {
      case PKT_MARKER:
      case PKT_SYMKEY_ENC:
      case PKT_ONEPASS_SIG:
      case PKT_PUBLIC_KEY:
      case PKT_SECRET_KEY:
      case PKT_PUBKEY_ENC:
      case PKT_SIGNATURE:
      case PKT_COMMENT:
      case PKT_OLD_COMMENT:
      case PKT_PLAINTEXT:
      case PKT_COMPRESSED:
      case PKT_ENCRYPTED:
	return 0; /* seems to be a regular packet: not armored */
    }

    return 1;
}


/****************
 * Try to check whether the iobuf is armored
 * Returns true if this may be the case; the caller should use the
 *	   filter to do further processing.
 */
int
use_armor_filter( IOBUF a )
{
    byte buf[1];
    int n;

    /* fixme: there might be a problem with iobuf_peek */
    n = iobuf_peek(a, buf, 1 );
    if( n == -1 )
	return 0; /* EOF, doesn't matter whether armored or not */
    if( !n )
	return 1; /* can't check it: try armored */
    return is_armored(buf);
}




static void
invalid_armor(void)
{
    write_status(STATUS_BADARMOR);
    g10_exit(1); /* stop here */
}


/****************
 * check whether the armor header is valid on a signed message.
 * this is for security reasons: the header lines are not included in the
 * hash and by using some creative formatting rules, Mallory could fake
 * any text at the beginning of a document; assuming it is read with
 * a simple viewer. We only allow the Hash Header.
 */
static int
parse_hash_header( const char *line )
{
    const char *s, *s2;
    unsigned found = 0;

    if( strlen(line) < 6  || strlen(line) > 60 )
	return 0; /* too short or too long */
    if( memcmp( line, "Hash:", 5 ) )
	return 0; /* invalid header */
    s = line+5;
    for(s=line+5;;s=s2) {
	for(; *s && (*s==' ' || *s == '\t'); s++ )
	    ;
	if( !*s )
	    break;
	for(s2=s+1; *s2 && *s2!=' ' && *s2 != '\t' && *s2 != ','; s2++ )
	    ;
	if( !strncmp( s, "RIPEMD160", s2-s ) )
	    found |= 1;
	else if( !strncmp( s, "SHA1", s2-s ) )
	    found |= 2;
	else if( !strncmp( s, "MD5", s2-s ) )
	    found |= 4;
	else if( !strncmp( s, "SHA224", s2-s ) )
	    found |= 8;
	else if( !strncmp( s, "SHA256", s2-s ) )
	    found |= 16;
	else if( !strncmp( s, "SHA384", s2-s ) )
	    found |= 32;
	else if( !strncmp( s, "SHA512", s2-s ) )
	    found |= 64;
	else
	    return 0;
	for(; *s2 && (*s2==' ' || *s2 == '\t'); s2++ )
	    ;
	if( *s2 && *s2 != ',' )
	    return 0;
	if( *s2 )
	    s2++;
    }
    return found;
}

/* Returns true if this is a valid armor tag as per RFC-2440bis-21. */
static int
is_armor_tag(const char *line)
{
  if(strncmp(line,"Version",7)==0
     || strncmp(line,"Comment",7)==0
     || strncmp(line,"MessageID",9)==0
     || strncmp(line,"Hash",4)==0
     || strncmp(line,"Charset",7)==0)
    return 1;

  return 0;
}

/****************
 * Check whether this is a armor line.
 * returns: -1 if it is not a armor header or the index number of the
 * armor header.
 */
static int
is_armor_header( byte *line, unsigned len )
{
    const char *s;
    byte *save_p, *p;
    int save_c;
    int i;

    if( len < 15 )
	return -1; /* too short */
    if( memcmp( line, "-----", 5 ) )
	return -1; /* no */
    p = strstr( line+5, "-----");
    if( !p )
	return -1;
    save_p = p;
    p += 5;

    /* Some Windows environments seem to add whitespace to the end of
       the line, so we strip it here.  This becomes strict if
       --rfc2440 is set since 2440 reads "The header lines, therefore,
       MUST start at the beginning of a line, and MUST NOT have text
       following them on the same line."  It is unclear whether "text"
       refers to all text or just non-whitespace text.  4880 clarified
       this was only non-whitespace text. */

    if(RFC2440)
      {
	if( *p == '\r' )
	  p++;
	if( *p == '\n' )
	  p++;
      }
    else
      while(*p==' ' || *p=='\r' || *p=='\n' || *p=='\t')
	p++;

    if( *p )
	return -1; /* garbage after dashes */
    save_c = *save_p; *save_p = 0;
    p = line+5;
    for(i=0; (s=head_strings[i]); i++ )
	if( !strcmp(s, p) )
	    break;
    *save_p = save_c;
    if( !s )
	return -1; /* unknown armor line */

    if( opt.verbose > 1 )
	log_info(_("armor: %s\n"), head_strings[i]);
    return i;
}



/****************
 * Parse a header lines
 * Return 0: Empty line (end of header lines)
 *	 -1: invalid header line
 *	 >0: Good header line
 */
static int
parse_header_line( armor_filter_context_t *afx, byte *line, unsigned int len )
{
    byte *p;
    int hashes=0;
    unsigned int len2;

    len2 = check_trailing_ws( line, len );
    if( !len2 ) {
        afx->buffer_pos = len2;  /* (it is not the fine way to do it here) */
	return 0; /* WS only: same as empty line */
    }

    /*
      This is fussy.  The spec says that a header line is delimited
      with a colon-space pair.  This means that a line such as
      "Comment: " (with nothing else) is actually legal as an empty
      string comment.  However, email and cut-and-paste being what it
      is, that trailing space may go away.  Therefore, we accept empty
      headers delimited with only a colon.  --rfc2440, as always,
      makes this strict and enforces the colon-space pair. -dms
    */

    p = strchr( line, ':');
    if( !p || (RFC2440 && p[1]!=' ')
	|| (!RFC2440 && p[1]!=' ' && p[1]!='\n' && p[1]!='\r'))
      {
	log_error(_("invalid armor header: "));
	print_string( stderr, line, len, 0 );
	putc('\n', stderr);
	return -1;
      }

    /* Chop off the whitespace we detected before */
    len=len2;
    line[len2]='\0';

    if( opt.verbose ) {
	log_info(_("armor header: "));
	print_string( stderr, line, len, 0 );
	putc('\n', stderr);
    }

    if( afx->in_cleartext )
      {
	if( (hashes=parse_hash_header( line )) )
	  afx->hashes |= hashes;
	else if( strlen(line) > 15 && !memcmp( line, "NotDashEscaped:", 15 ) )
	  afx->not_dash_escaped = 1;
	else
	  {
	    log_error(_("invalid clearsig header\n"));
	    return -1;
	  }
      }
    else if(!is_armor_tag(line))
      {
	/* Section 6.2: "Unknown keys should be reported to the user,
	   but OpenPGP should continue to process the message."  Note
	   that in a clearsigned message this applies to the signature
	   part (i.e. "BEGIN PGP SIGNATURE") and not the signed data
	   ("BEGIN PGP SIGNED MESSAGE").  The only key allowed in the
	   signed data section is "Hash". */

	log_info(_("unknown armor header: "));
	print_string( stderr, line, len, 0 );
	putc('\n', stderr);
      }

    return 1;
}



/* figure out whether the data is armored or not */
static int
check_input( armor_filter_context_t *afx, IOBUF a )
{
    int rc = 0;
    int i;
    byte *line;
    unsigned len;
    unsigned maxlen;
    int hdr_line = -1;

    /* read the first line to see whether this is armored data */
    maxlen = MAX_LINELEN;
    len = afx->buffer_len = iobuf_read_line( a, &afx->buffer,
					     &afx->buffer_size, &maxlen );
    line = afx->buffer;
    if( !maxlen ) {
	/* line has been truncated: assume not armored */
	afx->inp_checked = 1;
	afx->inp_bypass = 1;
	return 0;
    }

    if( !len ) {
	return -1; /* eof */
    }

    /* (the line is always a C string but maybe longer) */
    if( *line == '\n' || ( len && (*line == '\r' && line[1]=='\n') ) )
	;
    else if( !is_armored( line ) ) {
	afx->inp_checked = 1;
	afx->inp_bypass = 1;
	return 0;
    }

    /* find the armor header */
    while(len) {
	i = is_armor_header( line, len );
	if( i >= 0 && !(afx->only_keyblocks && i != 1 && i != 5 && i != 6 )) {
	    hdr_line = i;
	    if( hdr_line == BEGIN_SIGNED_MSG_IDX ) {
		if( afx->in_cleartext ) {
		    log_error(_("nested clear text signatures\n"));
		    rc = G10ERR_INVALID_ARMOR;
		}
		afx->in_cleartext = 1;
	    }
	    break;
	}
	/* read the next line (skip all truncated lines) */
	do {
	    maxlen = MAX_LINELEN;
	    afx->buffer_len = iobuf_read_line( a, &afx->buffer,
					       &afx->buffer_size, &maxlen );
	    line = afx->buffer;
	    len = afx->buffer_len;
	} while( !maxlen );
    }

    /* Parse the header lines.  */
    while(len) {
	/* Read the next line (skip all truncated lines). */
	do {
	    maxlen = MAX_LINELEN;
	    afx->buffer_len = iobuf_read_line( a, &afx->buffer,
					       &afx->buffer_size, &maxlen );
	    line = afx->buffer;
	    len = afx->buffer_len;
	} while( !maxlen );

	i = parse_header_line( afx, line, len );
	if( i <= 0 ) {
	    if (i && RFC2440)
		rc = G10ERR_INVALID_ARMOR;
	    break;
	}
    }


    if( rc )
	invalid_armor();
    else if( afx->in_cleartext )
	afx->faked = 1;
    else {
	afx->inp_checked = 1;
	afx->crc = CRCINIT;
	afx->idx = 0;
	afx->radbuf[0] = 0;
    }

    return rc;
}

#define PARTIAL_CHUNK 512
#define PARTIAL_POW   9

/****************
 * Fake a literal data packet and wait for the next armor line
 * fixme: empty line handling and null length clear text signature are
 *	  not implemented/checked.
 */
static int
fake_packet( armor_filter_context_t *afx, IOBUF a,
	     size_t *retn, byte *buf, size_t size  )
{
    int rc = 0;
    size_t len = 0;
    int lastline = 0;
    unsigned maxlen, n;
    byte *p;
    byte tempbuf[PARTIAL_CHUNK];
    size_t tempbuf_len=0;

    while( !rc && size-len>=(PARTIAL_CHUNK+1)) {
	/* copy what we have in the line buffer */
	if( afx->faked == 1 )
	    afx->faked++; /* skip the first (empty) line */
	else
	  {
	    /* It's full, so write this partial chunk */
	    if(tempbuf_len==PARTIAL_CHUNK)
	      {
		buf[len++]=0xE0+PARTIAL_POW;
		memcpy(&buf[len],tempbuf,PARTIAL_CHUNK);
		len+=PARTIAL_CHUNK;
		tempbuf_len=0;
		continue;
	      }

	    while( tempbuf_len < PARTIAL_CHUNK
		   && afx->buffer_pos < afx->buffer_len )
	      tempbuf[tempbuf_len++] = afx->buffer[afx->buffer_pos++];
	    if( tempbuf_len==PARTIAL_CHUNK )
	      continue;
	  }

	/* read the next line */
	maxlen = MAX_LINELEN;
	afx->buffer_pos = 0;
	afx->buffer_len = iobuf_read_line( a, &afx->buffer,
					   &afx->buffer_size, &maxlen );
	if( !afx->buffer_len ) {
	    rc = -1; /* eof (should not happen) */
	    continue;
	}
	if( !maxlen )
	    afx->truncated++;

	p = afx->buffer;
	n = afx->buffer_len;

	/* Armor header or dash-escaped line? */
	if(p[0]=='-')
	  {
	    /* 2440bis-10: When reversing dash-escaping, an
	       implementation MUST strip the string "- " if it occurs
	       at the beginning of a line, and SHOULD warn on "-" and
	       any character other than a space at the beginning of a
	       line.  */

	    if(p[1]==' ' && !afx->not_dash_escaped)
	      {
		/* It's a dash-escaped line, so skip over the
		   escape. */
		afx->buffer_pos = 2;
	      }
	    else if(p[1]=='-' && p[2]=='-' && p[3]=='-' && p[4]=='-')
	      {
		/* Five dashes in a row mean it's probably armor
		   header. */
		int type = is_armor_header( p, n );
		if( afx->not_dash_escaped && type != BEGIN_SIGNATURE )
		  ; /* this is okay */
		else
		  {
		    if( type != BEGIN_SIGNATURE )
		      {
			log_info(_("unexpected armor: "));
			print_string( stderr, p, n, 0 );
			putc('\n', stderr);
		      }

		    lastline = 1;
		    rc = -1;
		  }
	      }
	    else if(!afx->not_dash_escaped)
	      {
		/* Bad dash-escaping. */
		log_info(_("invalid dash escaped line: "));
		print_string( stderr, p, n, 0 );
		putc('\n', stderr);
	      }
	  }

	/* Now handle the end-of-line canonicalization */
	if( !afx->not_dash_escaped )
	  {
	    int crlf = n > 1 && p[n-2] == '\r' && p[n-1]=='\n';

	    /* PGP2 does not treat a tab as white space character */
	    afx->buffer_len=
	      trim_trailing_chars( &p[afx->buffer_pos], n-afx->buffer_pos,
				   afx->pgp2mode ? " \r\n" : " \t\r\n");
	    afx->buffer_len+=afx->buffer_pos;
	    /* the buffer is always allocated with enough space to append
	     * the removed [CR], LF and a Nul
	     * The reason for this complicated procedure is to keep at least
	     * the original type of lineending - handling of the removed
	     * trailing spaces seems to be impossible in our method
	     * of faking a packet; either we have to use a temporary file
	     * or calculate the hash here in this module and somehow find
	     * a way to send the hash down the processing line (well, a special
	     * faked packet could do the job).
	     */
	    if( crlf )
	      afx->buffer[afx->buffer_len++] = '\r';
	    afx->buffer[afx->buffer_len++] = '\n';
	    afx->buffer[afx->buffer_len] = '\0';
	  }
    }

    if( lastline ) { /* write last (ending) length header */
        if(tempbuf_len<192)
	  buf[len++]=tempbuf_len;
	else
	  {
	    buf[len++]=((tempbuf_len-192)/256) + 192;
	    buf[len++]=(tempbuf_len-192) % 256;
	  }
	memcpy(&buf[len],tempbuf,tempbuf_len);
	len+=tempbuf_len;

	rc = 0;
	afx->faked = 0;
	afx->in_cleartext = 0;
	/* and now read the header lines */
	afx->buffer_pos = 0;
	for(;;) {
	    int i;

	    /* read the next line (skip all truncated lines) */
	    do {
		maxlen = MAX_LINELEN;
		afx->buffer_len = iobuf_read_line( a, &afx->buffer,
						 &afx->buffer_size, &maxlen );
	    } while( !maxlen );
	    p = afx->buffer;
	    n = afx->buffer_len;
	    if( !n ) {
		rc = -1;
		break; /* eof */
	    }
	    i = parse_header_line( afx, p , n );
	    if( i <= 0 ) {
		if( i )
		    invalid_armor();
		break;
	    }
	}
	afx->inp_checked = 1;
	afx->crc = CRCINIT;
	afx->idx = 0;
	afx->radbuf[0] = 0;
    }

    *retn = len;
    return rc;
}


static int
invalid_crc(void)
{
    if ( opt.ignore_crc_error )
        return 0;
    log_inc_errorcount();
    return G10ERR_INVALID_ARMOR;
}


static int
radix64_read( armor_filter_context_t *afx, IOBUF a, size_t *retn,
	      byte *buf, size_t size )
{
    byte val;
    int c=0, c2; /*init c because gcc is not clever enough for the continue*/
    int checkcrc=0;
    int rc = 0;
    size_t n = 0;
    int  idx, i, onlypad=0;
    u32 crc;

    crc = afx->crc;
    idx = afx->idx;
    val = afx->radbuf[0];
    for( n=0; n < size; ) {

	if( afx->buffer_pos < afx->buffer_len )
	    c = afx->buffer[afx->buffer_pos++];
	else { /* read the next line */
	    unsigned maxlen = MAX_LINELEN;
	    afx->buffer_pos = 0;
	    afx->buffer_len = iobuf_read_line( a, &afx->buffer,
					       &afx->buffer_size, &maxlen );
	    if( !maxlen )
		afx->truncated++;
	    if( !afx->buffer_len )
		break; /* eof */
	    continue;
	}

      again:
	if( c == '\n' || c == ' ' || c == '\r' || c == '\t' )
	    continue;
	else if( c == '=' ) { /* pad character: stop */
	    /* some mailers leave quoted-printable encoded characters
	     * so we try to workaround this */
	    if( afx->buffer_pos+2 < afx->buffer_len ) {
		int cc1, cc2, cc3;
		cc1 = afx->buffer[afx->buffer_pos];
		cc2 = afx->buffer[afx->buffer_pos+1];
		cc3 = afx->buffer[afx->buffer_pos+2];
		if( isxdigit(cc1) && isxdigit(cc2)
				  && strchr( "=\n\r\t ", cc3 )) {
		    /* well it seems to be the case - adjust */
		    c = isdigit(cc1)? (cc1 - '0'): (ascii_toupper(cc1)-'A'+10);
		    c <<= 4;
		    c |= isdigit(cc2)? (cc2 - '0'): (ascii_toupper(cc2)-'A'+10);
		    afx->buffer_pos += 2;
		    afx->qp_detected = 1;
		    goto again;
		}
	    }
	    else if(n==0)
	      onlypad=1;

	    if( idx == 1 )
		buf[n++] = val;
	    checkcrc++;
	    break;
	}
	else if( (c = asctobin[(c2=c)]) == 255 ) {
	    log_error(_("invalid radix64 character %02X skipped\n"), c2);
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
	afx->any_data = 1;
	afx->inp_checked=0;
	afx->faked = 0;
	for(;;) { /* skip lf and pad characters */
	    if( afx->buffer_pos < afx->buffer_len )
		c = afx->buffer[afx->buffer_pos++];
	    else { /* read the next line */
		unsigned maxlen = MAX_LINELEN;
		afx->buffer_pos = 0;
		afx->buffer_len = iobuf_read_line( a, &afx->buffer,
						   &afx->buffer_size, &maxlen );
		if( !maxlen )
		    afx->truncated++;
		if( !afx->buffer_len )
		    break; /* eof */
		continue;
	    }
	    if( c == '\n' || c == ' ' || c == '\r'
		|| c == '\t' || c == '=' )
		continue;
	    break;
	}
	if( c == -1 )
	    log_error(_("premature eof (no CRC)\n"));
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
		for(;;) {
		    if( afx->buffer_pos < afx->buffer_len )
			c = afx->buffer[afx->buffer_pos++];
		    else { /* read the next line */
			unsigned maxlen = MAX_LINELEN;
			afx->buffer_pos = 0;
			afx->buffer_len = iobuf_read_line( a, &afx->buffer,
							   &afx->buffer_size,
								&maxlen );
			if( !maxlen )
			    afx->truncated++;
			if( !afx->buffer_len )
			    break; /* eof */
			continue;
		    }
		    break;
		}
		if( !afx->buffer_len )
		    break; /* eof */
	    } while( ++idx < 4 );
	    if( c == -1 ) {
		log_info(_("premature eof (in CRC)\n"));
		rc = invalid_crc();
	    }
	    else if( idx == 0 ) {
	        /* No CRC at all is legal ("MAY") */
	        rc=0;
	    }
	    else if( idx != 4 ) {
		log_info(_("malformed CRC\n"));
		rc = invalid_crc();
	    }
	    else if( mycrc != afx->crc ) {
                log_info (_("CRC error; %06lX - %06lX\n"),
				    (ulong)afx->crc, (ulong)mycrc);
                rc = invalid_crc();
	    }
	    else {
		rc = 0;
                /* FIXME: Here we should emit another control packet,
                 * so that we know in mainproc that we are processing
                 * a clearsign message */
#if 0
		for(rc=0;!rc;) {
		    rc = 0 /*check_trailer( &fhdr, c )*/;
		    if( !rc ) {
			if( (c=iobuf_get(a)) == -1 )
			    rc = 2;
		    }
		}
		if( rc == -1 )
		    rc = 0;
		else if( rc == 2 ) {
		    log_error(_("premature eof (in trailer)\n"));
		    rc = G10ERR_INVALID_ARMOR;
		}
		else {
		    log_error(_("error in trailer line\n"));
		    rc = G10ERR_INVALID_ARMOR;
		}
#endif
	    }
	}
    }

    if( !n && !onlypad )
	rc = -1;

    *retn = n;
    return rc;
}

/****************
 * This filter is used to handle the armor stuff
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
#if 0
    static FILE *fp ;

    if( !fp ) {
	fp = fopen("armor.out", "w");
	assert(fp);
    }
#endif

    if( DBG_FILTER )
	log_debug("armor-filter: control: %d\n", control );
    if( control == IOBUFCTRL_UNDERFLOW && afx->inp_bypass ) {
	n = 0;
	if( afx->buffer_len ) {
	    for(; n < size && afx->buffer_pos < afx->buffer_len; n++ )
		buf[n++] = afx->buffer[afx->buffer_pos++];
	    if( afx->buffer_pos >= afx->buffer_len )
		afx->buffer_len = 0;
	}
	for(; n < size; n++ ) {
	    if( (c=iobuf_get(a)) == -1 )
		break;
	    buf[n] = c & 0xff;
	}
	if( !n )
	    rc = -1;
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_UNDERFLOW ) {
        /* We need some space for the faked packet.  The minmum
         * required size is the PARTIAL_CHUNK size plus a byte for the
         * length itself */
	if( size < PARTIAL_CHUNK+1 ) 
	    BUG(); /* supplied buffer too short */

	if( afx->faked )
	    rc = fake_packet( afx, a, &n, buf, size );
	else if( !afx->inp_checked ) {
	    rc = check_input( afx, a );
	    if( afx->inp_bypass ) {
		for(n=0; n < size && afx->buffer_pos < afx->buffer_len; )
		    buf[n++] = afx->buffer[afx->buffer_pos++];
		if( afx->buffer_pos >= afx->buffer_len )
		    afx->buffer_len = 0;
		if( !n )
		    rc = -1;
	    }
	    else if( afx->faked ) {
	        unsigned int hashes = afx->hashes;
                const byte *sesmark;
                size_t sesmarklen;
                
                sesmark = get_session_marker( &sesmarklen );
                if ( sesmarklen > 20 )
                    BUG();

		/* the buffer is at least 15+n*15 bytes long, so it
		 * is easy to construct the packets */

		hashes &= 1|2|4|8|16|32|64;
		if( !hashes ) {
		    hashes |= 4;  /* default to MD 5 */
		    /* This is non-ideal since PGP 5-8 have the same
		       end-of-line bugs as PGP 2. However, we only
		       enable pgp2mode if there is no Hash: header. */
		    if( opt.pgp2_workarounds )
			afx->pgp2mode = 1;
		}
		n=0;
                /* First a gpg control packet... */
                buf[n++] = 0xff; /* new format, type 63, 1 length byte */
                n++;   /* see below */
                memcpy(buf+n, sesmark, sesmarklen ); n+= sesmarklen;
                buf[n++] = CTRLPKT_CLEARSIGN_START; 
                buf[n++] = afx->not_dash_escaped? 0:1; /* sigclass */
                if( hashes & 1 )
                    buf[n++] = DIGEST_ALGO_RMD160;
                if( hashes & 2 )
                    buf[n++] = DIGEST_ALGO_SHA1;
                if( hashes & 4 )
                    buf[n++] = DIGEST_ALGO_MD5;
                if( hashes & 8 )
                    buf[n++] = DIGEST_ALGO_SHA224;
                if( hashes & 16 )
                    buf[n++] = DIGEST_ALGO_SHA256;
                if( hashes & 32 )
                    buf[n++] = DIGEST_ALGO_SHA384;
                if( hashes & 64 )
                    buf[n++] = DIGEST_ALGO_SHA512;
                buf[1] = n - 2;

		/* ...followed by an invented plaintext packet.
		   Amusingly enough, this packet is not compliant with
		   2440 as the initial partial length is less than 512
		   bytes.  Of course, we'll accept it anyway ;) */

		buf[n++] = 0xCB; /* new packet format, type 11 */
		buf[n++] = 0xE1; /* 2^1 == 2 bytes */
		buf[n++] = 't';  /* canonical text mode */
		buf[n++] = 0;	 /* namelength */
		buf[n++] = 0xE2; /* 2^2 == 4 more bytes */
		memset(buf+n, 0, 4); /* timestamp */
		n += 4;
	    }
	    else if( !rc )
		rc = radix64_read( afx, a, &n, buf, size );
	}
	else
	    rc = radix64_read( afx, a, &n, buf, size );
#if 0
	if( n )
	    if( fwrite(buf, n, 1, fp ) != 1 )
		BUG();
#endif
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_FLUSH && !afx->cancel ) {
	if( !afx->status ) { /* write the header line */
	    const char *s;
	    STRLIST comment=opt.comments;

	    if( afx->what >= DIM(head_strings) )
		log_bug("afx->what=%d", afx->what);
	    iobuf_writestr(a, "-----");
	    iobuf_writestr(a, head_strings[afx->what] );
	    iobuf_writestr(a, "-----" );
	    iobuf_writestr(a,afx->eol);
	    if( !opt.no_version )
	      {
		iobuf_writestr(a, "Version: GnuPG v"  VERSION " ("
			       PRINTABLE_OS_NAME ")" );
		iobuf_writestr(a,afx->eol);
	      }

	    /* write the comment strings */
	    for(s=comment->d;comment;comment=comment->next,s=comment->d)
	      {
		iobuf_writestr(a, "Comment: " );
		for( ; *s; s++ )
		  {
		    if( *s == '\n' )
		      iobuf_writestr(a, "\\n" );
		    else if( *s == '\r' )
		      iobuf_writestr(a, "\\r" );
		    else if( *s == '\v' )
		      iobuf_writestr(a, "\\v" );
		    else
		      iobuf_put(a, *s );
		  }

		iobuf_writestr(a,afx->eol);
	      }

	    if ( afx->hdrlines ) {
                for ( s = afx->hdrlines; *s; s++ ) {
#ifdef HAVE_DOSISH_SYSTEM
                    if ( *s == '\n' )
                        iobuf_put( a, '\r');
#endif
                    iobuf_put(a, *s );
                }
            }

	    iobuf_writestr(a,afx->eol);
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
		if( ++idx2 >= (64/4) )
		  { /* pgp doesn't like 72 here */
		    iobuf_writestr(a,afx->eol);
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
    else if( control == IOBUFCTRL_INIT )
      {
	if( !is_initialized )
	  initialize();

	/* Figure out what we're using for line endings if the caller
	   didn't specify. */
	if(afx->eol[0]==0)
	  {
#ifdef HAVE_DOSISH_SYSTEM
	    afx->eol[0]='\r';
	    afx->eol[1]='\n';
#else
	    afx->eol[0]='\n';
#endif
	  }
      }
    else if( control == IOBUFCTRL_CANCEL ) {
	afx->cancel = 1;
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( afx->cancel )
	    ;
	else if( afx->status ) { /* pad, write cecksum, and bottom line */
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
		if( ++idx2 >= (64/4) )
		  { /* pgp doesn't like 72 here */
		    iobuf_writestr(a,afx->eol);
		    idx2=0;
		  }
	    }
	    /* may need a linefeed */
	    if( idx2 )
	      iobuf_writestr(a,afx->eol);
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
	    iobuf_writestr(a,afx->eol);
	    /* and the the trailer */
	    if( afx->what >= DIM(tail_strings) )
		log_bug("afx->what=%d", afx->what);
	    iobuf_writestr(a, "-----");
	    iobuf_writestr(a, tail_strings[afx->what] );
	    iobuf_writestr(a, "-----" );
	    iobuf_writestr(a,afx->eol);
	}
	else if( !afx->any_data && !afx->inp_bypass ) {
	    log_error(_("no valid OpenPGP data found.\n"));
	    afx->no_openpgp_data = 1;
	    write_status_text( STATUS_NODATA, "1" );
	}
	if( afx->truncated )
	    log_info(_("invalid armor: line longer than %d characters\n"),
		      MAX_LINELEN );
	/* issue an error to enforce dissemination of correct software */
	if( afx->qp_detected )
	    log_error(_("quoted printable character in armor - "
			"probably a buggy MTA has been used\n") );
	xfree( afx->buffer );
	afx->buffer = NULL;
        release_armor_context (afx);
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "armor_filter";
    return rc;
}


/****************
 * create a radix64 encoded string.
 */
char *
make_radix64_string( const byte *data, size_t len )
{
    char *buffer, *p;

    buffer = p = xmalloc( (len+2)/3*4 + 1 );
    for( ; len >= 3 ; len -= 3, data += 3 ) {
	*p++ = bintoasc[(data[0] >> 2) & 077];
	*p++ = bintoasc[(((data[0] <<4)&060)|((data[1] >> 4)&017))&077];
	*p++ = bintoasc[(((data[1]<<2)&074)|((data[2]>>6)&03))&077];
	*p++ = bintoasc[data[2]&077];
    }
    if( len == 2 ) {
	*p++ = bintoasc[(data[0] >> 2) & 077];
	*p++ = bintoasc[(((data[0] <<4)&060)|((data[1] >> 4)&017))&077];
	*p++ = bintoasc[((data[1]<<2)&074)];
    }
    else if( len == 1 ) {
	*p++ = bintoasc[(data[0] >> 2) & 077];
	*p++ = bintoasc[(data[0] <<4)&060];
    }
    *p = 0;
    return buffer;
}


/***********************************************
 *  For the pipemode command we can't use the armor filter for various
 *  reasons, so we use this new unarmor_pump stuff to remove the armor 
 */

enum unarmor_state_e {
    STA_init = 0,
    STA_bypass,
    STA_wait_newline,
    STA_wait_dash,
    STA_first_dash, 
    STA_compare_header,
    STA_found_header_wait_newline,
    STA_skip_header_lines,
    STA_skip_header_lines_non_ws,
    STA_read_data,
    STA_wait_crc,
    STA_read_crc,
    STA_ready
};

struct unarmor_pump_s {
    enum unarmor_state_e state;
    byte val;
    int checkcrc;
    int pos;   /* counts from 0..3 */
    u32 crc;
    u32 mycrc; /* the one store in the data */
};



UnarmorPump
unarmor_pump_new (void)
{
    UnarmorPump x;

    if( !is_initialized )
        initialize();
    x = xmalloc_clear (sizeof *x);
    return x;
}

void
unarmor_pump_release (UnarmorPump x)
{
    xfree (x);
}

/* 
 * Get the next character from the ascii armor taken from the IOBUF
 * created earlier by unarmor_pump_new().
 * Return:  c = Character
 *        256 = ignore this value
 *         -1 = End of current armor 
 *         -2 = Premature EOF (not used)
 *         -3 = Invalid armor
 */
int
unarmor_pump (UnarmorPump x, int c)
{
    int rval = 256; /* default is to ignore the return value */

    switch (x->state) {
      case STA_init:
        { 
            byte tmp[1];
            tmp[0] = c; 
            if ( is_armored (tmp) )
                x->state = c == '-'? STA_first_dash : STA_wait_newline;
            else {
                x->state = STA_bypass;
                return c;
            }
        }
        break;
      case STA_bypass:
        return c; /* return here to avoid crc calculation */
      case STA_wait_newline:
        if (c == '\n')
            x->state = STA_wait_dash;
        break;
      case STA_wait_dash:
        x->state = c == '-'? STA_first_dash : STA_wait_newline;
        break;
      case STA_first_dash: /* just need for initalization */
        x->pos = 0;
        x->state = STA_compare_header;
      case STA_compare_header:
        if ( "-----BEGIN PGP SIGNATURE-----"[++x->pos] == c ) {
            if ( x->pos == 28 ) 
                x->state = STA_found_header_wait_newline;
        }
        else 
            x->state = c == '\n'? STA_wait_dash : STA_wait_newline;
        break;
      case STA_found_header_wait_newline:
        /* to make CR,LF issues easier we simply allow for white space
           behind the 5 dashes */
        if ( c == '\n' )
            x->state = STA_skip_header_lines;
        else if ( c != '\r' && c != ' ' && c != '\t' )
            x->state = STA_wait_dash; /* garbage after the header line */
        break;
      case STA_skip_header_lines:
        /* i.e. wait for one empty line */
        if ( c == '\n' ) {
            x->state = STA_read_data;
            x->crc = CRCINIT;
            x->val = 0;
            x->pos = 0;
        }
        else if ( c != '\r' && c != ' ' && c != '\t' )
            x->state = STA_skip_header_lines_non_ws;
        break;
      case STA_skip_header_lines_non_ws:
        /* like above but we already encountered non white space */
        if ( c == '\n' )
            x->state = STA_skip_header_lines;
        break;
      case STA_read_data:
        /* fixme: we don't check for the trailing dash lines but rely
         * on the armor stop characters */
        if( c == '\n' || c == ' ' || c == '\r' || c == '\t' )
            break; /* skip all kind of white space */

        if( c == '=' ) { /* pad character: stop */
            if( x->pos == 1 ) /* in this case val has some value */
                rval = x->val;
            x->state = STA_wait_crc;
            break;
        }

        {
            int c2;
            if( (c = asctobin[(c2=c)]) == 255 ) {
                log_error(_("invalid radix64 character %02X skipped\n"), c2);
                break;
            }
        }
        
        switch(x->pos) {
          case 0:
            x->val = c << 2;
            break;
          case 1:
            x->val |= (c>>4)&3;
            rval = x->val;
            x->val = (c<<4)&0xf0;
            break;
          case 2:
            x->val |= (c>>2)&15;
            rval = x->val;
            x->val = (c<<6)&0xc0;
            break;
          case 3:
            x->val |= c&0x3f;
            rval = x->val;
            break;
        }
        x->pos = (x->pos+1) % 4;
        break;
      case STA_wait_crc:
        if( c == '\n' || c == ' ' || c == '\r' || c == '\t' || c == '=' )
            break; /* skip ws and pad characters */
        /* assume that we are at the next line */
        x->state = STA_read_crc;
        x->pos = 0;
        x->mycrc = 0;
      case STA_read_crc:
        if( (c = asctobin[c]) == 255 ) {
            rval = -1; /* ready */
            if( x->crc != x->mycrc ) {
                log_info (_("CRC error; %06lX - %06lX\n"),
                          (ulong)x->crc, (ulong)x->mycrc);
                if ( invalid_crc() )
                    rval = -3;
            }
            x->state = STA_ready; /* not sure whether this is correct */
            break;
        }
        
        switch(x->pos) {
          case 0:
            x->val = c << 2;
            break;
          case 1:
            x->val |= (c>>4)&3;
            x->mycrc |= x->val << 16;
            x->val = (c<<4)&0xf0;
            break;
          case 2:
            x->val |= (c>>2)&15;
            x->mycrc |= x->val << 8;
            x->val = (c<<6)&0xc0;
            break;
          case 3:
            x->val |= c&0x3f;
            x->mycrc |= x->val;
            break;
        }
        x->pos = (x->pos+1) % 4;
        break;
      case STA_ready:
        rval = -1;
        break;
    }

    if ( !(rval & ~255) ) { /* compute the CRC */
        x->crc = (x->crc << 8) ^ crc_table[((x->crc >> 16)&0xff) ^ rval];
        x->crc &= 0x00ffffff;
    }

    return rval;
}
