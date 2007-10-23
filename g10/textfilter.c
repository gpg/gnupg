/* textfilter.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2004 Free Software Foundation, Inc.
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

#include "errors.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "filter.h"
#include "i18n.h"
#include "options.h"
#include "status.h"

#ifdef HAVE_DOSISH_SYSTEM
#define LF "\r\n"
#else
#define LF "\n"
#endif

#define MAX_LINELEN 19995 /* a little bit smaller than in armor.c */
			  /* to make sure that a warning is displayed while */
			  /* creating a message */

static unsigned
len_without_trailing_chars( byte *line, unsigned len, const char *trimchars )
{
    byte *p, *mark;
    unsigned n;

    for(mark=NULL, p=line, n=0; n < len; n++, p++ ) {
	if( strchr( trimchars, *p ) ) {
	    if( !mark )
		mark = p;
	}
	else
	    mark = NULL;
    }

    return mark? (mark - line) : len;
}


static int
standard( text_filter_context_t *tfx, IOBUF a,
	  byte *buf, size_t size, size_t *ret_len)
{
    int rc=0;
    size_t len = 0;
    unsigned maxlen;

    assert( size > 10 );
    size -= 2;	/* reserve 2 bytes to append CR,LF */
    while( !rc && len < size ) {
	int lf_seen;

	while( len < size && tfx->buffer_pos < tfx->buffer_len )
	    buf[len++] = tfx->buffer[tfx->buffer_pos++];
	if( len >= size )
	    continue;

	/* read the next line */
	maxlen = MAX_LINELEN;
	tfx->buffer_pos = 0;
	tfx->buffer_len = iobuf_read_line( a, &tfx->buffer,
					   &tfx->buffer_size, &maxlen );
	if( !maxlen )
	    tfx->truncated++;
	if( !tfx->buffer_len ) {
	    if( !len )
		rc = -1; /* eof */
	    break;
	}
	lf_seen = tfx->buffer[tfx->buffer_len-1] == '\n';

	/* The story behind this is that 2440 says that textmode
	   hashes should canonicalize line endings to CRLF and remove
	   spaces and tabs.  2440bis-12 says to just canonicalize to
	   CRLF.  1.4.0 was released using the bis-12 behavior, but it
	   was discovered that many mail clients do not canonicalize
	   PGP/MIME signature text appropriately (and were relying on
	   GnuPG to handle trailing spaces).  So, we default to the
	   2440 behavior, but use the 2440bis-12 behavior if the user
	   specifies --no-rfc2440-text.  The default will be changed
	   at some point in the future when the mail clients have been
	   upgraded.  Aside from PGP/MIME and broken mail clients,
	   this makes no difference to any signatures in the real
	   world except for a textmode detached signature.  PGP always
	   used the 2440bis-12 behavior (ignoring 2440 itself), so
	   this actually makes us compatible with PGP textmode
	   detached signatures for the first time. */
	if(opt.rfc2440_text)
	  tfx->buffer_len=trim_trailing_chars(tfx->buffer,tfx->buffer_len,
					      " \t\r\n");
	else
	  tfx->buffer_len=trim_trailing_chars(tfx->buffer,tfx->buffer_len,
					      "\r\n");

	if( lf_seen ) {
	    tfx->buffer[tfx->buffer_len++] = '\r';
	    tfx->buffer[tfx->buffer_len++] = '\n';
	}
    }
    *ret_len = len;
    return rc;
}


/****************
 * The filter is used to make canonical text: Lines are terminated by
 * CR, LF, trailing white spaces are removed.
 */
int
text_filter( void *opaque, int control,
	     IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    text_filter_context_t *tfx = opaque;
    int rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	rc = standard( tfx, a, buf, size, ret_len );
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( tfx->truncated )
	    log_error(_("can't handle text lines longer than %d characters\n"),
			MAX_LINELEN );
	xfree( tfx->buffer );
	tfx->buffer = NULL;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "text_filter";
    return rc;
}


/****************
 * Copy data from INP to OUT and do some escaping if requested.
 * md is updated as required by rfc2440
 */
int
copy_clearsig_text( IOBUF out, IOBUF inp, MD_HANDLE md,
		    int escape_dash, int escape_from, int pgp2mode )
{
    unsigned maxlen;
    byte *buffer = NULL;    /* malloced buffer */
    unsigned bufsize;	    /* and size of this buffer */
    unsigned n;
    int truncated = 0;
    int pending_lf = 0;

    if( !opt.pgp2_workarounds )
	pgp2mode = 0;

    if( !escape_dash )
	escape_from = 0;

    write_status (STATUS_BEGIN_SIGNING);

    for(;;) {
	maxlen = MAX_LINELEN;
	n = iobuf_read_line( inp, &buffer, &bufsize, &maxlen );
	if( !maxlen )
	    truncated++;

	if( !n )
	    break; /* read_line has returned eof */

	/* update the message digest */
	if( escape_dash ) {
	    if( pending_lf ) {
		md_putc( md, '\r' );
		md_putc( md, '\n' );
	    }
	    md_write( md, buffer,
		     len_without_trailing_chars( buffer, n,
						 pgp2mode? " \r\n":" \t\r\n"));
	}
	else
	    md_write( md, buffer, n );
	pending_lf = buffer[n-1] == '\n';

	/* write the output */
	if(    ( escape_dash && *buffer == '-')
	    || ( escape_from && n > 4 && !memcmp(buffer, "From ", 5 ) ) ) {
	    iobuf_put( out, '-' );
	    iobuf_put( out, ' ' );
	}

#if  0 /*defined(HAVE_DOSISH_SYSTEM)*/
	/* We don't use this anymore because my interpretation of rfc2440 7.1
	 * is that there is no conversion needed.  If one decides to
	 * clearsign a unix file on a DOS box he will get a mixed line endings.
	 * If at some point it turns out, that a conversion is a nice feature
	 * we can make an option out of it.
	 */
	/* make sure the lines do end in CR,LF */
	if( n > 1 && ( (buffer[n-2] == '\r' && buffer[n-1] == '\n' )
			    || (buffer[n-2] == '\n' && buffer[n-1] == '\r'))) {
	    iobuf_write( out, buffer, n-2 );
	    iobuf_put( out, '\r');
	    iobuf_put( out, '\n');
	}
	else if( n && buffer[n-1] == '\n' ) {
	    iobuf_write( out, buffer, n-1 );
	    iobuf_put( out, '\r');
	    iobuf_put( out, '\n');
	}
	else
	    iobuf_write( out, buffer, n );

#else
	iobuf_write( out, buffer, n );
#endif
    }

    /* at eof */
    if( !pending_lf ) { /* make sure that the file ends with a LF */
	iobuf_writestr( out, LF );
	if( !escape_dash )
	    md_putc( md, '\n' );
    }

    if( truncated )
	log_info(_("input line longer than %d characters\n"), MAX_LINELEN );

    return 0; /* okay */
}
