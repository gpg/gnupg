/* textfilter.c
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include <errno.h>
#include <assert.h>

#include "errors.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "filter.h"




static int
read_line( byte *buf, size_t *r_buflen, IOBUF a )
{
    int c;
    int rc = 0;
    byte *p;
    size_t buflen;
    int no_lf=0;
    size_t n;

    buflen = *r_buflen;
    assert(buflen >= 20 );
    buflen -= 3; /* leave some room for CR,LF and one extra */

    for(c=0, n=0; n < buflen && (c=iobuf_get(a)) != -1 && c != '\n'; )
	buf[n++] = c;
    buf[n] = 0;
    if( c == -1 ) {
	rc = -1;
	if( !n || buf[n-1] != '\n' )
	    no_lf = 1;
    }
    else if( c != '\n' ) {
	IOBUF b = iobuf_temp();
	while( (c=iobuf_get(a)) != -1 && c != '\n' ) {
	    iobuf_put(b,c);
	    if( c != ' ' && c != '\t' && c != '\r' )
		break;
	}
	if( c == '\n' ) { /* okay we can skip the rest of the line */
	    iobuf_close(b);
	}
	else {
	    iobuf_unget_and_close_temp(a,b);
	    no_lf = 1;
	}
    }

    if( !no_lf ) {
	/* append CR,LF after removing trailing wspaces */
	for(p=buf+n-1; n; n--, p-- ) {
	    assert( *p != '\n' );
	    if( *p != ' ' && *p != '\t' && *p != '\r' ) {
		p[1] = '\r';
		p[2] = '\n';
		n += 2;
		break;
	    }
	}
	if( !n ) {
	    buf[0] = '\r';
	    buf[1] = '\n';
	    n = 2;
	}
    }


    *r_buflen = n;
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
    size_t len, n, nn;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert( size > 30 );
	len = 0;
	while( !rc && len < size ) {
	    if( tfx->idx < tfx->len ) { /* flush the last buffer */
		n = tfx->len;
		for(nn=tfx->idx; len < size && nn < n ; nn++ )
		    buf[len++] = tfx->buf[nn];
		tfx->idx = nn;
		continue;
	    }
	    if( tfx->eof ) {
		rc = -1;
		continue;
	    }
	    n = DIM(tfx->buf);
	    tfx->idx = 0;
	    if( read_line( tfx->buf, &n, a ) == -1 )
		tfx->eof = 1;
	    tfx->len = n;
	}
	*ret_len = len;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "text_filter";
    return rc;
}



