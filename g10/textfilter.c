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
#include "i18n.h"


#define MAX_LINELEN 20000


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
	size_t len = 0;
	unsigned maxlen;

	assert( size > 10 );
	size -= 2;  /* reserve 2 bytes to append CR,LF */
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
	    tfx->buffer_len = trim_trailing_ws( tfx->buffer, tfx->buffer_len );
	    if( lf_seen ) {
		tfx->buffer[tfx->buffer_len++] = '\r';
		tfx->buffer[tfx->buffer_len++] = '\n';
	    }
	}

	*ret_len = len;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "text_filter";
    else if( control == IOBUFCTRL_FREE ) {
	if( tfx->truncated )
	    log_error(_("can't handle text lines longer than %d characters\n"),
			MAX_LINELEN );
	m_free( tfx->buffer );
	tfx->buffer = NULL;
    }
    return rc;
}



