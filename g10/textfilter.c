/* textfilter.c
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
    int i, c, rc=0;
    byte *p;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	for(i=0; i < size; i++ ) {
	    if( !tfx->linelen && !tfx->eof ) { /* read a complete line */
		for(;;) {
		    if( (c = iobuf_get(a)) == -1 ) {
			tfx->eof=1;
			break;
		    }
		    if( c == '\n' )
			break;
		    if( tfx->linelen >= tfx->linesize ) {
			tfx->linesize += 500;
			tfx->line = m_realloc( tfx->line, tfx->linesize );
		    }
		    tfx->line[tfx->linelen++] = c;
		}
		/* remove trailing white spaces */
		p = tfx->line + tfx->linelen - 1;
		for( ; p >= tfx->line; p--, tfx->linelen-- ) {
		    if( *p != ' ' && *p == '\t' && *p != '\r' )
			break;
		}
		if( tfx->linelen+2 >= tfx->linesize ) {
		    tfx->linesize += 10;
		    tfx->line = m_realloc( tfx->line, tfx->linesize );
		}
		tfx->line[tfx->linelen++] = '\r';
		tfx->line[tfx->linelen++] = '\n';
		tfx->pos=0;
	    }
	    if( tfx->pos < tfx->linelen )
		buf[i] = tfx->line[tfx->pos++];
	    else if( tfx->eof )
		break;
	    else
		tfx->linelen = 0;
	}
	if( !i )
	    rc = -1;
	*ret_len = i;
    }
    else if( control == IOBUFCTRL_INIT ) {
	tfx->linesize = 500;
	tfx->line = m_alloc(tfx->linesize);
	tfx->linelen = 0;
	tfx->pos = 0;
	tfx->eof = 0;
    }
    else if( control == IOBUFCTRL_FREE ) {
	m_free( tfx->line );
	tfx->line = NULL;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "text_filter";
    return rc;
}



