/* mdfilter.c - filter data and calculate a message digest
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
 * The filter is used to collect a message digest
 */
int
md_filter( void *opaque, int control,
	       IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    md_filter_context_t *mfx = opaque;
    int i, c, rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	if( size > mfx->maxbuf_size )
	    size = mfx->maxbuf_size;
	for(i=0; i < size; i++ ) {
	    if( (c = iobuf_get(a)) == -1 )
		break;
	    buf[i] = c;
	}

	if( i ) {
	    if( mfx->md5 )
		md5_write(mfx->md5, buf, i );
	    if( mfx->rmd160 )
		rmd160_write(mfx->rmd160, buf, i );
	}
	else
	    rc = -1; /* eof */
	*ret_len = i;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "md_filter";
    return rc;
}

