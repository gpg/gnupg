/* mdfilter.c - filter data and calculate a message digest
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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



/****************
 * This filter is used to collect a message digest
 */
int
md_filter( void *opaque, int control,
	       IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    md_filter_context_t *mfx = opaque;
    int i, rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	if( mfx->maxbuf_size && size > mfx->maxbuf_size )
	    size = mfx->maxbuf_size;
	i = iobuf_read( a, buf, size );
	if( i == -1 ) i = 0;
	if( i ) {
	    md_write(mfx->md, buf, i );
	    if( mfx->md2 )
		md_write(mfx->md2, buf, i );
	}
	else
	    rc = -1; /* eof */
	*ret_len = i;
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "md_filter";
    return rc;
}


void
free_md_filter_context( md_filter_context_t *mfx )
{
    md_close(mfx->md);
    md_close(mfx->md2);
    mfx->md = NULL;
    mfx->md2 = NULL;
    mfx->maxbuf_size = 0;
}

