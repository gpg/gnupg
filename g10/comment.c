/* comment.c - write comment stuff
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

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "keydb.h"



int
write_comment( IOBUF out, const char *s )
{
    PACKET pkt;
    size_t n = strlen(s);
    int rc=0;

    pkt.pkttype = PKT_COMMENT;
    pkt.pkt.comment = m_alloc( sizeof *pkt.pkt.comment + n - 1 );
    pkt.pkt.comment->len = n;
    strcpy(pkt.pkt.comment->data, s);
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet(comment) failed: %s\n", g10_errstr(rc) );
    free_packet( &pkt );
    return rc;
}


KBNODE
make_comment_node( const char *s )
{
    PACKET *pkt = m_alloc_clear( sizeof *pkt );
    size_t n = strlen(s);

    pkt->pkttype = PKT_COMMENT;
    pkt->pkt.comment = m_alloc( sizeof *pkt->pkt.comment + n - 1 );
    pkt->pkt.comment->len = n;
    strcpy(pkt->pkt.comment->data, s);
    return new_kbnode( pkt );
}


