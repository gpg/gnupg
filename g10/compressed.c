/* compressed.c -  process an compressed packet
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
#include <unistd.h>
#include <errno.h>
/*#include <zlib.h>*/
#include "util.h"
#include "memory.h"
#include "packet.h"


/****************
 * Handle a compressed packet
 */
int
handle_compressed( PKT_compressed *zd )
{
  return -1;
  #if 0
    int c, zrc, rc = 0;
    z_stream *zs = NULL;
    unsigned inbufsize = 4096;
    unsigned outbufsize = 16384;
    unsigned n;
    byte *inbuf = NULL;
    byte *outbuf = NULL;

    if( zd->algorithm != 1 ) {
	rc =G10ERR_COMPR_ALGO;
	goto leave;
    }

    zs = m_alloc_clear( sizeof *zs );
    if( (zrc = inflateInit( zs )) != Z_OK ) {
	log_fatal("zlib problem: %s\n", zs->msg? zs->msg :
			      zrc == Z_MEM_ERROR ? "out of core" :
			      zrc == Z_VERSION_ERROR ? "invalid lib version" :
						       "unknown error" );
    }

    inbuf = m_alloc( inbufsize );
    outbuf = m_alloc( outbufsize ); /* Fixme: put it in secure space? */

    zs->next_in = inbuf;
    zs->avail_in = inbufsize;
    zs->next_out = outbuf;
    zs->avail_out = outbufsize;

    n = 0;
    inbuf[n++] = 0x58;
    inbuf[n++] = 0x09;
    for(; n < inbufsize && (c=iobuf_get(zd->buf)) != -1 ; n++ )
	inbuf[n] = c;
    if( n ) {
	{ int i;
	  printf("start of compressed packet (n=%u):\n", n);
	  for(i=0; i < 32 && i < n; i++ )
	    printf(" %02x", inbuf[i] );
	  putchar('\n');
	}
	zrc = inflate( zs, Z_PARTIAL_FLUSH );
	switch( zrc ) {
	  case Z_OK:
	    log_info("inflate returned okay\n");
	    break;
	  case Z_STREAM_END:
	    log_info("inflate returned stream-end\n");
	    break;
	  case Z_NEED_DICT:
	  case Z_DATA_ERROR:
	  case Z_STREAM_ERROR:
	  case Z_MEM_ERROR:
	  case Z_BUF_ERROR:
	  default:
	    if( zs->msg )
		log_error("zlib inflate problem: %s\n", zs->msg );
	    else
		log_error("zlib inflate problem: rc=%d\n", zrc );
	    break;
	}
    }

  leave:
    if( zs ) {
	inflateEnd(zs);
	m_free(zs);
    }
    m_free(inbuf);
    m_free(outbuf);
    return rc;
  #endif
}

