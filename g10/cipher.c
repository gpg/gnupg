/* cipher.c - En-/De-ciphering filter
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




/****************
 * This filter is used to en/de-cipher data.
 */
int
cipher_filter( void *opaque, int control,
	       IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    cipher_filter_context_t *cfx = opaque;
    int rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) { /* decipher */
	rc = -1; /* FIXME:*/
    }
    else if( control == IOBUFCTRL_FLUSH ) { /* encipher */
	assert(a);
	if( !cfx->header ) {
	    PACKET pkt;
	    PKT_encr_data ed;
	    byte temp[10];

	    memset( &ed, 0, sizeof ed );
	    ed.len = cfx->datalen;
	    init_packet( &pkt );
	    pkt.pkttype = PKT_ENCR_DATA;
	    pkt.pkt.encr_data = &ed;
	    if( build_packet( a, &pkt ))
		log_bug("build_packet(ENCR_DATA) failed\n");
	    randomize_buffer( temp, 8, 1 );
	    temp[8] = temp[6];
	    temp[9] = temp[7];
	    if( cfx->dek->algo == CIPHER_ALGO_BLOWFISH ) {
		cfx->bf_ctx = m_alloc_secure( sizeof *cfx->bf_ctx );
		blowfish_setkey( cfx->bf_ctx, cfx->dek->key, cfx->dek->keylen );
		blowfish_setiv( cfx->bf_ctx, NULL );
		blowfish_encode_cfb( cfx->bf_ctx, temp, temp, 10);
	    }
	    else
		log_bug("no cipher algo %d\n", cfx->dek->algo);

	    iobuf_write(a, temp, 10);
	    cfx->header=1;
	}

	if( cfx->dek->algo == CIPHER_ALGO_BLOWFISH )
	    blowfish_encode_cfb( cfx->bf_ctx, buf, buf, size);
	if( iobuf_write( a, buf, size ) )
	    rc = G10ERR_WRITE_FILE;
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( cfx->dek->algo == CIPHER_ALGO_BLOWFISH )
	    m_free(cfx->bf_ctx);
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "cipher_filter";
    }
    return rc;
}




