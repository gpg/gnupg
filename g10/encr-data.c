/* encr-data.c -  process an encrypted data packet
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "mpi.h"
#include "cipher.h"


static int decode_filter( void *opaque, int control, IOBUF a,
					byte *buf, size_t *ret_len);

typedef struct {
    BLOWFISH_context *bf_ctx;
} decode_filter_ctx_t;



/****************
 * Decrypt the data, specified by ED with the key DEK.
 */
int
decrypt_data( PKT_encr_data *ed, DEK *dek )
{
    decode_filter_ctx_t dfx;
    byte *p;
    int c, i;
    byte temp[16];


    if( dek->algo != CIPHER_ALGO_BLOWFISH )
	return G10ERR_CIPHER_ALGO;
    if( ed->len && ed->len < 10 )
	log_bug("Nanu\n");   /* oops: found a bug */

    dfx.bf_ctx = m_alloc_secure( sizeof *dfx.bf_ctx );
    blowfish_setkey( dfx.bf_ctx, dek->key, dek->keylen	);
    blowfish_setiv( dfx.bf_ctx, NULL );

    if( ed->len ) {
	iobuf_set_limit( ed->buf, ed->len );

	for(i=0; i < 10 && ed->len; i++, ed->len-- )
	    temp[i] = iobuf_get(ed->buf);
    }
    else {
	for(i=0; i < 10; i++ )
	    if( (c=iobuf_get(ed->buf)) == -1 )
		break;
	    else
		temp[i] = c;
    }
    blowfish_decode_cfb( dfx.bf_ctx, temp, temp, 10);
    p = temp;
    if( p[6] != p[8] || p[7] != p[9] ) {
	m_free(dfx.bf_ctx);
	return G10ERR_BAD_KEY;
    }
    iobuf_push_filter( ed->buf, decode_filter, &dfx );
    proc_packets(ed->buf);
    iobuf_pop_filter( ed->buf, decode_filter, &dfx );
    if( ed->len )
	iobuf_set_limit( ed->buf, 0 ); /* disable the readlimit */
    else
	iobuf_clear_eof( ed->buf );
    ed->buf = NULL;
    m_free(dfx.bf_ctx);
    return 0;
}

static int
decode_filter( void *opaque, int control, IOBUF a, byte *buf, size_t *ret_len)
{
    decode_filter_ctx_t *fc = opaque;
    size_t n, size = *ret_len;
    int rc = 0;
    int c;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert(a);
	for(n=0; n < size; n++ ) {
	    if( (c = iobuf_get(a)) == -1 )
		break;
	    buf[n] = c;
	}

	if( n )
	    blowfish_decode_cfb( fc->bf_ctx, buf, buf, n);
	else
	    rc = -1; /* eof */
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "decode_filter";
    }
    return rc;
}


