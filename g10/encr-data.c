/* encr-data.c -  process an encrypted data packet
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
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
#include "options.h"


static int decode_filter( void *opaque, int control, IOBUF a,
					byte *buf, size_t *ret_len);

typedef struct {
    int is_cast5;
    BLOWFISH_context *bf_ctx;
    CAST5_context *cast5_ctx;
} decode_filter_ctx_t;



/****************
 * Decrypt the data, specified by ED with the key DEK.
 */
int
decrypt_data( PKT_encrypted *ed, DEK *dek )
{
    decode_filter_ctx_t dfx;
    byte *p;
    int c, i;
    byte temp[16];

    if( opt.verbose ) {
	const char *s = cipher_algo_to_string( dek->algo );
	if( s )
	    log_info("%s encrypted data\n", s );
	else
	    log_info("encrypted with unknown algorithm %d\n", dek->algo );
    }
    if( dek->algo != CIPHER_ALGO_BLOWFISH
	&& dek->algo != CIPHER_ALGO_BLOWFISH128
	&& dek->algo != CIPHER_ALGO_CAST       )
	return G10ERR_CIPHER_ALGO;
    if( ed->len && ed->len < 10 )
	log_bug("Nanu\n");   /* oops: found a bug */

    if( dek->algo == CIPHER_ALGO_CAST ) {
	dfx.is_cast5 = 1;
	dfx.cast5_ctx = m_alloc_secure( sizeof *dfx.cast5_ctx );
	cast5_setkey( dfx.cast5_ctx, dek->key, dek->keylen  );
	cast5_setiv( dfx.cast5_ctx, NULL );
    }
    else {
	dfx.is_cast5 = 0;
	dfx.bf_ctx = m_alloc_secure( sizeof *dfx.bf_ctx );
	blowfish_setkey( dfx.bf_ctx, dek->key, dek->keylen  );
	blowfish_setiv( dfx.bf_ctx, NULL );
    }

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
    if( dfx.is_cast5 ) {
	cast5_decode_cfb( dfx.cast5_ctx, temp, temp, 10);
	cast5_sync_cfb( dfx.cast5_ctx );
    }
    else
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

	if( n ) {
	    if( fc->is_cast5 )
		cast5_decode_cfb( fc->cast5_ctx, buf, buf, n);
	    else
		blowfish_decode_cfb( fc->bf_ctx, buf, buf, n);
	}
	else
	    rc = -1; /* eof */
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "decode_filter";
    }
    return rc;
}


