/* encr-data.c -  process an encrypted data packet
 *	Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "mpi.h"
#include "cipher.h"
#include "options.h"
#include "i18n.h"


static int decode_filter( void *opaque, int control, IOBUF a,
					byte *buf, size_t *ret_len);

typedef struct {
    CIPHER_HANDLE cipher_hd;
} decode_filter_ctx_t;



/****************
 * Decrypt the data, specified by ED with the key DEK.
 */
int
decrypt_data( PKT_encrypted *ed, DEK *dek )
{
    decode_filter_ctx_t dfx;
    byte *p;
    int rc, c, i;
    byte temp[32];
    unsigned blocksize;
    unsigned nprefix;

    if( opt.verbose ) {
	const char *s = cipher_algo_to_string( dek->algo );
	if( s )
	    log_info(_("%s encrypted data\n"), s );
	else
	    log_info(_("encrypted with unknown algorithm %d\n"), dek->algo );
    }
    if( (rc=check_cipher_algo(dek->algo)) )
	return rc;
    blocksize = cipher_get_blocksize(dek->algo);
    if( !blocksize || blocksize > 16 )
	log_fatal("unsupported blocksize %u\n", blocksize );
    nprefix = blocksize;
    if( ed->len && ed->len < (nprefix+2) )
	BUG();

    dfx.cipher_hd = cipher_open( dek->algo, CIPHER_MODE_AUTO_CFB, 1 );
/* log_hexdump( "thekey", dek->key, dek->keylen );*/
    rc = cipher_setkey( dfx.cipher_hd, dek->key, dek->keylen );
    if( rc == G10ERR_WEAK_KEY )
	log_info(_("WARNING: message was encrypted with "
		    "a weak key in the symmetric cipher.\n"));
    else if( rc )
	log_error("key setup failed: %s\n", g10_errstr(rc) );

    cipher_setiv( dfx.cipher_hd, NULL, 0 );

    if( ed->len ) {
	for(i=0; i < (nprefix+2) && ed->len; i++, ed->len-- ) {
	    if( (c=iobuf_get(ed->buf)) == -1 )
		break;
	    else
		temp[i] = c;
	}
    }
    else {
	for(i=0; i < (nprefix+2); i++ )
	    if( (c=iobuf_get(ed->buf)) == -1 )
		break;
	    else
		temp[i] = c;
    }
    cipher_decrypt( dfx.cipher_hd, temp, temp, nprefix+2);
    cipher_sync( dfx.cipher_hd );
    p = temp;
/* log_hexdump( "prefix", temp, nprefix+2 ); */
    if( p[nprefix-2] != p[nprefix] || p[nprefix-1] != p[nprefix+1] ) {
	cipher_close(dfx.cipher_hd);
	return G10ERR_BAD_KEY;
    }
    iobuf_push_filter( ed->buf, decode_filter, &dfx );
    proc_packets(ed->buf);
    ed->buf = NULL;
    cipher_close(dfx.cipher_hd);
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
	    cipher_decrypt( fc->cipher_hd, buf, buf, n);
	else
	    rc = -1; /* eof */
	*ret_len = n;
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "decode_filter";
    }
    return rc;
}


