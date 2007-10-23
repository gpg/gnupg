/* encr-data.c -  process an encrypted data packet
 * Copyright (C) 1998, 1999, 2000, 2001, 2005,
 *               2006  Free Software Foundation, Inc.
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "mpi.h"
#include "cipher.h"
#include "options.h"
#include "i18n.h"


static int mdc_decode_filter( void *opaque, int control, IOBUF a,
					      byte *buf, size_t *ret_len);
static int decode_filter( void *opaque, int control, IOBUF a,
					byte *buf, size_t *ret_len);

typedef struct {
    CIPHER_HANDLE cipher_hd;
    MD_HANDLE mdc_hash;
    char defer[22];
    int  defer_filled;
    int  eof_seen;
    int  refcount;
} *decode_filter_ctx_t;


/* Helper to release the decode context.  */
static void
release_dfx_context (decode_filter_ctx_t dfx)
{
  if (!dfx)
    return;

  assert (dfx->refcount);
  if ( !--dfx->refcount )
    {
      cipher_close (dfx->cipher_hd);
      dfx->cipher_hd = NULL;
      md_close (dfx->mdc_hash);
      dfx->mdc_hash = NULL;
      xfree (dfx);
    }
}


/****************
 * Decrypt the data, specified by ED with the key DEK.
 */
int
decrypt_data( void *procctx, PKT_encrypted *ed, DEK *dek )
{
    decode_filter_ctx_t dfx;
    byte *p;
    int rc=0, c, i;
    byte temp[32];
    unsigned blocksize;
    unsigned nprefix;


    dfx = xcalloc (1, sizeof *dfx);
    dfx->refcount = 1;

    if( opt.verbose && !dek->algo_info_printed ) {
	const char *s = cipher_algo_to_string( dek->algo );
	if( s )
	    log_info(_("%s encrypted data\n"), s );
	else
	    log_info(_("encrypted with unknown algorithm %d\n"), dek->algo );
        dek->algo_info_printed = 1;
    }
    if( (rc=check_cipher_algo(dek->algo)) )
	goto leave;
    blocksize = cipher_get_blocksize(dek->algo);
    if( !blocksize || blocksize > 16 )
	log_fatal("unsupported blocksize %u\n", blocksize );
    nprefix = blocksize;
    if( ed->len && ed->len < (nprefix+2) )
	BUG();

    if( ed->mdc_method ) {
	dfx->mdc_hash = md_open ( ed->mdc_method, 0 );
	if ( DBG_HASHING )
	    md_start_debug (dfx->mdc_hash, "checkmdc");
    }
    dfx->cipher_hd = cipher_open ( dek->algo,
                                   ed->mdc_method? CIPHER_MODE_CFB
                                                 : CIPHER_MODE_AUTO_CFB, 1 );
    /* log_hexdump( "thekey", dek->key, dek->keylen );*/
    rc = cipher_setkey ( dfx->cipher_hd, dek->key, dek->keylen );
    if( rc == G10ERR_WEAK_KEY )
      {
	log_info(_("WARNING: message was encrypted with"
		   " a weak key in the symmetric cipher.\n"));
	rc=0;
      }
    else if( rc )
      {
	log_error("key setup failed: %s\n", g10_errstr(rc) );
	goto leave;
      
      }
    if (!ed->buf) {
        log_error(_("problem handling encrypted packet\n"));
        goto leave;
    }

    cipher_setiv ( dfx->cipher_hd, NULL, 0 );

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
    cipher_decrypt ( dfx->cipher_hd, temp, temp, nprefix+2);
    cipher_sync ( dfx->cipher_hd );
    p = temp;
/* log_hexdump( "prefix", temp, nprefix+2 ); */
    if(dek->symmetric
       && (p[nprefix-2] != p[nprefix] || p[nprefix-1] != p[nprefix+1]) )
      {
	rc = G10ERR_BAD_KEY;
	goto leave;
      }

    if ( dfx->mdc_hash )
	md_write ( dfx->mdc_hash, temp, nprefix+2 );

    dfx->refcount++;
    if ( ed->mdc_method )
	iobuf_push_filter( ed->buf, mdc_decode_filter, dfx );
    else
	iobuf_push_filter( ed->buf, decode_filter, dfx );

    proc_packets( procctx, ed->buf );
    ed->buf = NULL;
    if( ed->mdc_method && dfx->eof_seen == 2 )
	rc = G10ERR_INVALID_PACKET;
    else if( ed->mdc_method ) { /* check the mdc */
        /* We used to let parse-packet.c handle the MDC packet but
           this turned out to be a problem with compressed packets:
           With old style packets there is no length information
           available and the decompressor uses an implicit end.
           However we can't know this implicit end beforehand (:-) and
           thus may feed the decompressor with more bytes than
           actually needed.  It would be possible to unread the extra
           bytes but due to our weird iobuf system any unread is non
           reliable due to filters already popped off.  The easy and
           sane solution is to care about the MDC packet only here and
           never pass it to the packet parser.  Fortunatley the
           OpenPGP spec requires a strict format for the MDC packet so
           that we know that 22 bytes are appended.  */
	int datalen = md_digest_length( ed->mdc_method );

        assert (dfx->cipher_hd);
        assert (dfx->mdc_hash);
	cipher_decrypt ( dfx->cipher_hd, dfx->defer, dfx->defer, 22);
        md_write ( dfx->mdc_hash, dfx->defer, 2);
	md_final ( dfx->mdc_hash );
        if (dfx->defer[0] != '\xd3' || dfx->defer[1] != '\x14' ) {
            log_error("mdc_packet with invalid encoding\n");
            rc = G10ERR_INVALID_PACKET;
        }
	else if ( datalen != 20
	    || memcmp(md_read( dfx->mdc_hash, 0 ), dfx->defer+2, datalen) )
	    rc = G10ERR_BAD_SIGN;
	/*log_hexdump("MDC calculated:",md_read( dfx->mdc_hash, 0), datalen);*/
	/*log_hexdump("MDC message   :", dfx->defer, 20);*/
    }
    

  leave:
    release_dfx_context (dfx);
    return rc;
}



/* I think we should merge this with cipher_filter */
static int
mdc_decode_filter( void *opaque, int control, IOBUF a,
					      byte *buf, size_t *ret_len)
{
    decode_filter_ctx_t dfx = opaque;
    size_t n, size = *ret_len;
    int rc = 0;
    int c;

    if( control == IOBUFCTRL_UNDERFLOW && dfx->eof_seen ) {
	*ret_len = 0;
	rc = -1;
    }
    else if( control == IOBUFCTRL_UNDERFLOW ) {
	assert(a);
	assert( size > 44 );

	/* get at least 20 bytes and put it somewhere ahead in the buffer */
	for(n=22; n < 44 ; n++ ) {
	    if( (c = iobuf_get(a)) == -1 )
		break;
	    buf[n] = c;
	}
	if( n == 44 ) {
	    /* we have enough stuff - flush the deferred stuff */
	    /* (we have asserted that the buffer is large enough) */
	    if( !dfx->defer_filled ) { /* the first time */
		memcpy(buf, buf+22, 22 );
		n = 22;
	    }
	    else {
		memcpy(buf, dfx->defer, 22 );
	    }
	    /* now fill up */
	    for(; n < size; n++ ) {
		if( (c = iobuf_get(a)) == -1 )
		    break;
		buf[n] = c;
	    }
	    /* Move the last 22 bytes back to the defer buffer. */
	    /* (okay, we are wasting 22 bytes of supplied buffer) */
	    n -= 22;
	    memcpy( dfx->defer, buf+n, 22 );
	    dfx->defer_filled = 1;
	}
	else if( !dfx->defer_filled ) { /* eof seen buf empty defer */
	    /* this is bad because there is an incomplete hash */
	    n -= 22;
	    memcpy(buf, buf+22, n );
	    dfx->eof_seen = 2; /* eof with incomplete hash */
	}
	else { /* eof seen */
	    memcpy (buf, dfx->defer, 22 );
	    n -= 22;
	    memcpy( dfx->defer, buf+n, 22 );
	    dfx->eof_seen = 1; /* normal eof */
	}

	if( n ) {
            if (dfx->cipher_hd)
                cipher_decrypt( dfx->cipher_hd, buf, buf, n);
            if (dfx->mdc_hash)
                md_write( dfx->mdc_hash, buf, n );
	}
	else {
	    assert( dfx->eof_seen );
	    rc = -1; /* eof */
	}
	*ret_len = n;
    }
    else if ( control == IOBUFCTRL_FREE ) {
        release_dfx_context (dfx);
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "mdc_decode_filter";
    }
    return rc;
}

static int
decode_filter( void *opaque, int control, IOBUF a, byte *buf, size_t *ret_len)
{
    decode_filter_ctx_t fc = opaque;
    size_t n, size = *ret_len;
    int rc = 0;

    if( control == IOBUFCTRL_UNDERFLOW ) {
	assert(a);
	n = iobuf_read( a, buf, size );
	if( n == -1 ) n = 0;
	if( n ) {
            if (fc->cipher_hd)
                cipher_decrypt( fc->cipher_hd, buf, buf, n);
        }
	else
	    rc = -1; /* eof */
	*ret_len = n;
    }
    else if ( control == IOBUFCTRL_FREE ) {
        release_dfx_context (fc);
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "decode_filter";
    }
    return rc;
}

