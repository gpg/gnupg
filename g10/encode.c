/* encode.c - encode data
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
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "filter.h"


static int encode_simple( const char *filename, int mode );
static int write_pubkey_enc_from_list( PKC_LIST pkc_list, DEK *dek, IOBUF out );



/****************
 * Encode FILENAME only with the symmetric cipher. Take input from
 * stdin if FILENAME is NULL.
 */
int
encode_symmetric( const char *filename )
{
    return encode_simple( filename, 1 );
}

/****************
 * Encode FILENAME as literal data packet only. Take input from
 * stdin if FILENAME is NULL.
 */
int
encode_store( const char *filename )
{
    return encode_simple( filename, 0 );
}


static int
encode_simple( const char *filename, int mode )
{
    IOBUF inp, out;
    PACKET pkt;
    PKT_plaintext *pt;
    int rc = 0;
    u32 filesize;
    cipher_filter_context_t cfx;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);

    /* prepare iobufs */
    if( !(inp = iobuf_open(filename)) ) {
	log_error("can't open %s: %s\n", filename? filename: "[stdin]",
					strerror(errno) );
	return G10ERR_OPEN_FILE;
    }

    cfx.dek = NULL;
    if( mode ) {
	cfx.dek = m_alloc_secure( sizeof *cfx.dek );
	cfx.dek->algo = opt.def_cipher_algo;
	if( (rc = make_dek_from_passphrase( cfx.dek , 2, NULL )) ) {
	    m_free(cfx.dek);
	    iobuf_close(inp);
	    log_error("error creating passphrase: %s\n", g10_errstr(rc) );
	    return rc;
	}
    }

    if( !(out = open_outfile( filename, opt.armor? 1:0 )) ) {
	iobuf_close(inp);
	m_free(cfx.dek);
	return G10ERR_CREATE_FILE;  /* or user said: do not overwrite */
    }

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );

    write_comment( out, "#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")");

    if( opt.compress )
	iobuf_push_filter( out, compress_filter, &zfx );


    /* setup the inner packet */
    if( filename ) {
	pt = m_alloc( sizeof *pt + strlen(filename) - 1 );
	pt->namelen = strlen(filename);
	memcpy(pt->name, filename, pt->namelen );
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info("warning: '%s' is an empty file\n", filename );
    }
    else { /* no filename */
	pt = m_alloc( sizeof *pt - 1 );
	pt->namelen = 0;
	filesize = 0; /* stdin */
    }
    pt->timestamp = make_timestamp();
    pt->mode = 'b';
    pt->len = filesize;
    pt->buf = inp;
    pkt.pkttype = PKT_PLAINTEXT;
    pkt.pkt.plaintext = pt;
    cfx.datalen = filesize? calc_packet_length( &pkt ) : 0;

    /* register the cipher filter */
    if( mode )
	iobuf_push_filter( out, cipher_filter, &cfx );

    /* do the work */
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet failed: %s\n", g10_errstr(rc) );

    /* finish the stuff */
    iobuf_close(inp);
    iobuf_close(out); /* fixme: check returncode */
    pt->buf = NULL;
    free_packet(&pkt);
    m_free(cfx.dek);
    return rc;
}

/****************
 * Encrypt the file with the given userids (or ask if none
 * is supplied).
 */
int
encode_crypt( const char *filename, STRLIST remusr )
{
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    PKT_plaintext *pt = NULL;
    int rc = 0;
    u32 filesize;
    cipher_filter_context_t cfx;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    PKC_LIST pkc_list;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);

    if( (rc=build_pkc_list( remusr, &pkc_list)) )
	return rc;

    /* prepare iobufs */
    if( !(inp = iobuf_open(filename)) ) {
	log_error("can't open %s: %s\n", filename? filename: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }
    else if( opt.verbose )
	log_info("reading from '%s'\n", filename? filename: "[stdin]");

    if( !(out = open_outfile( filename, opt.armor? 1:0 )) ) {
	rc = G10ERR_CREATE_FILE;  /* or user said: do not overwrite */
	goto leave;
    }

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );

    write_comment( out, "#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")");

    if( opt.compress )
	iobuf_push_filter( out, compress_filter, &zfx );

    /* create a session key */
    cfx.dek = m_alloc_secure( sizeof *cfx.dek );
    cfx.dek->algo = opt.def_cipher_algo;
    make_session_key( cfx.dek );
    if( DBG_CIPHER )
	log_hexdump("DEK is: ", cfx.dek->key, cfx.dek->keylen );

    rc = write_pubkey_enc_from_list( pkc_list, cfx.dek, out );
    if( rc  )
	goto leave;

    /* setup the inner packet */
    if( filename ) {
	pt = m_alloc( sizeof *pt + strlen(filename) - 1 );
	pt->namelen = strlen(filename);
	memcpy(pt->name, filename, pt->namelen );
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info("warning: '%s' is an empty file\n", filename );
    }
    else { /* no filename */
	pt = m_alloc( sizeof *pt - 1 );
	pt->namelen = 0;
	filesize = 0; /* stdin */
    }
    pt->timestamp = make_timestamp();
    pt->mode = 'b';
    pt->len = filesize;
    pt->buf = inp;
    init_packet(&pkt);
    pkt.pkttype = PKT_PLAINTEXT;
    pkt.pkt.plaintext = pt;
    cfx.datalen = filesize? calc_packet_length( &pkt ) : 0;

    /* register the cipher filter */
    iobuf_push_filter( out, cipher_filter, &cfx );

    /* do the work */
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet failed: %s\n", g10_errstr(rc) );

    /* finish the stuff */
  leave:
    iobuf_close(inp);
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out); /* fixme: check returncode */
    if( pt )
	pt->buf = NULL;
    free_packet(&pkt);
    m_free(cfx.dek);
    release_pkc_list( pkc_list );
    return rc;
}


/****************
 * Filter to do a complete public key encryption.
 */
int
encrypt_filter( void *opaque, int control,
	       IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    encrypt_filter_context_t *efx = opaque;
    int rc=0;

    if( control == IOBUFCTRL_UNDERFLOW ) { /* decrypt */
	BUG(); /* not used */
    }
    else if( control == IOBUFCTRL_FLUSH ) { /* encrypt */
	if( !efx->header_okay ) {
	    efx->cfx.dek = m_alloc_secure( sizeof *efx->cfx.dek );
	    efx->cfx.dek->algo = opt.def_cipher_algo;
	    make_session_key( efx->cfx.dek );
	    if( DBG_CIPHER )
		log_hexdump("DEK is: ",
			     efx->cfx.dek->key, efx->cfx.dek->keylen );

	    rc = write_pubkey_enc_from_list( efx->pkc_list, efx->cfx.dek, a );
	    if( rc )
		return rc;

	    iobuf_push_filter( a, cipher_filter, &efx->cfx );

	    efx->header_okay = 1;
	}
	rc = iobuf_write( a, buf, size );

    }
    else if( control == IOBUFCTRL_FREE ) {
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "encrypt_filter";
    }
    return rc;
}


/****************
 * Write pubkey-enc packets from the list of PKCs to OUT.
 */
static int
write_pubkey_enc_from_list( PKC_LIST pkc_list, DEK *dek, IOBUF out )
{
    PACKET pkt;
    PKT_public_cert *pkc;
    PKT_pubkey_enc  *enc;
    int rc;

    for( ; pkc_list; pkc_list = pkc_list->next ) {

	pkc = pkc_list->pkc;
	enc = m_alloc_clear( sizeof *enc );
	enc->pubkey_algo = pkc->pubkey_algo;
	if( enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	    g10_elg_encrypt( pkc, enc, dek );
	else if( enc->pubkey_algo == PUBKEY_ALGO_RSA )
	    g10_rsa_encrypt( pkc, enc, dek );
	else
	    BUG();
	/* and write it */
	init_packet(&pkt);
	pkt.pkttype = PKT_PUBKEY_ENC;
	pkt.pkt.pubkey_enc = enc;
	rc = build_packet( out, &pkt );
	free_pubkey_enc(enc);
	if( rc ) {
	    log_error("build pubkey_enc packet failed: %s\n", g10_errstr(rc) );
	    return rc;
	}
    }
    return 0;
}

