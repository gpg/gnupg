/* encode.c - encode data
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "filter.h"




static int encode_simple( const char *filename, int mode );


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
	cfx.dek->algo = DEFAULT_CIPHER_ALGO;
	if( (rc = make_dek_from_passphrase( cfx.dek , 2 )) ) {
	    m_free(cfx.dek);
	    iobuf_close(inp);
	    log_error("error creating passphrase: %s\n", g10_errstr(rc) );
	    return rc;
	}
    }

    if( !(out = open_outfile( filename )) ) {
	iobuf_close(inp);
	m_free(cfx.dek);
	return G10ERR_CREATE_FILE;  /* or user said: do not overwrite */
    }

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );

    write_comment( out, "#Created by G10 pre-release " VERSION );

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
    IOBUF inp, out;
    PACKET pkt;
    PKT_plaintext *pt;
    PKT_public_cert *pkc = NULL;
    PKT_pubkey_enc  *enc = NULL;
    int last_rc, rc = 0;
    u32 filesize;
    cipher_filter_context_t cfx;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    int any_names = 0;
    STRLIST local_remusr = NULL;
    char *ustr;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);

    if( !remusr ) {
	remusr = NULL; /* fixme: ask */
	local_remusr = remusr;
    }

    /* prepare iobufs */
    if( !(inp = iobuf_open(filename)) ) {
	log_error("can't open %s: %s\n", filename? filename: "[stdin]",
					strerror(errno) );
	free_strlist(local_remusr);
	return G10ERR_OPEN_FILE;
    }
    else if( opt.verbose )
	log_error("reding from '%s'\n", filename? filename: "[stdin]");

    if( !(out = open_outfile( filename )) ) {
	iobuf_close(inp);
	free_strlist(local_remusr);
	return G10ERR_CREATE_FILE;  /* or user said: do not overwrite */
    }

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );

    write_comment( out, "#Created by G10 pre-release " VERSION );

    if( opt.compress )
	iobuf_push_filter( out, compress_filter, &zfx );

    /* create a session key */
    cfx.dek = m_alloc_secure( sizeof *cfx.dek );
    cfx.dek->algo = DEFAULT_CIPHER_ALGO;
    make_session_key( cfx.dek );
    if( DBG_CIPHER )
	log_hexdump("DEK is: ", cfx.dek->key, cfx.dek->keylen );

    /* loop over all user ids and build public key packets for each */
    for(last_rc=0 ; remusr; remusr = remusr->next ) {
	if( pkc )
	    free_public_cert( pkc );
	pkc = m_alloc_clear( sizeof *pkc );
	pkc->pubkey_algo = DEFAULT_PUBKEY_ALGO;

	if( (rc = get_pubkey_by_name( pkc, remusr->d )) ) {
	    last_rc = rc;
	    log_error("skipped '%s': %s\n", remusr->d, g10_errstr(rc) );
	    continue;
	}
	/* build the pubkey packet */
	enc = m_alloc_clear( sizeof *enc );
	enc->pubkey_algo = pkc->pubkey_algo;
	if( enc->pubkey_algo == PUBKEY_ALGO_ELGAMAL ) {
	    ELG_public_key pkey;
	    MPI frame;

	    enc->d.elg.a = mpi_alloc( mpi_get_nlimbs(pkc->d.elg.p) );
	    enc->d.elg.b = mpi_alloc( mpi_get_nlimbs(pkc->d.elg.p) );
	    keyid_from_pkc( pkc, enc->keyid );
	    frame = encode_session_key( cfx.dek, mpi_get_nbits(pkc->d.elg.p) );
	    pkey.p = pkc->d.elg.p;
	    pkey.g = pkc->d.elg.g;
	    pkey.y = pkc->d.elg.y;
	    if( DBG_CIPHER )
		log_mpidump("Plain DEK frame: ", frame);
	    elg_encrypt( enc->d.elg.a, enc->d.elg.b, frame, &pkey);
	    mpi_free( frame );
	    if( DBG_CIPHER ) {
		log_mpidump("Encry DEK a: ", enc->d.elg.a );
		log_mpidump("      DEK b: ", enc->d.elg.b );
	    }
	    if( opt.verbose ) {
		ustr = get_user_id_string( enc->keyid );
		log_info("ElGamal encrypteded for: %s\n", ustr );
		m_free(ustr);
	    }
	}
      #ifdef HAVE_RSA_CIPHER
	else if( enc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	    RSA_public_key pkey;

	    keyid_from_pkc( pkc, enc->keyid );
	    enc->d.rsa.rsa_integer = encode_session_key( cfx.dek,
					mpi_get_nbits(pkc->d.rsa.rsa_n) );
	    pkey.n = pkc->d.rsa.rsa_n;
	    pkey.e = pkc->d.rsa.rsa_e;
	    if( DBG_CIPHER )
		log_mpidump("Plain DEK frame: ", enc->d.rsa.rsa_integer);
	    rsa_public( enc->d.rsa.rsa_integer, enc->d.rsa.rsa_integer, &pkey);
	    if( DBG_CIPHER )
		log_mpidump("Encry DEK frame: ", enc->d.rsa.rsa_integer);
	    if( opt.verbose ) {
		ustr = get_user_id_string( enc->keyid );
		log_info("RSA encrypteded for: %s\n", ustr );
		m_free(ustr);
	    }
	}
      #endif/*HAVE_RSA_CIPHER*/
	else {
	    last_rc = rc = G10ERR_PUBKEY_ALGO;
	    log_error("skipped '%s': %s\n", remusr->d, g10_errstr(rc) );
	    free_pubkey_enc(enc);
	    continue;
	}
	/* and write it */
	init_packet(&pkt);
	pkt.pkttype = PKT_PUBKEY_ENC;
	pkt.pkt.pubkey_enc = enc;
	if( (rc = build_packet( out, &pkt )) ) {
	    last_rc = rc;
	    log_error("build pubkey_enc packet failed: %s\n", g10_errstr(rc) );
	    free_pubkey_enc(enc);
	    continue;
	}
	/* okay: a pubkey packet has been written */
	free_pubkey_enc(enc);
	any_names = 1;
    }
    if( pkc ) {
	free_public_cert( pkc );
	pkc = NULL;
    }
    if( !any_names ) {
	log_error("no valid keys - aborting further processing\n");
	iobuf_close(inp);
	iobuf_cancel(out);
	m_free(cfx.dek); /* free and burn the session key */
	free_strlist(local_remusr);
	return last_rc;
    }

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
    iobuf_close(inp);
    iobuf_close(out); /* fixme: check returncode */
    pt->buf = NULL;
    free_packet(&pkt);
    m_free(cfx.dek);
    free_strlist(local_remusr);
    return rc;
}



