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
#include "trustdb.h"
#include "i18n.h"


static int encode_simple( const char *filename, int mode );
static int write_pubkey_enc_from_list( PK_LIST pk_list, DEK *dek, IOBUF out );



/****************
 * Encode FILENAME with only the symmetric cipher.  Take input from
 * stdin if FILENAME is NULL.
 */
int
encode_symmetric( const char *filename )
{
    return encode_simple( filename, 1 );
}

/****************
 * Encode FILENAME as a literal data packet only. Take input from
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
    STRING2KEY *s2k = NULL;
    int rc = 0;
    u32 filesize;
    cipher_filter_context_t cfx;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    init_packet(&pkt);

    /* prepare iobufs */
    if( !(inp = iobuf_open(filename)) ) {
	log_error(_("%s: can't open: %s\n"), filename? filename: "[stdin]",
					strerror(errno) );
	return G10ERR_OPEN_FILE;
    }

    cfx.dek = NULL;
    if( mode ) {
	s2k = m_alloc_clear( sizeof *s2k );
	s2k->mode = opt.rfc1991? 0:1;
	s2k->hash_algo = opt.def_digest_algo ? opt.def_digest_algo
					     : DEFAULT_DIGEST_ALGO;
	cfx.dek = passphrase_to_dek( NULL,
		       opt.def_cipher_algo ? opt.def_cipher_algo
					   : DEFAULT_CIPHER_ALGO , s2k, 2 );
	if( !cfx.dek || !cfx.dek->keylen ) {
	    rc = G10ERR_PASSPHRASE;
	    m_free(cfx.dek);
	    m_free(s2k);
	    iobuf_close(inp);
	    log_error(_("error creating passphrase: %s\n"), g10_errstr(rc) );
	    return rc;
	}
    }

    if( (rc = open_outfile( filename, opt.armor? 1:0, &out )) ) {
	iobuf_close(inp);
	m_free(cfx.dek);
	m_free(s2k);
	return rc;
    }

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );
    else {
	write_comment( out, "#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")");
	if( opt.comment_string )
	    write_comment( out, opt.comment_string );
    }
    if( s2k && !opt.rfc1991 ) {
	PKT_symkey_enc *enc = m_alloc_clear( sizeof *enc );
	enc->version = 4;
	enc->cipher_algo = cfx.dek->algo;
	enc->s2k = *s2k;
	pkt.pkttype = PKT_SYMKEY_ENC;
	pkt.pkt.symkey_enc = enc;
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build symkey packet failed: %s\n", g10_errstr(rc) );
	m_free(enc);
    }

    /* setup the inner packet */
    if( filename || opt.set_filename ) {
	const char *s = opt.set_filename ? opt.set_filename : filename;
	pt = m_alloc( sizeof *pt + strlen(s) - 1 );
	pt->namelen = strlen(s);
	memcpy(pt->name, s, pt->namelen );
    }
    else { /* no filename */
	pt = m_alloc( sizeof *pt - 1 );
	pt->namelen = 0;
    }
    if( filename ) {
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info(_("%s: warning: empty file\n"), filename );
    }
    else
	filesize = 0; /* stdin */
    pt->timestamp = make_timestamp();
    pt->mode = 'b';
    pt->len = filesize;
    pt->buf = inp;
    pkt.pkttype = PKT_PLAINTEXT;
    pkt.pkt.plaintext = pt;
    cfx.datalen = filesize && !opt.compress ? calc_packet_length( &pkt ) : 0;

    /* register the cipher filter */
    if( mode )
	iobuf_push_filter( out, cipher_filter, &cfx );
    /* register the compress filter */
    if( opt.compress )
	iobuf_push_filter( out, compress_filter, &zfx );

    /* do the work */
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet failed: %s\n", g10_errstr(rc) );

    /* finish the stuff */
    iobuf_close(inp);
    iobuf_close(out); /* fixme: check returncode */
    pt->buf = NULL;
    free_packet(&pkt);
    m_free(cfx.dek);
    m_free(s2k);
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
    PK_LIST pk_list;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    init_packet(&pkt);

    if( (rc=build_pk_list( remusr, &pk_list, PUBKEY_USAGE_ENC)) )
	return rc;

    /* prepare iobufs */
    if( !(inp = iobuf_open(filename)) ) {
	log_error(_("can't open %s: %s\n"), filename? filename: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }
    else if( opt.verbose )
	log_info(_("reading from '%s'\n"), filename? filename: "[stdin]");

    if( (rc = open_outfile( filename, opt.armor? 1:0, &out )) )
	goto leave;


    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );
    else {
	write_comment( out, "#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")");
	if( opt.comment_string )
	    write_comment( out, opt.comment_string );
    }

    /* create a session key */
    cfx.dek = m_alloc_secure( sizeof *cfx.dek );
    if( !opt.def_cipher_algo ) { /* try to get it from the prefs */
	cfx.dek->algo = select_algo_from_prefs( pk_list, PREFTYPE_SYM );
	if( cfx.dek->algo == -1 )
	    cfx.dek->algo = DEFAULT_CIPHER_ALGO;
    }
    else
	cfx.dek->algo = opt.def_cipher_algo;
    make_session_key( cfx.dek );
    if( DBG_CIPHER )
	log_hexdump("DEK is: ", cfx.dek->key, cfx.dek->keylen );

    rc = write_pubkey_enc_from_list( pk_list, cfx.dek, out );
    if( rc  )
	goto leave;

    /* setup the inner packet */
    if( filename || opt.set_filename ) {
	const char *s = opt.set_filename ? opt.set_filename : filename;
	pt = m_alloc( sizeof *pt + strlen(s) - 1 );
	pt->namelen = strlen(s);
	memcpy(pt->name, s, pt->namelen );
    }
    else { /* no filename */
	pt = m_alloc( sizeof *pt - 1 );
	pt->namelen = 0;
    }
    if( filename ) {
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info(_("%s: warning: empty file\n"), filename );
    }
    else
	filesize = 0; /* stdin */
    pt->timestamp = make_timestamp();
    pt->mode = 'b';
    pt->len = filesize;
    pt->new_ctb = !pt->len && !opt.rfc1991;
    pt->buf = inp;
    pkt.pkttype = PKT_PLAINTEXT;
    pkt.pkt.plaintext = pt;
    cfx.datalen = filesize && !opt.compress? calc_packet_length( &pkt ) : 0;

    /* register the cipher filter */
    iobuf_push_filter( out, cipher_filter, &cfx );
    /* register the compress filter */
    if( opt.compress ) {
	int compr_algo = select_algo_from_prefs( pk_list, PREFTYPE_COMPR );
	if( !compr_algo )
	    ; /* don't use compression */
	else {
	    if( compr_algo == 1 )
		zfx.algo = 1; /* default is 2 */
	    iobuf_push_filter( out, compress_filter, &zfx );
	}
    }

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
    release_pk_list( pk_list );
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

	    if( !opt.def_cipher_algo  ) { /* try to get it from the prefs */
		efx->cfx.dek->algo =
			  select_algo_from_prefs( efx->pk_list, PREFTYPE_SYM );
		if( efx->cfx.dek->algo == -1 )
		    efx->cfx.dek->algo = DEFAULT_CIPHER_ALGO;
	    }
	    else
		efx->cfx.dek->algo = opt.def_cipher_algo;
	    make_session_key( efx->cfx.dek );
	    if( DBG_CIPHER )
		log_hexdump("DEK is: ",
			     efx->cfx.dek->key, efx->cfx.dek->keylen );

	    rc = write_pubkey_enc_from_list( efx->pk_list, efx->cfx.dek, a );
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
 * Write pubkey-enc packets from the list of PKs to OUT.
 */
static int
write_pubkey_enc_from_list( PK_LIST pk_list, DEK *dek, IOBUF out )
{
    PACKET pkt;
    PKT_public_key *pk;
    PKT_pubkey_enc  *enc;
    int rc;

    for( ; pk_list; pk_list = pk_list->next ) {
	MPI frame;

	pk = pk_list->pk;
	if( is_RSA(pk->pubkey_algo) )
	    do_not_use_RSA();
	enc = m_alloc_clear( sizeof *enc );
	enc->pubkey_algo = pk->pubkey_algo;
	keyid_from_pk( pk, enc->keyid );
	frame = encode_session_key( dek, pubkey_nbits( pk->pubkey_algo,
							  pk->pkey ) );
	rc = pubkey_encrypt( pk->pubkey_algo, enc->data, frame, pk->pkey );
	mpi_free( frame );
	if( rc )
	    log_error("pubkey_encrypt failed: %s\n", g10_errstr(rc) );
	else {
	    if( opt.verbose ) {
		char *ustr = get_user_id_string( enc->keyid );
		log_info(_("%s encrypted for: %s\n"),
		    pubkey_algo_to_string(enc->pubkey_algo), ustr );
		m_free(ustr);
	    }
	    /* and write it */
	    init_packet(&pkt);
	    pkt.pkttype = PKT_PUBKEY_ENC;
	    pkt.pkt.pubkey_enc = enc;
	    rc = build_packet( out, &pkt );
	    if( rc )
	       log_error("build_packet(pubkey_enc) failed: %s\n", g10_errstr(rc));
	}
	free_pubkey_enc(enc);
	if( rc )
	    return rc;
    }
    return 0;
}

