/* encode.c - encode data
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
static int encode_crypt_mdc( const char* fname, STRLIST remusr );
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
    text_filter_context_t tfx;
    int do_compress = opt.compress && !opt.rfc1991;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &tfx, 0, sizeof tfx);
    init_packet(&pkt);

    /* prepare iobufs */
    if( !(inp = iobuf_open(filename)) ) {
	log_error(_("%s: can't open: %s\n"), filename? filename: "[stdin]",
					strerror(errno) );
	return G10ERR_OPEN_FILE;
    }

    if( opt.textmode )
	iobuf_push_filter( inp, text_filter, &tfx );

    cfx.dek = NULL;
    if( mode ) {
	s2k = m_alloc_clear( sizeof *s2k );
	s2k->mode = opt.rfc1991? 0:opt.s2k_mode;
	s2k->hash_algo = opt.def_digest_algo ? opt.def_digest_algo
					     : opt.s2k_digest_algo;
	cfx.dek = passphrase_to_dek( NULL,
		       opt.def_cipher_algo ? opt.def_cipher_algo
					   : opt.s2k_cipher_algo , s2k, 2 );
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
  #ifdef ENABLE_COMMENT_PACKETS
    else {
	write_comment( out, "#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")");
	if( opt.comment_string )
	    write_comment( out, opt.comment_string );
    }
  #endif
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
	char *s = make_basename( opt.set_filename ? opt.set_filename : filename );
	pt = m_alloc( sizeof *pt + strlen(s) - 1 );
	pt->namelen = strlen(s);
	memcpy(pt->name, s, pt->namelen );
	m_free(s);
    }
    else { /* no filename */
	pt = m_alloc( sizeof *pt - 1 );
	pt->namelen = 0;
    }
    /* pgp5 has problems to decrypt symmetrically encrypted data from
     * GnuPG if the filelength is in the inner packet.	It works
     * when only partial length headers are use.  Until we have
     * tracked this problem down. We use this temporary fix
     * (fixme: remove the && !mode )
     */
    if( filename && !opt.textmode && !mode ) {
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info(_("%s: WARNING: empty file\n"), filename );
    }
    else
	filesize = 0; /* stdin */
    pt->timestamp = make_timestamp();
    pt->mode = opt.textmode? 't' : 'b';
    pt->len = filesize;
    pt->buf = inp;
    pkt.pkttype = PKT_PLAINTEXT;
    pkt.pkt.plaintext = pt;
    cfx.datalen = filesize && !do_compress ? calc_packet_length( &pkt ) : 0;

    /* register the cipher filter */
    if( mode )
	iobuf_push_filter( out, cipher_filter, &cfx );
    /* register the compress filter */
    if( do_compress )
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
    text_filter_context_t tfx;
    PK_LIST pk_list;
    int do_compress = opt.compress && !opt.rfc1991;

    if( opt.force_mdc )
	return encode_crypt_mdc( filename, remusr );


    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &tfx, 0, sizeof tfx);
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
	log_info(_("reading from `%s'\n"), filename? filename: "[stdin]");

    if( opt.textmode )
	iobuf_push_filter( inp, text_filter, &tfx );

    if( (rc = open_outfile( filename, opt.armor? 1:0, &out )) )
	goto leave;


    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );
  #ifdef ENABLE_COMMENT_PACKETS
    else {
	write_comment( out, "#created by GNUPG v" VERSION " ("
					    PRINTABLE_OS_NAME ")");
	if( opt.comment_string )
	    write_comment( out, opt.comment_string );
    }
  #endif
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
	char *s = make_basename( opt.set_filename ? opt.set_filename : filename );
	pt = m_alloc( sizeof *pt + strlen(s) - 1 );
	pt->namelen = strlen(s);
	memcpy(pt->name, s, pt->namelen );
	m_free(s);
    }
    else { /* no filename */
	pt = m_alloc( sizeof *pt - 1 );
	pt->namelen = 0;
    }
    if( filename && !opt.textmode ) {
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info(_("%s: WARNING: empty file\n"), filename );
    }
    else
	filesize = 0; /* stdin */
    pt->timestamp = make_timestamp();
    pt->mode = opt.textmode ? 't' : 'b';
    pt->len = filesize;
    pt->new_ctb = !pt->len && !opt.rfc1991;
    pt->buf = inp;
    pkt.pkttype = PKT_PLAINTEXT;
    pkt.pkt.plaintext = pt;
    cfx.datalen = filesize && !do_compress? calc_packet_length( &pkt ) : 0;

    /* register the cipher filter */
    iobuf_push_filter( out, cipher_filter, &cfx );
    /* register the compress filter */
    if( do_compress ) {
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



static int
encode_crypt_mdc( const char* fname, STRLIST remusr )
{
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    md_filter_context_t mfx;
    text_filter_context_t tfx;
    encrypt_filter_context_t efx;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    PKT_plaintext *pt = NULL;
    u32 filesize;
    int rc = 0;
    PK_LIST pk_list = NULL;
    int compr_algo = -1; /* unknown */


    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &tfx, 0, sizeof tfx);
    memset( &efx, 0, sizeof efx);
    init_packet( &pkt );

    if( (rc=build_pk_list( remusr, &pk_list, PUBKEY_USAGE_ENC )) )
	goto leave;
    compr_algo = select_algo_from_prefs( pk_list, PREFTYPE_COMPR );

    /* prepare iobufs */
    if( !(inp = iobuf_open(fname)) ) {
	log_error("can't open %s: %s\n", fname? fname: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( (rc = open_outfile( fname, opt.armor? 1: 0, &out )))
	goto leave;

    /* prepare to calculate the MD over the input */
    mfx.md = md_open( DIGEST_ALGO_SHA1, 0 );
    iobuf_push_filter( inp, md_filter, &mfx );

    if( opt.armor )
	iobuf_push_filter( out, armor_filter, &afx );
    efx.pk_list = pk_list;
    /* fixme: set efx.cfx.datalen if known */
    iobuf_push_filter( out, encrypt_filter, &efx );

    if( opt.compress ) {
	if( !compr_algo )
	    ; /* don't use compression */
	else {
	    if( compr_algo == 1 )
		zfx.algo = 1;
	    iobuf_push_filter( out, compress_filter, &zfx );
	}
    }

    /* build a one pass packet */
    {
	PKT_onepass_sig *ops;

	ops = m_alloc_clear( sizeof *ops );
	ops->sig_class = 0x00;
	ops->digest_algo = DIGEST_ALGO_SHA1;
	ops->pubkey_algo = 0;
	ops->keyid[0] = 0;
	ops->keyid[1] = 0;
	ops->last = 1;

	init_packet(&pkt);
	pkt.pkttype = PKT_ONEPASS_SIG;
	pkt.pkt.onepass_sig = ops;
	rc = build_packet( out, &pkt );
	free_packet( &pkt );
	if( rc ) {
	    log_error("build onepass_sig packet failed: %s\n",
							g10_errstr(rc));
	    goto leave;
	}
    }

    /* setup the inner packet */
    if( fname || opt.set_filename ) {
	char *s = make_basename( opt.set_filename ? opt.set_filename : fname );
	pt = m_alloc( sizeof *pt + strlen(s) - 1 );
	pt->namelen = strlen(s);
	memcpy(pt->name, s, pt->namelen );
	m_free(s);
    }
    else { /* no filename */
	pt = m_alloc( sizeof *pt - 1 );
	pt->namelen = 0;
    }
    if( fname ) {
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info(_("WARNING: `%s' is an empty file\n"), fname );

	/* because the text_filter modifies the length of the
	 * data, it is not possible to know the used length
	 * without a double read of the file - to avoid that
	 * we simple use partial length packets.
	 */
	if( opt.textmode )
	    filesize = 0;
    }
    else
	filesize = 0; /* stdin */
    pt->timestamp = make_timestamp();
    pt->mode = opt.textmode ? 't':'b';
    pt->len = filesize;
    pt->new_ctb = !pt->len;
    pt->buf = inp;
    pkt.pkttype = PKT_PLAINTEXT;
    pkt.pkt.plaintext = pt;
    /*cfx.datalen = filesize? calc_packet_length( &pkt ) : 0;*/
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet(PLAINTEXT) failed: %s\n", g10_errstr(rc) );
    pt->buf = NULL;

    /* build the MDC faked signature packet */
    {
	PKT_signature *sig;
	MD_HANDLE md;
	byte buf[6];
	size_t n;

	sig = m_alloc_clear( sizeof *sig );
	sig->version = 4;
	sig->digest_algo = DIGEST_ALGO_SHA1;
	md = md_copy( mfx.md );

	md_putc( md, sig->version );
	md_putc( md, sig->sig_class );
	md_putc( md, sig->pubkey_algo );
	md_putc( md, sig->digest_algo );
	n = 6;
	/* add some magic */
	buf[0] = sig->version;
	buf[1] = 0xff; buf[2] = 0; buf[3] = 0; buf[4] = 0; buf[5] = 6;
	md_write( md, buf, 6 );
	md_final( md );

	/* pack the hash into data[0] */
	memcpy( sig->digest_start, md_read( md, DIGEST_ALGO_SHA1), 2 );
	sig->data[0] = mpi_alloc( (20+BYTES_PER_MPI_LIMB-1)
				  /BYTES_PER_MPI_LIMB );
	mpi_set_buffer( sig->data[0], md_read(md, DIGEST_ALGO_SHA1),
				 md_digest_length(DIGEST_ALGO_SHA1), 0 );

	md_close( md );

	if( !rc ) { /* and write it */
	    init_packet(&pkt);
	    pkt.pkttype = PKT_SIGNATURE;
	    pkt.pkt.signature = sig;
	    rc = build_packet( out, &pkt );
	    free_packet( &pkt );
	    if( rc )
		log_error("build MDC packet failed: %s\n", g10_errstr(rc) );
	}
	if( rc )
	    goto leave;
    }


  leave:
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    iobuf_close(inp);
    md_close( mfx.md );
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

	print_pubkey_algo_note( pk->pubkey_algo );
	enc = m_alloc_clear( sizeof *enc );
	enc->pubkey_algo = pk->pubkey_algo;
	keyid_from_pk( pk, enc->keyid );
	enc->throw_keyid = opt.throw_keyid;
	frame = encode_session_key( dek, pubkey_nbits( pk->pubkey_algo,
							  pk->pkey ) );
	rc = pubkey_encrypt( pk->pubkey_algo, enc->data, frame, pk->pkey );
	mpi_free( frame );
	if( rc )
	    log_error("pubkey_encrypt failed: %s\n", g10_errstr(rc) );
	else {
	    if( opt.verbose ) {
		char *ustr = get_user_id_string( enc->keyid );
		log_info(_("%s/%s encrypted for: %s\n"),
		    pubkey_algo_to_string(enc->pubkey_algo),
		    cipher_algo_to_string(dek->algo), ustr );
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

