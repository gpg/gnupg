/* encode.c - encode data
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include "status.h"

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
    PKT_plaintext *pt = NULL;
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
	cfx.dek = passphrase_to_dek( NULL, 0,
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
	iobuf_cancel(inp);
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

    if (!opt.no_literal) {
	/* setup the inner packet */
	if( filename || opt.set_filename ) {
	    char *s = make_basename( opt.set_filename ? opt.set_filename
						      : filename );
	    pt = m_alloc( sizeof *pt + strlen(s) - 1 );
	    pt->namelen = strlen(s);
	    memcpy(pt->name, s, pt->namelen );
	    m_free(s);
	}
	else { /* no filename */
	    pt = m_alloc( sizeof *pt - 1 );
	    pt->namelen = 0;
	}
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
        /* we can't yet encode the length of very large files,
         * so we switch to partial lengthn encoding in this case */
        if ( filesize >= IOBUF_FILELENGTH_LIMIT )
            filesize = 0;

    }
    else
	filesize = opt.set_filesize ? opt.set_filesize : 0; /* stdin */

    if (!opt.no_literal) {
	pt->timestamp = make_timestamp();
	pt->mode = opt.textmode? 't' : 'b';
	pt->len = filesize;
	pt->new_ctb = !pt->len && !opt.rfc1991;
	pt->buf = inp;
	pkt.pkttype = PKT_PLAINTEXT;
	pkt.pkt.plaintext = pt;
	cfx.datalen = filesize && !do_compress ? calc_packet_length( &pkt ) : 0;
    }
    else
	cfx.datalen = filesize && !do_compress ? filesize : 0;

    /* register the cipher filter */
    if( mode )
	iobuf_push_filter( out, cipher_filter, &cfx );
    /* register the compress filter */
    if( do_compress )
	iobuf_push_filter( out, compress_filter, &zfx );

    /* do the work */
    if (!opt.no_literal) {
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build_packet failed: %s\n", g10_errstr(rc) );
    }
    else {
	/* user requested not to create a literal packet,
	 * so we copy the plain data */
	byte copy_buffer[4096];
	int  bytes_copied;
	while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
	    if (iobuf_write(out, copy_buffer, bytes_copied) == -1) {
		rc = G10ERR_WRITE_FILE;
		log_error("copying input to output failed: %s\n", g10_errstr(rc) );
		break;
	    }
	memset(copy_buffer, 0, 4096); /* burn buffer */
    }

    /* finish the stuff */
    iobuf_close(inp);
    if (rc)
	iobuf_cancel(out);
    else {
	iobuf_close(out); /* fixme: check returncode */
        if (mode)
            write_status( STATUS_END_ENCRYPTION );
    }
    if (pt)
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

    if (!opt.no_literal) {
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
    }

    if( filename && !opt.textmode ) {
	if( !(filesize = iobuf_get_filelength(inp)) )
	    log_info(_("%s: WARNING: empty file\n"), filename );
        /* we can't yet encode the length of very large files,
         * so we switch to partial length encoding in this case */
        if ( filesize >= IOBUF_FILELENGTH_LIMIT )
            filesize = 0;
    }
    else
	filesize = opt.set_filesize ? opt.set_filesize : 0; /* stdin */

    if (!opt.no_literal) {
	pt->timestamp = make_timestamp();
	pt->mode = opt.textmode ? 't' : 'b';
	pt->len = filesize;
	pt->new_ctb = !pt->len && !opt.rfc1991;
	pt->buf = inp;
	pkt.pkttype = PKT_PLAINTEXT;
	pkt.pkt.plaintext = pt;
	cfx.datalen = filesize && !do_compress? calc_packet_length( &pkt ) : 0;
    }
    else
	cfx.datalen = filesize && !do_compress ? filesize : 0;

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
    if (!opt.no_literal) {
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build_packet failed: %s\n", g10_errstr(rc) );
    }
    else {
	/* user requested not to create a literal packet, so we copy the plain data */
	byte copy_buffer[4096];
	int  bytes_copied;
	while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
	    if (iobuf_write(out, copy_buffer, bytes_copied) == -1) {
		rc = G10ERR_WRITE_FILE;
		log_error("copying input to output failed: %s\n", g10_errstr(rc) );
		break;
	    }
	memset(copy_buffer, 0, 4096); /* burn buffer */
    }

    /* finish the stuff */
  leave:
    iobuf_close(inp);
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out); /* fixme: check returncode */
        write_status( STATUS_END_ENCRYPTION );
    }
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

	print_pubkey_algo_note( pk->pubkey_algo );
	enc = m_alloc_clear( sizeof *enc );
	enc->pubkey_algo = pk->pubkey_algo;
	keyid_from_pk( pk, enc->keyid );
	enc->throw_keyid = opt.throw_keyid;

	/* Okay, what's going on: We have the session key somewhere in
	 * the structure DEK and want to encode this session key in
	 * an integer value of n bits.	pubkey_nbits gives us the
	 * number of bits we have to use.  We then encode the session
	 * key in some way and we get it back in the big intger value
	 * FRAME.  Then we use FRAME, the public key PK->PKEY and the
	 * algorithm number PK->PUBKEY_ALGO and pass it to pubkey_encrypt
	 * which returns the encrypted value in the array ENC->DATA.
	 * This array has a size which depends on the used algorithm
	 * (e.g. 2 for ElGamal).  We don't need frame anymore because we
	 * have everything now in enc->data which is the passed to
	 * build_packet()
	 */
	frame = encode_session_key( dek, pubkey_nbits( pk->pubkey_algo,
							  pk->pkey ) );
	rc = pubkey_encrypt( pk->pubkey_algo, enc->data, frame, pk->pkey );
	mpi_free( frame );
	if( rc )
	    log_error("pubkey_encrypt failed: %s\n", g10_errstr(rc) );
	else {
	    if( opt.verbose ) {
		char *ustr = get_user_id_string_native( enc->keyid );
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

