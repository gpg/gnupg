/* encode.c - encode/sign data
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




static int encode_simple( const char *filename, int mode );
static IOBUF open_outfile( const char *iname );
static int armor_filter( void *opaque, int control,
			 IOBUF chain, byte *buf, size_t *ret_len);
static int compress_filter( void *opaque, int control,
			    IOBUF chain, byte *buf, size_t *ret_len);
static int cipher_filter( void *opaque, int control,
			  IOBUF chain, byte *buf, size_t *ret_len);



typedef struct {
    DEK *dek;
    PKT_encr_data ed;
    BLOWFISH_context *bf_ctx;
    int header;
} cipher_filter_context_t;


typedef struct {
    int status;
    int what;
    byte buf[3];
    int  idx, idx2;
    u32 crc;
} armor_filter_context_t;



#define CRCINIT 0xB704CE
#define CRCPOLY 0X864CFB
#define CRCUPDATE(a,c) do {						    \
			a = ((a) << 8) ^ crc_table[((a)&0xff >> 16) ^ (c)]; \
			a &= 0x00ffffff;				    \
		    } while(0)
static u32 crc_table[256];
static int crc_table_initialized;



static void
init_crc_table(void)
{
    int i, j;
    u32 t;

    crc_table[0] = 0;
    for(i=j=0; j < 128; j++ ) {
	t = crc_table[j];
	if( t & 0x00800000 ) {
	    t <<= 1;
	    crc_table[i++] = t ^ CRCPOLY;
	    crc_table[i++] = t;
	}
	else {
	    t <<= 1;
	    crc_table[i++] = t;
	    crc_table[i++] = t ^ CRCPOLY;
	}
    }

    crc_table_initialized=1;
}



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

static void
write_comment( IOBUF out, const char *s )
{
    PACKET pkt;
    size_t n = strlen(s);
    int rc;

    pkt.pkttype = PKT_COMMENT;
    pkt.pkt.comment = m_alloc( sizeof *pkt.pkt.comment + n - 1 );
    pkt.pkt.comment->len = n;
    strcpy(pkt.pkt.comment->data, s);
    if( (rc = build_packet( out, &pkt )) )
	log_error("build_packet(comment) failed: %s\n", g10_errstr(rc) );
    free_packet( &pkt );
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

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);

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
	iobuf_push_filter( out, compress_filter, NULL );


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
    cfx.ed.len = filesize? calc_packet_length( &pkt ) : 0;
    cfx.ed.buf = NULL; /* not used! */

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
    PKT_pubkey_cert *pkc = NULL;
    PKT_pubkey_enc  *enc = NULL;
    int last_rc, rc = 0;
    u32 filesize;
    cipher_filter_context_t cfx;
    armor_filter_context_t afx;
    int any_names = 0;
    STRLIST local_remusr = NULL;
    char *ustr;

    memset( &cfx, 0, sizeof cfx);
    memset( &afx, 0, sizeof afx);

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
	iobuf_push_filter( out, compress_filter, NULL );

    /* create a session key */
    cfx.dek = m_alloc_secure( sizeof *cfx.dek );
    cfx.dek->algo = DEFAULT_CIPHER_ALGO;
    make_session_key( cfx.dek );
    if( DBG_CIPHER )
	log_hexdump("DEK is: ", cfx.dek->key, cfx.dek->keylen );

    /* loop over all user ids and build public key packets for each */
    for(last_rc=0 ; remusr; remusr = remusr->next ) {
	if( pkc )
	    free_pubkey_cert( pkc );
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
	if( enc->pubkey_algo == PUBKEY_ALGO_RSA ) {
	    RSA_public_key pkey;

	    mpi_get_keyid( pkc->d.rsa.rsa_n, enc->keyid );
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
		log_info("RSA enciphered for: %s\n", ustr );
		m_free(ustr);
	    }
	}
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
	free_pubkey_cert( pkc );
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
    cfx.ed.len = filesize? calc_packet_length( &pkt ) : 0;
    cfx.ed.buf = NULL; /* not used! */

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


/****************
 * Make an output filename for the inputfile INAME.
 * Returns an
 */
static IOBUF
open_outfile( const char *iname )
{
    IOBUF a = NULL;
    int rc;

    if( (!iname && !opt.outfile) || opt.outfile_is_stdout ) {
	if( !(a = iobuf_create(NULL)) )
	    log_error("can't open [stdout]: %s\n", strerror(errno) );
	else if( opt.verbose )
	    log_info("writing to stdout\n");
    }
    else {
	char *buf=NULL;
	const char *name;

	if( opt.outfile )
	    name = opt.outfile;
	else {
	    buf = m_alloc(strlen(iname)+4+1);
	    strcpy(stpcpy(buf,iname), ".g10");
	    name = buf;
	}
	if( !(rc=overwrite_filep( name )) ) {
	    if( !(a = iobuf_create( name )) )
		log_error("can't create %s: %s\n", name, strerror(errno) );
	    else if( opt.verbose )
		log_info("writing to '%s'\n", name );
	}
	else if( rc != -1 )
	    log_error("oops: overwrite_filep(%s): %s\n", name, g10_errstr(rc) );
	m_free(buf);
    }
    return a;
}

static int
armor_filter( void *opaque, int control,
	      IOBUF a, byte *buffer, size_t *ret_len)
{
    static byte bintoasc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			     "abcdefghijklmnopqrstuvwxyz"
			     "0123456789+/";
    size_t size = *ret_len;
    armor_filter_context_t *afx = opaque;
    int rc=0, i, c;
    byte buf[3];
    int  idx, idx2;
    u32 crc;


    if( control == IOBUFCTRL_FLUSH ) {
	if( !afx->status ) { /* write the header line */
	    if( !afx->what )
		iobuf_writestr(a, "-----BEGIN PGP MESSAGE-----\n");
	    else
		iobuf_writestr(a, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
	    iobuf_writestr(a, "Version: G10 pre-release "  VERSION "\n");
	    iobuf_writestr(a, "Comment: This is a alpha test version!\n\n");
	    afx->status++;
	    afx->idx = 0;
	    afx->idx2 = 0;
	    afx->crc = CRCINIT;
	}
	crc = afx->crc;
	idx = afx->idx;
	idx2 = afx->idx2;
	for(i=0; i < idx; i++ )
	    buf[i] = afx->buf[i];

	for(i=0; i < size; i++ )
	    crc = (crc << 8) ^ crc_table[(crc >> 16)&0xff ^ buffer[i]];
	crc &= 0x00ffffff;

	for( ; size; buffer++, size-- ) {
	    buf[idx++] = *buffer;
	    if( idx > 2 ) {
		idx = 0;
		c = bintoasc[(*buf >> 2) & 077];
		iobuf_put(a, c);
		c = bintoasc[(((*buf<<4)&060)|((buf[1] >> 4)&017))&077];
		iobuf_put(a, c);
		c = bintoasc[(((buf[1]<<2)&074)|((buf[2]>>6)&03))&077];
		iobuf_put(a, c);
		c = bintoasc[buf[2]&077];
		iobuf_put(a, c);
		if( ++idx2 > (72/4) ) {
		    iobuf_put(a, '\n');
		    idx2=0;
		}
	    }
	}
	for(i=0; i < idx; i++ )
	    afx->buf[i] = buf[i];
	afx->idx = idx;
	afx->idx2 = idx2;
	afx->crc  = crc;
    }
    else if( control == IOBUFCTRL_INIT ) {
	if( !crc_table_initialized )
	    init_crc_table();
    }
    else if( control == IOBUFCTRL_FREE ) {
	if( afx->status ) { /* pad, write cecksum, and bottom line */
	    crc = afx->crc;
	    idx = afx->idx;
	    idx2 = afx->idx2;
	    for(i=0; i < idx; i++ )
		buf[i] = afx->buf[i];
	    if( idx ) {
		c = bintoasc[(*buf>>2)&077];
		iobuf_put(a, c);
		if( idx == 1 ) {
		    c = bintoasc[((*buf << 4) & 060) & 077];
		    iobuf_put(a, c);
		    iobuf_put(a, '=');
		    iobuf_put(a, '=');
		}
		else { /* 2 */
		    c = bintoasc[(((*buf<<4)&060)|((buf[1]>>4)&017))&077];
		    iobuf_put(a, c);
		    c = bintoasc[((buf[1] << 2) & 074) & 077];
		    iobuf_put(a, c);
		    iobuf_put(a, '=');
		}
		++idx2;
	    }
	    /* may need a linefeed */
	    if( idx2 < (72/4) )
		iobuf_put(a, '\n');
	    /* write the CRC */
	    iobuf_put(a, '=');
	    buf[0] = crc >>16;
	    buf[1] = crc >> 8;
	    buf[2] = crc;
	    c = bintoasc[(*buf >> 2) & 077];
	    iobuf_put(a, c);
	    c = bintoasc[(((*buf<<4)&060)|((buf[1] >> 4)&017))&077];
	    iobuf_put(a, c);
	    c = bintoasc[(((buf[1]<<2)&074)|((buf[2]>>6)&03))&077];
	    iobuf_put(a, c);
	    c = bintoasc[buf[2]&077];
	    iobuf_put(a, c);
	    iobuf_put(a, '\n');
	    /* and the the trailer */
	    if( !afx->what )
		iobuf_writestr(a, "-----END PGP MESSAGE-----\n");
	    else
		iobuf_writestr(a, "-----END PGP PUBLIC KEY BLOCK-----\n");
	}
    }
    else if( control == IOBUFCTRL_DESC )
	*(char**)buf = "armor_filter";
    return 0;
}

static int
compress_filter( void *opaque, int control,
		 IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    int rc=0;

    if( control == IOBUFCTRL_FLUSH ) {
	assert(a);
	if( iobuf_write( a, buf, size ) )
	    rc = G10ERR_WRITE_FILE;
    }
    else if( control == IOBUFCTRL_DESC ) {
	*(char**)buf = "compress_filter";
    }
    return rc;
}


/****************
 * The filter is used to encipher data.
 */
static int
cipher_filter( void *opaque, int control,
	       IOBUF a, byte *buf, size_t *ret_len)
{
    size_t size = *ret_len;
    cipher_filter_context_t *cfx = opaque;
    int rc=0;

    if( control == IOBUFCTRL_FLUSH ) {
	assert(a);
	if( !cfx->header ) {
	    PACKET pkt;
	    byte temp[10];

	    pkt.pkttype = PKT_ENCR_DATA;
	    pkt.pkt.encr_data = &cfx->ed;
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

