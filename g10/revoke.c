/* revoke.c
 *	Copyright (c) 1998 by Werner Koch (dd9jn)
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "ttyio.h"


/****************
 * Generate a revocation certificate for UNAME
 */
int
gen_revoke( const char *uname )
{
    int rc = 0;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    PACKET pkt;
    PKT_secret_cert *skc; /* used as pointer into a kbnode */
    PKT_public_cert *pkc = NULL;
    PKT_signature *sig = NULL;
    u32 skc_keyid[2];
    IOBUF out = NULL;
    KBNODE keyblock = NULL;
    KBNODE node;
    KBPOS kbpos;
    char *answer;
    int yes;

    if( opt.batch ) {
	log_error("sorry, can't do this in batch mode\n");
	return G10ERR_GENERAL;
    }


    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    init_packet( &pkt );


    /* search the userid */
    rc = find_secret_keyblock_byname( &kbpos, uname );
    if( rc ) {
	log_error("secret key for user '%s' not found\n", uname );
	goto leave;
    }

    /* read the keyblock */
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("error reading the certificate: %s\n", g10_errstr(rc) );
	goto leave;
    }

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, PKT_SECRET_CERT );
    if( !node ) { /* maybe better to use log_bug ? */
	log_error("Oops; secret key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    /* FIXME: should make a function out of this stuff,
     * it's used all over the source */
    skc = node->pkt->pkt.secret_cert;
    keyid_from_skc( skc, skc_keyid );
    tty_printf("\nsec  %4u%c/%08lX %s   ",
	      nbits_from_skc( skc ),
	      pubkey_letter( skc->pubkey_algo ),
	      skc_keyid[1], datestr_from_skc(skc) );
    {
	size_t n;
	char *p = get_user_id( skc_keyid, &n );
	tty_print_string( p, n );
	m_free(p);
	tty_printf("\n");
    }
    /* the the pkc */
    pkc = m_alloc_clear( sizeof *pkc );
    rc = get_pubkey( pkc, skc_keyid );
    if( rc ) {
	log_error("no corresponding public key: %s\n", g10_errstr(rc) );
	goto leave;
    }
    if( cmp_public_secret_cert( pkc, skc ) ) {
	log_error("public key does not match secret key!\n" );
	rc = G10ERR_GENERAL;
	goto leave;
    }

    tty_printf("\n");
    answer = tty_get("Create a revocation certificate for this key? ");
    tty_kill_prompt();
    yes = answer_is_yes(answer);
    m_free(answer);
    if( !yes ) {
	rc = 0;
	goto leave;
    }

    switch( is_secret_key_protected( skc ) ) {
      case -1:
	log_error("unknown protection algorithm\n");
	rc = G10ERR_PUBKEY_ALGO;
	break;
      case 0:
	tty_printf("Warning: This key is not protected!\n");
	break;
      default:
	rc = check_secret_key( skc );
	break;
    }
    if( rc )
	goto leave;


    if( !opt.armor )
	tty_printf("ASCII armored output forced.\n");

    if( !(out = open_outfile( NULL, 0 )) ) {
	rc = G10ERR_CREATE_FILE;
	goto leave;
    }

    afx.what = 1;
    afx.hdrlines = "Comment: A revocation certificate should follow\n";
    iobuf_push_filter( out, armor_filter, &afx );
    if( opt.compress )
	iobuf_push_filter( out, compress_filter, &zfx );


    /* create it */
    rc = make_keysig_packet( &sig, pkc, NULL, skc, 0x20, DIGEST_ALGO_RMD160);
    if( rc ) {
	log_error("make_keysig_packet failed: %s\n", g10_errstr(rc));
	goto leave;
    }
    init_packet( &pkt );
    pkt.pkttype = PKT_SIGNATURE;
    pkt.pkt.signature = sig;

    rc = build_packet( out, &pkt );
    if( rc ) {
	log_error("build_packet failed: %s\n", g10_errstr(rc) );
	goto leave;
    }

    /* and issue a usage notice */
    tty_printf("Revocation certificate created.\n\n"
"Please move it to a media, which you can hide away; if Mallory gets\n"
"access to this certificate he can use it to make your key unusable.\n"
"It is clever to print this certificate and store it away, just in the case\n"
"your media gets unreadable.  But have some caution:  The printer system of\n"
"your machine might store the data and make it availabe to others!\n");



  leave:
    if( pkc )
	free_public_cert( pkc );
    if( sig )
	free_seckey_enc( sig );
    release_kbnode( keyblock );
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    return rc;
}


