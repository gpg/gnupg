/* sign.c - sign data
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
#include "ttyio.h"





static int
complete_sig( PKT_signature *sig, PKT_secret_cert *skc, MD_HANDLE md )
{
    int rc=0;

    if( (rc=check_secret_key( skc )) )
	;
    else if( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	g10_elg_sign( skc, sig, md, 0 );
    else if( sig->pubkey_algo == PUBKEY_ALGO_RSA )
	g10_rsa_sign( skc, sig, md, 0 );
    else
	BUG();

    /* fixme: should we check wether the signature is okay? */

    return rc;
}





/****************
 * Sign the files whose names are in FILENAME.
 * If DETACHED has the value true,
 * make a detached signature.  If FILENAMES->d is NULL read from stdin
 * and ignore the detached mode.  Sign the file with all secret keys
 * which can be taken from LOCUSR, if this is NULL, use the default one
 * If ENCRYPT is true, use REMUSER (or ask if it is NULL) to encrypt the
 * signed data for these users.
 * If OUTFILE is not NULL; this file is used for output and the function
 * does not ask for overwrite permission; output is then always
 * uncompressed, non-armored and in binary mode.
 */
int
sign_file( STRLIST filenames, int detached, STRLIST locusr,
	   int encrypt, STRLIST remusr, const char *outfile )
{
    const char *fname;
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
    PKC_LIST pkc_list = NULL;
    SKC_LIST skc_list = NULL;
    SKC_LIST skc_rover = NULL;
    int multifile = 0;

    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &tfx, 0, sizeof tfx);
    memset( &efx, 0, sizeof efx);
    init_packet( &pkt );

    if( filenames ) {
	fname = filenames->d;
	multifile = !!filenames->next;
    }
    else
	fname = NULL;

    if( fname && filenames->next && (!detached || encrypt) )
	log_bug("multiple files can only be detached signed");

    if( (rc=build_skc_list( locusr, &skc_list, 1 )) )
	goto leave;
    if( encrypt ) {
	if( (rc=build_pkc_list( remusr, &pkc_list )) )
	    goto leave;
    }

    /* prepare iobufs */
    if( multifile )  /* have list of filenames */
	inp = NULL; /* we do it later */
    else if( !(inp = iobuf_open(fname)) ) {
	log_error("can't open %s: %s\n", fname? fname: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( outfile ) {
	if( !(out = iobuf_create( outfile )) ) {
	    log_error("can't create %s: %s\n", outfile, strerror(errno) );
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	}
	else if( opt.verbose )
	    log_info("writing to '%s'\n", outfile );
    }
    else if( !(out = open_outfile( fname, opt.armor? 1: detached? 2:0 )) ) {
	rc = G10ERR_CREATE_FILE;
	goto leave;
    }

    /* prepare to calculate the MD over the input */
    if( opt.textmode && !outfile )
	iobuf_push_filter( inp, text_filter, &tfx );
    mfx.md = md_open(DIGEST_ALGO_RMD160, 0);
    if( !multifile )
	iobuf_push_filter( inp, md_filter, &mfx );

    if( opt.armor && !outfile  )
	iobuf_push_filter( out, armor_filter, &afx );
    write_comment( out, "#created by G10 v" VERSION " ("
					    PRINTABLE_OS_NAME ")");
    if( opt.compress && !outfile )
	iobuf_push_filter( out, compress_filter, &zfx );

    if( encrypt ) {
	efx.pkc_list = pkc_list;
	/* fixme: set efx.cfx.datalen if known */
	iobuf_push_filter( out, encrypt_filter, &efx );
    }

    /* loop over the secret certificates and build headers */
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	PKT_secret_cert *skc;
	PKT_onepass_sig *ops;

	skc = skc_rover->skc;
	ops = m_alloc_clear( sizeof *ops );
	ops->sig_class = opt.textmode && !outfile ? 0x01 : 0x00;
	ops->digest_algo = DIGEST_ALGO_RMD160;
	ops->pubkey_algo = skc->pubkey_algo;
	keyid_from_skc( skc, ops->keyid );
	ops->last = !skc_rover->next;

	init_packet(&pkt);
	pkt.pkttype = PKT_ONEPASS_SIG;
	pkt.pkt.onepass_sig = ops;
	rc = build_packet( out, &pkt );
	free_packet( &pkt );
	if( rc ) {
	    log_error("build onepass_sig packet failed: %s\n", g10_errstr(rc));
	    goto leave;
	}
    }


    /* setup the inner packet */
    if( detached ) {
	if( multifile ) {
	    STRLIST sl;

	    if( opt.verbose )
		log_info("signing:" );
	    /* must walk reverse trough this list */
	    for( sl = strlist_last(filenames); sl;
			sl = strlist_prev( filenames, sl ) ) {
		if( !(inp = iobuf_open(sl->d)) ) {
		    log_error("can't open %s: %s\n", sl->d, strerror(errno) );
		    rc = G10ERR_OPEN_FILE;
		    goto leave;
		}
		if( opt.verbose )
		    fprintf(stderr, " '%s'", sl->d );
		iobuf_push_filter( inp, md_filter, &mfx );
		while( iobuf_get(inp) != -1 )
		    ;
		iobuf_close(inp); inp = NULL;
	    }
	    if( opt.verbose )
		putc( '\n', stderr );
	}
	else {
	    /* read, so that the filter can calculate the digest */
	    while( iobuf_get(inp) != -1 )
		;
	}
    }
    else {
	if( fname ) {
	    pt = m_alloc( sizeof *pt + strlen(fname) - 1 );
	    pt->namelen = strlen(fname);
	    memcpy(pt->name, fname, pt->namelen );
	    if( !(filesize = iobuf_get_filelength(inp)) )
		log_info("warning: '%s' is an empty file\n", fname );
	}
	else { /* no filename */
	    pt = m_alloc( sizeof *pt - 1 );
	    pt->namelen = 0;
	    filesize = 0; /* stdin */
	}
	pt->timestamp = make_timestamp();
	pt->mode = opt.textmode && !outfile ? 't':'b';
	pt->len = filesize;
	pt->buf = inp;
	pkt.pkttype = PKT_PLAINTEXT;
	pkt.pkt.plaintext = pt;
	/*cfx.datalen = filesize? calc_packet_length( &pkt ) : 0;*/
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build_packet(PLAINTEXT) failed: %s\n", g10_errstr(rc) );
	pt->buf = NULL;
    }

    /* loop over the secret certificates */
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	PKT_secret_cert *skc;
	PKT_signature *sig;
	MD_HANDLE md;

	skc = skc_rover->skc;

	/* build the signature packet */
	sig = m_alloc_clear( sizeof *sig );
	sig->pubkey_algo = skc->pubkey_algo;
	sig->timestamp = make_timestamp();
	sig->sig_class = opt.textmode && !outfile? 0x01 : 0x00;

	md = md_copy( mfx.md );
	md_putc( md, sig->sig_class );
	{   u32 a = sig->timestamp;
	    md_putc( md, (a >> 24) & 0xff );
	    md_putc( md, (a >> 16) & 0xff );
	    md_putc( md, (a >>	8) & 0xff );
	    md_putc( md,  a	   & 0xff );
	}
	md_final( md );

	if( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	    g10_elg_sign( skc, sig, md, DIGEST_ALGO_RMD160 );
	else if( sig->pubkey_algo == PUBKEY_ALGO_RSA )
	    g10_rsa_sign( skc, sig, md, DIGEST_ALGO_RMD160 );
	else
	    BUG();

	md_close( md );

	/* and write it */
	init_packet(&pkt);
	pkt.pkttype = PKT_SIGNATURE;
	pkt.pkt.signature = sig;
	rc = build_packet( out, &pkt );
	free_packet( &pkt );
	if( rc ) {
	    log_error("build signature packet failed: %s\n", g10_errstr(rc) );
	    goto leave;
	}
    }


  leave:
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    iobuf_close(inp);
    md_close( mfx.md );
    release_skc_list( skc_list );
    release_pkc_list( pkc_list );
    return rc;
}



/****************
 * note: we do not count empty lines at the beginning
 */
static int
write_dash_escaped( IOBUF inp, IOBUF out, MD_HANDLE md )
{
    int c;
    int lastlf = 1;
    int skip_empty = 1;

    while( (c = iobuf_get(inp)) != -1 ) {
	/* Note: We don't escape "From " because the MUA should cope with it */
	if( lastlf ) {
	    if( c == '-' ) {
		iobuf_put( out, c );
		iobuf_put( out, ' ' );
		skip_empty = 0;
	    }
	    else if( skip_empty && c == '\r' )
		skip_empty = 2;
	    else
		skip_empty = 0;
	}

	if( !skip_empty )
	    md_putc(md, c );
	iobuf_put( out, c );
	lastlf = c == '\n';
	if( skip_empty == 2 )
	    skip_empty = lastlf ? 0 : 1;
    }
    return 0; /* fixme: add error handling */
}


/****************
 * make a clear signature. note that opt.armor is not needed
 */
int
clearsign_file( const char *fname, STRLIST locusr, const char *outfile )
{
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    text_filter_context_t tfx;
    MD_HANDLE textmd = NULL;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    int rc = 0;
    SKC_LIST skc_list = NULL;
    SKC_LIST skc_rover = NULL;

    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &tfx, 0, sizeof tfx);
    init_packet( &pkt );

    if( (rc=build_skc_list( locusr, &skc_list, 1 )) )
	goto leave;

    /* prepare iobufs */
    if( !(inp = iobuf_open(fname)) ) {
	log_error("can't open %s: %s\n", fname? fname: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( outfile ) {
	if( !(out = iobuf_create( outfile )) ) {
	    log_error("can't create %s: %s\n", outfile, strerror(errno) );
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	}
	else if( opt.verbose )
	    log_info("writing to '%s'\n", outfile );
    }
    else if( !(out = open_outfile( fname, 1 )) ) {
	rc = G10ERR_CREATE_FILE;
	goto leave;
    }

    iobuf_writestr(out, "-----BEGIN PGP SIGNED MESSAGE-----\n"
			"Hash: RIPEMD160\n\n" );

    textmd = md_open(DIGEST_ALGO_RMD160, 0);
    iobuf_push_filter( inp, text_filter, &tfx );
    rc = write_dash_escaped( inp, out, textmd );
    if( rc )
	goto leave;

    iobuf_writestr(out, "\n" );
    afx.what = 2;
    iobuf_push_filter( out, armor_filter, &afx );

    /* loop over the secret certificates */
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	PKT_secret_cert *skc;
	PKT_signature *sig;
	MD_HANDLE md;

	skc = skc_rover->skc;

	/* build the signature packet */
	sig = m_alloc_clear( sizeof *sig );
	sig->pubkey_algo = skc->pubkey_algo;
	sig->timestamp = make_timestamp();
	sig->sig_class = 0x01;

	md = md_copy( textmd );
	md_putc( md, sig->sig_class );
	{   u32 a = sig->timestamp;
	    md_putc( md, (a >> 24) & 0xff );
	    md_putc( md, (a >> 16) & 0xff );
	    md_putc( md, (a >>	8) & 0xff );
	    md_putc( md,  a	   & 0xff );
	}
	md_final( md );

	if( sig->pubkey_algo == PUBKEY_ALGO_ELGAMAL )
	    g10_elg_sign( skc, sig, md, DIGEST_ALGO_RMD160 );
	else if( sig->pubkey_algo == PUBKEY_ALGO_RSA )
	    g10_rsa_sign( skc, sig, md, DIGEST_ALGO_RMD160 );
	else
	    BUG();

	md_close( md );

	/* and write it */
	init_packet(&pkt);
	pkt.pkttype = PKT_SIGNATURE;
	pkt.pkt.signature = sig;
	rc = build_packet( out, &pkt );
	free_packet( &pkt );
	if( rc ) {
	    log_error("build signature packet failed: %s\n", g10_errstr(rc) );
	    goto leave;
	}
    }


  leave:
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    iobuf_close(inp);
    md_close( textmd );
    release_skc_list( skc_list );
    return rc;
}




static void
show_fingerprint( PKT_public_cert *pkc )
{
    byte *array, *p;
    size_t i, n;

    p = array = fingerprint_from_pkc( pkc, &n );
    tty_printf("             Fingerprint:");
    if( n == 20 ) {
	for(i=0; i < n ; i++, i++, p += 2 ) {
	    if( i == 10 )
		tty_printf(" ");
	    tty_printf(" %02X%02X", *p, p[1] );
	}
    }
    else {
	for(i=0; i < n ; i++, p++ ) {
	    if( i && !(i%8) )
		tty_printf(" ");
	    tty_printf(" %02X", *p );
	}
    }
    tty_printf("\n");
    m_free(array);
}


/****************
 * Ask wether the user is willing to sign the key. Return true if so.
 */
static int
sign_it_p( PKT_public_cert *pkc, PKT_user_id *uid )
{
    char *answer;
    int yes;

    tty_printf("\nAre you really sure that you want so sign this key:\n\n"
	       "%4u%c/%08lX %s ",
	      nbits_from_pkc( pkc ),
	      pubkey_letter( pkc->pubkey_algo ),
	      (ulong)keyid_from_pkc( pkc, NULL ),
	      datestr_from_pkc( pkc )		    );
    tty_print_string( uid->name, uid->len );
    tty_printf("\n");
    show_fingerprint(pkc);
    tty_printf("\n");
    answer = tty_get("Sign this key? ");
    tty_kill_prompt();
    yes = answer_is_yes(answer);
    m_free(answer);
    return yes;
}


/****************
 * Check the keysigs and set the flags to indicate errors.
 * Usage of nodes flag bits:
 * Bit	0 = bad signature
 *	1 = no public key
 *	2 = other error
 * Returns true if error found.
 */
static int
check_all_keysigs( KBNODE keyblock )
{
    KBNODE kbctx;
    KBNODE node;
    int rc;
    int inv_sigs = 0;
    int no_key = 0;
    int oth_err = 0;

    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	if( node->pkt->pkttype == PKT_SIGNATURE
	    && (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    int sigrc;

	    tty_printf("sig");
	    switch( (rc = check_key_signature( keyblock, node,NULL)) ) {
	      case 0:		     node->flag = 0; sigrc = '!'; break;
	      case G10ERR_BAD_SIGN:  inv_sigs++; node->flag = 1; sigrc = '-'; break;
	      case G10ERR_NO_PUBKEY: no_key++;	 node->flag = 2; sigrc = '?'; break;
	      default:		     oth_err++;  node->flag = 4; sigrc = '%'; break;
	    }
	    tty_printf("%c       %08lX %s   ",
		    sigrc, sig->keyid[1], datestr_from_sig(sig));
	    if( sigrc == '%' )
		tty_printf("[%s] ", g10_errstr(rc) );
	    else if( sigrc == '?' )
		;
	    else {
		size_t n;
		char *p = get_user_id( sig->keyid, &n );
		tty_print_string( p, n > 40? 40 : n );
		m_free(p);
	    }
	    tty_printf("\n");
	    /* FIXME: update the trustdb */
	}
    }
    if( inv_sigs )
	tty_printf("%d bad signatures\n", inv_sigs );
    if( no_key )
	tty_printf("No public key for %d signatures\n", no_key );
    if( oth_err )
	tty_printf("%d signatures not checked due to errors\n", oth_err );
    return inv_sigs || no_key || oth_err;
}


/****************
 * Ask and remove invalid signatures are to be removed.
 */
static int
remove_keysigs( KBNODE keyblock, u32 *keyid, int all )
{
    KBNODE kbctx;
    KBNODE node;
    char *answer;
    int yes;
    int count;

    count = 0;
    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	if( ((node->flag & 7) || all )
	    && node->pkt->pkttype == PKT_SIGNATURE
	    && (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
	    PKT_signature *sig = node->pkt->pkt.signature;

	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] ) {
		/* fixme: skip self-sig */
	    }

	    tty_printf("\n \"%08lX %s   ",
			sig->keyid[1], datestr_from_sig(sig));
	    if( node->flag & 6 )
		tty_printf("[User name not available] ");
	    else {
		size_t n;
		char *p = get_user_id( sig->keyid, &n );
		tty_print_string( p, n );
		m_free(p);
	    }
	    tty_printf("\"\n");
	    if( node->flag & 1 )
		tty_printf("This is a BAD signature!\n");
	    else if( node->flag & 2 )
		tty_printf("Public key not available.\n");
	    else if( node->flag & 4 )
		tty_printf("The signature could not be checked!\n");

	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		continue; /* do not remove self-signatures */

	    answer = tty_get("\nRemove this signature? ");
	    tty_kill_prompt();
	    if( answer_is_yes(answer) ) {
		node->flag |= 128;     /* use bit 7 to mark this node */
		count++;
	    }
	    m_free(answer);
	}
    }

    if( !count )
	return 0; /* nothing to remove */
    answer = tty_get("Do you really want to remove the selected signatures? ");
    tty_kill_prompt();
    yes = answer_is_yes(answer);
    m_free(answer);
    if( !yes )
	return 0;

    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 1)) ; ) {
	if( node->flag & 128)
	    delete_kbnode(node );
    }

    return 1;
}


/****************
 * This functions signs the key of USERNAME with all users listed in
 * LOCUSR. If LOCUSR is NULL the default secret certificate will
 * be used.  This works on all keyrings, so there is no armor or
 * compress stuff here.
 */
int
sign_key( const char *username, STRLIST locusr )
{
    md_filter_context_t mfx;
    int rc = 0;
    SKC_LIST skc_list = NULL;
    SKC_LIST skc_rover = NULL;
    KBNODE keyblock = NULL;
    KBNODE kbctx, node;
    KBPOS kbpos;
    PKT_public_cert *pkc;
    u32 pkc_keyid[2];
    char *answer;

    memset( &mfx, 0, sizeof mfx);

    /* search the userid */
    rc = find_keyblock_byname( &kbpos, username );
    if( rc ) {
	log_error("user '%s' not found\n", username );
	goto leave;
    }

    /* build a list of all signators */
    rc=build_skc_list( locusr, &skc_list, 0 );
    if( rc )
	goto leave;


    /* read the keyblock */
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("error reading the certificate: %s\n", g10_errstr(rc) );
	goto leave;
    }

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, PKT_PUBLIC_CERT );
    if( !node ) {
	log_error("Oops; public key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    pkc = node->pkt->pkt.public_cert;
    keyid_from_pkc( pkc, pkc_keyid );
    log_info("Checking signatures of this public key certificate:\n");
    tty_printf("pub  %4u%c/%08lX %s   ",
	      nbits_from_pkc( pkc ),
	      pubkey_letter( pkc->pubkey_algo ),
	      pkc_keyid[1], datestr_from_pkc(pkc) );
    {
	size_t n;
	char *p = get_user_id( pkc_keyid, &n );
	tty_print_string( p, n > 40? 40 : n );
	m_free(p);
	tty_printf("\n");
    }

    clear_kbnode_flags( keyblock );
    if( check_all_keysigs( keyblock ) ) {
	if( !opt.batch ) {
	    /* ask wether we really should do anything */
	    answer = tty_get("To you want to remove some of the invalid sigs? ");
	    tty_kill_prompt();
	    if( answer_is_yes(answer) )
		remove_keysigs( keyblock, pkc_keyid, 0 );
	    m_free(answer);
	}
    }

    /* check wether we have already signed it */
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	u32 akeyid[2];

	keyid_from_skc( skc_rover->skc, akeyid );
	for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	    if( node->pkt->pkttype == PKT_SIGNATURE
		&& (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
		if( akeyid[0] == node->pkt->pkt.signature->keyid[0]
		    && akeyid[1] == node->pkt->pkt.signature->keyid[1] ) {
		    log_info("Already signed by keyid %08lX\n",
							(ulong)akeyid[1] );
		    skc_rover->mark = 1;
		}
	    }
	}
    }
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	if( !skc_rover->mark )
	    break;
    }
    if( !skc_rover ) {
	log_info("Nothing to sign\n");
	goto leave;
    }

    /* Loop over all signers and all user ids and sign */
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	if( skc_rover->mark )
	    continue;
	for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	    if( node->pkt->pkttype == PKT_USER_ID ) {
		if( sign_it_p( pkc, node->pkt->pkt.user_id ) ) {
		    PACKET *pkt;
		    PKT_signature *sig;

		    rc = make_keysig_packet( &sig, pkc,
						   node->pkt->pkt.user_id,
						   skc_rover->skc,
						   0x10,
						   DIGEST_ALGO_RMD160 );
		    if( rc ) {
			log_error("make_keysig_packet failed: %s\n", g10_errstr(rc));
			goto leave;
		    }

		    pkt = m_alloc_clear( sizeof *pkt );
		    pkt->pkttype = PKT_SIGNATURE;
		    pkt->pkt.signature = sig;
		    insert_kbnode( node, new_kbnode(pkt), PKT_USER_ID );
		}
	    }
	}
    }

    rc = update_keyblock( &kbpos, keyblock );
    if( rc ) {
	log_error("update_keyblock failed: %s\n", g10_errstr(rc) );
	goto leave;
    }

  leave:
    release_kbnode( keyblock );
    release_skc_list( skc_list );
    md_close( mfx.md );
    return rc;
}



int
edit_keysigs( const char *username )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    KBNODE node;
    KBPOS kbpos;
    PKT_public_cert *pkc;
    u32 pkc_keyid[2];

    /* search the userid */
    rc = find_keyblock_byname( &kbpos, username );
    if( rc ) {
	log_error("%s: user not found\n", username );
	goto leave;
    }

    /* read the keyblock */
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("%s: certificate read problem: %s\n", username, g10_errstr(rc) );
	goto leave;
    }

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, PKT_PUBLIC_CERT );
    if( !node ) {
	log_error("Oops; public key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    pkc = node->pkt->pkt.public_cert;
    keyid_from_pkc( pkc, pkc_keyid );
    log_info("Checking signatures of this public key certificate:\n");
    tty_printf("pub  %4u%c/%08lX %s   ",
	      nbits_from_pkc( pkc ),
	      pubkey_letter( pkc->pubkey_algo ),
	      pkc_keyid[1], datestr_from_pkc(pkc) );
    {
	size_t n;
	char *p = get_user_id( pkc_keyid, &n );
	tty_print_string( p, n > 40? 40 : n );
	m_free(p);
	tty_printf("\n");
    }

    clear_kbnode_flags( keyblock );
    check_all_keysigs( keyblock );
    if( remove_keysigs( keyblock, pkc_keyid, 1 ) ) {
	rc = update_keyblock( &kbpos, keyblock );
	if( rc ) {
	    log_error("update_keyblock failed: %s\n", g10_errstr(rc) );
	    goto leave;
	}
    }

  leave:
    release_kbnode( keyblock );
    return rc;
}


int
change_passphrase( const char *username )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    KBNODE node;
    KBPOS kbpos;
    PKT_secret_cert *skc;
    u32 skc_keyid[2];
    char *answer;
    int changed=0;

    /* search the userid */
    rc = find_secret_keyblock_byname( &kbpos, username );
    if( rc ) {
	log_error("secret key for user '%s' not found\n", username );
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
    if( !node ) {
	log_error("Oops; secret key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    skc = node->pkt->pkt.secret_cert;
    keyid_from_skc( skc, skc_keyid );
    tty_printf("sec  %4u%c/%08lX %s   ",
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

    clear_kbnode_flags( keyblock );
    switch( is_secret_key_protected( skc ) ) {
      case -1:
	rc = G10ERR_PUBKEY_ALGO;
	break;
      case 0:
	tty_printf("This key is not protected.\n");
	break;
      default:
	tty_printf("Key is protected.\n");
	rc = check_secret_key( skc );
	break;
    }

    if( rc )
	tty_printf("Can't edit this key: %s\n", g10_errstr(rc));
    else {
	DEK *dek = m_alloc_secure( sizeof *dek );

	tty_printf( "Enter the new passphrase for this secret key.\n\n" );

	for(;;) {
	    dek->algo = CIPHER_ALGO_BLOWFISH;
	    rc = make_dek_from_passphrase( dek , 2 );
	    if( rc == -1 ) {
		rc = 0;
		tty_printf( "You don't want a passphrase -"
			    " this is probably a *bad* idea!\n\n");
		answer = tty_get("Do you really want to do this? ");
		tty_kill_prompt();
		if( answer_is_yes(answer) )
		    changed++;
		m_free(answer);
		break;
	    }
	    else if( rc == G10ERR_PASSPHRASE ) {
		tty_printf("passphrase not correctly repeated; try again.\n");
	    }
	    else if( rc ) {
		m_free(dek); dek = NULL;
		log_error("Error getting the passphrase: %s\n", g10_errstr(rc));
		break;
	    }
	    else { /* okay */
		skc->d.elg.protect_algo = CIPHER_ALGO_BLOWFISH;
		randomize_buffer(skc->d.elg.protect.blowfish.iv, 8, 1);
		rc = protect_secret_key( skc, dek );
		if( rc )
		    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
		else
		    changed++;
		break;
	    }
	}
	m_free(dek);
    }


    if( changed ) {
	rc = update_keyblock( &kbpos, keyblock );
	if( rc ) {
	    log_error("update_keyblock failed: %s\n", g10_errstr(rc) );
	    goto leave;
	}
    }

  leave:
    release_kbnode( keyblock );
    return rc;
}


/****************
 * Create a signature packet for the given public key certificate
 * and the user id and return it in ret_sig. User signature class SIGCLASS
 * user-id is not used (and may be NULL if sigclass is 0x20)
 */
int
make_keysig_packet( PKT_signature **ret_sig, PKT_public_cert *pkc,
		    PKT_user_id *uid, PKT_secret_cert *skc,
		    int sigclass, int digest_algo )
{
    PKT_signature *sig;
    int rc=0;
    MD_HANDLE md;

    assert( (sigclass >= 0x10 && sigclass <= 0x13) || sigclass == 0x20 );
    md = md_open( digest_algo, 0 );

    /* hash the public key certificate and the user id */
    hash_public_cert( md, pkc );
    if( sigclass != 0x20 )
	md_write( md, uid->name, uid->len );
    /* and make the signature packet */
    sig = m_alloc_clear( sizeof *sig );
    sig->pubkey_algo = skc->pubkey_algo;
    sig->timestamp = make_timestamp();
    sig->sig_class = sigclass;

    md_putc( md, sig->sig_class );
    {	u32 a = sig->timestamp;
	md_putc( md, (a >> 24) & 0xff );
	md_putc( md, (a >> 16) & 0xff );
	md_putc( md, (a >>  8) & 0xff );
	md_putc( md,  a        & 0xff );
    }
    md_final(md);

    rc = complete_sig( sig, skc, md );

    md_close( md );
    if( rc )
	free_seckey_enc( sig );
    else
	*ret_sig = sig;
    return rc;
}

