/* keylist.c
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"
#include "main.h"
#include "i18n.h"

static void list_all(int);
static void list_one(const char *name, int secret);
static void fingerprint( PKT_public_cert *pkc, PKT_secret_cert *skc );


/****************
 * List the keys
 * If NNAMES is 0; all available keys are listed
 */
void
public_key_list( int nnames, char **names )
{
    if( !nnames )
	list_all(0);
    else { /* List by user id */
	for( ; nnames ; nnames--, names++ )
	    list_one( *names, 0 );
    }
}

void
secret_key_list( int nnames, char **names )
{
    if( !nnames )
	list_all(1);
    else { /* List by user id */
	for( ; nnames ; nnames--, names++ )
	    list_one( *names, 1 );
    }
}


static void
list_all( int secret )
{
    int i, seq=0;
    const char *s;
    IOBUF a;

    while( (s=secret? get_secret_keyring(seq++):get_keyring(seq++)) ) {
	if( !(a = iobuf_open(s)) ) {
	    log_error(_("can't open %s: %s\n"), s, strerror(errno));
	    continue;
	}
	if( seq > 1 )
	    putchar('\n');
	printf("%s\n", s );
	for(i=strlen(s); i; i-- )
	    putchar('-');
	putchar('\n');

	proc_packets( a );
	iobuf_close(a);
    }
}

static void
list_one( const char *name, int secret )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    KBNODE kbctx;
    KBNODE node;
    KBPOS kbpos;
    PKT_public_cert *pkc;
    PKT_secret_cert *skc;
    u32 keyid[2];
    int any=0;
    int trustletter = 0;

    /* search the userid */
    rc = secret? find_secret_keyblock_byname( &kbpos, name )
	       : find_keyblock_byname( &kbpos, name );
    if( rc ) {
	log_error("%s: user not found\n", name );
	goto leave;
    }

    /* read the keyblock */
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("%s: keyblock read problem: %s\n", name, g10_errstr(rc) );
	goto leave;
    }


    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, secret? PKT_SECRET_CERT : PKT_PUBLIC_CERT );
    if( !node ) {
	log_error("Oops; key lost!\n");
	goto leave;
    }

    if( secret ) {
	pkc = NULL;
	skc = node->pkt->pkt.secret_cert;
	keyid_from_skc( skc, keyid );
	if( opt.with_colons )
	    printf("sec::%u:%d:%08lX%08lX:%s:%u:::",
		    nbits_from_skc( skc ),
		    skc->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    datestr_from_skc( skc ),
		    (unsigned)skc->valid_days
		    /* fixme: add LID here */ );
	else
	    printf("sec  %4u%c/%08lX %s ", nbits_from_skc( skc ),
				       pubkey_letter( skc->pubkey_algo ),
				       (ulong)keyid[1],
				       datestr_from_skc( skc ) );
    }
    else {
	pkc = node->pkt->pkt.public_cert;
	skc = NULL;
	keyid_from_pkc( pkc, keyid );
	if( opt.with_colons ) {
	    trustletter = query_trust_info( pkc );
	    printf("pub:%c:%u:%d:%08lX%08lX:%s:%u:",
		    trustletter,
		    nbits_from_pkc( pkc ),
		    pkc->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    datestr_from_pkc( pkc ),
		    (unsigned)pkc->valid_days );
	    if( pkc->local_id )
		printf("%lu", pkc->local_id );
	    putchar(':');
	    /* fixme: add ownertrust here */
	    putchar(':');
	}
	else
	    printf("pub  %4u%c/%08lX %s ", nbits_from_pkc( pkc ),
				       pubkey_letter( pkc->pubkey_algo ),
				       (ulong)keyid[1],
				       datestr_from_pkc( pkc ) );
    }

    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    if( any ) {
		if( opt.with_colons )
		    printf("uid:::::::::");
		else
		    printf("uid%*s", 28, "");
	    }
	    print_string( stdout,  node->pkt->pkt.user_id->name,
			  node->pkt->pkt.user_id->len, opt.with_colons );
	    if( opt.with_colons )
		putchar(':');
	    putchar('\n');
	    if( !any ) {
		if( opt.fingerprint )
		    fingerprint( pkc, skc );
		any = 1;
	    }
	}
	else if( node->pkt->pkttype == PKT_PUBKEY_SUBCERT ) {
	    u32 keyid2[2];
	    PKT_public_cert *pkc2 = node->pkt->pkt.public_cert;

	    if( !any ) {
		putchar('\n');
		if( opt.fingerprint )
		    fingerprint( pkc, skc ); /* of the main key */
		any = 1;
	    }

	    keyid_from_pkc( pkc2, keyid2 );
	    if( opt.with_colons ) {
		printf("sub:%c:%u:%d:%08lX%08lX:%s:%u:",
			trustletter,
			nbits_from_pkc( pkc2 ),
			pkc2->pubkey_algo,
			(ulong)keyid2[0],(ulong)keyid2[1],
			datestr_from_pkc( pkc2 ),
			(unsigned)pkc2->valid_days
			/* fixme: add LID and ownertrust here */
						);
		if( pkc->local_id ) /* use the local_id of the main key??? */
		    printf("%lu", pkc->local_id );
		putchar(':');
		putchar(':');
		putchar('\n');
	    }
	    else
		printf("sub  %4u%c/%08lX %s\n", nbits_from_pkc( pkc2 ),
					   pubkey_letter( pkc2->pubkey_algo ),
					   (ulong)keyid2[1],
					   datestr_from_pkc( pkc2 ) );
	}
	else if( node->pkt->pkttype == PKT_SECKEY_SUBCERT ) {
	    u32 keyid2[2];
	    PKT_secret_cert *skc2 = node->pkt->pkt.secret_cert;

	    if( !any ) {
		putchar('\n');
		if( opt.fingerprint )
		    fingerprint( pkc, skc ); /* of the main key */
		any = 1;
	    }

	    keyid_from_skc( skc2, keyid2 );
	    if( opt.with_colons )
		printf("ssb::%u:%d:%08lX%08lX:%s:%u:::\n",
			nbits_from_skc( skc2 ),
			skc2->pubkey_algo,
			(ulong)keyid2[0],(ulong)keyid2[1],
			datestr_from_skc( skc2 ),
			(unsigned)skc2->valid_days
			/* fixme: add LID */
						);
	    else
		printf("ssb  %4u%c/%08lX %s\n", nbits_from_skc( skc2 ),
					   pubkey_letter( skc2->pubkey_algo ),
					   (ulong)keyid2[1],
					   datestr_from_skc( skc2 ) );
	}
	else if( opt.list_sigs && node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    int sigrc;

	    if( !any ) { /* no user id, (maybe a revocation follows)*/
		if( sig->sig_class == 0x20 )
		    puts("[revoked]");
		else if( sig->sig_class == 0x18 )
		    puts("[key binding]");
		else
		    putchar('\n');
		if( opt.fingerprint )
		    fingerprint( pkc, skc );
		any=1;
	    }

	    if( sig->sig_class == 0x20 || sig->sig_class == 0x30 )
		fputs("rev", stdout);
	    else if( (sig->sig_class&~3) == 0x10 )
		fputs("sig", stdout);
	    else if( sig->sig_class == 0x18 )
		fputs("sig", stdout);
	    else {
		if( opt.with_colons )
		    printf("sig::::::::::%02x:\n",sig->sig_class );
		else
		    printf("sig                             "
		       "[unexpected signature class 0x%02x]\n",sig->sig_class );
		continue;
	    }
	    if( opt.check_sigs ) {
		fflush(stdout);
		rc = check_key_signature( keyblock, node, NULL );
		switch( rc ) {
		  case 0:		   sigrc = '!'; break;
		  case G10ERR_BAD_SIGN:    sigrc = '-'; break;
		  case G10ERR_NO_PUBKEY:   sigrc = '?'; break;
		  default:		   sigrc = '%'; break;
		}
	    }
	    else {
		rc = 0;
		sigrc = ' ';
	    }
	    if( opt.with_colons ) {
		putchar(':');
		if( sigrc != ' ' )
		    putchar(sigrc);
		printf(":::%08lX%08lX:%s::::", (ulong)sig->keyid[0],
			   (ulong)sig->keyid[1], datestr_from_sig(sig));
	    }
	    else
		printf("%c       %08lX %s  ",
		    sigrc, (ulong)sig->keyid[1], datestr_from_sig(sig));
	    if( sigrc == '%' )
		printf("[%s] ", g10_errstr(rc) );
	    else if( sigrc == '?' )
		;
	    else {
		size_t n;
		char *p = get_user_id( sig->keyid, &n );
		print_string( stdout, p, n, opt.with_colons );
		m_free(p);
	    }
	    if( opt.with_colons )
		printf(":%02x:", sig->sig_class );
	    putchar('\n');
	}
    }
    if( !any ) {/* oops, no user id */
	if( opt.with_colons )
	    putchar(':');
	putchar('\n');
    }


  leave:
    release_kbnode( keyblock );
}

static void
fingerprint( PKT_public_cert *pkc, PKT_secret_cert *skc )
{
    byte *array, *p;
    size_t i, n;

    p = array = pkc? fingerprint_from_pkc( pkc, &n )
		   : fingerprint_from_skc( skc, &n );
    if( opt.with_colons ) {
	printf("fpr:::::::::");
	for(i=0; i < n ; i++, p++ )
	    printf("%02X", *p );
	putchar(':');
    }
    else {
	printf("     Key fingerprint =");
	if( n == 20 ) {
	    for(i=0; i < n ; i++, i++, p += 2 ) {
		if( i == 10 )
		    putchar(' ');
		printf(" %02X%02X", *p, p[1] );
	    }
	}
	else {
	    for(i=0; i < n ; i++, p++ ) {
		if( i && !(i%8) )
		    putchar(' ');
		printf(" %02X", *p );
	    }
	}
    }
    putchar('\n');
    m_free(array);
}

