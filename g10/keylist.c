/* keylist.c
 *	Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "trustdb.h"
#include "main.h"
#include "i18n.h"

static void list_all(int);
static void list_one( STRLIST names, int secret);
static void list_keyblock( KBNODE keyblock, int secret );
static void fingerprint( PKT_public_key *pk, PKT_secret_key *sk );


/****************
 * List the keys
 * If list is NULL, all available keys are listed
 */
void
public_key_list( STRLIST list )
{
    if( !list )
	list_all(0);
    else
	list_one( list, 0 );
}

void
secret_key_list( STRLIST list )
{
    if( !list )
	list_all(1);
    else  /* List by user id */
	list_one( list, 1 );
}


static void
list_all( int secret )
{
    KBPOS kbpos;
    KBNODE keyblock = NULL;
    int rc=0;
    int lastresno;

    rc = enum_keyblocks( secret? 5:0, &kbpos, &keyblock );
    if( rc ) {
	if( rc != -1 )
	    log_error("enum_keyblocks(open) failed: %s\n", g10_errstr(rc) );
	goto leave;
    }

    lastresno = -1;
    while( !(rc = enum_keyblocks( 1, &kbpos, &keyblock )) ) {
	if( lastresno != kbpos.resno ) {
	    const char *s = keyblock_resource_name( &kbpos );
	    int i;

	    lastresno = kbpos.resno;
	    printf("%s\n", s );
	    for(i=strlen(s); i; i-- )
		putchar('-');
	    putchar('\n');
	}
	merge_keys_and_selfsig( keyblock );
	list_keyblock( keyblock, secret );
	release_kbnode( keyblock ); keyblock = NULL;
    }

    if( rc && rc != -1 )
	log_error("enum_keyblocks(read) failed: %s\n", g10_errstr(rc));

  leave:
    enum_keyblocks( 2, &kbpos, &keyblock ); /* close */
    release_kbnode( keyblock );
}


/****************
 * Check whether the user ID at NODE is valid; that is it has a
 * valid self-signature but no later valid revocation.
 * Caller has to pass the keyID of the primary in mainkey.
 * Returns: NULL = valid
 *	    string with the reason why it is invalid
 */
static const char *
is_uid_valid ( KBNODE keyblock, KBNODE uidnode, u32 *mainkid )
{
    KBNODE node;
    PKT_signature *selfsig = NULL; /* the latest valid self signature */

    /* The key signature verify function can's handle secret keys yet and
     * becuase we are not sure whether the duplication of user IDs and
     * self-signatures should be kept on secret keys we are not going to fix
     * it there. */
    if ( keyblock->pkt->pkttype == PKT_SECRET_KEY )
	return NULL;

    assert ( uidnode->pkt->pkttype == PKT_USER_ID
	     || uidnode->pkt->pkttype == PKT_PHOTO_ID );

    /* first find out about the latest valid self-signature */
    for ( node = uidnode->next; node; node = node->next ) {
	PKT_signature *sig;

	if ( node->pkt->pkttype == PKT_USER_ID
	     || node->pkt->pkttype == PKT_PHOTO_ID
	     || node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	     || node->pkt->pkttype == PKT_SECRET_SUBKEY )
	    break;
	if ( node->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	sig = node->pkt->pkt.signature;
	if ( mainkid[0] != sig->keyid[0] || mainkid[1] != sig->keyid[1] )
	    continue; /* we only care about self-signatures for now */

	if ( (sig->sig_class&~3) == 0x10 ) { /* regular self signature */
	    if ( !check_key_signature( keyblock, node, NULL ) ) {
		if ( !selfsig )
		    selfsig = sig; /* use the first valid sig */
		else if ( sig->timestamp > selfsig->timestamp
			  && sig->sig_class >= selfsig->sig_class )
		    selfsig = sig; /* but this one is newer */
	    }
	}
    }

    if ( !selfsig )
	return _("invalid"); /* no valid self signature */

    /* watch out for a newer revocation */
    for ( node = uidnode->next; node; node = node->next ) {
	PKT_signature *sig;

	if ( node->pkt->pkttype == PKT_USER_ID
	     || node->pkt->pkttype == PKT_PHOTO_ID
	     || node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	     || node->pkt->pkttype == PKT_SECRET_SUBKEY )
	    break;
	if ( node->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	sig = node->pkt->pkt.signature;
	if ( mainkid[0] != sig->keyid[0] || mainkid[1] != sig->keyid[1] )
	    continue; /* we only care about self-signatures for now */

	if ( sig->sig_class == 0x30
	     && sig->timestamp >= selfsig->timestamp ) {
	    if ( !check_key_signature( keyblock, node, NULL ) )
		return _("revoked");
	}
    }

    return NULL; /* UID is valid */
}



static void
list_one( STRLIST names, int secret )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    GETKEY_CTX ctx;

    if( secret ) {
	rc = get_seckey_bynames( &ctx, NULL, names, &keyblock );
	if( rc ) {
	    log_error("error reading key: %s\n",  g10_errstr(rc) );
	    get_seckey_end( ctx );
	    return;
	}
	do {
	    merge_keys_and_selfsig( keyblock );
	    list_keyblock( keyblock, 1 );
	    release_kbnode( keyblock );
	} while( !get_seckey_next( ctx, NULL, &keyblock ) );
	get_seckey_end( ctx );
    }
    else {
	rc = get_pubkey_bynames( &ctx, NULL, names, &keyblock );
	if( rc ) {
	    log_error("error reading key: %s\n", g10_errstr(rc) );
	    get_pubkey_end( ctx );
	    return;
	}
	do {
	    merge_keys_and_selfsig( keyblock );
	    list_keyblock( keyblock, 0 );
	    release_kbnode( keyblock );
	} while( !get_pubkey_next( ctx, NULL, &keyblock ) );
	get_pubkey_end( ctx );
    }
}

static void
print_key_data( PKT_public_key *pk, u32 *keyid )
{
    int n = pk ? pubkey_get_npkey( pk->pubkey_algo ) : 0;
    int i;

    for(i=0; i < n; i++ ) {
	printf("pkd:%d:%u:", i, mpi_get_nbits( pk->pkey[i] ) );
	mpi_print(stdout, pk->pkey[i], 1 );
	putchar(':');
	putchar('\n');
    }
}


static void
list_keyblock( KBNODE keyblock, int secret )
{
    int rc = 0;
    KBNODE kbctx;
    KBNODE node;
    PKT_public_key *pk;
    PKT_secret_key *sk;
    u32 keyid[2];
    int any=0;
    int trustletter = 0;
    int ulti_hack = 0;

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, secret? PKT_SECRET_KEY : PKT_PUBLIC_KEY );
    if( !node ) {
	log_error("Oops; key lost!\n");
	dump_kbnode( keyblock );
	return;
    }

    if( secret ) {
	pk = NULL;
	sk = node->pkt->pkt.secret_key;
	keyid_from_sk( sk, keyid );
	if( opt.with_colons )
	    printf("sec:u:%u:%d:%08lX%08lX:%s:%s:::",
		    nbits_from_sk( sk ),
		    sk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    datestr_from_sk( sk ),
		    sk->expiredate? strtimestamp(sk->expiredate):""
		    /* fixme: add LID here */ );
	else
	    printf("sec  %4u%c/%08lX %s ", nbits_from_sk( sk ),
				       pubkey_letter( sk->pubkey_algo ),
				       (ulong)keyid[1],
				       datestr_from_sk( sk ) );
    }
    else {
	pk = node->pkt->pkt.public_key;
	sk = NULL;
	keyid_from_pk( pk, keyid );
	if( opt.with_colons ) {
	    if ( opt.fast_list_mode ) {
		fputs( "pub::", stdout );
		trustletter = 0;
	    }
	    else {
		trustletter = query_trust_info( pk, NULL );
		if( trustletter == 'u' )
		    ulti_hack = 1;
		printf("pub:%c:", trustletter );
	    }
	    printf("%u:%d:%08lX%08lX:%s:%s:",
		    nbits_from_pk( pk ),
		    pk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    datestr_from_pk( pk ),
		    pk->expiredate? strtimestamp(pk->expiredate):"" );
	    if( pk->local_id )
		printf("%lu", pk->local_id );
	    putchar(':');
	    if( pk->local_id && !opt.fast_list_mode )
		putchar( get_ownertrust_info( pk->local_id ) );
	    putchar(':');
	}
	else
	    printf("pub  %4u%c/%08lX %s ", nbits_from_pk( pk ),
				       pubkey_letter( pk->pubkey_algo ),
				       (ulong)keyid[1],
				       datestr_from_pk( pk ) );
    }

    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	if( node->pkt->pkttype == PKT_USER_ID && !opt.fast_list_mode ) {
	    if( any ) {
		if ( opt.with_colons ) {
		    byte namehash[20];

		    if( pk && !ulti_hack ) {
			if( node->pkt->pkt.user_id->photo )
			    rmd160_hash_buffer( namehash,
					    node->pkt->pkt.user_id->name,
					    node->pkt->pkt.user_id->len  );
			else
			    rmd160_hash_buffer( namehash,
					    node->pkt->pkt.user_id->name,
					    node->pkt->pkt.user_id->len  );
			trustletter = query_trust_info( pk, namehash );
		    }
		    else
			trustletter = 'u';
		    printf("uid:%c::::::::", trustletter);
		}
		else
		    printf("uid%*s", 28, "");
	    }
	    if( opt.with_colons ) {
		/* FIXME: check that uID is valid here too */
		print_string( stdout,  node->pkt->pkt.user_id->name,
			      node->pkt->pkt.user_id->len, ':' );
		putchar(':');
	    }
	    else {
		const char *s = is_uid_valid ( keyblock, node, keyid );
		if ( s )
		    printf ("[%s] ", s );
		print_utf8_string( stdout,  node->pkt->pkt.user_id->name,
				   node->pkt->pkt.user_id->len );
	    }
	    putchar('\n');
	    if( !any ) {
		if( opt.fingerprint )
		    fingerprint( pk, sk );
		if( opt.with_key_data )
		    print_key_data( pk, keyid );
		any = 1;
	    }
	}
	else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    u32 keyid2[2];
	    PKT_public_key *pk2 = node->pkt->pkt.public_key;

	    if( !any ) {
		putchar('\n');
		if( opt.fingerprint )
		    fingerprint( pk, sk ); /* of the main key */
		any = 1;
	    }



	    keyid_from_pk( pk2, keyid2 );
	    if( opt.with_colons ) {
		if ( opt.fast_list_mode ) {
		    fputs( "sub::", stdout );
		}
		else {
		    printf("sub:%c:", trustletter );
		}
		printf("%u:%d:%08lX%08lX:%s:%s:",
			nbits_from_pk( pk2 ),
			pk2->pubkey_algo,
			(ulong)keyid2[0],(ulong)keyid2[1],
			datestr_from_pk( pk2 ),
			pk2->expiredate? strtimestamp(pk2->expiredate):""
			/* fixme: add LID and ownertrust here */
						);
		if( pk->local_id ) /* use the local_id of the main key??? */
		    printf("%lu", pk->local_id );
		putchar(':');
		putchar(':');
		putchar('\n');
	    }
	    else {
		printf("sub  %4u%c/%08lX %s", nbits_from_pk( pk2 ),
					   pubkey_letter( pk2->pubkey_algo ),
					   (ulong)keyid2[1],
					   datestr_from_pk( pk2 ) );
		if( pk2->expiredate ) {
		    printf(_(" [expires: %s]"), expirestr_from_pk( pk2 ) );
		}
		putchar('\n');
	    }
	    if( opt.fingerprint > 1 )
		fingerprint( pk2, NULL );
	    if( opt.with_key_data )
		print_key_data( pk2, keyid2 );
	}
	else if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    u32 keyid2[2];
	    PKT_secret_key *sk2 = node->pkt->pkt.secret_key;

	    if( !any ) {
		putchar('\n');
		if( opt.fingerprint )
		    fingerprint( pk, sk ); /* of the main key */
		any = 1;
	    }

	    keyid_from_sk( sk2, keyid2 );
	    if( opt.with_colons )
		printf("ssb::%u:%d:%08lX%08lX:%s:%s:::\n",
			nbits_from_sk( sk2 ),
			sk2->pubkey_algo,
			(ulong)keyid2[0],(ulong)keyid2[1],
			datestr_from_sk( sk2 ),
			sk2->expiredate? strtimestamp(sk2->expiredate):""
			/* fixme: add LID */
						);
	    else
		printf("ssb  %4u%c/%08lX %s\n", nbits_from_sk( sk2 ),
					   pubkey_letter( sk2->pubkey_algo ),
					   (ulong)keyid2[1],
					   datestr_from_sk( sk2 ) );
	    if( opt.fingerprint > 1 )
		fingerprint( NULL, sk2 );

	}
	else if( opt.list_sigs && node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    int sigrc;
	   char *sigstr;

	    if( !any ) { /* no user id, (maybe a revocation follows)*/
		if( sig->sig_class == 0x20 )
		    puts("[revoked]");
		else if( sig->sig_class == 0x18 )
		    puts("[key binding]");
		else if( sig->sig_class == 0x28 )
		    puts("[subkey revoked]");
		else
		    putchar('\n');
		if( opt.fingerprint )
		    fingerprint( pk, sk );
		any=1;
	    }

	    if( sig->sig_class == 0x20 || sig->sig_class == 0x28
				       || sig->sig_class == 0x30 )
	       sigstr = "rev";
	    else if( (sig->sig_class&~3) == 0x10 )
	       sigstr = "sig";
	    else if( sig->sig_class == 0x18 )
	       sigstr = "sig";
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
	   fputs( sigstr, stdout );
	    if( opt.with_colons ) {
		putchar(':');
		if( sigrc != ' ' )
		    putchar(sigrc);
		printf("::%d:%08lX%08lX:%s::::", sig->pubkey_algo,
						 (ulong)sig->keyid[0],
			   (ulong)sig->keyid[1], datestr_from_sig(sig));
	    }
	    else
		printf("%c       %08lX %s  ",
		    sigrc, (ulong)sig->keyid[1], datestr_from_sig(sig));
	    if( sigrc == '%' )
		printf("[%s] ", g10_errstr(rc) );
	    else if( sigrc == '?' )
		;
	    else if ( !opt.fast_list_mode ) {
		size_t n;
		char *p = get_user_id( sig->keyid, &n );
		if( opt.with_colons )
		    print_string( stdout, p, n, ':' );
		else
		    print_utf8_string( stdout, p, n );
		m_free(p);
	    }
	    if( opt.with_colons )
		printf(":%02x:", sig->sig_class );
	    putchar('\n');
	    /* FIXME: check or list other sigs here (subpkt PRIV_ADD_SIG)*/
	}
    }
    if( !any ) {/* oops, no user id */
	if( opt.with_colons )
	    putchar(':');
	putchar('\n');
    }
    else if( !opt.with_colons )
	putchar('\n');  /* separator line */
}



static void
fingerprint( PKT_public_key *pk, PKT_secret_key *sk )
{
    byte *array, *p;
    size_t i, n;

    p = array = pk? fingerprint_from_pk( pk, NULL, &n )
		   : fingerprint_from_sk( sk, NULL, &n );
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

