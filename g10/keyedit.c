/* keyedit.c - keyedit stuff
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
#include "ttyio.h"
#include "i18n.h"



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
 * Ask whether the user is willing to sign the key. Return true if so.
 */
static int
sign_it_p( PKT_public_cert *pkc, PKT_user_id *uid )
{
    char *answer;
    int yes;

    tty_printf("\nAre you really sure that you want to sign this key:\n\n"
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
 * Ask and remove invalid signatures that are to be removed.
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
 * This function signs the key of USERNAME with all users listed in
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
    rc=build_skc_list( locusr, &skc_list, 0, 1 );
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
	    /* ask whether we really should do anything */
	    answer = tty_get("To you want to remove some of the invalid sigs? ");
	    tty_kill_prompt();
	    if( answer_is_yes(answer) )
		remove_keysigs( keyblock, pkc_keyid, 0 );
	    m_free(answer);
	}
    }

    /* check whether we it is possible to sign this key */
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	u32 akeyid[2];

	keyid_from_skc( skc_rover->skc, akeyid );
	for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	    if( node->pkt->pkttype == PKT_USER_ID )
		skc_rover->mark = 1;
	    else if( node->pkt->pkttype == PKT_SIGNATURE
		&& (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
		if( akeyid[0] == node->pkt->pkt.signature->keyid[0]
		    && akeyid[1] == node->pkt->pkt.signature->keyid[1] ) {
		    log_info("Already signed by keyid %08lX\n",
							(ulong)akeyid[1] );
		    skc_rover->mark = 0;
		}
	    }
	}
    }
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	if( skc_rover->mark )
	    break;
    }
    if( !skc_rover ) {
	log_info("Nothing to sign\n");
	goto leave;
    }

    /* Loop over all signers and all user ids and sign */
    /* FIXME: we have to change it: Present all user-ids and
     * then ask whether all those ids shall be signed if the user
     * answers yes, go and make a 0x14 sign class packet and remove
     * old one-user-id-only-sigs (user should be noted of this
     * condition while presenting the user-ids); if he had answered
     * no, present each user-id in turn and ask which one should be signed
     * (only one) - if there is already a single-user-sig, do nothing.
     * (this is propably already out in the world) */
    for( skc_rover = skc_list; skc_rover; skc_rover = skc_rover->next ) {
	if( !skc_rover->mark )
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


/****************
 * Delete a public or secret key from a keyring.
 */
int
delete_key( const char *username, int secret )
{
    int rc = 0;
    KBNODE keyblock = NULL;
    KBNODE node;
    KBPOS kbpos;
    PKT_public_cert *pkc = NULL;
    PKT_secret_cert *skc = NULL;
    u32 keyid[2];
    int okay=0;

    /* search the userid */
    rc = secret? find_secret_keyblock_byname( &kbpos, username )
	       : find_keyblock_byname( &kbpos, username );
    if( rc ) {
	log_error("%s: user not found\n", username );
	goto leave;
    }

    /* read the keyblock */
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("%s: read problem: %s\n", username, g10_errstr(rc) );
	goto leave;
    }

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, secret? PKT_SECRET_CERT:PKT_PUBLIC_CERT );
    if( !node ) {
	log_error("Oops; key not found anymore!\n");
	rc = G10ERR_GENERAL;
	goto leave;
    }

    if( secret ) {
	skc = node->pkt->pkt.secret_cert;
	keyid_from_skc( skc, keyid );
    }
    else {
	pkc = node->pkt->pkt.public_cert;
	keyid_from_pkc( pkc, keyid );
	rc = seckey_available( keyid );
	if( !rc ) {
	    log_error(_(
	    "there is a secret key for this public key!\n"));
	    log_info(_(
	    "use option \"--delete-secret-key\" to delete it first.\n"));
	    rc = -1;
	}
	else if( rc != G10ERR_NO_SECKEY )
	    log_error("%s: get secret key: %s\n", username, g10_errstr(rc) );
	else
	    rc = 0;
    }

    if( rc )
	rc = 0;
    else if( opt.batch && secret )
	log_error(_("can't do that in batch-mode\n"));
    else if( opt.batch && opt.answer_yes )
	okay++;
    else if( opt.batch )
	log_error(_("can't do that in batch-mode without \"--yes\"\n"));
    else {
	char *p;
	size_t n;

	if( secret )
	    tty_printf("sec  %4u%c/%08lX %s   ",
		      nbits_from_skc( skc ),
		      pubkey_letter( skc->pubkey_algo ),
		      keyid[1], datestr_from_skc(skc) );
	else
	    tty_printf("pub  %4u%c/%08lX %s   ",
		      nbits_from_pkc( pkc ),
		      pubkey_letter( pkc->pubkey_algo ),
		      keyid[1], datestr_from_pkc(pkc) );
	p = get_user_id( keyid, &n );
	tty_print_string( p, n );
	m_free(p);
	tty_printf("\n\n");

	p = tty_get(_("Delete this key from the keyring? "));
	tty_kill_prompt();
	if( secret && answer_is_yes(p)) {
	    /* I think it is not required to check a passphrase; if
	     * the user is so stupid as to let others access his secret keyring
	     * (and has no backup) - it is up him to read some very
	     * basic texts about security.
	     */
	    m_free(p);
	    p = tty_get(_("This is a secret key! - really delete? "));
	}
	if( answer_is_yes(p) )
	    okay++;
	m_free(p);
    }


    if( okay ) {
	rc = delete_keyblock( &kbpos );
	if( rc ) {
	    log_error("delete_keyblock failed: %s\n", g10_errstr(rc) );
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

    /* find the userid */
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
	DEK *dek = NULL;
	STRING2KEY *s2k = m_alloc_secure( sizeof *s2k );

	tty_printf(_("Enter the new passphrase for this secret key.\n\n") );

	for(;;) {
	    s2k->mode = 1;
	    s2k->hash_algo = DIGEST_ALGO_RMD160;
	    dek = passphrase_to_dek( NULL, CIPHER_ALGO_BLOWFISH, s2k, 2 );
	    if( !dek ) {
		tty_printf(_("passphrase not correctly repeated; try again.\n"));
	    }
	    else if( !dek->keylen ) {
		rc = 0;
		tty_printf(_( "You don't want a passphrase -"
			    " this is probably a *bad* idea!\n\n"));
		answer = tty_get(_("Do you really want to do this? "));
		tty_kill_prompt();
		if( answer_is_yes(answer) )
		    changed++;
		m_free(answer);
		break;
	    }
	    else { /* okay */
		skc->protect.algo = dek->algo;
		skc->protect.s2k = *s2k;
		rc = protect_secret_key( skc, dek );
		if( rc )
		    log_error("protect_secret_key failed: %s\n", g10_errstr(rc) );
		else
		    changed++;
		break;
	    }
	}
	m_free(s2k);
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

