/* keyedit.c - keyedit stuff
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
#include <ctype.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "trustdb.h"
#include "filter.h"
#include "ttyio.h"
#include "status.h"
#include "i18n.h"

static void show_prefs( KBNODE keyblock, PKT_user_id *uid, int verbose );
static void show_key_with_all_names( KBNODE keyblock,
	    int only_marked, int with_fpr, int with_subkeys, int with_prefs );
static void show_key_and_fingerprint( KBNODE keyblock );
static void show_fingerprint( PKT_public_key *pk );
static int menu_adduid( KBNODE keyblock, KBNODE sec_keyblock );
static void menu_deluid( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int  menu_delsig( KBNODE pub_keyblock );
static void menu_delkey( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_expire( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_select_uid( KBNODE keyblock, int idx );
static int menu_select_key( KBNODE keyblock, int idx );
static int count_uids( KBNODE keyblock );
static int count_uids_with_flag( KBNODE keyblock, unsigned flag );
static int count_keys_with_flag( KBNODE keyblock, unsigned flag );
static int count_selected_uids( KBNODE keyblock );
static int count_selected_keys( KBNODE keyblock );
static int menu_revsig( KBNODE keyblock );
static int menu_revkey( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int enable_disable_key( KBNODE keyblock, int disable );

#define CONTROL_D ('D' - 'A' + 1)

#define NODFLG_BADSIG (1<<0)  /* bad signature */
#define NODFLG_NOKEY  (1<<1)  /* no public key */
#define NODFLG_SIGERR (1<<2)  /* other sig error */

#define NODFLG_MARK_A (1<<4)  /* temporary mark */

#define NODFLG_SELUID (1<<8)  /* indicate the selected userid */
#define NODFLG_SELKEY (1<<9)  /* indicate the selected key */
#define NODFLG_SELSIG (1<<10) /* indicate a selected signature */


struct sign_attrib {
    int non_exportable;
    struct revocation_reason_info *reason;
};




static int
get_keyblock_byname( KBNODE *keyblock, KBPOS *kbpos, const char *username )
{
    int rc;

    *keyblock = NULL;
    /* search the userid */
    rc = find_keyblock_byname( kbpos, username );
    if( rc ) {
	log_error(_("%s: user not found\n"), username );
	return rc;
    }

    /* read the keyblock */
    rc = read_keyblock( kbpos, keyblock );
    if( rc )
	log_error("%s: keyblock read problem: %s\n", username, g10_errstr(rc));
    else
	merge_keys_and_selfsig( *keyblock ); 

    return rc;
}


/****************
 * Print information about a signature, chek it and return true
 * if the signature is okay. NODE must be a signature packet.
 */
static int
print_and_check_one_sig( KBNODE keyblock, KBNODE node,
			 int *inv_sigs, int *no_key, int *oth_err,
			int *is_selfsig, int print_without_key )
{
    PKT_signature *sig = node->pkt->pkt.signature;
    int rc, sigrc;
    int is_rev = sig->sig_class == 0x30;

    switch( (rc = check_key_signature( keyblock, node, is_selfsig)) ) {
      case 0:
	node->flag &= ~(NODFLG_BADSIG|NODFLG_NOKEY|NODFLG_SIGERR);
	sigrc = '!';
	break;
      case G10ERR_BAD_SIGN:
	node->flag = NODFLG_BADSIG;
	sigrc = '-';
	if( inv_sigs )
	    ++*inv_sigs;
	break;
      case G10ERR_NO_PUBKEY:
      case G10ERR_UNU_PUBKEY:
	node->flag = NODFLG_NOKEY;
	sigrc = '?';
	if( no_key )
	    ++*no_key;
	break;
      default:
	node->flag = NODFLG_SIGERR;
	sigrc = '%';
	if( oth_err )
	    ++*oth_err;
	break;
    }
    if( sigrc != '?' || print_without_key ) {
	tty_printf("%s%c       %08lX %s   ",
		is_rev? "rev":"sig",
		sigrc, (ulong)sig->keyid[1], datestr_from_sig(sig));
	if( sigrc == '%' )
	    tty_printf("[%s] ", g10_errstr(rc) );
	else if( sigrc == '?' )
	    ;
	else if( *is_selfsig ) {
	    tty_printf( is_rev? _("[revocation]")
			      : _("[self-signature]") );
	}
	else {
	    size_t n;
	    char *p = get_user_id( sig->keyid, &n );
	    tty_print_utf8_string2( p, n, 40 );
	    m_free(p);
	}
	tty_printf("\n");
    }
    return (sigrc == '!');
}



/****************
 * Check the keysigs and set the flags to indicate errors.
 * Returns true if error found.
 */
static int
check_all_keysigs( KBNODE keyblock, int only_selected )
{
    KBNODE kbctx;
    KBNODE node;
    int inv_sigs = 0;
    int no_key = 0;
    int oth_err = 0;
    int has_selfsig = 0;
    int mis_selfsig = 0;
    int selected = !only_selected;
    int anyuid = 0;

    for( kbctx=NULL; (node=walk_kbnode( keyblock, &kbctx, 0)) ; ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;

	    if( only_selected )
		selected = (node->flag & NODFLG_SELUID);
	    if( selected ) {
		tty_printf("uid  ");
		tty_print_utf8_string( uid->name, uid->len );
		tty_printf("\n");
		if( anyuid && !has_selfsig )
		    mis_selfsig++;
		has_selfsig = 0;
		anyuid = 1;
	    }
	}
	else if( selected && node->pkt->pkttype == PKT_SIGNATURE
		 && ( (node->pkt->pkt.signature->sig_class&~3) == 0x10
		     || node->pkt->pkt.signature->sig_class == 0x30 )  ) {
	    int selfsig;

	    if( print_and_check_one_sig( keyblock, node, &inv_sigs,
					&no_key, &oth_err, &selfsig, 0 ) ) {
		if( selfsig )
		    has_selfsig = 1;
	    }
	    /* Hmmm: should we update the trustdb here? */
	}
    }
    if( !has_selfsig )
	mis_selfsig++;
    if( inv_sigs == 1 )
	tty_printf(_("1 bad signature\n") );
    else if( inv_sigs )
	tty_printf(_("%d bad signatures\n"), inv_sigs );
    if( no_key == 1 )
	tty_printf(_("1 signature not checked due to a missing key\n") );
    else if( no_key )
	tty_printf(_("%d signatures not checked due to missing keys\n"), no_key );
    if( oth_err == 1 )
	tty_printf(_("1 signature not checked due to an error\n") );
    else if( oth_err )
	tty_printf(_("%d signatures not checked due to errors\n"), oth_err );
    if( mis_selfsig == 1 )
	tty_printf(_("1 user ID without valid self-signature detected\n"));
    else if( mis_selfsig  )
	tty_printf(_("%d user IDs without valid self-signatures detected\n"),
								    mis_selfsig);

    return inv_sigs || no_key || oth_err || mis_selfsig;
}




static int
sign_mk_attrib( PKT_signature *sig, void *opaque )
{
    struct sign_attrib *attrib = opaque;
    byte buf[8];

    if( attrib->non_exportable ) {
	buf[0] = 0; /* not exportable */
	build_sig_subpkt( sig, SIGSUBPKT_EXPORTABLE, buf, 1 );
    }
    if( attrib->reason )
	revocation_reason_build_cb( sig, attrib->reason );

    return 0;
}



/****************
 * Loop over all locusr and and sign the uids after asking.
 * If no user id is marked, all user ids will be signed;
 * if some user_ids are marked those will be signed.
 */
static int
sign_uids( KBNODE keyblock, STRLIST locusr, int *ret_modified, int local )
{
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    PKT_secret_key *sk = NULL;
    KBNODE node, uidnode;
    PKT_public_key *primary_pk=NULL;
    int select_all = !count_selected_uids(keyblock);
    int upd_trust = 0;

    /* build a list of all signators */
    rc=build_sk_list( locusr, &sk_list, 0, 1 );
    if( rc )
	goto leave;

    /* loop over all signaturs */
    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	u32 sk_keyid[2];
	size_t n;
	char *p;

	/* we have to use a copy of the sk, because make_keysig_packet
	 * may remove the protection from sk and if we did other
	 * changes to the secret key, we would save the unprotected
	 * version */
	if( sk )
	    free_secret_key(sk);
	sk = copy_secret_key( NULL, sk_rover->sk );
	keyid_from_sk( sk, sk_keyid );
	/* set mark A for all selected user ids */
	for( node=keyblock; node; node = node->next ) {
	    if( select_all || (node->flag & NODFLG_SELUID) )
		node->flag |= NODFLG_MARK_A;
	    else
		node->flag &= ~NODFLG_MARK_A;
	}
	/* reset mark for uids which are already signed */
	uidnode = NULL;
	for( node=keyblock; node; node = node->next ) {
	    if( node->pkt->pkttype == PKT_USER_ID ) {
		uidnode = (node->flag & NODFLG_MARK_A)? node : NULL;
	    }
	    else if( uidnode && node->pkt->pkttype == PKT_SIGNATURE
		&& (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
		if( sk_keyid[0] == node->pkt->pkt.signature->keyid[0]
		    && sk_keyid[1] == node->pkt->pkt.signature->keyid[1] ) {
		    /* Fixme: see whether there is a revocation in which
		     * case we should allow to sign it again. */
		    tty_printf(_("Already signed by key %08lX\n"),
							(ulong)sk_keyid[1] );
		    uidnode->flag &= ~NODFLG_MARK_A; /* remove mark */
		}
	    }
	}
	/* check whether any uids are left for signing */
	if( !count_uids_with_flag(keyblock, NODFLG_MARK_A) ) {
	    tty_printf(_("Nothing to sign with key %08lX\n"),
						  (ulong)sk_keyid[1] );
	    continue;
	}
	/* Ask whether we really should sign these user id(s) */
	tty_printf("\n");
	show_key_with_all_names( keyblock, 1, 1, 0, 0 );
	tty_printf("\n");
	tty_printf(_(
	     "Are you really sure that you want to sign this key\n"
	     "with your key: \""));
	p = get_user_id( sk_keyid, &n );
	tty_print_utf8_string( p, n );
	m_free(p); p = NULL;
	tty_printf("\"\n\n");

	if( local )
	    tty_printf(
		  _("The signature will be marked as non-exportable.\n\n"));


	if( opt.batch && opt.answer_yes )
	    ;
	else if( !cpr_get_answer_is_yes("sign_uid.okay", _("Really sign? ")) )
	    continue;
	/* now we can sign the user ids */
      reloop: /* (must use this, because we are modifing the list) */
	primary_pk = NULL;
	for( node=keyblock; node; node = node->next ) {
	    if( node->pkt->pkttype == PKT_PUBLIC_KEY )
		primary_pk = node->pkt->pkt.public_key;
	    else if( node->pkt->pkttype == PKT_USER_ID
		     && (node->flag & NODFLG_MARK_A) ) {
		PACKET *pkt;
		PKT_signature *sig;
		struct sign_attrib attrib;

		assert( primary_pk );
		memset( &attrib, 0, sizeof attrib );
		attrib.non_exportable = local;
		node->flag &= ~NODFLG_MARK_A;
		rc = make_keysig_packet( &sig, primary_pk,
					       node->pkt->pkt.user_id,
					       NULL,
					       sk,
					       0x10, 0,
					       sign_mk_attrib,
					       &attrib );
		if( rc ) {
		    log_error(_("signing failed: %s\n"), g10_errstr(rc));
		    goto leave;
		}
		*ret_modified = 1; /* we changed the keyblock */
		upd_trust = 1;

		pkt = m_alloc_clear( sizeof *pkt );
		pkt->pkttype = PKT_SIGNATURE;
		pkt->pkt.signature = sig;
		insert_kbnode( node, new_kbnode(pkt), PKT_SIGNATURE );
		goto reloop;
	    }
	}
    } /* end loop over signators */
    if( upd_trust && primary_pk ) {
	rc = clear_trust_checked_flag( primary_pk );
    }


  leave:
    release_sk_list( sk_list );
    if( sk )
	free_secret_key(sk);
    return rc;
}



/****************
 * Change the passphrase of the primary and all secondary keys.
 * We use only one passphrase for all keys.
 */
static int
change_passphrase( KBNODE keyblock )
{
    int rc = 0;
    int changed=0;
    KBNODE node;
    PKT_secret_key *sk;
    char *passphrase = NULL;
    int no_primary_secrets = 0;

    node = find_kbnode( keyblock, PKT_SECRET_KEY );
    if( !node ) {
	log_error("Oops; secret key not found anymore!\n");
	goto leave;
    }
    sk = node->pkt->pkt.secret_key;

    switch( is_secret_key_protected( sk ) ) {
      case -1:
	rc = G10ERR_PUBKEY_ALGO;
	break;
      case 0:
	tty_printf(_("This key is not protected.\n"));
	break;
      default:
	if( sk->protect.s2k.mode == 1001 ) {
	    tty_printf(_("Secret parts of primary key are not available.\n"));
	    no_primary_secrets = 1;
	}
	else {
	    tty_printf(_("Key is protected.\n"));
	    rc = check_secret_key( sk, 0 );
	    if( !rc )
		passphrase = get_last_passphrase();
	}
	break;
    }

    /* unprotect all subkeys (use the supplied passphrase or ask)*/
    for(node=keyblock; !rc && node; node = node->next ) {
	if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    PKT_secret_key *subsk = node->pkt->pkt.secret_key;
	    set_next_passphrase( passphrase );
	    rc = check_secret_key( subsk, 0 );
	    if( !rc && !passphrase )
		passphrase = get_last_passphrase();
	}
    }

    if( rc )
	tty_printf(_("Can't edit this key: %s\n"), g10_errstr(rc));
    else {
	DEK *dek = NULL;
	STRING2KEY *s2k = m_alloc_secure( sizeof *s2k );

	tty_printf(_("Enter the new passphrase for this secret key.\n\n") );

	set_next_passphrase( NULL );
	for(;;) {
	    s2k->mode = opt.s2k_mode;
	    s2k->hash_algo = opt.s2k_digest_algo;
	    dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo, s2k, 2 );
	    if( !dek ) {
		tty_printf(_("passphrase not correctly repeated; try again.\n"));
	    }
	    else if( !dek->keylen ) {
		rc = 0;
		tty_printf(_( "You don't want a passphrase -"
			    " this is probably a *bad* idea!\n\n"));
		if( cpr_get_answer_is_yes("change_passwd.empty.okay",
			       _("Do you really want to do this? ")))
		    changed++;
		break;
	    }
	    else { /* okay */
		rc = 0;
		if( !no_primary_secrets ) {
		    sk->protect.algo = dek->algo;
		    sk->protect.s2k = *s2k;
		    rc = protect_secret_key( sk, dek );
		}
		for(node=keyblock; !rc && node; node = node->next ) {
		    if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
			PKT_secret_key *subsk = node->pkt->pkt.secret_key;
			subsk->protect.algo = dek->algo;
			subsk->protect.s2k = *s2k;
			rc = protect_secret_key( subsk, dek );
		    }
		}
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

  leave:
    m_free( passphrase );
    set_next_passphrase( NULL );
    return changed && !rc;
}


/****************
 * There are some keys out (due to a bug in gnupg), where the sequence
 * of the packets is wrong.  This function fixes that.
 * Returns: true if the keyblock has been fixed.
 *
 * Note:  This function does not work if there is more than one user ID.
 */
static int
fix_keyblock( KBNODE keyblock )
{
    KBNODE node, last, subkey;
    int fixed=0;

    /* locate key signatures of class 0x10..0x13 behind sub key packets */
    for( subkey=last=NULL, node = keyblock; node;
					    last=node, node = node->next ) {
	switch( node->pkt->pkttype ) {
	  case PKT_PUBLIC_SUBKEY:
	  case PKT_SECRET_SUBKEY:
	    if( !subkey )
		subkey = last; /* actually it is the one before the subkey */
	    break;
	  case PKT_SIGNATURE:
	    if( subkey ) {
		PKT_signature *sig = node->pkt->pkt.signature;
		if( sig->sig_class >= 0x10 && sig->sig_class <= 0x13 ) {
		    log_info(_(
			"moving a key signature to the correct place\n"));
		    last->next = node->next;
		    node->next = subkey->next;
		    subkey->next = node;
		    node = last;
		    fixed=1;
		}
	    }
	    break;
	  default: break;
	}
    }

    return fixed;
}

/****************
 * Menu driven key editor.  If sign_mode is true semi-automatical signing
 * will be performed. commands are ignore in this case
 *
 * Note: to keep track of some selection we use node->mark MARKBIT_xxxx.
 */

void
keyedit_menu( const char *username, STRLIST locusr, STRLIST commands,
						    int sign_mode )
{
    enum cmdids { cmdNONE = 0,
	   cmdQUIT, cmdHELP, cmdFPR, cmdLIST, cmdSELUID, cmdCHECK, cmdSIGN,
	   cmdLSIGN, cmdREVSIG, cmdREVKEY, cmdDELSIG,
	   cmdDEBUG, cmdSAVE, cmdADDUID, cmdDELUID, cmdADDKEY, cmdDELKEY,
	   cmdTOGGLE, cmdSELKEY, cmdPASSWD, cmdTRUST, cmdPREF, cmdEXPIRE,
           cmdENABLEKEY, cmdDISABLEKEY,  cmdSHOWPREF,
	   cmdINVCMD, cmdNOP };
    static struct { const char *name;
		    enum cmdids id;
		    int need_sk;
		    int not_with_sk;
		    int signmode;
		    const char *desc;
		  } cmds[] = {
	{ N_("quit")    , cmdQUIT      , 0,0,1, N_("quit this menu") },
	{ N_("q")       , cmdQUIT      , 0,0,1, NULL   },
	{ N_("save")    , cmdSAVE      , 0,0,1, N_("save and quit") },
	{ N_("help")    , cmdHELP      , 0,0,1, N_("show this help") },
	{    "?"        , cmdHELP      , 0,0,1, NULL   },
	{ N_("fpr")     , cmdFPR       , 0,0,1, N_("show fingerprint") },
	{ N_("list")    , cmdLIST      , 0,0,1, N_("list key and user IDs") },
	{ N_("l")       , cmdLIST      , 0,0,1, NULL   },
	{ N_("uid")     , cmdSELUID    , 0,0,1, N_("select user ID N") },
	{ N_("key")     , cmdSELKEY    , 0,0,0, N_("select secondary key N") },
	{ N_("check")   , cmdCHECK     , 0,0,1, N_("list signatures") },
	{ N_("c")       , cmdCHECK     , 0,0,1, NULL },
	{ N_("sign")    , cmdSIGN      , 0,1,1, N_("sign the key") },
	{ N_("s")       , cmdSIGN      , 0,1,1, NULL },
	{ N_("lsign")   , cmdLSIGN     , 0,1,1, N_("sign the key locally") },
	{ N_("debug")   , cmdDEBUG     , 0,0,0, NULL },
	{ N_("adduid")  , cmdADDUID    , 1,1,0, N_("add a user ID") },
	{ N_("deluid")  , cmdDELUID    , 0,1,0, N_("delete user ID") },
	{ N_("addkey")  , cmdADDKEY    , 1,1,0, N_("add a secondary key") },
	{ N_("delkey")  , cmdDELKEY    , 0,1,0, N_("delete a secondary key") },
	{ N_("delsig")  , cmdDELSIG    , 0,1,0, N_("delete signatures") },
	{ N_("expire")  , cmdEXPIRE    , 1,1,0, N_("change the expire date") },
	{ N_("toggle")  , cmdTOGGLE    , 1,0,0, N_("toggle between secret "
						   "and public key listing") },
	{ N_("t"     )  , cmdTOGGLE    , 1,0,0, NULL },
	{ N_("pref")    , cmdPREF      , 0,1,0, N_("list preferences") },
	{ N_("showpref"), cmdSHOWPREF  , 0,1,0, N_("list preferences") },
	{ N_("passwd")  , cmdPASSWD    , 1,1,0, N_("change the passphrase") },
	{ N_("trust")   , cmdTRUST     , 0,1,0, N_("change the ownertrust") },
	{ N_("revsig")  , cmdREVSIG    , 0,1,0, N_("revoke signatures") },
	{ N_("revkey")  , cmdREVKEY    , 1,1,0, N_("revoke a secondary key") },
	{ N_("disable") , cmdDISABLEKEY, 0,1,0, N_("disable a key") },
	{ N_("enable")  , cmdENABLEKEY , 0,1,0, N_("enable a key") },

    { NULL, cmdNONE } };
    enum cmdids cmd = 0;
    int rc = 0;
    KBNODE keyblock = NULL;
    KBPOS keyblockpos;
    KBNODE sec_keyblock = NULL;
    KBPOS sec_keyblockpos;
    KBNODE cur_keyblock;
    char *answer = NULL;
    int redisplay = 1;
    int modified = 0;
    int sec_modified = 0;
    int toggle;
    int have_commands = !!commands;

    if ( opt.command_fd != -1 )
        ;
    else if( opt.batch && !have_commands  ) {
	log_error(_("can't do that in batchmode\n"));
	goto leave;
    }

    if( sign_mode ) {
	commands = NULL;
	append_to_strlist( &commands, sign_mode == 1? "sign":"lsign" );
	have_commands = 1;
    }


    if( !sign_mode ) {
	/* first try to locate it as secret key */
	rc = find_secret_keyblock_byname( &sec_keyblockpos, username );
	if( !rc ) {
	    rc = read_keyblock( &sec_keyblockpos, &sec_keyblock );
	    if( rc ) {
		log_error("%s: secret keyblock read problem: %s\n",
						username, g10_errstr(rc));
		goto leave;
	    }
	    merge_keys_and_selfsig( sec_keyblock );
	    if( fix_keyblock( sec_keyblock ) )
		sec_modified++;
	}
    }

    /* and now get the public key */
    rc = get_keyblock_byname( &keyblock, &keyblockpos, username );
    if( rc )
	goto leave;
    if( fix_keyblock( keyblock ) )
	modified++;
    if( collapse_uids( &keyblock ) )
	modified++;

    if( sec_keyblock ) { /* check that they match */
	/* fixme: check that they both match */
	tty_printf(_("Secret key is available.\n"));
    }

    toggle = 0;
    cur_keyblock = keyblock;
    for(;;) { /* main loop */
	int i, arg_number;
	char *p;

	tty_printf("\n");
	if( redisplay ) {
	    show_key_with_all_names( cur_keyblock, 0, 0, 1, 0 );
	    tty_printf("\n");
	    redisplay = 0;
	}
	do {
	    m_free(answer);
	    if( have_commands ) {
		if( commands ) {
		    answer = m_strdup( commands->d );
		    commands = commands->next;
		}
		else if( opt.batch ) {
		    answer = m_strdup("quit");
		}
		else
		    have_commands = 0;
	    }
	    if( !have_commands ) {
		answer = cpr_get_no_help("keyedit.prompt", _("Command> "));
		cpr_kill_prompt();
	    }
	    trim_spaces(answer);
	} while( *answer == '#' );

	arg_number = 0; /* Yes, here is the init which egcc complains about*/
	if( !*answer )
	    cmd = cmdLIST;
	else if( *answer == CONTROL_D )
	    cmd = cmdQUIT;
	else if( isdigit( *answer ) ) {
	    cmd = cmdSELUID;
	    arg_number = atoi(answer);
	}
	else {
	    if( (p=strchr(answer,' ')) ) {
		*p++ = 0;
		trim_spaces(answer);
		trim_spaces(p);
		arg_number = atoi(p);
	    }

	    for(i=0; cmds[i].name; i++ ) {
		if( !stricmp( answer, cmds[i].name ) )
		    break;
	    }
	    if( sign_mode && !cmds[i].signmode )
		cmd = cmdINVCMD;
	    else if( cmds[i].need_sk && !sec_keyblock ) {
		tty_printf(_("Need the secret key to do this.\n"));
		cmd = cmdNOP;
	    }
	    else if( cmds[i].not_with_sk && sec_keyblock && toggle ) {
		tty_printf(_("Please use the command \"toggle\" first.\n"));
		cmd = cmdNOP;
	    }
	    else
		cmd = cmds[i].id;
	}
	switch( cmd )  {
	  case cmdHELP:
	    for(i=0; cmds[i].name; i++ ) {
		if( sign_mode && !cmds[i].signmode )
		    ;
		else if( cmds[i].need_sk && !sec_keyblock )
		    ; /* skip if we do not have the secret key */
		else if( cmds[i].desc )
		    tty_printf("%-10s %s\n", cmds[i].name, _(cmds[i].desc) );
	    }
	    break;

	  case cmdLIST:
	    redisplay = 1;
	    break;

	  case cmdFPR:
	    show_key_and_fingerprint( keyblock );
	    break;

	  case cmdSELUID:
	    if( menu_select_uid( cur_keyblock, arg_number ) )
		redisplay = 1;
	    break;

	  case cmdSELKEY:
	    if( menu_select_key( cur_keyblock, arg_number ) )
		redisplay = 1;
	    break;

	  case cmdCHECK:
	    /* we can only do this with the public key becuase the
	     * check functions can't cope with secret keys and it
	     * is questionable whether this would make sense at all */
	    check_all_keysigs( keyblock, count_selected_uids(keyblock) );
	    break;

	  case cmdSIGN: /* sign (only the public key) */
	  case cmdLSIGN: /* sign (only the public key) */
	    if( count_uids(keyblock) > 1 && !count_selected_uids(keyblock) ) {
		if( !cpr_get_answer_is_yes("keyedit.sign_all.okay",
					   _("Really sign all user IDs? ")) ) {
		    tty_printf(_("Hint: Select the user IDs to sign\n"));
		    break;
		}
	    }
	    if( !sign_uids( keyblock, locusr, &modified, cmd == cmdLSIGN )
		&& sign_mode )
		goto do_cmd_save;
	    /* Actually we should do a update_trust_record() here so that
	     * the trust gets displayed correctly. however this is not possible
	     * because we would have to save the keyblock first - something
	     * we don't want to do without an explicit save command.
	     */
	    break;

	  case cmdDEBUG:
	    dump_kbnode( cur_keyblock );
	    break;

	  case cmdTOGGLE:
	    toggle = !toggle;
	    cur_keyblock = toggle? sec_keyblock : keyblock;
	    redisplay = 1;
	    break;

	  case cmdADDUID:
	    if( menu_adduid( keyblock, sec_keyblock ) ) {
		redisplay = 1;
		sec_modified = modified = 1;
		/* must update the trustdb already here, so that preferences
		 * get listed correctly */
		rc = update_trust_record( keyblock, 0, NULL );
		if( rc ) {
		    log_error(_("update of trustdb failed: %s\n"),
				g10_errstr(rc) );
		    rc = 0;
		}
	    }
	    break;

	  case cmdDELUID: {
		int n1;

		if( !(n1=count_selected_uids(keyblock)) )
		    tty_printf(_("You must select at least one user ID.\n"));
		else if( count_uids(keyblock) - n1 < 1 )
		    tty_printf(_("You can't delete the last user ID!\n"));
		else if( cpr_get_answer_is_yes(
			    "keyedit.remove.uid.okay",
			n1 > 1? _("Really remove all selected user IDs? ")
			      : _("Really remove this user ID? ")
		       ) ) {
		    menu_deluid( keyblock, sec_keyblock );
		    redisplay = 1;
		    modified = 1;
		    if( sec_keyblock )
		       sec_modified = 1;
		}
	    }
	    break;

	  case cmdDELSIG: {
		int n1;

		if( !(n1=count_selected_uids(keyblock)) )
		    tty_printf(_("You must select at least one user ID.\n"));
		else if( menu_delsig( keyblock ) ) {
		    /* no redisplay here, because it may scroll away some
		     * status output of delsig */
		    modified = 1;
		}
	    }
	    break;

	  case cmdADDKEY:
	    if( generate_subkeypair( keyblock, sec_keyblock ) ) {
		redisplay = 1;
		sec_modified = modified = 1;
	    }
	    break;


	  case cmdDELKEY: {
		int n1;

		if( !(n1=count_selected_keys( keyblock )) )
		    tty_printf(_("You must select at least one key.\n"));
		else if( sec_keyblock && !cpr_get_answer_is_yes(
			    "keyedit.remove.subkey.okay",
		       n1 > 1?
			_("Do you really want to delete the selected keys? "):
			_("Do you really want to delete this key? ")
		       ))
		    ;
		else {
		    menu_delkey( keyblock, sec_keyblock );
		    redisplay = 1;
		    modified = 1;
		    if( sec_keyblock )
		       sec_modified = 1;
		}
	    }
	    break;

	  case cmdREVKEY: {
		int n1;

		if( !(n1=count_selected_keys( keyblock )) )
		    tty_printf(_("You must select at least one key.\n"));
		else if( sec_keyblock && !cpr_get_answer_is_yes(
			    "keyedit.revoke.subkey.okay",
		       n1 > 1?
			_("Do you really want to revoke the selected keys? "):
			_("Do you really want to revoke this key? ")
		       ))
		    ;
		else {
		    if( menu_revkey( keyblock, sec_keyblock ) ) {
			modified = 1;
			/*sec_modified = 1;*/
		    }
		    redisplay = 1;
		}
	    }
	    break;

	  case cmdEXPIRE:
	    if( menu_expire( keyblock, sec_keyblock ) ) {
		merge_keys_and_selfsig( sec_keyblock );
		merge_keys_and_selfsig( keyblock );
		sec_modified = 1;
		modified = 1;
		redisplay = 1;
	    }
	    break;

	  case cmdPASSWD:
	    if( change_passphrase( sec_keyblock ) )
		sec_modified = 1;
	    break;

	  case cmdTRUST:
	    show_key_with_all_names( keyblock, 0, 0, 1, 0 );
	    tty_printf("\n");
	    if( edit_ownertrust( find_kbnode( keyblock,
		      PKT_PUBLIC_KEY )->pkt->pkt.public_key->local_id, 1 ) )
		redisplay = 1;
	    /* we don't need to set modified here, as the trustvalues
	     * are updated immediately */
	    break;

	  case cmdPREF:
	    show_key_with_all_names( keyblock, 0, 0, 0, 1 );
	    break;

	  case cmdSHOWPREF:
	    show_key_with_all_names( keyblock, 0, 0, 0, 2 );
	    break;

	  case cmdNOP:
	    break;

	  case cmdREVSIG:
	    if( menu_revsig( keyblock ) ) {
		redisplay = 1;
		modified = 1;
	    }
	    break;

	  case cmdENABLEKEY:
	  case cmdDISABLEKEY:
	    if( enable_disable_key( keyblock, cmd == cmdDISABLEKEY ) ) {
		redisplay = 1;
		modified = 1;
	    }
	    break;

	  case cmdQUIT:
	    if( have_commands )
		goto leave;
	    if( !modified && !sec_modified )
		goto leave;
	    if( !cpr_get_answer_is_yes("keyedit.save.okay",
					_("Save changes? ")) ) {
		if( cpr_enabled()
		    || cpr_get_answer_is_yes("keyedit.cancel.okay",
					     _("Quit without saving? ")) )
		    goto leave;
		break;
	    }
	    /* fall thru */
	  case cmdSAVE:
	  do_cmd_save:
	    if( modified || sec_modified  ) {
		if( modified ) {
		    rc = update_keyblock( &keyblockpos, keyblock );
		    if( rc ) {
			log_error(_("update failed: %s\n"), g10_errstr(rc) );
			break;
		    }
		}
		if( sec_modified ) {
		    rc = update_keyblock( &sec_keyblockpos, sec_keyblock );
		    if( rc ) {
			log_error(_("update secret failed: %s\n"),
							    g10_errstr(rc) );
			break;
		    }
		}
	    }
	    else
		tty_printf(_("Key not changed so no update needed.\n"));
	    /* TODO: we should keep track whether we have changed
	     *	     something relevant to the trustdb */
	    if( !modified && sign_mode )
		rc = 0; /* we can skip at least in this case */
	    else
		rc = update_trust_record( keyblock, 0, NULL );
	    if( rc )
		log_error(_("update of trustdb failed: %s\n"),
			    g10_errstr(rc) );
	    goto leave;

	  case cmdINVCMD:
	  default:
	    tty_printf("\n");
	    tty_printf(_("Invalid command  (try \"help\")\n"));
	    break;
	}
    } /* end main loop */

  leave:
    release_kbnode( keyblock );
    release_kbnode( sec_keyblock );
    m_free(answer);
}


/****************
 * show preferences of a public keyblock.
 */
static void
show_prefs( KBNODE keyblock, PKT_user_id *uid, int verbose )
{
    KBNODE node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
    PKT_public_key *pk;
    byte *p;
    int i;
    size_t n;
    byte namehash[20];

    if( !node )
	return; /* is a secret keyblock */
    pk = node->pkt->pkt.public_key;
    if( !pk->local_id ) {
	log_error("oops: no LID\n");
	return;
    }

    if( uid->photo )
	rmd160_hash_buffer( namehash, uid->photo, uid->photolen );
    else
	rmd160_hash_buffer( namehash, uid->name, uid->len );

    p = get_pref_data( pk->local_id, namehash, &n );
    if( !p )
	return;

    if (verbose) {
        int any, des_seen=0;

        tty_printf ("     Cipher: ");
        for(i=any=0; i < n; i+=2 ) {
            if( p[i] == PREFTYPE_SYM ) {
                const char *s = cipher_algo_to_string (p[i+1]);
                
                if (any)
                    tty_printf (", ");
                any = 1;
                /* We don't want to display strings for experimental algos */
                if (s && p[i+1] < 100 )
                    tty_printf ("%s", s );
                else
                    tty_printf ("[%d]", p[i+1]);
                if (p[i+1] == CIPHER_ALGO_3DES )
                    des_seen = 1;
            }    
        }
        if (!des_seen) {
            if (any)
                tty_printf (", ");
            tty_printf ("3DES");
        }
        tty_printf ("\n     Hash: ");
        for(i=any=0; i < n; i+=2 ) {
            if( p[i] == PREFTYPE_HASH ) {
                const char *s = digest_algo_to_string (p[i+1]);
                
                if (any)
                    tty_printf (", ");
                any = 1;
                /* We don't want to display strings for experimental algos */
                if (s && p[i+1] < 100 )
                    tty_printf ("%s", s );
                else
                    tty_printf ("[%d]", p[i+1]);
            }    
        }
        tty_printf("\n");
    }
    else {
        tty_printf("    ");
        for(i=0; i < n; i+=2 ) {
            if( p[i] )
                tty_printf( " %c%d", p[i] == PREFTYPE_SYM   ? 'S' :
                                     p[i] == PREFTYPE_HASH  ? 'H' :
                                     p[i] == PREFTYPE_COMPR ? 'Z':'?', p[i+1]);
        }
        tty_printf("\n");
    }

    m_free(p);
}


/****************
 * Display the key a the user ids, if only_marked is true, do only
 * so for user ids with mark A flag set and dont display the index number
 */
static void
show_key_with_all_names( KBNODE keyblock, int only_marked,
			 int with_fpr, int with_subkeys, int with_prefs )
{
    KBNODE node;
    int i, rc;

    /* the keys */
    for( node = keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || (with_subkeys && node->pkt->pkttype == PKT_PUBLIC_SUBKEY) ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;
	    int otrust=0, trust=0;

	    if( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
		/* do it here, so that debug messages don't clutter the
		 * output */
		trust = query_trust_info(pk, NULL);
		otrust = get_ownertrust_info( pk->local_id );
	    }

	    tty_printf(_("%s%c %4u%c/%08lX  created: %s expires: %s"),
			  node->pkt->pkttype == PKT_PUBLIC_KEY? "pub":"sub",
			  (node->flag & NODFLG_SELKEY)? '*':' ',
			  nbits_from_pk( pk ),
			  pubkey_letter( pk->pubkey_algo ),
			  (ulong)keyid_from_pk(pk,NULL),
			  datestr_from_pk(pk),
			  expirestr_from_pk(pk) );
	    if( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
		tty_printf(_(" trust: %c/%c"), otrust, trust );
		if( node->pkt->pkttype == PKT_PUBLIC_KEY
		    && (get_ownertrust( pk->local_id )&TRUST_FLAG_DISABLED)) {
		    tty_printf("\n*** ");
		    tty_printf(_("This key has been disabled"));
		}

		if( with_fpr  ) {
		    tty_printf("\n");
		    show_fingerprint( pk );
		}
	    }
	    tty_printf("\n");
	}
	else if( node->pkt->pkttype == PKT_SECRET_KEY
	    || (with_subkeys && node->pkt->pkttype == PKT_SECRET_SUBKEY) ) {
	    PKT_secret_key *sk = node->pkt->pkt.secret_key;
	    tty_printf(_("%s%c %4u%c/%08lX  created: %s expires: %s"),
			  node->pkt->pkttype == PKT_SECRET_KEY? "sec":"ssb",
			  (node->flag & NODFLG_SELKEY)? '*':' ',
			  nbits_from_sk( sk ),
			  pubkey_letter( sk->pubkey_algo ),
			  (ulong)keyid_from_sk(sk,NULL),
			  datestr_from_sk(sk),
			  expirestr_from_sk(sk) );
	    tty_printf("\n");
	}
	else if( with_subkeys && node->pkt->pkttype == PKT_SIGNATURE
		 && node->pkt->pkt.signature->sig_class == 0x28       ) {
	    PKT_signature *sig = node->pkt->pkt.signature;

	    rc = check_key_signature( keyblock, node, NULL );
	    if( !rc )
		tty_printf( _("rev! subkey has been revoked: %s\n"),
			    datestr_from_sig( sig ) );
	    else if( rc == G10ERR_BAD_SIGN )
		tty_printf( _("rev- faked revocation found\n") );
	    else if( rc )
		tty_printf( _("rev? problem checking revocation: %s\n"),
							 g10_errstr(rc) );
	}
    }
    /* the user ids */
    i = 0;
    for( node = keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;
	    ++i;
	    if( !only_marked || (only_marked && (node->flag & NODFLG_MARK_A))){
		if( only_marked )
		   tty_printf("     ");
		else if( node->flag & NODFLG_SELUID )
		   tty_printf("(%d)* ", i);
		else if( uid->is_primary )
		   tty_printf("(%d). ", i);
		else
		   tty_printf("(%d)  ", i);
                if ( uid->is_revoked )
                    tty_printf ("[revoked] ");
		tty_print_utf8_string( uid->name, uid->len );
		tty_printf("\n");
		if( with_prefs )
		    show_prefs( keyblock, uid, with_prefs == 2 );
	    }
	}
    }
}

static void
show_key_and_fingerprint( KBNODE keyblock )
{
    KBNODE node;
    PKT_public_key *pk = NULL;

    for( node = keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
	    pk = node->pkt->pkt.public_key;
	    tty_printf("pub  %4u%c/%08lX %s ",
			  nbits_from_pk( pk ),
			  pubkey_letter( pk->pubkey_algo ),
			  (ulong)keyid_from_pk(pk,NULL),
			  datestr_from_pk(pk) );
	}
	else if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;
	    tty_print_utf8_string( uid->name, uid->len );
	    break;
	}
    }
    tty_printf("\n");
    if( pk )
	show_fingerprint( pk );
}


static void
show_fingerprint( PKT_public_key *pk )
{
    byte array[MAX_FINGERPRINT_LEN], *p;
    size_t i, n;

    fingerprint_from_pk( pk, array, &n );
    p = array;
    tty_printf(_("             Fingerprint:"));
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
}


/****************
 * Ask for a new user id , do the selfsignature and put it into
 * both keyblocks.
 * Return true if there is a new user id
 */
static int
menu_adduid( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    PKT_user_id *uid;
    PKT_public_key *pk=NULL;
    PKT_secret_key *sk=NULL;
    PKT_signature *sig=NULL;
    PACKET *pkt;
    KBNODE node;
    KBNODE pub_where=NULL, sec_where=NULL;
    int rc;

    uid = generate_user_id();
    if( !uid )
	return 0;

    for( node = pub_keyblock; node; pub_where = node, node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY )
	    pk = node->pkt->pkt.public_key;
	else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break;
    }
    if( !node ) /* no subkey */
	pub_where = NULL;
    for( node = sec_keyblock; node; sec_where = node, node = node->next ) {
	if( node->pkt->pkttype == PKT_SECRET_KEY )
	    sk = copy_secret_key( NULL, node->pkt->pkt.secret_key);
	else if( node->pkt->pkttype == PKT_SECRET_SUBKEY )
	    break;
    }
    if( !node ) /* no subkey */
	sec_where = NULL;
    assert(pk && sk );

    rc = make_keysig_packet( &sig, pk, uid, NULL, sk, 0x13, 0,
			     keygen_add_std_prefs, pk );
    free_secret_key( sk );
    if( rc ) {
	log_error("signing failed: %s\n", g10_errstr(rc) );
	free_user_id(uid);
	return 0;
    }

    /* insert/append to secret keyblock */
    pkt = m_alloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = copy_user_id(NULL, uid);
    node = new_kbnode(pkt);
    if( sec_where )
	insert_kbnode( sec_where, node, 0 );
    else
	add_kbnode( sec_keyblock, node );
    pkt = m_alloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = copy_signature(NULL, sig);
    if( sec_where )
	insert_kbnode( node, new_kbnode(pkt), 0 );
    else
	add_kbnode( sec_keyblock, new_kbnode(pkt) );
    /* insert/append to public keyblock */
    pkt = m_alloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = uid;
    node = new_kbnode(pkt);
    if( pub_where )
	insert_kbnode( pub_where, node, 0 );
    else
	add_kbnode( pub_keyblock, node );
    pkt = m_alloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = copy_signature(NULL, sig);
    if( pub_where )
	insert_kbnode( node, new_kbnode(pkt), 0 );
    else
	add_kbnode( pub_keyblock, new_kbnode(pkt) );
    return 1;
}


/****************
 * Remove all selceted userids from the keyrings
 */
static void
menu_deluid( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    KBNODE node;
    int selected=0;

    for( node = pub_keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    selected = node->flag & NODFLG_SELUID;
	    if( selected ) {
		delete_kbnode( node );
		if( sec_keyblock ) {
		    KBNODE snode;
		    int s_selected = 0;
		    PKT_user_id *uid = node->pkt->pkt.user_id;
		    for( snode = sec_keyblock; snode; snode = snode->next ) {
			if( snode->pkt->pkttype == PKT_USER_ID ) {
			    PKT_user_id *suid = snode->pkt->pkt.user_id;

			    s_selected =
				(uid->len == suid->len
				 && !memcmp( uid->name, suid->name, uid->len));
			    if( s_selected )
				delete_kbnode( snode );
			}
			else if( s_selected
				 && snode->pkt->pkttype == PKT_SIGNATURE )
			    delete_kbnode( snode );
			else if( snode->pkt->pkttype == PKT_SECRET_SUBKEY )
			    s_selected = 0;
		    }
		}
	    }
	}
	else if( selected && node->pkt->pkttype == PKT_SIGNATURE )
	    delete_kbnode( node );
	else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    selected = 0;
    }
    commit_kbnode( &pub_keyblock );
    if( sec_keyblock )
	commit_kbnode( &sec_keyblock );
}


static int
menu_delsig( KBNODE pub_keyblock )
{
    KBNODE node;
    PKT_user_id *uid = NULL;
    int changed=0;

    for( node = pub_keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    uid = (node->flag & NODFLG_SELUID)? node->pkt->pkt.user_id : NULL;
	}
	else if( uid && node->pkt->pkttype == PKT_SIGNATURE ) {
	   int okay, valid, selfsig, inv_sig, no_key, other_err;

	    tty_printf("uid  ");
	    tty_print_utf8_string( uid->name, uid->len );
	    tty_printf("\n");

	   okay = inv_sig = no_key = other_err = 0;
	    valid = print_and_check_one_sig( pub_keyblock, node,
					    &inv_sig, &no_key, &other_err,
					    &selfsig, 1 );

	   if( valid )
	       okay = cpr_get_answer_yes_no_quit(
		   "keyedit.delsig.valid",
		   _("Delete this good signature? (y/N/q)"));
	   else if( inv_sig || other_err )
	       okay = cpr_get_answer_yes_no_quit(
		   "keyedit.delsig.invalid",
		   _("Delete this invalid signature? (y/N/q)"));
	   else if( no_key )
	       okay = cpr_get_answer_yes_no_quit(
		   "keyedit.delsig.unknown",
		   _("Delete this unknown signature? (y/N/q)"));

	    if( okay == -1 )
		break;
	   if( okay && selfsig && !cpr_get_answer_is_yes(
			       "keyedit.delsig.selfsig",
			      _("Really delete this self-signature? (y/N)") ))
		okay = 0;
	    if( okay ) {
		delete_kbnode( node );
		changed++;
	    }

	}
	else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    uid = NULL;
    }

    if( changed ) {
	commit_kbnode( &pub_keyblock );
	tty_printf( changed == 1? _("Deleted %d signature.\n")
				: _("Deleted %d signatures.\n"), changed );
    }
    else
	tty_printf( _("Nothing deleted.\n") );

    return changed;
}


/****************
 * Remove some of the secondary keys
 */
static void
menu_delkey( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    KBNODE node;
    int selected=0;

    for( node = pub_keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    selected = node->flag & NODFLG_SELKEY;
	    if( selected ) {
		delete_kbnode( node );
		if( sec_keyblock ) {
		    KBNODE snode;
		    int s_selected = 0;
		    u32 ki[2];

		    keyid_from_pk( node->pkt->pkt.public_key, ki );
		    for( snode = sec_keyblock; snode; snode = snode->next ) {
			if( snode->pkt->pkttype == PKT_SECRET_SUBKEY ) {
			    u32 ki2[2];

			    keyid_from_sk( snode->pkt->pkt.secret_key, ki2 );
			    s_selected = (ki[0] == ki2[0] && ki[1] == ki2[1]);
			    if( s_selected )
				delete_kbnode( snode );
			}
			else if( s_selected
				 && snode->pkt->pkttype == PKT_SIGNATURE )
			    delete_kbnode( snode );
			else
			    s_selected = 0;
		    }
		}
	    }
	}
	else if( selected && node->pkt->pkttype == PKT_SIGNATURE )
	    delete_kbnode( node );
	else
	    selected = 0;
    }
    commit_kbnode( &pub_keyblock );
    if( sec_keyblock )
	commit_kbnode( &sec_keyblock );
}



static int
menu_expire( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    int n1, signumber, rc;
    u32 expiredate;
    int mainkey=0;
    PKT_secret_key *sk;    /* copy of the main sk */
    PKT_public_key *main_pk, *sub_pk;
    PKT_user_id *uid;
    KBNODE node;
    u32 keyid[2];

    if( count_selected_keys( sec_keyblock ) ) {
	tty_printf(_("Please remove selections from the secret keys.\n"));
	return 0;
    }

    n1 = count_selected_keys( pub_keyblock );
    if( n1 > 1 ) {
	tty_printf(_("Please select at most one secondary key.\n"));
	return 0;
    }
    else if( n1 )
	tty_printf(_("Changing expiration time for a secondary key.\n"));
    else {
	tty_printf(_("Changing expiration time for the primary key.\n"));
	mainkey=1;
    }

    expiredate = ask_expiredate();
    node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
    sk = copy_secret_key( NULL, node->pkt->pkt.secret_key);

    /* Now we can actually change the self signature(s) */
    main_pk = sub_pk = NULL;
    uid = NULL;
    signumber = 0;
    for( node=pub_keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
	    main_pk = node->pkt->pkt.public_key;
	    keyid_from_pk( main_pk, keyid );
	    main_pk->expiredate = expiredate;
	}
	else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		 && (node->flag & NODFLG_SELKEY ) ) {
	    sub_pk = node->pkt->pkt.public_key;
	    sub_pk->expiredate = expiredate;
	}
	else if( node->pkt->pkttype == PKT_USER_ID )
	    uid = node->pkt->pkt.user_id;
	else if( main_pk && node->pkt->pkttype == PKT_SIGNATURE
		 && ( mainkey || sub_pk ) ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
		&& (	(mainkey && uid && (sig->sig_class&~3) == 0x10)
		     || (!mainkey && sig->sig_class == 0x18)  ) ) {
		/* this is a selfsignature which is to be replaced */
		PKT_signature *newsig;
		PACKET *newpkt;
		KBNODE sn;
		int signumber2 = 0;

		signumber++;

		if( (mainkey && main_pk->version < 4)
		    || (!mainkey && sub_pk->version < 4 ) ) {
		    log_info(_(
			"You can't change the expiration date of a v3 key\n"));
		    free_secret_key( sk );
		    return 0;
		}

		/* find the corresponding secret self-signature */
		for( sn=sec_keyblock; sn; sn = sn->next ) {
		    if( sn->pkt->pkttype == PKT_SIGNATURE ) {
			PKT_signature *b = sn->pkt->pkt.signature;
			if( keyid[0] == b->keyid[0] && keyid[1] == b->keyid[1]
			    && sig->sig_class == b->sig_class
			    && ++signumber2 == signumber )
			    break;
		    }
		}
		if( !sn )
		    log_info(_("No corresponding signature in secret ring\n"));

		/* create new self signature */
		if( mainkey )
		    rc = make_keysig_packet( &newsig, main_pk, uid, NULL,
					     sk, 0x13, 0,
					     keygen_add_std_prefs, main_pk );
		else
		    rc = make_keysig_packet( &newsig, main_pk, NULL, sub_pk,
					     sk, 0x18, 0,
					     keygen_add_key_expire, sub_pk );
		if( rc ) {
		    log_error("make_keysig_packet failed: %s\n",
						    g10_errstr(rc));
		    free_secret_key( sk );
		    return 0;
		}
		/* replace the packet */
		newpkt = m_alloc_clear( sizeof *newpkt );
		newpkt->pkttype = PKT_SIGNATURE;
		newpkt->pkt.signature = newsig;
		free_packet( node->pkt );
		m_free( node->pkt );
		node->pkt = newpkt;
		if( sn ) {
		    newpkt = m_alloc_clear( sizeof *newpkt );
		    newpkt->pkttype = PKT_SIGNATURE;
		    newpkt->pkt.signature = copy_signature( NULL, newsig );
		    free_packet( sn->pkt );
		    m_free( sn->pkt );
		    sn->pkt = newpkt;
		}
		sub_pk = NULL;
	    }
	}
    }

    free_secret_key( sk );
    return 1;
}


/****************
 * Select one user id or remove all selection if index is 0.
 * Returns: True if the selection changed;
 */
static int
menu_select_uid( KBNODE keyblock, int idx )
{
    KBNODE node;
    int i;

    /* first check that the index is valid */
    if( idx ) {
	for( i=0, node = keyblock; node; node = node->next ) {
	    if( node->pkt->pkttype == PKT_USER_ID ) {
		if( ++i == idx )
		    break;
	    }
	}
	if( !node ) {
	    tty_printf(_("No user ID with index %d\n"), idx );
	    return 0;
	}
    }
    else { /* reset all */
	for( i=0, node = keyblock; node; node = node->next ) {
	    if( node->pkt->pkttype == PKT_USER_ID )
		node->flag &= ~NODFLG_SELUID;
	}
	return 1;
    }
    /* and toggle the new index */
    for( i=0, node = keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    if( ++i == idx ) {
		if( (node->flag & NODFLG_SELUID) )
		    node->flag &= ~NODFLG_SELUID;
		else
		    node->flag |= NODFLG_SELUID;
	    }
	}
    }

    return 1;
}

/****************
 * Select secondary keys
 * Returns: True if the selection changed;
 */
static int
menu_select_key( KBNODE keyblock, int idx )
{
    KBNODE node;
    int i;

    /* first check that the index is valid */
    if( idx ) {
	for( i=0, node = keyblock; node; node = node->next ) {
	    if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		|| node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
		if( ++i == idx )
		    break;
	    }
	}
	if( !node ) {
	    tty_printf(_("No secondary key with index %d\n"), idx );
	    return 0;
	}
    }
    else { /* reset all */
	for( i=0, node = keyblock; node; node = node->next ) {
	    if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		|| node->pkt->pkttype == PKT_SECRET_SUBKEY )
		node->flag &= ~NODFLG_SELKEY;
	}
	return 1;
    }
    /* and set the new index */
    for( i=0, node = keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    if( ++i == idx ) {
		if( (node->flag & NODFLG_SELKEY) )
		    node->flag &= ~NODFLG_SELKEY;
		else
		    node->flag |= NODFLG_SELKEY;
	    }
	}
    }

    return 1;
}


static int
count_uids_with_flag( KBNODE keyblock, unsigned flag )
{
    KBNODE node;
    int i=0;

    for( node = keyblock; node; node = node->next )
	if( node->pkt->pkttype == PKT_USER_ID && (node->flag & flag) )
	    i++;
    return i;
}

static int
count_keys_with_flag( KBNODE keyblock, unsigned flag )
{
    KBNODE node;
    int i=0;

    for( node = keyblock; node; node = node->next )
	if( ( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	      || node->pkt->pkttype == PKT_SECRET_SUBKEY)
	    && (node->flag & flag) )
	    i++;
    return i;
}

static int
count_uids( KBNODE keyblock )
{
    KBNODE node;
    int i=0;

    for( node = keyblock; node; node = node->next )
	if( node->pkt->pkttype == PKT_USER_ID )
	    i++;
    return i;
}


/****************
 * Returns true if there is at least one selected user id
 */
static int
count_selected_uids( KBNODE keyblock )
{
    return count_uids_with_flag( keyblock, NODFLG_SELUID);
}

static int
count_selected_keys( KBNODE keyblock )
{
    return count_keys_with_flag( keyblock, NODFLG_SELKEY);
}

/*
 * Ask whether the signature should be revoked.  If the user commits this,
 * flag bit MARK_A is set on the signature and the user ID.
 */
static void
ask_revoke_sig( KBNODE keyblock, KBNODE node )
{
    PKT_signature *sig = node->pkt->pkt.signature;
    KBNODE unode = find_prev_kbnode( keyblock, node, PKT_USER_ID );

    if( !unode ) {
	log_error("Oops: no user ID for signature\n");
	return;
    }

    tty_printf(_("user ID: \""));
    tty_print_utf8_string( unode->pkt->pkt.user_id->name,
			   unode->pkt->pkt.user_id->len );
    tty_printf(_("\"\nsigned with your key %08lX at %s\n"),
		(ulong)sig->keyid[1], datestr_from_sig(sig) );

    if( cpr_get_answer_is_yes("ask_revoke_sig.one",
	 _("Create a revocation certificate for this signature? (y/N)")) ) {
	node->flag |= NODFLG_MARK_A;
	unode->flag |= NODFLG_MARK_A;
    }
}

/****************
 * Display all user ids of the current public key together with signatures
 * done by one of our keys.  Then walk over all this sigs and ask the user
 * whether he wants to revoke this signature.
 * Return: True when the keyblock has changed.
 */
static int
menu_revsig( KBNODE keyblock )
{
    PKT_signature *sig;
    PKT_public_key *primary_pk;
    KBNODE node;
    int changed = 0;
    int upd_trust = 0;
    int rc, any;
    struct revocation_reason_info *reason = NULL;

    /* FIXME: detect duplicates here  */
    tty_printf(_("You have signed these user IDs:\n"));
    for( node = keyblock; node; node = node->next ) {
	node->flag &= ~(NODFLG_SELSIG | NODFLG_MARK_A);
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;
	    /* Hmmm: Should we show only UIDs with a signature? */
	    tty_printf("     ");
	    tty_print_utf8_string( uid->name, uid->len );
	    tty_printf("\n");
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE
		&& ((sig = node->pkt->pkt.signature),
		     !seckey_available( sig->keyid )  ) ) {
	    if( (sig->sig_class&~3) == 0x10 ) {
		tty_printf(_("   signed by %08lX at %s\n"),
			    (ulong)sig->keyid[1], datestr_from_sig(sig) );
		node->flag |= NODFLG_SELSIG;
	    }
	    else if( sig->sig_class == 0x30 ) {
		tty_printf(_("   revoked by %08lX at %s\n"),
			    (ulong)sig->keyid[1], datestr_from_sig(sig) );
	    }
	}
    }

    /* ask */
    for( node = keyblock; node; node = node->next ) {
	if( !(node->flag & NODFLG_SELSIG) )
	    continue;
	ask_revoke_sig( keyblock, node );
    }

    /* present selected */
    any = 0;
    for( node = keyblock; node; node = node->next ) {
	if( !(node->flag & NODFLG_MARK_A) )
	    continue;
	if( !any ) {
	    any = 1;
	    tty_printf(_("You are about to revoke these signatures:\n"));
	}
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    PKT_user_id *uid = node->pkt->pkt.user_id;
	    tty_printf("     ");
	    tty_print_utf8_string( uid->name, uid->len );
	    tty_printf("\n");
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	    sig = node->pkt->pkt.signature;
	    tty_printf(_("   signed by %08lX at %s\n"),
			    (ulong)sig->keyid[1], datestr_from_sig(sig) );
	}
    }
    if( !any )
	return 0; /* none selected */

    if( !cpr_get_answer_is_yes("ask_revoke_sig.okay",
	 _("Really create the revocation certificates? (y/N)")) )
	return 0; /* forget it */

    reason = ask_revocation_reason( 0, 1, 0 );
    if( !reason ) { /* user decided to cancel */
	return 0;
    }

    /* now we can sign the user ids */
  reloop: /* (must use this, because we are modifing the list) */
    primary_pk = keyblock->pkt->pkt.public_key;
    for( node=keyblock; node; node = node->next ) {
	KBNODE unode;
	PACKET *pkt;
	struct sign_attrib attrib;
	PKT_secret_key *sk;

	if( !(node->flag & NODFLG_MARK_A)
	    || node->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	unode = find_prev_kbnode( keyblock, node, PKT_USER_ID );
	assert( unode ); /* we already checked this */

	memset( &attrib, 0, sizeof attrib );
	attrib.reason = reason;

	node->flag &= ~NODFLG_MARK_A;
	sk = m_alloc_secure_clear( sizeof *sk );
	if( get_seckey( sk, node->pkt->pkt.signature->keyid ) ) {
	    log_info(_("no secret key\n"));
	    continue;
	}
	rc = make_keysig_packet( &sig, primary_pk,
				       unode->pkt->pkt.user_id,
				       NULL,
				       sk,
				       0x30, 0,
				       sign_mk_attrib,
				       &attrib );
	free_secret_key(sk);
	if( rc ) {
	    log_error(_("signing failed: %s\n"), g10_errstr(rc));
	    release_revocation_reason_info( reason );
	    return changed;
	}
	changed = 1; /* we changed the keyblock */
	upd_trust = 1;

	pkt = m_alloc_clear( sizeof *pkt );
	pkt->pkttype = PKT_SIGNATURE;
	pkt->pkt.signature = sig;
	insert_kbnode( unode, new_kbnode(pkt), 0 );
	goto reloop;
    }

    if( upd_trust )
	clear_trust_checked_flag( primary_pk );
    release_revocation_reason_info( reason );
    return changed;
}

/****************
 * Revoke some of the secondary keys.
 * Hmmm: Should we add a revocation to the secret keyring too?
 *	 Does its all make sense to duplicate most of the information?
 */
static int
menu_revkey( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    PKT_public_key *mainpk;
    KBNODE node;
    int changed = 0;
    int upd_trust = 0;
    int rc;
    struct revocation_reason_info *reason = NULL;

    reason = ask_revocation_reason( 1, 0, 0 );
    if( !reason ) { /* user decided to cancel */
	return 0;
    }


  reloop: /* (better this way because we are modifing the keyring) */
    mainpk = pub_keyblock->pkt->pkt.public_key;
    for( node = pub_keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    && (node->flag & NODFLG_SELKEY) ) {
	    PACKET *pkt;
	    PKT_signature *sig;
	    PKT_secret_key *sk;
	    PKT_public_key *subpk = node->pkt->pkt.public_key;
	    struct sign_attrib attrib;

	    memset( &attrib, 0, sizeof attrib );
	    attrib.reason = reason;

	    node->flag &= ~NODFLG_SELKEY;
	    sk = copy_secret_key( NULL, sec_keyblock->pkt->pkt.secret_key );
	    rc = make_keysig_packet( &sig, mainpk, NULL, subpk, sk, 0x28, 0,
				       sign_mk_attrib,
				       &attrib );
	    free_secret_key(sk);
	    if( rc ) {
		log_error(_("signing failed: %s\n"), g10_errstr(rc));
		release_revocation_reason_info( reason );
		return changed;
	    }
	    changed = 1; /* we changed the keyblock */
	    upd_trust = 1;

	    pkt = m_alloc_clear( sizeof *pkt );
	    pkt->pkttype = PKT_SIGNATURE;
	    pkt->pkt.signature = sig;
	    insert_kbnode( node, new_kbnode(pkt), 0 );
	    goto reloop;
	}
    }
    commit_kbnode( &pub_keyblock );
    /*commit_kbnode( &sec_keyblock );*/

    if( upd_trust )
	clear_trust_checked_flag( mainpk );

    release_revocation_reason_info( reason );
    return changed;
}


static int
enable_disable_key( KBNODE keyblock, int disable )
{
    ulong lid = find_kbnode( keyblock, PKT_PUBLIC_KEY )
			    ->pkt->pkt.public_key->local_id;
    unsigned int trust, newtrust;

    /* Note: Because the keys have beed displayed, we have
     * ensured that local_id has been set */
    trust = newtrust = get_ownertrust( lid );
    newtrust &= ~TRUST_FLAG_DISABLED;
    if( disable )
	newtrust |= TRUST_FLAG_DISABLED;
    if( trust == newtrust )
	return 0; /* already in that state */
    if( !update_ownertrust( lid, newtrust ) )
	return 1;
    return 0;
}

