/* revoke.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "ttyio.h"
#include "status.h"
#include "i18n.h"


struct revocation_reason_info {
    int code;
    char *desc;
};


int
revocation_reason_build_cb( PKT_signature *sig, void *opaque )
{
    struct revocation_reason_info *reason = opaque;
    char *ud = NULL;
    byte *buffer;
    size_t buflen = 1;

    if(!reason)
      return 0;

    if( reason->desc ) {
	ud = native_to_utf8( reason->desc );
	buflen += strlen(ud);
    }
    buffer = m_alloc( buflen );
    *buffer = reason->code;
    if( ud ) {
	memcpy(buffer+1, ud, strlen(ud) );
	m_free( ud );
    }

    build_sig_subpkt( sig, SIGSUBPKT_REVOC_REASON, buffer, buflen );
    m_free( buffer );
    return 0;
}



/****************
 * Generate a revocation certificate for UNAME via a designated revoker
 */
int
gen_desig_revoke( const char *uname )
{
    int rc = 0;
    armor_filter_context_t afx;
    PACKET pkt;
    PKT_public_key *pk = NULL;
    PKT_secret_key *sk = NULL;
    PKT_signature *sig = NULL;
    IOBUF out = NULL;
    struct revocation_reason_info *reason = NULL;
    KEYDB_HANDLE kdbhd;
    KEYDB_SEARCH_DESC desc;
    KBNODE keyblock=NULL,node;
    u32 keyid[2];
    int i,any=0;

    if( opt.batch ) {
	log_error(_("sorry, can't do this in batch mode\n"));
	return G10ERR_GENERAL;
    }

    memset( &afx, 0, sizeof afx);

    kdbhd = keydb_new (0);
    classify_user_id (uname, &desc);
    rc = desc.mode? keydb_search (kdbhd, &desc, 1) : G10ERR_INV_USER_ID;
    if (rc) {
	log_error (_("key `%s' not found: %s\n"),uname, g10_errstr (rc));
	goto leave;
    }

    rc = keydb_get_keyblock (kdbhd, &keyblock );
    if( rc ) {
	log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
	goto leave;
    }

    /* To parse the revkeys */
    merge_keys_and_selfsig(keyblock);

    /* get the key from the keyblock */
    node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
    if( !node ) 
      BUG ();

    pk=node->pkt->pkt.public_key;

    keyid_from_pk(pk,keyid);

    /* Are we a designated revoker for this key? */

    if(!pk->revkey && pk->numrevkeys)
      BUG();

    for(i=0;i<pk->numrevkeys;i++)
      {
	if(sk)
	  free_secret_key(sk);

	sk=m_alloc_clear(sizeof(*sk));

	rc=get_seckey_byfprint(sk,pk->revkey[i].fpr,MAX_FINGERPRINT_LEN);

	/* We have the revocation key */
	if(!rc)
	  {
	    size_t n;
	    char *p;
	    u32 sk_keyid[2];
	    PKT_user_id *uid=NULL;
	    PKT_signature *selfsig=NULL,*revsig=NULL;

	    any=1;
	    keyid_from_sk(sk,sk_keyid);

	    tty_printf("\npub  %4u%c/%08lX %s   ",
		       nbits_from_pk( pk ),
		       pubkey_letter( pk->pubkey_algo ),
		       (ulong)keyid[1], datestr_from_pk(pk) );

	    p = get_user_id( keyid, &n );
	    tty_print_utf8_string( p, n );
	    m_free(p);
	    tty_printf("\n\n");

	    tty_printf(_("To be revoked by:\n"));

	    tty_printf("\nsec  %4u%c/%08lX %s   ",
		       nbits_from_sk( sk ),
		       pubkey_letter( sk->pubkey_algo ),
		       (ulong)sk_keyid[1], datestr_from_sk(sk) );

	    p = get_user_id( sk_keyid, &n );
	    tty_print_utf8_string( p, n );
	    m_free(p);
	    tty_printf("\n");
	    if(pk->revkey[i].class&0x40)
	      tty_printf(_("(This is a sensitive revocation key)\n"));
	    tty_printf("\n");

	    if( !cpr_get_answer_is_yes("gen_desig_revoke.okay",
		       _("Create a revocation certificate for this key? ")) )
	      continue;

	    /* get the reason for the revocation (this is always v4) */
	    reason = ask_revocation_reason( 1, 0, 1 );
	    if( !reason )
	      continue;

	    rc = check_secret_key( sk, 0 );
	    if( rc )
	      continue;

	    if( !opt.armor )
	      tty_printf(_("ASCII armored output forced.\n"));

	    if( (rc = open_outfile( NULL, 0, &out )) )
	      goto leave;

	    afx.what = 1;
	    afx.hdrlines = "Comment: A revocation certificate should follow\n";
	    iobuf_push_filter( out, armor_filter, &afx );

	    /* create it */
	    rc = make_keysig_packet( &sig, pk, NULL, NULL, sk, 0x20, 0,
				     0, 0, 0,
				     revocation_reason_build_cb, reason );
	    if( rc ) {
	      log_error(_("make_keysig_packet failed: %s\n"), g10_errstr(rc));
	      goto leave;
	    }

	    /* Spit out a minimal pk as well, since otherwise there is
               no way to know which key to attach this revocation
               to. */

	    node=find_kbnode(keyblock,PKT_PUBLIC_KEY);
	    if(!node)
	      {
		rc=G10ERR_GENERAL;
		log_error(_("key %08lX incomplete\n"),(ulong)keyid[1]);
		goto leave;
	      }

	    pkt = *node->pkt;
	    rc=build_packet(out,&pkt);
	    if( rc ) {
	      log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	      goto leave;
	    }

	    /* Include the direct key signature that contains this
               revocation key.  We're allowed to include sensitive
               revocation keys along with a revocation, and this may
               be the only time the recipient has seen it. */
	    while(!revsig)
	      {
		KBNODE signode;

		signode=find_next_kbnode(node,PKT_SIGNATURE);
		if(!signode)
		  break;

		node=signode;

		if(keyid[0]==signode->pkt->pkt.signature->keyid[0] &&
		   keyid[1]==signode->pkt->pkt.signature->keyid[1] &&
		   IS_KEY_SIG(signode->pkt->pkt.signature))
		  {
		    int j;

		    for(j=0;j<signode->pkt->pkt.signature->numrevkeys;j++)
		      {
			if(pk->revkey[i].class==
			   signode->pkt->pkt.signature->revkey[j]->class &&
			   pk->revkey[i].algid==
			   signode->pkt->pkt.signature->revkey[j]->algid &&
			   memcmp(pk->revkey[i].fpr,
				  signode->pkt->pkt.signature->revkey[j]->fpr,
				  MAX_FINGERPRINT_LEN)==0)
			  {
			    revsig=signode->pkt->pkt.signature;
			    break;
			  }
		      }
		  }
	      }

	    if(revsig)
	      {
		pkt.pkttype = PKT_SIGNATURE;
		pkt.pkt.signature = revsig;

		rc = build_packet( out, &pkt );
		if( rc ) {
		  log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
		  goto leave;
		}
	      }
	    else
	      BUG();

	    init_packet( &pkt );
	    pkt.pkttype = PKT_SIGNATURE;
	    pkt.pkt.signature = sig;

	    rc = build_packet( out, &pkt );
	    if( rc ) {
	      log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	      goto leave;
	    }

	    while(!selfsig)
	      {
		KBNODE signode;

		node=find_next_kbnode(node,PKT_USER_ID);
		if(!node)
		  {
		    /* We're out of user IDs - none were
                       self-signed. */
		    if(uid)
		      break;
		    else
		      {
			rc=G10ERR_GENERAL;
			log_error(_("key %08lX incomplete\n"),(ulong)keyid[1]);
			goto leave;
		      }
		  }

		if(node->pkt->pkt.user_id->attrib_data)
		  continue;

		uid=node->pkt->pkt.user_id;
		signode=node;

		while((signode=find_next_kbnode(signode,PKT_SIGNATURE)))
		  {
		    if(keyid[0]==signode->pkt->pkt.signature->keyid[0] &&
		       keyid[1]==signode->pkt->pkt.signature->keyid[1] &&
		       IS_UID_SIG(signode->pkt->pkt.signature))
		      {
			selfsig=signode->pkt->pkt.signature;
			break;
		      }
		  }
	      }

	    pkt.pkttype = PKT_USER_ID;
	    pkt.pkt.user_id = uid;

	    rc = build_packet( out, &pkt );
	    if( rc ) {
	      log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	      goto leave;
	    }

	    if(selfsig)
	      {
		pkt.pkttype = PKT_SIGNATURE;
		pkt.pkt.signature = selfsig;

		rc = build_packet( out, &pkt );
		if( rc ) {
		  log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
		  goto leave;
		}
	      }

	    /* and issue a usage notice */
	    tty_printf(_("Revocation certificate created.\n"));
	    break;
	  }
      }

    if(!any)
      log_error(_("no revocation keys found for `%s'\n"),uname);

  leave:
    if( pk )
	free_public_key( pk );
    if( sk )
	free_secret_key( sk );
    if( sig )
	free_seckey_enc( sig );

    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    release_revocation_reason_info( reason );
    return rc;
}


/****************
 * Generate a revocation certificate for UNAME
 */
int
gen_revoke( const char *uname )
{
    int rc = 0;
    armor_filter_context_t afx;
    PACKET pkt;
    PKT_secret_key *sk; /* used as pointer into a kbnode */
    PKT_public_key *pk = NULL;
    PKT_signature *sig = NULL;
    u32 sk_keyid[2];
    IOBUF out = NULL;
    KBNODE keyblock = NULL;
    KBNODE node;
    KEYDB_HANDLE kdbhd;
    struct revocation_reason_info *reason = NULL;
    KEYDB_SEARCH_DESC desc;

    if( opt.batch ) {
	log_error(_("sorry, can't do this in batch mode\n"));
	return G10ERR_GENERAL;
    }

    memset( &afx, 0, sizeof afx);
    init_packet( &pkt );

    /* search the userid: 
     * We don't want the whole getkey stuff here but the entire keyblock
     */
    kdbhd = keydb_new (1);
    classify_user_id (uname, &desc);
    rc = desc.mode? keydb_search (kdbhd, &desc, 1) : G10ERR_INV_USER_ID;
    if (rc) {
	log_error (_("secret key `%s' not found: %s\n"),
                   uname, g10_errstr (rc));
	goto leave;
    }

    rc = keydb_get_keyblock (kdbhd, &keyblock );
    if( rc ) {
	log_error (_("error reading keyblock: %s\n"), g10_errstr(rc) );
	goto leave;
    }

    /* get the keyid from the keyblock */
    node = find_kbnode( keyblock, PKT_SECRET_KEY );
    if( !node ) 
	BUG ();

    /* fixme: should make a function out of this stuff,
     * it's used all over the source */
    sk = node->pkt->pkt.secret_key;
    keyid_from_sk( sk, sk_keyid );
    tty_printf("\nsec  %4u%c/%08lX %s   ",
	      nbits_from_sk( sk ),
	      pubkey_letter( sk->pubkey_algo ),
	      (ulong)sk_keyid[1], datestr_from_sk(sk) );
    {
	size_t n;
	char *p = get_user_id( sk_keyid, &n );
	tty_print_utf8_string( p, n );
	m_free(p);
	tty_printf("\n");
    }
    pk = m_alloc_clear( sizeof *pk );

    /* FIXME: We should get the public key direct from the secret one */
    rc = get_pubkey( pk, sk_keyid );
    if( rc ) {
	log_error(_("no corresponding public key: %s\n"), g10_errstr(rc) );
	goto leave;
    }
    if( cmp_public_secret_key( pk, sk ) ) {
	log_error(_("public key does not match secret key!\n") );
	rc = G10ERR_GENERAL;
	goto leave;
    }

    tty_printf("\n");
    if( !cpr_get_answer_is_yes("gen_revoke.okay",
			_("Create a revocation certificate for this key? ")) ){
	rc = 0;
	goto leave;
    }

    if(sk->version>=4 || opt.force_v4_certs) {
      /* get the reason for the revocation */
      reason = ask_revocation_reason( 1, 0, 1 );
      if( !reason ) { /* user decided to cancel */
	rc = 0;
	goto leave;
      }
    }

    switch( is_secret_key_protected( sk ) ) {
      case -1:
	log_error(_("unknown protection algorithm\n"));
	rc = G10ERR_PUBKEY_ALGO;
	break;
      case 0:
	tty_printf(_("NOTE: This key is not protected!\n"));
	break;
      default:
	rc = check_secret_key( sk, 0 );
	break;
    }
    if( rc )
	goto leave;


    if( !opt.armor )
	tty_printf(_("ASCII armored output forced.\n"));

    if( (rc = open_outfile( NULL, 0, &out )) )
	goto leave;

    afx.what = 1;
    afx.hdrlines = "Comment: A revocation certificate should follow\n";
    iobuf_push_filter( out, armor_filter, &afx );

    /* create it */
    rc = make_keysig_packet( &sig, pk, NULL, NULL, sk, 0x20, 0,
			     opt.force_v4_certs?4:0, 0, 0,
			     revocation_reason_build_cb, reason );
    if( rc ) {
	log_error(_("make_keysig_packet failed: %s\n"), g10_errstr(rc));
	goto leave;
    }
    init_packet( &pkt );
    pkt.pkttype = PKT_SIGNATURE;
    pkt.pkt.signature = sig;

    rc = build_packet( out, &pkt );
    if( rc ) {
	log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	goto leave;
    }

    /* and issue a usage notice */
    tty_printf(_("Revocation certificate created.\n\n"
"Please move it to a medium which you can hide away; if Mallory gets\n"
"access to this certificate he can use it to make your key unusable.\n"
"It is smart to print this certificate and store it away, just in case\n"
"your media become unreadable.  But have some caution:  The print system of\n"
"your machine might store the data and make it available to others!\n"));



  leave:
    if( pk )
	free_public_key( pk );
    if( sig )
	free_seckey_enc( sig );
    release_kbnode( keyblock );
    keydb_release (kdbhd);
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    release_revocation_reason_info( reason );
    return rc;
}



struct revocation_reason_info *
ask_revocation_reason( int key_rev, int cert_rev, int hint )
{
    int code=-1;
    char *description = NULL;
    struct revocation_reason_info *reason;
    const char *text_0 = _("No reason specified");
    const char *text_1 = _("Key has been compromised");
    const char *text_2 = _("Key is superseded");
    const char *text_3 = _("Key is no longer used");
    const char *text_4 = _("User ID is no longer valid");
    const char *code_text = NULL;

    do {
	m_free(description);
	description = NULL;

	tty_printf(_("Please select the reason for the revocation:\n"));
	tty_printf(    "  0 = %s\n", text_0 );
	if( key_rev )
	    tty_printf("  1 = %s\n", text_1 );
	if( key_rev )
	    tty_printf("  2 = %s\n", text_2 );
	if( key_rev )
	    tty_printf("  3 = %s\n", text_3 );
	if( cert_rev )
	    tty_printf("  4 = %s\n", text_4 );
	tty_printf(    "  Q = %s\n", _("Cancel") );
	if( hint )
	    tty_printf(_("(Probably you want to select %d here)\n"), hint );

	while(code==-1) {
	    int n;
	    char *answer = cpr_get("ask_revocation_reason.code",
						_("Your decision? "));
	    trim_spaces( answer );
	    cpr_kill_prompt();
	    if( *answer == 'q' || *answer == 'Q')
	      return NULL; /* cancel */
	    if( hint && !*answer )
		n = hint;
	    else if(!isdigit( *answer ) )
 	        n = -1;
	    else
		n = atoi(answer);
	    m_free(answer);
	    if( n == 0 ) {
	        code = 0x00; /* no particular reason */
		code_text = text_0;
	    }
	    else if( key_rev && n == 1 ) {
		code = 0x02; /* key has been compromised */
		code_text = text_1;
	    }
	    else if( key_rev && n == 2 ) {
		code = 0x01; /* key is superseded */
		code_text = text_2;
	    }
	    else if( key_rev && n == 3 ) {
		code = 0x03; /* key is no longer used */
		code_text = text_3;
	    }
	    else if( cert_rev && n == 4 ) {
		code = 0x20; /* uid is no longer valid */
		code_text = text_4;
	    }
	    else
		tty_printf(_("Invalid selection.\n"));
	}

	tty_printf(_("Enter an optional description; "
		     "end it with an empty line:\n") );
	for(;;) {
	    char *answer = cpr_get("ask_revocation_reason.text", "> " );
	    trim_trailing_ws( answer, strlen(answer) );
	    cpr_kill_prompt();
	    if( !*answer ) {
		m_free(answer);
		break;
	    }

	    {
		char *p = make_printable_string( answer, strlen(answer), 0 );
		m_free(answer);
		answer = p;
	    }

	    if( !description )
		description = m_strdup(answer);
	    else {
		char *p = m_alloc( strlen(description) + strlen(answer) + 2 );
		strcpy(stpcpy(stpcpy( p, description),"\n"),answer);
		m_free(description);
		description = p;
	    }
	    m_free(answer);
	}

	tty_printf(_("Reason for revocation: %s\n"), code_text );
	if( !description )
	    tty_printf(_("(No description given)\n") );
	else
	    tty_printf("%s\n", description );

    } while( !cpr_get_answer_is_yes("ask_revocation_reason.okay",
					    _("Is this okay? "))  );

    reason = m_alloc( sizeof *reason );
    reason->code = code;
    reason->desc = description;
    return reason;
}

void
release_revocation_reason_info( struct revocation_reason_info *reason )
{
    if( reason ) {
	m_free( reason->desc );
	m_free( reason );
    }
}
