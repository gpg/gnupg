/* revoke.c
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003,
 *               2004 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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
    buffer = xmalloc( buflen );
    *buffer = reason->code;
    if( ud ) {
	memcpy(buffer+1, ud, strlen(ud) );
	xfree( ud );
    }

    build_sig_subpkt( sig, SIGSUBPKT_REVOC_REASON, buffer, buflen );
    xfree( buffer );
    return 0;
}

/* Outputs a minimal pk (as defined by 2440) from a keyblock.  A
   minimal pk consists of the public key packet and a user ID.  We try
   and pick a user ID that has a uid signature, and include it if
   possible. */
static int
export_minimal_pk(IOBUF out,KBNODE keyblock,
		  PKT_signature *revsig,PKT_signature *revkey)
{
  KBNODE node;
  PACKET pkt;
  PKT_user_id *uid=NULL;
  PKT_signature *selfsig=NULL;
  u32 keyid[2];
  int rc;

  node=find_kbnode(keyblock,PKT_PUBLIC_KEY);
  if(!node)
    {
      log_error("key incomplete\n");
      return G10ERR_GENERAL;
    }

  keyid_from_pk(node->pkt->pkt.public_key,keyid);

  pkt=*node->pkt;
  rc=build_packet(out,&pkt);
  if(rc)
    {
      log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
      return rc;
    }

  init_packet(&pkt);
  pkt.pkttype=PKT_SIGNATURE;

  /* the revocation itself, if any.  2440 likes this to come first. */
  if(revsig)
    {
      pkt.pkt.signature=revsig;
      rc=build_packet(out,&pkt);
      if(rc)
	{
	  log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	  return rc;
	}
    }

  /* If a revkey in a 1F sig is present, include it too */
  if(revkey)
    {
      pkt.pkt.signature=revkey;
      rc=build_packet(out,&pkt);
      if(rc)
	{
	  log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	  return rc;
	}
    }

  while(!selfsig)
    {
      KBNODE signode;

      node=find_next_kbnode(node,PKT_USER_ID);
      if(!node)
	{
	  /* We're out of user IDs - none were self-signed. */
	  if(uid)
	    break;
	  else
	    {
	      log_error(_("key %s has no user IDs\n"),keystr(keyid));
	      return G10ERR_GENERAL;
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

  pkt.pkttype=PKT_USER_ID;
  pkt.pkt.user_id=uid;

  rc=build_packet(out,&pkt);
  if(rc)
    {
      log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
      return rc;
    }

  if(selfsig)
    {
      pkt.pkttype=PKT_SIGNATURE;
      pkt.pkt.signature=selfsig;

      rc=build_packet(out,&pkt);
      if(rc)
	{
	  log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	  return rc;
	}
    }

  return 0;
}

/****************
 * Generate a revocation certificate for UNAME via a designated revoker
 */
int
gen_desig_revoke( const char *uname, STRLIST locusr )
{
    int rc = 0;
    armor_filter_context_t afx;
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
    SK_LIST sk_list=NULL;

    if( opt.batch )
      {
	log_error(_("can't do this in batch mode\n"));
	return G10ERR_GENERAL;
      }

    memset( &afx, 0, sizeof afx);

    kdbhd = keydb_new (0);
    classify_user_id (uname, &desc);
    rc = desc.mode? keydb_search (kdbhd, &desc, 1) : G10ERR_INV_USER_ID;
    if (rc) {
	log_error (_("key \"%s\" not found: %s\n"),uname, g10_errstr (rc));
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

    if(locusr)
      {
	rc=build_sk_list(locusr,&sk_list,0,PUBKEY_USAGE_CERT);
	if(rc)
	  goto leave;
      }

    /* Are we a designated revoker for this key? */

    if(!pk->revkey && pk->numrevkeys)
      BUG();

    for(i=0;i<pk->numrevkeys;i++)
      {
	SK_LIST list;

	if(sk)
	  free_secret_key(sk);

	if(sk_list)
	  {
	    for(list=sk_list;list;list=list->next)
	      {
		byte fpr[MAX_FINGERPRINT_LEN];
		size_t fprlen;

		fingerprint_from_sk(list->sk,fpr,&fprlen);

		/* Don't get involved with keys that don't have 160
		   bit fingerprints */
		if(fprlen!=20)
		  continue;

		if(memcmp(fpr,pk->revkey[i].fpr,20)==0)
		  break;
	      }

	    if(list)
	      sk=copy_secret_key(NULL,list->sk);
	    else
	      continue;
	  }
	else
	  {
	    sk=xmalloc_secure_clear(sizeof(*sk));
	    rc=get_seckey_byfprint(sk,pk->revkey[i].fpr,MAX_FINGERPRINT_LEN);
	  }

	/* We have the revocation key */
	if(!rc)
	  {
	    PKT_signature *revkey = NULL;

	    any = 1;

            print_pubkey_info (NULL, pk);
	    tty_printf ("\n");

	    tty_printf (_("To be revoked by:\n"));
            print_seckey_info (sk);

	    if(pk->revkey[i].class&0x40)
	      tty_printf(_("(This is a sensitive revocation key)\n"));
	    tty_printf("\n");

	    if( !cpr_get_answer_is_yes("gen_desig_revoke.okay",
         _("Create a designated revocation certificate for this key? (y/N) ")))
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
	    afx.hdrlines = "Comment: A designated revocation certificate"
	      " should follow\n";
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
               no way to know which key to attach this revocation to.
               Also include the direct key signature that contains
               this revocation key.  We're allowed to include
               sensitive revocation keys along with a revocation, as
               this may be the only time the recipient has seen it.
               Note that this means that if we have multiple different
               sensitive revocation keys in a given direct key
               signature, we're going to include them all here.  This
               is annoying, but the good outweighs the bad, since
               without including this a sensitive revoker can't really
               do their job.  People should not include multiple
               sensitive revocation keys in one signature: 2440 says
               "Note that it may be appropriate to isolate this
               subpacket within a separate signature so that it is not
               combined with other subpackets that need to be
               exported." -dms */

	    while(!revkey)
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
			    revkey=signode->pkt->pkt.signature;
			    break;
			  }
		      }
		  }
	      }

	    if(!revkey)
	      BUG();

	    rc=export_minimal_pk(out,keyblock,sig,revkey);
	    if(rc)
	      goto leave;

	    /* and issue a usage notice */
	    tty_printf(_("Revocation certificate created.\n"));
	    break;
	  }
      }

    if(!any)
      log_error(_("no revocation keys found for \"%s\"\n"),uname);

  leave:
    if( pk )
	free_public_key( pk );
    if( sk )
	free_secret_key( sk );
    if( sig )
	free_seckey_enc( sig );

    release_sk_list(sk_list);

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
    KBNODE keyblock = NULL, pub_keyblock = NULL;
    KBNODE node;
    KEYDB_HANDLE kdbhd;
    struct revocation_reason_info *reason = NULL;
    KEYDB_SEARCH_DESC desc;

    if( opt.batch )
      {
	log_error(_("can't do this in batch mode\n"));
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
    if (rc)
      {
	log_error (_("secret key \"%s\" not found: %s\n"),
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
    print_seckey_info (sk);

    pk = xmalloc_clear( sizeof *pk );

    /* FIXME: We should get the public key direct from the secret one */

    pub_keyblock=get_pubkeyblock(sk_keyid);
    if(!pub_keyblock)
      {
	log_error(_("no corresponding public key: %s\n"), g10_errstr(rc) );
	goto leave;
      }

    node=find_kbnode(pub_keyblock,PKT_PUBLIC_KEY);
    if(!node)
      BUG();

    pk=node->pkt->pkt.public_key;

    if( cmp_public_secret_key( pk, sk ) ) {
	log_error(_("public key does not match secret key!\n") );
	rc = G10ERR_GENERAL;
	goto leave;
    }

    tty_printf("\n");
    if( !cpr_get_answer_is_yes("gen_revoke.okay",
		  _("Create a revocation certificate for this key? (y/N) ")) )
      {
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
      case -3:
	tty_printf (_("Secret parts of primary key are not available.\n"));
        rc = G10ERR_NO_SECKEY;
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

    if(PGP2 || PGP6 || PGP7 || PGP8)
      {
	/* Use a minimal pk for PGPx mode, since PGP can't import bare
	   revocation certificates. */
	rc=export_minimal_pk(out,pub_keyblock,sig,NULL);
	if(rc)
	  goto leave;
      }
    else
      {
	init_packet( &pkt );
	pkt.pkttype = PKT_SIGNATURE;
	pkt.pkt.signature = sig;

	rc = build_packet( out, &pkt );
	if( rc ) {
	  log_error(_("build_packet failed: %s\n"), g10_errstr(rc) );
	  goto leave;
	}
      }

    /* and issue a usage notice */
    tty_printf(_("Revocation certificate created.\n\n"
"Please move it to a medium which you can hide away; if Mallory gets\n"
"access to this certificate he can use it to make your key unusable.\n"
"It is smart to print this certificate and store it away, just in case\n"
"your media become unreadable.  But have some caution:  The print system of\n"
"your machine might store the data and make it available to others!\n"));

  leave:
    if( sig )
	free_seckey_enc( sig );
    release_kbnode( keyblock );
    release_kbnode( pub_keyblock );
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
        code=-1;
	xfree(description);
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
	    else if(!digitp( answer ) )
 	        n = -1;
	    else
		n = atoi(answer);
	    xfree(answer);
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
		xfree(answer);
		break;
	    }

	    {
		char *p = make_printable_string( answer, strlen(answer), 0 );
		xfree(answer);
		answer = p;
	    }

	    if( !description )
		description = xstrdup(answer);
	    else {
		char *p = xmalloc( strlen(description) + strlen(answer) + 2 );
		strcpy(stpcpy(stpcpy( p, description),"\n"),answer);
		xfree(description);
		description = p;
	    }
	    xfree(answer);
	}

	tty_printf(_("Reason for revocation: %s\n"), code_text );
	if( !description )
	    tty_printf(_("(No description given)\n") );
	else
	    tty_printf("%s\n", description );

    } while( !cpr_get_answer_is_yes("ask_revocation_reason.okay",
					    _("Is this okay? (y/N) "))  );

    reason = xmalloc( sizeof *reason );
    reason->code = code;
    reason->desc = description;
    return reason;
}

void
release_revocation_reason_info( struct revocation_reason_info *reason )
{
    if( reason ) {
	xfree( reason->desc );
	xfree( reason );
    }
}
