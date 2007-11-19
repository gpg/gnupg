/* keyedit.c - keyedit stuff
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
 *               2007 Free Software Foundation, Inc.
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
#ifdef HAVE_LIBREADLINE
#include <stdio.h>
#include <readline/readline.h>
#endif
#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "photoid.h"
#include "util.h"
#include "main.h"
#include "trustdb.h"
#include "filter.h"
#include "ttyio.h"
#include "status.h"
#include "i18n.h"
#include "keyserver-internal.h"

static void show_prefs( PKT_user_id *uid, PKT_signature *selfsig, int verbose);
static void show_names(KBNODE keyblock,PKT_public_key *pk,
		       unsigned int flag,int with_prefs);
static void show_key_with_all_names( KBNODE keyblock, int only_marked,
	    int with_revoker, int with_fpr, int with_subkeys, int with_prefs );
static void show_key_and_fingerprint( KBNODE keyblock );
static int menu_adduid( KBNODE keyblock, KBNODE sec_keyblock,
			int photo, const char *photo_name );
static void menu_deluid( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_delsig( KBNODE pub_keyblock );
static int menu_clean(KBNODE keyblock,int self_only);
static void menu_delkey( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_addrevoker( KBNODE pub_keyblock,
			    KBNODE sec_keyblock, int sensitive );
static int menu_expire( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_backsign(KBNODE pub_keyblock,KBNODE sec_keyblock);
static int menu_set_primary_uid( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_set_preferences( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_set_keyserver_url (const char *url,
				   KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_set_notation(const char *string,
			     KBNODE pub_keyblock,KBNODE sec_keyblock);
static int menu_select_uid( KBNODE keyblock, int idx );
static int menu_select_uid_namehash( KBNODE keyblock, const char *namehash );
static int menu_select_key( KBNODE keyblock, int idx );
static int count_uids( KBNODE keyblock );
static int count_uids_with_flag( KBNODE keyblock, unsigned flag );
static int count_keys_with_flag( KBNODE keyblock, unsigned flag );
static int count_selected_uids( KBNODE keyblock );
static int real_uids_left( KBNODE keyblock );
static int count_selected_keys( KBNODE keyblock );
static int menu_revsig( KBNODE keyblock );
static int menu_revuid( KBNODE keyblock, KBNODE sec_keyblock );
static int menu_revkey( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int menu_revsubkey( KBNODE pub_keyblock, KBNODE sec_keyblock );
static int enable_disable_key( KBNODE keyblock, int disable );
static void menu_showphoto( KBNODE keyblock );

static int update_trust=0;

#define CONTROL_D ('D' - 'A' + 1)

#define NODFLG_BADSIG (1<<0)  /* bad signature */
#define NODFLG_NOKEY  (1<<1)  /* no public key */
#define NODFLG_SIGERR (1<<2)  /* other sig error */

#define NODFLG_MARK_A (1<<4)  /* temporary mark */
#define NODFLG_DELSIG (1<<5)  /* to be deleted */

#define NODFLG_SELUID (1<<8)  /* indicate the selected userid */
#define NODFLG_SELKEY (1<<9)  /* indicate the selected key */
#define NODFLG_SELSIG (1<<10) /* indicate a selected signature */

struct sign_attrib {
    int non_exportable,non_revocable;
    struct revocation_reason_info *reason;
    byte trust_depth,trust_value;
    char *trust_regexp;
};


#ifdef ENABLE_CARD_SUPPORT
/* Given a node SEC_NODE with a secret key or subkey, locate the
   corresponding public key from pub_keyblock. */
static PKT_public_key *
find_pk_from_sknode (KBNODE pub_keyblock, KBNODE sec_node)
{
  KBNODE node = pub_keyblock;
  PKT_secret_key *sk;
  PKT_public_key *pk;
  
  if (sec_node->pkt->pkttype == PKT_SECRET_KEY
      && node->pkt->pkttype == PKT_PUBLIC_KEY)
    return node->pkt->pkt.public_key;
  if (sec_node->pkt->pkttype != PKT_SECRET_SUBKEY)
    return NULL;
  sk = sec_node->pkt->pkt.secret_key;
  for (; node; node = node->next)
    if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
      {
        pk = node->pkt->pkt.public_key;
        if (pk->keyid[0] == sk->keyid[0] && pk->keyid[1] == sk->keyid[1])
          return pk;
      }
      
  return NULL;
}
#endif /* ENABLE_CARD_SUPPORT */


/* TODO: Fix duplicated code between here and the check-sigs/list-sigs
   code in keylist.c. */
static int
print_and_check_one_sig_colon( KBNODE keyblock, KBNODE node,
			       int *inv_sigs, int *no_key, int *oth_err,
			       int *is_selfsig, int print_without_key )
{
  PKT_signature *sig = node->pkt->pkt.signature;
  int rc, sigrc;

  /* TODO: Make sure a cached sig record here still has the pk that
     issued it.  See also keylist.c:list_keyblock_print */

  switch((rc=check_key_signature(keyblock,node,is_selfsig)))
    {
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

  if( sigrc != '?' || print_without_key )
    {
      printf("sig:%c::%d:%08lX%08lX:%lu:%lu:",
	     sigrc,sig->pubkey_algo,(ulong)sig->keyid[0],(ulong)sig->keyid[1],
	     (ulong)sig->timestamp,(ulong)sig->expiredate);

      if(sig->trust_depth || sig->trust_value)
	printf("%d %d",sig->trust_depth,sig->trust_value);

      printf(":");

      if(sig->trust_regexp)
	print_string(stdout,sig->trust_regexp,strlen(sig->trust_regexp),':');

      printf("::%02x%c\n",sig->sig_class,sig->flags.exportable?'x':'l');

      if(opt.show_subpackets)
      	print_subpackets_colon(sig);
    }

  return (sigrc == '!');
}


/****************
 * Print information about a signature, check it and return true
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

    /* TODO: Make sure a cached sig record here still has the pk that
       issued it.  See also keylist.c:list_keyblock_print */

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
        tty_printf("%s%c%c %c%c%c%c%c%c %s %s",
		   is_rev? "rev":"sig",sigrc,
		   (sig->sig_class-0x10>0 &&
		    sig->sig_class-0x10<4)?'0'+sig->sig_class-0x10:' ',
		   sig->flags.exportable?' ':'L',
		   sig->flags.revocable?' ':'R',
		   sig->flags.policy_url?'P':' ',
		   sig->flags.notation?'N':' ',
                   sig->flags.expired?'X':' ',
		   (sig->trust_depth>9)?'T':
		   (sig->trust_depth>0)?'0'+sig->trust_depth:' ',
		   keystr(sig->keyid),datestr_from_sig(sig));
	if(opt.list_options&LIST_SHOW_SIG_EXPIRE)
	  tty_printf(" %s",expirestr_from_sig(sig));
	tty_printf("  ");
	if( sigrc == '%' )
	    tty_printf("[%s] ", g10_errstr(rc) );
	else if( sigrc == '?' )
	    ;
	else if( *is_selfsig ) {
	    tty_printf( is_rev? _("[revocation]")
			      : _("[self-signature]") );
	}
	else
	  {
	    size_t n;
	    char *p = get_user_id( sig->keyid, &n );
	    tty_print_utf8_string2(p, n, opt.screen_columns-keystrlen()-26-
			       ((opt.list_options&LIST_SHOW_SIG_EXPIRE)?11:0));
	    xfree(p);
	  }
	tty_printf("\n");

	if(sig->flags.policy_url && (opt.list_options&LIST_SHOW_POLICY_URLS))
	  show_policy_url(sig,3,0);

	if(sig->flags.notation && (opt.list_options&LIST_SHOW_NOTATIONS))
	  show_notation(sig,3,0,
			((opt.list_options&LIST_SHOW_STD_NOTATIONS)?1:0)+
			((opt.list_options&LIST_SHOW_USER_NOTATIONS)?2:0));

	if(sig->flags.pref_ks && (opt.list_options&LIST_SHOW_KEYSERVER_URLS))
	  show_keyserver_url(sig,3,0);
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

    if( attrib->non_revocable ) {
	buf[0] = 0; /* not revocable */
	build_sig_subpkt( sig, SIGSUBPKT_REVOCABLE, buf, 1 );
    }

    if( attrib->reason )
	revocation_reason_build_cb( sig, attrib->reason );

    if(attrib->trust_depth)
      {
	/* Not critical.  If someone doesn't understand trust sigs,
	   this can still be a valid regular signature. */
        buf[0] = attrib->trust_depth;
	buf[1] = attrib->trust_value;
	build_sig_subpkt(sig,SIGSUBPKT_TRUST,buf,2);

	/* Critical.  If someone doesn't understands regexps, this
	   whole sig should be invalid.  Note the +1 for the length -
	   regexps are null terminated. */
	if(attrib->trust_regexp)
	  build_sig_subpkt(sig,SIGSUBPKT_FLAG_CRITICAL|SIGSUBPKT_REGEXP,
			   attrib->trust_regexp,
			   strlen(attrib->trust_regexp)+1);
      }

    return 0;
}

static void
trustsig_prompt(byte *trust_value,byte *trust_depth,char **regexp)
{
  char *p;

  *trust_value=0;
  *trust_depth=0;
  *regexp=NULL;

  /* Same string as pkclist.c:do_edit_ownertrust */
  tty_printf(_("Please decide how far you trust this user to correctly verify"
	       " other users' keys\n(by looking at passports, checking"
	       " fingerprints from different sources, etc.)\n"));
  tty_printf("\n");
  tty_printf (_("  %d = I trust marginally\n"), 1);
  tty_printf (_("  %d = I trust fully\n"), 2);
  tty_printf("\n");

  while(*trust_value==0)
    {
      p = cpr_get("trustsig_prompt.trust_value",_("Your selection? "));
      trim_spaces(p);
      cpr_kill_prompt();
      /* 60 and 120 are as per RFC2440 */
      if(p[0]=='1' && !p[1])
	*trust_value=60;
      else if(p[0]=='2' && !p[1])
	*trust_value=120;
      xfree(p);
    }

  tty_printf("\n");

  tty_printf(_(
	      "Please enter the depth of this trust signature.\n"
	      "A depth greater than 1 allows the key you are signing to make\n"
	      "trust signatures on your behalf.\n"));
  tty_printf("\n");

  while(*trust_depth==0)
    {
      p = cpr_get("trustsig_prompt.trust_depth",_("Your selection? "));
      trim_spaces(p);
      cpr_kill_prompt();
      *trust_depth=atoi(p);
      xfree(p);
    }

  tty_printf("\n");

  tty_printf(_("Please enter a domain to restrict this signature, "
	       "or enter for none.\n"));

  tty_printf("\n");

  p=cpr_get("trustsig_prompt.trust_regexp",_("Your selection? "));
  trim_spaces(p);
  cpr_kill_prompt();

  if(strlen(p)>0)
    {
      char *q=p;
      int regexplen=100,ind;

      *regexp=xmalloc(regexplen);

      /* Now mangle the domain the user entered into a regexp.  To do
	 this, \-escape everything that isn't alphanumeric, and attach
	 "<[^>]+[@.]" to the front, and ">$" to the end. */

      strcpy(*regexp,"<[^>]+[@.]");
      ind=strlen(*regexp);

      while(*q)
	{
	  if(!((*q>='A' && *q<='Z')
	       || (*q>='a' && *q<='z') || (*q>='0' && *q<='9')))
	    (*regexp)[ind++]='\\';

	  (*regexp)[ind++]=*q;

	  if((regexplen-ind)<3)
	    {
	      regexplen+=100;
	      *regexp=xrealloc(*regexp,regexplen);
	    }

	  q++;
	}

      (*regexp)[ind]='\0';
      strcat(*regexp,">$");
    }

  xfree(p);
  tty_printf("\n");
}

/****************
 * Loop over all locusr and and sign the uids after asking.
 * If no user id is marked, all user ids will be signed;
 * if some user_ids are marked those will be signed.
 */
static int
sign_uids( KBNODE keyblock, STRLIST locusr, int *ret_modified,
	   int local, int nonrevocable, int trust, int interactive )
{
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    PKT_secret_key *sk = NULL;
    KBNODE node, uidnode;
    PKT_public_key *primary_pk=NULL;
    int select_all = !count_selected_uids(keyblock) || interactive;
    int all_v3=1;
    u32 timestamp=make_timestamp();

    /* Are there any non-v3 sigs on this key already? */
    if(PGP2)
      for(node=keyblock;node;node=node->next)
	if(node->pkt->pkttype==PKT_SIGNATURE &&
	   node->pkt->pkt.signature->version>3)
	  {
	    all_v3=0;
	    break;
	  }

    /* build a list of all signators.
     *    
     * We use the CERT flag to request the primary which must always
     * be one which is capable of signing keys.  I can't see a reason
     * why to sign keys using a subkey.  Implementation of USAGE_CERT
     * is just a hack in getkey.c and does not mean that a subkey
     * marked as certification capable will be used. */
    rc=build_sk_list( locusr, &sk_list, 0, PUBKEY_USAGE_CERT);
    if( rc )
	goto leave;

    /* loop over all signators */
    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
        u32 sk_keyid[2],pk_keyid[2];
	char *p,*trust_regexp=NULL;
	int force_v4=0,class=0,selfsig=0;
	u32 duration=0;
	byte trust_depth=0,trust_value=0;

	if(local || nonrevocable || trust ||
	   opt.cert_policy_url || opt.cert_notations)
	  force_v4=1;

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
	    if( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
  	        primary_pk=node->pkt->pkt.public_key;
		keyid_from_pk( primary_pk, pk_keyid );

		/* Is this a self-sig? */
		if(pk_keyid[0]==sk_keyid[0] && pk_keyid[1]==sk_keyid[1])
		  {
		    selfsig=1;
		    /* Do not force a v4 sig here, otherwise it would
                       be difficult to remake a v3 selfsig.  If this
                       is a v3->v4 promotion case, then we set
                       force_v4 later anyway. */
		    force_v4=0;
		  }
	    }
	    else if( node->pkt->pkttype == PKT_USER_ID )
	      {
		uidnode = (node->flag & NODFLG_MARK_A)? node : NULL;
		if(uidnode)
		  {
		    int yesreally=0;
		    char *user=utf8_to_native(uidnode->pkt->pkt.user_id->name,
					      uidnode->pkt->pkt.user_id->len,
					      0);

		    if(uidnode->pkt->pkt.user_id->is_revoked)
		      {
			tty_printf(_("User ID \"%s\" is revoked."),user);

			if(selfsig)
			  tty_printf("\n");
			else if(opt.expert)
			  {
			    tty_printf("\n");
			    /* No, so remove the mark and continue */
			    if(!cpr_get_answer_is_yes("sign_uid.revoke_okay",
						      _("Are you sure you "
							"still want to sign "
							"it? (y/N) ")))
			      {
				uidnode->flag &= ~NODFLG_MARK_A;
				uidnode=NULL;
			      }
			    else if(interactive)
			      yesreally=1;
			  }
			else
			  {
			    uidnode->flag &= ~NODFLG_MARK_A;
			    uidnode=NULL;
			    tty_printf(_("  Unable to sign.\n"));
			  }
		      }
		    else if(uidnode->pkt->pkt.user_id->is_expired)
		      {
			tty_printf(_("User ID \"%s\" is expired."),user);

			if(selfsig)
			  tty_printf("\n");
			else if(opt.expert)
			  {
			    tty_printf("\n");
			    /* No, so remove the mark and continue */
			    if(!cpr_get_answer_is_yes("sign_uid.expire_okay",
						      _("Are you sure you "
							"still want to sign "
							"it? (y/N) ")))
			      {
				uidnode->flag &= ~NODFLG_MARK_A;
				uidnode=NULL;
			      }
			    else if(interactive)
			      yesreally=1;
			  }
			else
			  {
			    uidnode->flag &= ~NODFLG_MARK_A;
			    uidnode=NULL;
			    tty_printf(_("  Unable to sign.\n"));
			  }
		      }
		    else if(!uidnode->pkt->pkt.user_id->created && !selfsig)
		      {
			tty_printf(_("User ID \"%s\" is not self-signed."),
				   user);

			if(opt.expert)
			  {
			    tty_printf("\n");
			    /* No, so remove the mark and continue */
			    if(!cpr_get_answer_is_yes("sign_uid.nosig_okay",
						      _("Are you sure you "
							"still want to sign "
							"it? (y/N) ")))
			      {
				uidnode->flag &= ~NODFLG_MARK_A;
				uidnode=NULL;
			      }
			    else if(interactive)
			      yesreally=1;
			  }
			else
			  {
			    uidnode->flag &= ~NODFLG_MARK_A;
			    uidnode=NULL;
			    tty_printf(_("  Unable to sign.\n"));
			  }
		      }

		    if(uidnode && interactive && !yesreally)
		      {
			tty_printf(_("User ID \"%s\" is signable.  "),user);
			if(!cpr_get_answer_is_yes("sign_uid.sign_okay",
						  _("Sign it? (y/N) ")))
			  {
			    uidnode->flag &= ~NODFLG_MARK_A;
			    uidnode=NULL;
			  }
		      }

		    xfree(user);
		  }
	      }
	    else if( uidnode && node->pkt->pkttype == PKT_SIGNATURE
		&& (node->pkt->pkt.signature->sig_class&~3) == 0x10 ) {
		if( sk_keyid[0] == node->pkt->pkt.signature->keyid[0]
		    && sk_keyid[1] == node->pkt->pkt.signature->keyid[1] ) {
                    char buf[50];
		    char *user=utf8_to_native(uidnode->pkt->pkt.user_id->name,
					      uidnode->pkt->pkt.user_id->len,
					      0);

		    /* It's a v3 self-sig.  Make it into a v4 self-sig? */
		    if(node->pkt->pkt.signature->version<4 && selfsig)
		      {
			tty_printf(_("The self-signature on \"%s\"\n"
				     "is a PGP 2.x-style signature.\n"),user);
 
			/* Note that the regular PGP2 warning below
			   still applies if there are no v4 sigs on
			   this key at all. */

			if(opt.expert)
			  if(cpr_get_answer_is_yes("sign_uid.v4_promote_okay",
						   _("Do you want to promote "
						     "it to an OpenPGP self-"
						     "signature? (y/N) ")))
			    {
			      force_v4=1;
			      node->flag|=NODFLG_DELSIG;
			      xfree(user);
			      continue;
			    }
		      }

		    /* Is the current signature expired? */
		    if(node->pkt->pkt.signature->flags.expired)
		      {
			tty_printf(_("Your current signature on \"%s\"\n"
				     "has expired.\n"),user);

			if(cpr_get_answer_is_yes("sign_uid.replace_expired_okay",
						 _("Do you want to issue a "
						   "new signature to replace "
						   "the expired one? (y/N) ")))
			  {
			    /* Mark these for later deletion.  We
                               don't want to delete them here, just in
                               case the replacement signature doesn't
                               happen for some reason.  We only delete
                               these after the replacement is already
                               in place. */

			    node->flag|=NODFLG_DELSIG;
			    xfree(user);
			    continue;
			  }
		      }

		    if(!node->pkt->pkt.signature->flags.exportable && !local)
		      {
			/* It's a local sig, and we want to make a
                           exportable sig. */
			tty_printf(_("Your current signature on \"%s\"\n"
				     "is a local signature.\n"),user);

			if(cpr_get_answer_is_yes("sign_uid.local_promote_okay",
						 _("Do you want to promote "
						   "it to a full exportable "
						   "signature? (y/N) ")))
			  {
			    /* Mark these for later deletion.  We
                               don't want to delete them here, just in
                               case the replacement signature doesn't
                               happen for some reason.  We only delete
                               these after the replacement is already
                               in place. */

			    node->flag|=NODFLG_DELSIG;
			    xfree(user);
			    continue;
			  }
		      }

		    /* Fixme: see whether there is a revocation in which
		     * case we should allow to sign it again. */
                    if (!node->pkt->pkt.signature->flags.exportable && local)
                      tty_printf(_(
			      "\"%s\" was already locally signed by key %s\n"),
				 user,keystr_from_sk(sk));
                    else
                      tty_printf(_("\"%s\" was already signed by key %s\n"),
                                 user,keystr_from_sk(sk));

		    if(opt.expert
		       && cpr_get_answer_is_yes("sign_uid.dupe_okay",
						_("Do you want to sign it "
						  "again anyway? (y/N) ")))
		      {
			/* Don't delete the old sig here since this is
			   an --expert thing. */
			xfree(user);
			continue;
		      }

                    sprintf (buf, "%08lX%08lX",
                             (ulong)sk->keyid[0], (ulong)sk->keyid[1] );
                    write_status_text (STATUS_ALREADY_SIGNED, buf);
		    uidnode->flag &= ~NODFLG_MARK_A; /* remove mark */

		    xfree(user);
		}
	    }
	}

	/* check whether any uids are left for signing */
	if( !count_uids_with_flag(keyblock, NODFLG_MARK_A) )
	  {
	    tty_printf(_("Nothing to sign with key %s\n"),keystr_from_sk(sk));
	    continue;
	  }

	/* Ask whether we really should sign these user id(s) */
	tty_printf("\n");
	show_key_with_all_names( keyblock, 1, 0, 1, 0, 0 );
	tty_printf("\n");

	if(primary_pk->expiredate && !selfsig)
	  {
	    if(primary_pk->expiredate<=timestamp)
	      {
		tty_printf(_("This key has expired!"));

		if(opt.expert)
		  {
		    tty_printf("  ");
		    if(!cpr_get_answer_is_yes("sign_uid.expired_okay",
					      _("Are you sure you still "
						"want to sign it? (y/N) ")))
		      continue;
		  }
		else
		  {
		    tty_printf(_("  Unable to sign.\n"));
		    continue;
		  }
	      }
	    else
	      {
		tty_printf(_("This key is due to expire on %s.\n"),
			   expirestr_from_pk(primary_pk));

		if(opt.ask_cert_expire)
		  {
		    char *answer=cpr_get("sign_uid.expire",
					 _("Do you want your signature to "
					   "expire at the same time? (Y/n) "));
		    if(answer_is_yes_no_default(answer,1))
		      {
			/* Set our signature expiration date to match
			   when the key is going to expire. */
			duration=primary_pk->expiredate-timestamp;
			force_v4=1;
		      }

		    cpr_kill_prompt();
		    xfree(answer);
		  }
	      }
	  }

	/* Only ask for duration if we haven't already set it to match
           the expiration of the pk */
	if(!duration && !selfsig)
	  {
	    if(opt.ask_cert_expire)
	      duration=ask_expire_interval(timestamp,1,opt.def_cert_expire);
	    else
	      duration=parse_expire_string(timestamp,opt.def_cert_expire);
	  }

	if(duration)
	  force_v4=1;

	/* Is --pgp2 on, it's a v3 key, all the sigs on the key are
	   currently v3 and we're about to sign it with a v4 sig?  If
	   so, danger! */
	if(PGP2 && all_v3 &&
	   (sk->version>3 || force_v4) && primary_pk->version<=3)
	  {
	    tty_printf(_("You may not make an OpenPGP signature on a "
			 "PGP 2.x key while in --pgp2 mode.\n"));
	    tty_printf(_("This would make the key unusable in PGP 2.x.\n"));

	    if(opt.expert)
	      {
		if(!cpr_get_answer_is_yes("sign_uid.v4_on_v3_okay",
					  _("Are you sure you still "
					    "want to sign it? (y/N) ")))
		  continue;

		all_v3=0;
	      }
	    else
	      continue;
	  }

	if(selfsig)
	  ;
	else
	  {
	    if(opt.batch || !opt.ask_cert_level)
	      class=0x10+opt.def_cert_level;
	    else
	      {
		char *answer;

		tty_printf(_("How carefully have you verified the key you are "
			     "about to sign actually belongs\nto the person "
			     "named above?  If you don't know what to "
			     "answer, enter \"0\".\n"));
		tty_printf("\n");
		tty_printf(_("   (0) I will not answer.%s\n"),
			   opt.def_cert_level==0?" (default)":"");
		tty_printf(_("   (1) I have not checked at all.%s\n"),
			   opt.def_cert_level==1?" (default)":"");
		tty_printf(_("   (2) I have done casual checking.%s\n"),
			   opt.def_cert_level==2?" (default)":"");
		tty_printf(_("   (3) I have done very careful checking.%s\n"),
			   opt.def_cert_level==3?" (default)":"");
		tty_printf("\n");

		while(class==0)
		  {
		    answer = cpr_get("sign_uid.class",_("Your selection? "
					"(enter `?' for more information): "));
		    if(answer[0]=='\0')
		      class=0x10+opt.def_cert_level; /* Default */
		    else if(ascii_strcasecmp(answer,"0")==0)
		      class=0x10; /* Generic */
		    else if(ascii_strcasecmp(answer,"1")==0)
		      class=0x11; /* Persona */
		    else if(ascii_strcasecmp(answer,"2")==0)
		      class=0x12; /* Casual */
		    else if(ascii_strcasecmp(answer,"3")==0)
		      class=0x13; /* Positive */
		    else
		      tty_printf(_("Invalid selection.\n"));

		    xfree(answer);
		  }
	      }

	    if(trust)
	      trustsig_prompt(&trust_value,&trust_depth,&trust_regexp);
	  }

	p=get_user_id_native(sk_keyid);
	tty_printf(_("Are you sure that you want to sign this key with your\n"
		     "key \"%s\" (%s)\n"),p,keystr_from_sk(sk));
	xfree(p);

	if(selfsig)
	  {
            tty_printf("\n");
	    tty_printf(_("This will be a self-signature.\n"));

	    if( local )
              {
                tty_printf("\n");
                tty_printf(
			 _("WARNING: the signature will not be marked "
			   "as non-exportable.\n"));
              }

	    if( nonrevocable )
              {
                tty_printf("\n");
                tty_printf(
			 _("WARNING: the signature will not be marked "
			   "as non-revocable.\n"));
              }
	  }
	else
	  {
	    if( local )
              {
                tty_printf("\n");
                tty_printf(
		     _("The signature will be marked as non-exportable.\n"));
              }

	    if( nonrevocable )
              {
                tty_printf("\n");
                tty_printf(
		      _("The signature will be marked as non-revocable.\n"));
              }

	    switch(class)
	      {
	      case 0x11:
                tty_printf("\n");
		tty_printf(_("I have not checked this key at all.\n"));
		break;

	      case 0x12:
                tty_printf("\n");
		tty_printf(_("I have checked this key casually.\n"));
		break;

	      case 0x13:
                tty_printf("\n");
		tty_printf(_("I have checked this key very carefully.\n"));
		break;
	      }
	  }

	tty_printf("\n");

	if( opt.batch && opt.answer_yes )
	  ;
	else if( !cpr_get_answer_is_yes("sign_uid.okay",
					_("Really sign? (y/N) ")) )
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
		attrib.non_revocable = nonrevocable;
		attrib.trust_depth = trust_depth;
		attrib.trust_value = trust_value;
		attrib.trust_regexp = trust_regexp;
		node->flag &= ~NODFLG_MARK_A;

                /* we force creation of a v4 signature for local
                 * signatures, otherwise we would not generate the
                 * subpacket with v3 keys and the signature becomes
                 * exportable */

		if(selfsig)
		  rc = make_keysig_packet( &sig, primary_pk,
					   node->pkt->pkt.user_id,
					   NULL,
					   sk,
					   0x13, 0, force_v4?4:0, 0, 0,
					   keygen_add_std_prefs, primary_pk);
		else
		  rc = make_keysig_packet( &sig, primary_pk,
					   node->pkt->pkt.user_id,
					   NULL,
					   sk,
					   class, 0, force_v4?4:0,
					   timestamp, duration,
					   sign_mk_attrib, &attrib );
		if( rc ) {
		    log_error(_("signing failed: %s\n"), g10_errstr(rc));
		    goto leave;
		}

		*ret_modified = 1; /* we changed the keyblock */
		update_trust = 1;

		pkt = xmalloc_clear( sizeof *pkt );
		pkt->pkttype = PKT_SIGNATURE;
		pkt->pkt.signature = sig;
		insert_kbnode( node, new_kbnode(pkt), PKT_SIGNATURE );
		goto reloop;
	    }
	}

	/* Delete any sigs that got promoted */
	for( node=keyblock; node; node = node->next )
	  if( node->flag & NODFLG_DELSIG)
	    delete_kbnode(node);
    } /* end loop over signators */

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
    int any;

    node = find_kbnode( keyblock, PKT_SECRET_KEY );
    if( !node ) {
	log_error("Oops; secret key not found anymore!\n");
	goto leave;
    }
    sk = node->pkt->pkt.secret_key;

    for (any = 0, node=keyblock; node; node = node->next) {
	if (node->pkt->pkttype == PKT_SECRET_KEY 
            || node->pkt->pkttype == PKT_SECRET_SUBKEY) {
	    PKT_secret_key *tmpsk = node->pkt->pkt.secret_key;
            if (!(tmpsk->is_protected
                  && (tmpsk->protect.s2k.mode == 1001 
                      || tmpsk->protect.s2k.mode == 1002))) {
                any = 1;
                break;
            }
        }
    }
    if (!any) {
        tty_printf (_("Key has only stub or on-card key items - "
                      "no passphrase to change.\n"));
        goto leave;
    }
        
    /* See how to handle this key.  */
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
	else if( sk->protect.s2k.mode == 1002 ) {
	    tty_printf(_("Secret parts of primary key are stored on-card.\n"));
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

    /* Unprotect all subkeys (use the supplied passphrase or ask)*/
    for(node=keyblock; !rc && node; node = node->next ) {
	if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    PKT_secret_key *subsk = node->pkt->pkt.secret_key;
            if ( !(subsk->is_protected
                   && (subsk->protect.s2k.mode == 1001 
                       || subsk->protect.s2k.mode == 1002))) {
                set_next_passphrase( passphrase );
                rc = check_secret_key( subsk, 0 );
                if( !rc && !passphrase )
                    passphrase = get_last_passphrase();
            }
	}
    }

    if( rc )
	tty_printf(_("Can't edit this key: %s\n"), g10_errstr(rc));
    else {
	DEK *dek = NULL;
	STRING2KEY *s2k = xmalloc_secure( sizeof *s2k );
        const char *errtext = NULL;

	tty_printf(_("Enter the new passphrase for this secret key.\n\n") );

	set_next_passphrase( NULL );
	for(;;) {
	    s2k->mode = opt.s2k_mode;
	    s2k->hash_algo = S2K_DIGEST_ALGO;
	    dek = passphrase_to_dek( NULL, 0, opt.s2k_cipher_algo,
                                     s2k, 2, errtext, NULL);
	    if( !dek ) {
		errtext = N_("passphrase not correctly repeated; try again");
		tty_printf ("%s.\n", _(errtext));
	    }
	    else if( !dek->keylen ) {
		rc = 0;
		tty_printf(_( "You don't want a passphrase -"
			    " this is probably a *bad* idea!\n\n"));
		if( cpr_get_answer_is_yes("change_passwd.empty.okay",
			       _("Do you really want to do this? (y/N) ")))
		  {
		    changed++;
		    break;
		  }
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
                        if ( !(subsk->is_protected
                               && (subsk->protect.s2k.mode == 1001 
                                   || subsk->protect.s2k.mode == 1002))) {
                            subsk->protect.algo = dek->algo;
                            subsk->protect.s2k = *s2k;
                            rc = protect_secret_key( subsk, dek );
                        }
		    }
		}
		if( rc )
		    log_error("protect_secret_key failed: %s\n",
                              g10_errstr(rc) );
		else
		    changed++;
		break;
	    }
	}
	xfree(s2k);
	xfree(dek);
    }

  leave:
    xfree( passphrase );
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

static int
parse_sign_type(const char *str,int *localsig,int *nonrevokesig,int *trustsig)
{
  const char *p=str;

  while(*p)
    {
      if(ascii_strncasecmp(p,"l",1)==0)
	{
	  *localsig=1;
	  p++;
	}
      else if(ascii_strncasecmp(p,"nr",2)==0)
	{
	  *nonrevokesig=1;
	  p+=2;
	}
      else if(ascii_strncasecmp(p,"t",1)==0)
	{
	  *trustsig=1;
	  p++;
	}
      else
	return 0;
    }

  return 1;
}


/****************
 * Menu driven key editor.  If seckey_check is true, then a secret key
 * that matches username will be looked for.  If it is false, not all
 * commands will be available.
 *
 * Note: to keep track of some selection we use node->mark MARKBIT_xxxx.
 */

/* Need an SK for this command */
#define KEYEDIT_NEED_SK 1
/* Cannot be viewing the SK for this command */
#define KEYEDIT_NOT_SK  2
/* Must be viewing the SK for this command */
#define KEYEDIT_ONLY_SK 4
/* Match the tail of the string */
#define KEYEDIT_TAIL_MATCH 8

enum cmdids
  {
    cmdNONE = 0,
    cmdQUIT, cmdHELP, cmdFPR, cmdLIST, cmdSELUID, cmdCHECK, cmdSIGN,
    cmdREVSIG, cmdREVKEY, cmdREVUID, cmdDELSIG, cmdPRIMARY, cmdDEBUG,
    cmdSAVE, cmdADDUID, cmdADDPHOTO, cmdDELUID, cmdADDKEY, cmdDELKEY,
    cmdADDREVOKER, cmdTOGGLE, cmdSELKEY, cmdPASSWD, cmdTRUST, cmdPREF,
    cmdEXPIRE, cmdBACKSIGN, cmdENABLEKEY, cmdDISABLEKEY, cmdSHOWPREF,
    cmdSETPREF, cmdPREFKS, cmdNOTATION, cmdINVCMD, cmdSHOWPHOTO, cmdUPDTRUST,
    cmdCHKTRUST, cmdADDCARDKEY, cmdKEYTOCARD, cmdBKUPTOCARD, cmdCLEAN,
    cmdMINIMIZE, cmdNOP
  };

static struct
{
  const char *name;
  enum cmdids id;
  int flags;
  const char *desc;
} cmds[] =
  { 
    { "quit"    , cmdQUIT      , 0, N_("quit this menu") },
    { "q"       , cmdQUIT      , 0, NULL   },
    { "save"    , cmdSAVE      , 0, N_("save and quit") },
    { "help"    , cmdHELP      , 0, N_("show this help") },
    { "?"       , cmdHELP      , 0, NULL   },
    { "fpr"     , cmdFPR       , 0, N_("show key fingerprint") },
    { "list"    , cmdLIST      , 0, N_("list key and user IDs") },
    { "l"       , cmdLIST      , 0, NULL   },
    { "uid"     , cmdSELUID    , 0, N_("select user ID N") },
    { "key"     , cmdSELKEY    , 0, N_("select subkey N") },
    { "check"   , cmdCHECK     , 0, N_("check signatures") },
    { "c"       , cmdCHECK     , 0, NULL },
    { "cross-certify", cmdBACKSIGN  , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK, NULL },
    { "backsign", cmdBACKSIGN  , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK, NULL },
    { "sign"    , cmdSIGN      , KEYEDIT_NOT_SK|KEYEDIT_TAIL_MATCH,
      N_("sign selected user IDs [* see below for related commands]") },
    { "s"       , cmdSIGN      , KEYEDIT_NOT_SK, NULL },
    /* "lsign" and friends will never match since "sign" comes first
       and it is a tail match.  They are just here so they show up in
       the help menu. */
    { "lsign"   , cmdNOP       , 0, N_("sign selected user IDs locally") },
    { "tsign"   , cmdNOP       , 0,
      N_("sign selected user IDs with a trust signature") },
    { "nrsign"  , cmdNOP       , 0,
      N_("sign selected user IDs with a non-revocable signature") },

    { "debug"   , cmdDEBUG     , 0, NULL },
    { "adduid"  , cmdADDUID    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("add a user ID") },
    { "addphoto", cmdADDPHOTO  , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("add a photo ID") },
    { "deluid"  , cmdDELUID    , KEYEDIT_NOT_SK,
      N_("delete selected user IDs") },
    /* delphoto is really deluid in disguise */
    { "delphoto", cmdDELUID    , KEYEDIT_NOT_SK, NULL },

    { "addkey"  , cmdADDKEY    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("add a subkey") },

#ifdef ENABLE_CARD_SUPPORT
    { "addcardkey", cmdADDCARDKEY , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("add a key to a smartcard") },
    { "keytocard", cmdKEYTOCARD , KEYEDIT_NEED_SK|KEYEDIT_ONLY_SK, 
      N_("move a key to a smartcard")},
    { "bkuptocard", cmdBKUPTOCARD , KEYEDIT_NEED_SK|KEYEDIT_ONLY_SK, 
      N_("move a backup key to a smartcard")},
#endif /*ENABLE_CARD_SUPPORT*/

    { "delkey"  , cmdDELKEY    , KEYEDIT_NOT_SK,
      N_("delete selected subkeys") },
    { "addrevoker",cmdADDREVOKER,KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("add a revocation key") },
    { "delsig"  , cmdDELSIG    , KEYEDIT_NOT_SK,
      N_("delete signatures from the selected user IDs") },
    { "expire"  , cmdEXPIRE    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("change the expiration date for the key or selected subkeys") },
    { "primary" , cmdPRIMARY   , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("flag the selected user ID as primary")},
    { "toggle"  , cmdTOGGLE    , KEYEDIT_NEED_SK,
      N_("toggle between the secret and public key listings") },
    { "t"       , cmdTOGGLE    , KEYEDIT_NEED_SK, NULL },
    { "pref"    , cmdPREF      , KEYEDIT_NOT_SK,
      N_("list preferences (expert)")},
    { "showpref", cmdSHOWPREF  , KEYEDIT_NOT_SK,
      N_("list preferences (verbose)") },
    { "setpref" , cmdSETPREF   , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("set preference list for the selected user IDs") },
    /* Alias */
    { "updpref" , cmdSETPREF   , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK, NULL },

    { "keyserver",cmdPREFKS    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("set the preferred keyserver URL for the selected user IDs")},
    { "notation", cmdNOTATION  , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("set a notation for the selected user IDs")},
    { "passwd"  , cmdPASSWD    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("change the passphrase") },
    /* Alias */
    { "password", cmdPASSWD    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK, NULL },

    { "trust"   , cmdTRUST     , KEYEDIT_NOT_SK, N_("change the ownertrust") },
    { "revsig"  , cmdREVSIG    , KEYEDIT_NOT_SK,
      N_("revoke signatures on the selected user IDs") },
    { "revuid"  , cmdREVUID    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("revoke selected user IDs") },
    /* Alias */
    { "revphoto", cmdREVUID    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK, NULL },

    { "revkey"  , cmdREVKEY    , KEYEDIT_NOT_SK|KEYEDIT_NEED_SK,
      N_("revoke key or selected subkeys") },
    { "enable"  , cmdENABLEKEY , KEYEDIT_NOT_SK, N_("enable key") },
    { "disable" , cmdDISABLEKEY, KEYEDIT_NOT_SK, N_("disable key") },
    { "showphoto",cmdSHOWPHOTO , 0, N_("show selected photo IDs") },
    { "clean",    cmdCLEAN     , KEYEDIT_NOT_SK,
      N_("compact unusable user IDs and remove unusable signatures from key")},
    { "minimize", cmdMINIMIZE  , KEYEDIT_NOT_SK,
      N_("compact unusable user IDs and remove all signatures from key") },
    { NULL, cmdNONE, 0, NULL }
  };

#ifdef HAVE_LIBREADLINE

/* These two functions are used by readline for command completion. */

static char *
command_generator(const char *text,int state)
{
  static int list_index,len;
  const char *name;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the
     index variable to 0. */
  if(!state)
    {
      list_index=0;
      len=strlen(text);
    }

  /* Return the next partial match */
  while((name=cmds[list_index].name))
    {
      /* Only complete commands that have help text */
      if(cmds[list_index++].desc && strncmp(name,text,len)==0)
	return strdup(name);
    }

  return NULL;
}

static char **
keyedit_completion(const char *text, int start, int end)
{
  /* If we are at the start of a line, we try and command-complete.
     If not, just do nothing for now. */

  if(start==0)
    return rl_completion_matches(text,command_generator);

  rl_attempted_completion_over=1;

  return NULL;
}
#endif /* HAVE_LIBREADLINE */


void
keyedit_menu( const char *username, STRLIST locusr,
	      STRLIST commands, int quiet, int seckey_check )
{
    enum cmdids cmd = 0;
    int rc = 0;
    KBNODE keyblock = NULL;
    KEYDB_HANDLE kdbhd = NULL;
    KBNODE sec_keyblock = NULL;
    KEYDB_HANDLE sec_kdbhd = NULL;
    KBNODE cur_keyblock;
    char *answer = NULL;
    int redisplay = 1;
    int modified = 0;
    int sec_modified = 0;
    int toggle;
    int have_commands = !!commands;

    if ( opt.command_fd != -1 )
        ;
    else if( opt.batch && !have_commands )
      {
	log_error(_("can't do this in batch mode\n"));
	goto leave;
      }

#ifdef HAVE_W32_SYSTEM
    /* Due to Windows peculiarities we need to make sure that the
       trustdb stale check is done before we open another file
       (i.e. by searching for a key).  In theory we could make sure
       that the files are closed after use but the open/close caches
       inhibits that and flushing the cache right before the stale
       check is not easy to implement.  Thus we take the easy way out
       and run the stale check as early as possible.  Note, that for
       non- W32 platforms it is run indirectly trough a call to
       get_validity ().  */
    check_trustdb_stale ();
#endif

    /* Get the public key */
    rc = get_pubkey_byname (NULL, username, &keyblock, &kdbhd, 1);
    if( rc )
	goto leave;
    if( fix_keyblock( keyblock ) )
	modified++;
    if( collapse_uids( &keyblock ) )
	modified++;
    reorder_keyblock(keyblock);
    /* We modified the keyblock, so let's make sure the flags are
       right. */
    if(modified)
      merge_keys_and_selfsig( keyblock );

    if(seckey_check)
      {/* see whether we have a matching secret key */
        PKT_public_key *pk = keyblock->pkt->pkt.public_key;

        sec_kdbhd = keydb_new (1);
        {
            byte afp[MAX_FINGERPRINT_LEN];
            size_t an;

            fingerprint_from_pk (pk, afp, &an);
            while (an < MAX_FINGERPRINT_LEN) 
                afp[an++] = 0;
            rc = keydb_search_fpr (sec_kdbhd, afp);
        }
	if (!rc)
	  {
	    rc = keydb_get_keyblock (sec_kdbhd, &sec_keyblock);
	    if (rc)
	      {
		log_error (_("error reading secret keyblock \"%s\": %s\n"),
			   username, g10_errstr(rc));
	      }
            else
	      {
                merge_keys_and_selfsig( sec_keyblock );
                if( fix_keyblock( sec_keyblock ) )
		  sec_modified++;
	      }
	  }

        if (rc) {
            sec_keyblock = NULL;
            keydb_release (sec_kdbhd); sec_kdbhd = NULL;
            rc = 0;
        }

	if( sec_keyblock && !quiet )
	  tty_printf(_("Secret key is available.\n"));
    }

    toggle = 0;
    cur_keyblock = keyblock;
    for(;;) { /* main loop */
	int i, arg_number, photo;
        const char *arg_string = "";
	char *p;
	PKT_public_key *pk=keyblock->pkt->pkt.public_key;

	tty_printf("\n");

	if( redisplay && !quiet )
	  {
	    show_key_with_all_names( cur_keyblock, 0, 1, 0, 1, 0 );
	    tty_printf("\n");
	    redisplay = 0;
	  }
	do {
	    xfree(answer);
	    if( have_commands ) {
		if( commands ) {
		    answer = xstrdup( commands->d );
		    commands = commands->next;
		}
		else if( opt.batch ) {
		    answer = xstrdup("quit");
		}
		else
		    have_commands = 0;
	    }
	    if( !have_commands )
	      {
		tty_enable_completion(keyedit_completion);
		answer = cpr_get_no_help("keyedit.prompt", _("Command> "));
		cpr_kill_prompt();
		tty_disable_completion();
	      }
	    trim_spaces(answer);
	} while( *answer == '#' );

	arg_number = 0; /* Yes, here is the init which egcc complains about */
	photo = 0; /* This too */
	if( !*answer )
	    cmd = cmdLIST;
	else if( *answer == CONTROL_D )
	    cmd = cmdQUIT;
	else if( digitp(answer ) ) {
	    cmd = cmdSELUID;
	    arg_number = atoi(answer);
	}
	else {
	    if( (p=strchr(answer,' ')) ) {
		*p++ = 0;
		trim_spaces(answer);
		trim_spaces(p);
		arg_number = atoi(p);
                arg_string = p;
	    }

	    for(i=0; cmds[i].name; i++ )
	      {
		if(cmds[i].flags & KEYEDIT_TAIL_MATCH)
		  {
		    size_t l=strlen(cmds[i].name);
		    size_t a=strlen(answer);
		    if(a>=l)
		      {
			if(ascii_strcasecmp(&answer[a-l],cmds[i].name)==0)
			  {
			    answer[a-l]='\0';
			    break;
			  }
		      }
		  }
		else if( !ascii_strcasecmp( answer, cmds[i].name ) )
		  break;
	      }
	    if((cmds[i].flags & KEYEDIT_NEED_SK) && !sec_keyblock )
	      {
		tty_printf(_("Need the secret key to do this.\n"));
		cmd = cmdNOP;
	      }
	    else if(((cmds[i].flags & KEYEDIT_NOT_SK) && sec_keyblock
		     && toggle)
                    ||((cmds[i].flags & KEYEDIT_ONLY_SK) && sec_keyblock
		       && !toggle))
	      {
		tty_printf(_("Please use the command \"toggle\" first.\n"));
		cmd = cmdNOP;
	      }
	    else
	      cmd = cmds[i].id;
	}
	switch( cmd )
	  {
	  case cmdHELP:
	    for(i=0; cmds[i].name; i++ )
	      {
		if((cmds[i].flags & KEYEDIT_NEED_SK) && !sec_keyblock )
		  ; /* skip if we do not have the secret key */
		else if( cmds[i].desc )
		  tty_printf("%-11s %s\n", cmds[i].name, _(cmds[i].desc) );
	      }

	    tty_printf("\n");
	    tty_printf(_(
"* The `sign' command may be prefixed with an `l' for local "
"signatures (lsign),\n"
"  a `t' for trust signatures (tsign), an `nr' for non-revocable signatures\n"
"  (nrsign), or any combination thereof (ltsign, tnrsign, etc.).\n"));

	    break;

	  case cmdLIST:
	    redisplay = 1;
	    break;

	  case cmdFPR:
	    show_key_and_fingerprint( keyblock );
	    break;

	  case cmdSELUID:
	    if(strlen(arg_string)==NAMEHASH_LEN*2)
	      redisplay=menu_select_uid_namehash(cur_keyblock,arg_string);
	    else
	      redisplay=menu_select_uid(cur_keyblock,arg_number);
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
	    {
	      int localsig=0,nonrevokesig=0,trustsig=0,interactive=0;

	      if( pk->is_revoked )
		{
		  tty_printf(_("Key is revoked."));

		  if(opt.expert)
		    {
		      tty_printf("  ");
		      if(!cpr_get_answer_is_yes("keyedit.sign_revoked.okay",
						_("Are you sure you still want"
						  " to sign it? (y/N) ")))
			break;
		    }
		  else
		    {
		      tty_printf(_("  Unable to sign.\n"));
		      break;
		    }
		}

	      if(count_uids(keyblock) > 1 && !count_selected_uids(keyblock)
		 && !cpr_get_answer_is_yes("keyedit.sign_all.okay",
					   _("Really sign all user IDs?"
					     " (y/N) ")))
                {
                  if(opt.interactive)
		    interactive=1;
		  else
                    {
		      tty_printf(_("Hint: Select the user IDs to sign\n"));
                      have_commands = 0;
                      break;
                    }

                }
	      /* What sort of signing are we doing? */
	      if(!parse_sign_type(answer,&localsig,&nonrevokesig,&trustsig))
		{
		  tty_printf(_("Unknown signature type `%s'\n"),answer);
		  break;
		}

	      sign_uids(keyblock, locusr, &modified,
			localsig, nonrevokesig, trustsig, interactive);
	    }
	    break;

	  case cmdDEBUG:
	    dump_kbnode( cur_keyblock );
	    break;

	  case cmdTOGGLE:
	    toggle = !toggle;
	    cur_keyblock = toggle? sec_keyblock : keyblock;
	    redisplay = 1;
	    break;

	  case cmdADDPHOTO:
            if (RFC2440 || RFC1991 || PGP2)
              {
                tty_printf(
                   _("This command is not allowed while in %s mode.\n"),
		   compliance_option_string());
                break;
              }
	    photo=1;
	    /* fall through */

	  case cmdADDUID:
	    if( menu_adduid( keyblock, sec_keyblock, photo, arg_string ) )
	      {
	        update_trust = 1;
		redisplay = 1;
		sec_modified = modified = 1;
		merge_keys_and_selfsig( sec_keyblock );
		merge_keys_and_selfsig( keyblock );
	      }
	    break;

	  case cmdDELUID: {
		int n1;

		if( !(n1=count_selected_uids(keyblock)) )
		    tty_printf(_("You must select at least one user ID.\n"));
		else if( real_uids_left(keyblock) < 1 )
		    tty_printf(_("You can't delete the last user ID!\n"));
		else if( cpr_get_answer_is_yes("keyedit.remove.uid.okay",
	       	n1 > 1? _("Really remove all selected user IDs? (y/N) ")
			    : _("Really remove this user ID? (y/N) ")
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
		merge_keys_and_selfsig( sec_keyblock );
		merge_keys_and_selfsig( keyblock );
	    }
	    break;

#ifdef ENABLE_CARD_SUPPORT
	  case cmdADDCARDKEY:
	    if (card_generate_subkey (keyblock, sec_keyblock)) {
		redisplay = 1;
		sec_modified = modified = 1;
		merge_keys_and_selfsig( sec_keyblock );
		merge_keys_and_selfsig( keyblock );
	    }
	    break;

        case cmdKEYTOCARD:
	  {
	    KBNODE node=NULL;
	    switch ( count_selected_keys (sec_keyblock) )
	      {
	      case 0:
		if (cpr_get_answer_is_yes("keyedit.keytocard.use_primary",
				     _("Really move the primary key? (y/N) ")))
		  node = sec_keyblock;
		break;
	      case 1:
		for (node = sec_keyblock; node; node = node->next )
		  {
		    if (node->pkt->pkttype == PKT_SECRET_SUBKEY 
			&& node->flag & NODFLG_SELKEY)
		      break;
		  }
		break;
	      default:
		tty_printf(_("You must select exactly one key.\n"));
		break;
	      }
	    if (node)
	      {
		PKT_public_key *xxpk = find_pk_from_sknode (keyblock, node);
		if (card_store_subkey (node, xxpk?xxpk->pubkey_usage:0))
		  {
		    redisplay = 1;
		    sec_modified = 1;
		  }
	      }
	  }
          break;

        case cmdBKUPTOCARD:
	  {
            /* Ask for a filename, check whether this is really a
               backup key as generated by the card generation, parse
               that key and store it on card. */
	    KBNODE node;
            const char *fname;
            PACKET *pkt;
            IOBUF a;

            fname = arg_string;
            if (!*fname)
              {
                tty_printf (_("Command expects a filename argument\n"));
                break;
              }

            /* Open that file.  */
            a = iobuf_open (fname);
            if (a && is_secured_file (iobuf_get_fd (a)))
              {
                iobuf_close (a);
                a = NULL;
                errno = EPERM;
              }
            if (!a)
              {
	        tty_printf (_("Can't open `%s': %s\n"),
                            fname, strerror(errno));
                break;
              }
            
            /* Parse and check that file.  */
            pkt = xmalloc (sizeof *pkt);
            init_packet (pkt);
            rc = parse_packet (a, pkt);
            iobuf_close (a);
            iobuf_ioctl (NULL, 2, 0, (char*)fname); /* (invalidate cache).  */
            if (!rc 
                && pkt->pkttype != PKT_SECRET_KEY 
                && pkt->pkttype != PKT_SECRET_SUBKEY)
              rc = G10ERR_NO_SECKEY;
            if (rc)
              {
                tty_printf(_("Error reading backup key from `%s': %s\n"),
                           fname, g10_errstr (rc));
                free_packet (pkt);
                xfree (pkt);
                break;
              }
            node = new_kbnode (pkt);

            /* Store it.  */
            if (card_store_subkey (node, 0))
              {
                redisplay = 1;
                sec_modified = 1;
              }
            release_kbnode (node);
	  }
          break;

#endif /* ENABLE_CARD_SUPPORT */

	  case cmdDELKEY: {
		int n1;

		if( !(n1=count_selected_keys( keyblock )) )
		    tty_printf(_("You must select at least one key.\n"));
		else if( !cpr_get_answer_is_yes( "keyedit.remove.subkey.okay",
		       n1 > 1?
		   _("Do you really want to delete the selected keys? (y/N) "):
			_("Do you really want to delete this key? (y/N) ")
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

	  case cmdADDREVOKER:
	    {
	      int sensitive=0;

	      if(ascii_strcasecmp(arg_string,"sensitive")==0)
		sensitive=1;
	      if( menu_addrevoker( keyblock, sec_keyblock, sensitive ) ) {
		redisplay = 1;
		sec_modified = modified = 1;
		merge_keys_and_selfsig( sec_keyblock );
		merge_keys_and_selfsig( keyblock );
	      }
	    }
	    break;

	  case cmdREVUID: {
		int n1;

		if( !(n1=count_selected_uids(keyblock)) )
		    tty_printf(_("You must select at least one user ID.\n"));
		else if( cpr_get_answer_is_yes(
			    "keyedit.revoke.uid.okay",
		       n1 > 1? _("Really revoke all selected user IDs? (y/N) ")
		             : _("Really revoke this user ID? (y/N) ")
		       ) ) {
		  if(menu_revuid(keyblock,sec_keyblock))
		    {
		      modified=1;
		      redisplay=1;
		    }
		}
	    }
	    break;

	  case cmdREVKEY:
	    {
	      int n1;

	      if( !(n1=count_selected_keys( keyblock )) )
		{
		  if(cpr_get_answer_is_yes("keyedit.revoke.subkey.okay",
					   _("Do you really want to revoke"
					     " the entire key? (y/N) ")))
		    {
		      if(menu_revkey(keyblock,sec_keyblock))
			modified=1;

		      redisplay=1;
		    }
		}
	      else if(cpr_get_answer_is_yes("keyedit.revoke.subkey.okay",
					    n1 > 1?
					    _("Do you really want to revoke"
					      " the selected subkeys? (y/N) "):
					    _("Do you really want to revoke"
					      " this subkey? (y/N) ")))
		{
		  if( menu_revsubkey( keyblock, sec_keyblock ) )
		    modified = 1;

		  redisplay = 1;
		}

	      if(modified)
		merge_keys_and_selfsig( keyblock );
	    }
	    break;

	  case cmdEXPIRE:
	    if( menu_expire( keyblock, sec_keyblock ) )
	      {
		merge_keys_and_selfsig( sec_keyblock );
		merge_keys_and_selfsig( keyblock );
		sec_modified = 1;
		modified = 1;
		redisplay = 1;
	      }
	    break;

	  case cmdBACKSIGN:
	    if(menu_backsign(keyblock,sec_keyblock))
	      {
		sec_modified = 1;
		modified = 1;
		redisplay = 1;
	      }
	    break;

	  case cmdPRIMARY:
	    if( menu_set_primary_uid ( keyblock, sec_keyblock ) ) {
		merge_keys_and_selfsig( keyblock );
		modified = 1;
		redisplay = 1;
	    }
	    break;

	  case cmdPASSWD:
	    if( change_passphrase( sec_keyblock ) )
		sec_modified = 1;
	    break;

	  case cmdTRUST:
	    if(opt.trust_model==TM_EXTERNAL)
	      {
		tty_printf(_("Owner trust may not be set while "
			     "using a user provided trust database\n"));
		break;
	      }

	    show_key_with_all_names( keyblock, 0, 0, 0, 1, 0 );
	    tty_printf("\n");
	    if( edit_ownertrust( find_kbnode( keyblock,
                                 PKT_PUBLIC_KEY )->pkt->pkt.public_key, 1 ) ) {
		redisplay = 1;
		/* No real need to set update_trust here as
		   edit_ownertrust() calls revalidation_mark()
		   anyway. */
		update_trust=1;
            }
	    break;

	  case cmdPREF:
	    {
	      int count=count_selected_uids(keyblock);
	      assert(keyblock->pkt->pkttype==PKT_PUBLIC_KEY);
	      show_names(keyblock,keyblock->pkt->pkt.public_key,
			 count?NODFLG_SELUID:0,1);
	    }
	    break;

	  case cmdSHOWPREF:
	    {
	      int count=count_selected_uids(keyblock);
	      assert(keyblock->pkt->pkttype==PKT_PUBLIC_KEY);
	      show_names(keyblock,keyblock->pkt->pkt.public_key,
			 count?NODFLG_SELUID:0,2);
	    }
	    break;

          case cmdSETPREF:
	    {
	      PKT_user_id *tempuid;

	      keygen_set_std_prefs(!*arg_string?"default" : arg_string, 0);

	      tempuid=keygen_get_std_prefs();
	      tty_printf(_("Set preference list to:\n"));
	      show_prefs(tempuid,NULL,1);
	      free_user_id(tempuid);

	      if(cpr_get_answer_is_yes("keyedit.setpref.okay",
				       count_selected_uids (keyblock)?
				       _("Really update the preferences"
					 " for the selected user IDs? (y/N) "):
				       _("Really update the preferences? (y/N) ")))
		{
		  if ( menu_set_preferences (keyblock, sec_keyblock) )
		    {
		      merge_keys_and_selfsig (keyblock);
		      modified = 1;
		      redisplay = 1;
		    }
		}
	    }
	    break;

	  case cmdPREFKS:
	    if( menu_set_keyserver_url ( *arg_string?arg_string:NULL,
					 keyblock, sec_keyblock ) )
	      {
		merge_keys_and_selfsig( keyblock );
		modified = 1;
		redisplay = 1;
	      }
	    break;

	  case cmdNOTATION:
	    if( menu_set_notation ( *arg_string?arg_string:NULL,
				    keyblock, sec_keyblock ) )
	      {
		merge_keys_and_selfsig( keyblock );
		modified = 1;
		redisplay = 1;
	      }
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

	  case cmdSHOWPHOTO:
	    menu_showphoto(keyblock);
	    break;

	  case cmdCLEAN:
	    redisplay=modified=menu_clean(keyblock,0);
	    break;

	  case cmdMINIMIZE:
	    redisplay=modified=menu_clean(keyblock,1);
	    break;

	  case cmdQUIT:
	    if( have_commands )
		goto leave;
	    if( !modified && !sec_modified )
		goto leave;
	    if( !cpr_get_answer_is_yes("keyedit.save.okay",
					_("Save changes? (y/N) ")) ) {
		if( cpr_enabled()
		    || cpr_get_answer_is_yes("keyedit.cancel.okay",
					     _("Quit without saving? (y/N) ")))
		    goto leave;
		break;
	    }
	    /* fall thru */
	  case cmdSAVE:
	    if( modified || sec_modified  ) {
		if( modified ) {
		    rc = keydb_update_keyblock (kdbhd, keyblock);
		    if( rc ) {
			log_error(_("update failed: %s\n"), g10_errstr(rc) );
			break;
		    }
		}
		if( sec_modified ) {
		    rc = keydb_update_keyblock (sec_kdbhd, sec_keyblock );
		    if( rc ) {
			log_error( _("update secret failed: %s\n"),
                                   g10_errstr(rc) );
			break;
		    }
		}
	    }
	    else
		tty_printf(_("Key not changed so no update needed.\n"));

	    if( update_trust )
	      {
		revalidation_mark ();
		update_trust=0;
	      }
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
    keydb_release (kdbhd);
    xfree(answer);
}

static void
tty_print_notations(int indent,PKT_signature *sig)
{
  int first=1;
  struct notation *notation,*nd;

  if(indent<0)
    {
      first=0;
      indent=-indent;
    }

  notation=sig_to_notation(sig);

  for(nd=notation;nd;nd=nd->next)
    {
      if(!first)
	tty_printf("%*s",indent,"");
      else
	first=0;

      tty_print_utf8_string(nd->name,strlen(nd->name));
      tty_printf("=");
      tty_print_utf8_string(nd->value,strlen(nd->value));
      tty_printf("\n");
    }

  free_notation(notation);
}

/****************
 * show preferences of a public keyblock.
 */
static void
show_prefs (PKT_user_id *uid, PKT_signature *selfsig, int verbose)
{
    const prefitem_t fake={0,0};
    const prefitem_t *prefs;
    int i;

    if( !uid )
        return;

    if( uid->prefs )
        prefs=uid->prefs;
    else if(verbose)
        prefs=&fake;
    else
      return;

    if (verbose) {
        int any, des_seen=0, sha1_seen=0, uncomp_seen=0;

        tty_printf ("     ");
	tty_printf (_("Cipher: "));
        for(i=any=0; prefs[i].type; i++ ) {
            if( prefs[i].type == PREFTYPE_SYM ) {
                const char *s = cipher_algo_to_string (prefs[i].value);
                
                if (any)
                    tty_printf (", ");
                any = 1;
                /* We don't want to display strings for experimental algos */
                if (s && prefs[i].value < 100 )
                    tty_printf ("%s", s );
                else
                    tty_printf ("[%d]", prefs[i].value);
                if (prefs[i].value == CIPHER_ALGO_3DES )
                    des_seen = 1;
            }    
        }
        if (!des_seen) {
            if (any)
                tty_printf (", ");
            tty_printf ("%s",cipher_algo_to_string(CIPHER_ALGO_3DES));
        }
        tty_printf ("\n     ");
	tty_printf (_("Digest: "));
        for(i=any=0; prefs[i].type; i++ ) {
            if( prefs[i].type == PREFTYPE_HASH ) {
                const char *s = digest_algo_to_string (prefs[i].value);
                
                if (any)
                    tty_printf (", ");
                any = 1;
                /* We don't want to display strings for experimental algos */
                if (s && prefs[i].value < 100 )
                    tty_printf ("%s", s );
                else
                    tty_printf ("[%d]", prefs[i].value);
                if (prefs[i].value == DIGEST_ALGO_SHA1 )
                    sha1_seen = 1;
            }
        }
        if (!sha1_seen) {
            if (any)
                tty_printf (", ");
            tty_printf ("%s",digest_algo_to_string(DIGEST_ALGO_SHA1));
        }
        tty_printf ("\n     ");
	tty_printf (_("Compression: "));
        for(i=any=0; prefs[i].type; i++ ) {
            if( prefs[i].type == PREFTYPE_ZIP ) {
                const char *s=compress_algo_to_string(prefs[i].value);
                
                if (any)
                    tty_printf (", ");
                any = 1;
                /* We don't want to display strings for experimental algos */
                if (s && prefs[i].value < 100 )
                    tty_printf ("%s", s );
                else
                    tty_printf ("[%d]", prefs[i].value);
                if (prefs[i].value == COMPRESS_ALGO_NONE )
                    uncomp_seen = 1;
            }
        }
        if (!uncomp_seen) {
            if (any)
                tty_printf (", ");
	    else {
	      tty_printf ("%s",compress_algo_to_string(COMPRESS_ALGO_ZIP));
	      tty_printf (", ");
	    }
	    tty_printf ("%s",compress_algo_to_string(COMPRESS_ALGO_NONE));
        }
	if(uid->flags.mdc || !uid->flags.ks_modify)
	  {
	    tty_printf ("\n     ");
	    tty_printf (_("Features: "));
	    any=0;
	    if(uid->flags.mdc)
	      {
		tty_printf ("MDC");
		any=1;
	      }
	    if(!uid->flags.ks_modify)
	      {
		if(any)
		  tty_printf (", ");
		tty_printf (_("Keyserver no-modify"));
	      }
	  }
	tty_printf("\n");

	if(selfsig)
	  {
	    const byte *pref_ks;
	    size_t pref_ks_len;

	    pref_ks=parse_sig_subpkt(selfsig->hashed,
				     SIGSUBPKT_PREF_KS,&pref_ks_len);
	    if(pref_ks && pref_ks_len)
	      {
		tty_printf ("     ");
		tty_printf(_("Preferred keyserver: "));
		tty_print_utf8_string(pref_ks,pref_ks_len);
		tty_printf("\n");
	      }

	    if(selfsig->flags.notation)
	      {
		tty_printf ("     ");
		tty_printf(_("Notations: "));
		tty_print_notations(5+strlen(_("Notations: ")),selfsig);
	      }
	  }
    }
    else {
        tty_printf("    ");
        for(i=0; prefs[i].type; i++ ) {
            tty_printf( " %c%d", prefs[i].type == PREFTYPE_SYM   ? 'S' :
                                 prefs[i].type == PREFTYPE_HASH  ? 'H' :
                                 prefs[i].type == PREFTYPE_ZIP ? 'Z':'?',
                                 prefs[i].value);
        }
        if (uid->flags.mdc)
            tty_printf (" [mdc]");
        if (!uid->flags.ks_modify)
            tty_printf (" [no-ks-modify]");
        tty_printf("\n");
    }
}

/* This is the version of show_key_with_all_names used when
   opt.with_colons is used.  It prints all available data in a easy to
   parse format and does not translate utf8 */
static void
show_key_with_all_names_colon (KBNODE keyblock)
{
  KBNODE node;
  int i, j, ulti_hack=0;
  byte pk_version=0;
  PKT_public_key *primary=NULL;

  /* the keys */
  for ( node = keyblock; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY
          || (node->pkt->pkttype == PKT_PUBLIC_SUBKEY) )
        {
          PKT_public_key *pk = node->pkt->pkt.public_key;
          u32 keyid[2];

          if (node->pkt->pkttype == PKT_PUBLIC_KEY)
            {
              pk_version = pk->version;
	      primary=pk;
	    }

          keyid_from_pk (pk, keyid);

          fputs (node->pkt->pkttype == PKT_PUBLIC_KEY?"pub:":"sub:", stdout);
          if (!pk->is_valid)
            putchar ('i');
          else if (pk->is_revoked)
            putchar ('r');
          else if (pk->has_expired)
            putchar ('e');
          else if (!(opt.fast_list_mode || opt.no_expensive_trust_checks ))
	    {
	      int trust = get_validity_info (pk, NULL);
	      if(trust=='u')
		ulti_hack=1;
	      putchar (trust);
	    }

          printf (":%u:%d:%08lX%08lX:%lu:%lu::",
                  nbits_from_pk (pk),
                  pk->pubkey_algo,
                  (ulong)keyid[0], (ulong)keyid[1],
                  (ulong)pk->timestamp,
                  (ulong)pk->expiredate );
          if (node->pkt->pkttype==PKT_PUBLIC_KEY
	      && !(opt.fast_list_mode || opt.no_expensive_trust_checks ))
	    putchar(get_ownertrust_info (pk));
          putchar(':');
          putchar('\n');
          
          print_fingerprint (pk, NULL, 0);
	  print_revokers(pk);
        }
    }
  
    /* the user ids */
    i = 0;
    for (node = keyblock; node; node = node->next) 
      {
	if ( node->pkt->pkttype == PKT_USER_ID )
          {
            PKT_user_id *uid = node->pkt->pkt.user_id;

	    ++i;

	    if(uid->attrib_data)
	      printf("uat:");
	    else
	      printf("uid:");

	    if ( uid->is_revoked )
	      printf("r::::::::");
	    else if ( uid->is_expired )
	      printf("e::::::::");
	    else if ( opt.fast_list_mode || opt.no_expensive_trust_checks )
	      printf("::::::::");
	    else
	      {
		int uid_validity;

		if( primary && !ulti_hack )
		  uid_validity = get_validity_info( primary, uid );
		else
		  uid_validity = 'u';
		printf("%c::::::::",uid_validity);
	      }

	    if(uid->attrib_data)
	      printf ("%u %lu",uid->numattribs,uid->attrib_len);
	    else
	      print_string (stdout, uid->name, uid->len, ':');

            putchar (':');
            /* signature class */
            putchar (':');
            /* capabilities */
            putchar (':');
            /* preferences */
            if (pk_version>3 || uid->selfsigversion>3)
              {
                const prefitem_t *prefs = uid->prefs;
                
                for (j=0; prefs && prefs[j].type; j++)
                  {
                    if (j)
                      putchar (' ');
                    printf ("%c%d", prefs[j].type == PREFTYPE_SYM   ? 'S' :
                            prefs[j].type == PREFTYPE_HASH  ? 'H' :
                            prefs[j].type == PREFTYPE_ZIP ? 'Z':'?',
                            prefs[j].value);
                  } 
                if (uid->flags.mdc)
                  printf (",mdc");
                if (!uid->flags.ks_modify)
                  printf (",no-ks-modify");
              } 
            putchar (':');
            /* flags */
            printf ("%d,", i);
            if (uid->is_primary)
              putchar ('p');
            if (uid->is_revoked)
              putchar ('r');
            if (uid->is_expired)
              putchar ('e');
            if ((node->flag & NODFLG_SELUID))
              putchar ('s');
            if ((node->flag & NODFLG_MARK_A))
              putchar ('m');
            putchar (':');
            putchar('\n');
          }
      }
}

static void
show_names(KBNODE keyblock,PKT_public_key *pk,unsigned int flag,int with_prefs)
{
  KBNODE node;
  int i=0;

  for( node = keyblock; node; node = node->next )
    {
      if( node->pkt->pkttype == PKT_USER_ID
	  && !is_deleted_kbnode(node))
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  ++i;
	  if(!flag || (flag && (node->flag & flag)))
	    {
	      if(!(flag&NODFLG_MARK_A) && pk)
		tty_printf("%s ",uid_trust_string_fixed(pk,uid));

	      if( flag & NODFLG_MARK_A )
		tty_printf("     ");
	      else if( node->flag & NODFLG_SELUID )
		tty_printf("(%d)* ", i);
	      else if( uid->is_primary )
		tty_printf("(%d). ", i);
	      else
		tty_printf("(%d)  ", i);
	      tty_print_utf8_string( uid->name, uid->len );
	      tty_printf("\n");
	      if(with_prefs && pk)
		{
		  if(pk->version>3 || uid->selfsigversion>3)
		    {
		      PKT_signature *selfsig=NULL;
		      KBNODE signode;

		      for(signode=node->next;
			  signode && signode->pkt->pkttype==PKT_SIGNATURE;
			  signode=signode->next)
			{
			  if(signode->pkt->pkt.signature->
			     flags.chosen_selfsig)
			    {
			      selfsig=signode->pkt->pkt.signature;
			      break;
			    }
			}

		      show_prefs (uid, selfsig, with_prefs == 2);
		    }
		  else
		    tty_printf(_("There are no preferences on a"
				 " PGP 2.x-style user ID.\n"));
		}
	    }
	}
    }
}

/****************
 * Display the key a the user ids, if only_marked is true, do only
 * so for user ids with mark A flag set and dont display the index number
 */
static void
show_key_with_all_names( KBNODE keyblock, int only_marked, int with_revoker,
			 int with_fpr, int with_subkeys, int with_prefs )
{
    KBNODE node;
    int i;
    int do_warn = 0;
    byte pk_version=0;
    PKT_public_key *primary=NULL;

    if (opt.with_colons)
      {
        show_key_with_all_names_colon (keyblock);
        return;
      }

    /* the keys */
    for( node = keyblock; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_KEY
	    || (with_subkeys && node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		&& !is_deleted_kbnode(node)) ) {
	    PKT_public_key *pk = node->pkt->pkt.public_key;
	    const char *otrust="err",*trust="err";

	    if( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
		/* do it here, so that debug messages don't clutter the
		 * output */
                static int did_warn = 0;

                trust = get_validity_string (pk, NULL);
		otrust = get_ownertrust_string (pk);

                /* Show a warning once */
                if (!did_warn
                    && (get_validity (pk, NULL) & TRUST_FLAG_PENDING_CHECK)) {
                    did_warn = 1;
                    do_warn = 1;
                }

		pk_version=pk->version;
		primary=pk;
	    }

	    if(pk->is_revoked)
	      {
		char *user=get_user_id_string_native(pk->revoked.keyid);
		const char *algo=pubkey_algo_to_string(pk->revoked.algo);
		tty_printf(_("This key was revoked on %s by %s key %s\n"),
			   revokestr_from_pk(pk),algo?algo:"?",user);
		xfree(user);
	      }

	    if(with_revoker)
	      {
	        if( !pk->revkey && pk->numrevkeys )
		  BUG();
	        else
		  for(i=0;i<pk->numrevkeys;i++)
		    {
		      u32 r_keyid[2];
		      char *user;
		      const char *algo=
			pubkey_algo_to_string(pk->revkey[i].algid);

		      keyid_from_fingerprint(pk->revkey[i].fpr,
					     MAX_FINGERPRINT_LEN,r_keyid);

		      user=get_user_id_string_native(r_keyid);
		      tty_printf(_("This key may be revoked by %s key %s"),
				 algo?algo:"?",user);

		      if(pk->revkey[i].class&0x40)
			{
			  tty_printf(" ");
			  tty_printf(_("(sensitive)"));
			}

		      tty_printf ("\n");
		      xfree(user);
		    }
	      }

	    keyid_from_pk(pk,NULL);
	    tty_printf("%s%c %4u%c/%s  ",
		       node->pkt->pkttype == PKT_PUBLIC_KEY? "pub":"sub",
		       (node->flag & NODFLG_SELKEY)? '*':' ',
		       nbits_from_pk( pk ),
		       pubkey_letter( pk->pubkey_algo ),
		       keystr(pk->keyid));

	    tty_printf(_("created: %s"),datestr_from_pk(pk));
	    tty_printf("  ");
	    if(pk->is_revoked)
	      tty_printf(_("revoked: %s"),revokestr_from_pk(pk));
	    else if(pk->has_expired)
	      tty_printf(_("expired: %s"),expirestr_from_pk(pk));
	    else
	      tty_printf(_("expires: %s"),expirestr_from_pk(pk));
	    tty_printf("  ");
            tty_printf(_("usage: %s"),usagestr_from_pk(pk));
	    tty_printf("\n");

	    if( node->pkt->pkttype == PKT_PUBLIC_KEY )
	      {
		if(opt.trust_model!=TM_ALWAYS)
		  {
		    tty_printf("%*s", (int)keystrlen()+13,"");
		    /* Ownertrust is only meaningful for the PGP or
		       classic trust models */
		    if(opt.trust_model==TM_PGP || opt.trust_model==TM_CLASSIC)
		      {
			int width=14-strlen(otrust);
			if(width<=0)
			  width=1;
			tty_printf(_("trust: %s"), otrust);
			tty_printf("%*s",width,"");
		      }
		    
		    tty_printf(_("validity: %s"), trust );
		    tty_printf("\n");
		  }
		if( node->pkt->pkttype == PKT_PUBLIC_KEY
		    && (get_ownertrust (pk)&TRUST_FLAG_DISABLED))
		  {
		    tty_printf("*** ");
		    tty_printf(_("This key has been disabled"));
		    tty_printf("\n");
		  }
	      }

	    if( node->pkt->pkttype == PKT_PUBLIC_KEY && with_fpr )
	      {
		print_fingerprint ( pk, NULL, 2 );
		tty_printf("\n");
	      }
	}
	else if( node->pkt->pkttype == PKT_SECRET_KEY
	    || (with_subkeys && node->pkt->pkttype == PKT_SECRET_SUBKEY) )
	  {
	    PKT_secret_key *sk = node->pkt->pkt.secret_key;
	    tty_printf("%s%c %4u%c/%s  ",
		       node->pkt->pkttype == PKT_SECRET_KEY? "sec":"ssb",
		       (node->flag & NODFLG_SELKEY)? '*':' ',
		       nbits_from_sk( sk ),
		       pubkey_letter( sk->pubkey_algo ),
		       keystr_from_sk(sk));
	    tty_printf(_("created: %s"),datestr_from_sk(sk));
	    tty_printf("  ");
	    tty_printf(_("expires: %s"),expirestr_from_sk(sk));
	    tty_printf("\n");
            if (sk->is_protected && sk->protect.s2k.mode == 1002)
              {
		tty_printf("                     ");
                tty_printf(_("card-no: ")); 
                if (sk->protect.ivlen == 16
                    && !memcmp (sk->protect.iv, "\xD2\x76\x00\x01\x24\x01", 6))
                  { /* This is an OpenPGP card. */
                    for (i=8; i < 14; i++)
                      {
                        if (i == 10)
                          tty_printf (" ");
                        tty_printf ("%02X", sk->protect.iv[i]);
                      }
                  }
                else
                  { /* Something is wrong: Print all. */
                    for (i=0; i < sk->protect.ivlen; i++)
                      tty_printf ("%02X", sk->protect.iv[i]);
                  }
                tty_printf ("\n");
              }
	  }
    }

    show_names(keyblock,primary,only_marked?NODFLG_MARK_A:0,with_prefs);

    if (do_warn)
        tty_printf (_("Please note that the shown key validity"
                      " is not necessarily correct\n"
                      "unless you restart the program.\n")); 
}


/* Display basic key information.  This function is suitable to show
   information on the key without any dependencies on the trustdb or
   any other internal GnuPG stuff.  KEYBLOCK may either be a public or
   a secret key.*/
void
show_basic_key_info ( KBNODE keyblock )
{
  KBNODE node;
  int i;

  /* The primary key */
  for (node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_KEY)
        {
          PKT_public_key *pk = node->pkt->pkt.public_key;
          
          /* Note, we use the same format string as in other show
             functions to make the translation job easier. */
          tty_printf ("%s  %4u%c/%s  ",
                      node->pkt->pkttype == PKT_PUBLIC_KEY? "pub":"sub",
                      nbits_from_pk( pk ),
                      pubkey_letter( pk->pubkey_algo ),
                      keystr_from_pk(pk));
	  tty_printf(_("created: %s"),datestr_from_pk(pk));
	  tty_printf("  ");
	  tty_printf(_("expires: %s"),expirestr_from_pk(pk));
          tty_printf("\n");
          print_fingerprint ( pk, NULL, 3 );
          tty_printf("\n");
	}
      else if (node->pkt->pkttype == PKT_SECRET_KEY)
        {
          PKT_secret_key *sk = node->pkt->pkt.secret_key;
          tty_printf("%s  %4u%c/%s",
                     node->pkt->pkttype == PKT_SECRET_KEY? "sec":"ssb",
                     nbits_from_sk( sk ),
                     pubkey_letter( sk->pubkey_algo ),
                     keystr_from_sk(sk));
	  tty_printf(_("created: %s"),datestr_from_sk(sk));
	  tty_printf("  ");
	  tty_printf(_("expires: %s"),expirestr_from_sk(sk));
          tty_printf("\n");
          print_fingerprint (NULL, sk, 3 );
          tty_printf("\n");
	}
    }

  /* The user IDs. */
  for (i=0, node = keyblock; node; node = node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          PKT_user_id *uid = node->pkt->pkt.user_id;
          ++i;
     
          tty_printf ("     ");
          if (uid->is_revoked)
            tty_printf("[%s] ",_("revoked"));
          else if ( uid->is_expired )
            tty_printf("[%s] ",_("expired"));
          tty_print_utf8_string (uid->name, uid->len);
          tty_printf ("\n");
        }
    }
}

static void
show_key_and_fingerprint( KBNODE keyblock )
{
  KBNODE node;
  PKT_public_key *pk = NULL;

  for( node = keyblock; node; node = node->next )
    {
      if( node->pkt->pkttype == PKT_PUBLIC_KEY )
	{
	  pk = node->pkt->pkt.public_key;
	  tty_printf("pub   %4u%c/%s %s ",
		     nbits_from_pk( pk ),
		     pubkey_letter( pk->pubkey_algo ),
		     keystr_from_pk(pk),
		     datestr_from_pk(pk) );
	}
      else if( node->pkt->pkttype == PKT_USER_ID )
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  tty_print_utf8_string( uid->name, uid->len );
	  break;
	}
    }
  tty_printf("\n");
  if( pk )
    print_fingerprint( pk, NULL, 2 );
}


/* Show a warning if no uids on the key have the primary uid flag
   set. */
static void
no_primary_warning(KBNODE keyblock)
{
  KBNODE node;
  int have_primary=0,uid_count=0;

  /* TODO: if we ever start behaving differently with a primary or
     non-primary attribute ID, we will need to check for attributes
     here as well. */

  for(node=keyblock; node; node = node->next)
    {
      if(node->pkt->pkttype==PKT_USER_ID
	 && node->pkt->pkt.user_id->attrib_data==NULL)
	{
	  uid_count++;

	  if(node->pkt->pkt.user_id->is_primary==2)
	    {
	      have_primary=1;
	      break;
	    }
	}
    }

  if(uid_count>1 && !have_primary)
    log_info(_("WARNING: no user ID has been marked as primary.  This command"
	       " may\n              cause a different user ID to become"
	       " the assumed primary.\n"));
}

/****************
 * Ask for a new user id, do the selfsignature and put it into
 * both keyblocks.
 * Return true if there is a new user id
 */
static int
menu_adduid( KBNODE pub_keyblock, KBNODE sec_keyblock,
	     int photo, const char *photo_name)
{
    PKT_user_id *uid;
    PKT_public_key *pk=NULL;
    PKT_secret_key *sk=NULL;
    PKT_signature *sig=NULL;
    PACKET *pkt;
    KBNODE node;
    KBNODE pub_where=NULL, sec_where=NULL;
    int rc;

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
    assert(pk && sk);

    if(photo) {
      int hasattrib=0;

      for( node = pub_keyblock; node; node = node->next )
	if( node->pkt->pkttype == PKT_USER_ID &&
	    node->pkt->pkt.user_id->attrib_data!=NULL)
	  {
	    hasattrib=1;
	    break;
	  }

      /* It is legal but bad for compatibility to add a photo ID to a
         v3 key as it means that PGP2 will not be able to use that key
         anymore.  Also, PGP may not expect a photo on a v3 key.
         Don't bother to ask this if the key already has a photo - any
         damage has already been done at that point. -dms */
      if(pk->version==3 && !hasattrib)
	{
	  if(opt.expert)
	    {
	      tty_printf(_("WARNING: This is a PGP2-style key.  "
			   "Adding a photo ID may cause some versions\n"
			   "         of PGP to reject this key.\n"));

	      if(!cpr_get_answer_is_yes("keyedit.v3_photo.okay",
					_("Are you sure you still want "
					  "to add it? (y/N) ")))
		return 0;
	    }
	  else
	    {
	      tty_printf(_("You may not add a photo ID to "
			   "a PGP2-style key.\n"));
	      return 0;
	    }
	}

      uid = generate_photo_id(pk,photo_name);
    } else
      uid = generate_user_id();
    if( !uid )
	return 0;

    rc = make_keysig_packet( &sig, pk, uid, NULL, sk, 0x13, 0, 0, 0, 0,
			     keygen_add_std_prefs, pk );
    free_secret_key( sk );
    if( rc ) {
	log_error("signing failed: %s\n", g10_errstr(rc) );
	free_user_id(uid);
	return 0;
    }

    /* insert/append to secret keyblock */
    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = scopy_user_id(uid);
    node = new_kbnode(pkt);
    if( sec_where )
	insert_kbnode( sec_where, node, 0 );
    else
	add_kbnode( sec_keyblock, node );
    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = copy_signature(NULL, sig);
    if( sec_where )
	insert_kbnode( node, new_kbnode(pkt), 0 );
    else
	add_kbnode( sec_keyblock, new_kbnode(pkt) );
    /* insert/append to public keyblock */
    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = uid;
    node = new_kbnode(pkt);
    if( pub_where )
	insert_kbnode( pub_where, node, 0 );
    else
	add_kbnode( pub_keyblock, node );
    pkt = xmalloc_clear( sizeof *pkt );
    pkt->pkttype = PKT_SIGNATURE;
    pkt->pkt.signature = copy_signature(NULL, sig);
    if( pub_where )
	insert_kbnode( node, new_kbnode(pkt), 0 );
    else
	add_kbnode( pub_keyblock, new_kbnode(pkt) );
    return 1;
}


/****************
 * Remove all selected userids from the keyrings
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
		/* Only cause a trust update if we delete a
                   non-revoked user id */
		if(!node->pkt->pkt.user_id->is_revoked)
		  update_trust=1;
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
	    if(opt.with_colons)
	      valid = print_and_check_one_sig_colon( pub_keyblock, node,
					       &inv_sig, &no_key, &other_err,
					       &selfsig, 1 );
	    else
	      valid = print_and_check_one_sig( pub_keyblock, node,
					       &inv_sig, &no_key, &other_err,
					       &selfsig, 1 );

	   if( valid ) {
	       okay = cpr_get_answer_yes_no_quit(
		   "keyedit.delsig.valid",
		   _("Delete this good signature? (y/N/q)"));

	       /* Only update trust if we delete a good signature.
                  The other two cases do not affect trust. */
	       if(okay)
		 update_trust=1;
	   }
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

static int
menu_clean(KBNODE keyblock,int self_only)
{
  KBNODE uidnode;
  int modified=0,select_all=!count_selected_uids(keyblock);

  for(uidnode=keyblock->next;
      uidnode && uidnode->pkt->pkttype!=PKT_PUBLIC_SUBKEY;
      uidnode=uidnode->next)
    {
      if(uidnode->pkt->pkttype==PKT_USER_ID
	 && (uidnode->flag&NODFLG_SELUID || select_all))
	{
	  int uids=0,sigs=0;
	  char *user=utf8_to_native(uidnode->pkt->pkt.user_id->name,
				    uidnode->pkt->pkt.user_id->len,
				    0);

	  clean_one_uid(keyblock,uidnode,opt.verbose,self_only,&uids,&sigs);
	  if(uids)
	    {
	      const char *reason;

	      if(uidnode->pkt->pkt.user_id->is_revoked)
		reason=_("revoked");
	      else if(uidnode->pkt->pkt.user_id->is_expired)
		reason=_("expired");
	      else
		reason=_("invalid");

	      tty_printf (_("User ID \"%s\" compacted: %s\n"), user, reason);

	      modified=1;
	    }
	  else if(sigs)
	    {
	      tty_printf (sigs==1?
			  _("User ID \"%s\": %d signature removed\n"):
                          _("User ID \"%s\": %d signatures removed\n"),
                          user,sigs);

	      modified=1;
	    }
	  else
	    {
	      tty_printf (self_only==1?
                          _("User ID \"%s\": already minimized\n"):
                          _("User ID \"%s\": already clean\n"),
                          user);
	    }

	  xfree(user);
	}
    }

  return modified;
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

    /* No need to set update_trust here since signing keys are no
       longer used to certify other keys, so there is no change in
       trust when revoking/removing them */
}


/****************
 * Ask for a new revoker, do the selfsignature and put it into
 * both keyblocks.
 * Return true if there is a new revoker
 */
static int
menu_addrevoker( KBNODE pub_keyblock, KBNODE sec_keyblock, int sensitive )
{
  PKT_public_key *pk=NULL,*revoker_pk=NULL;
  PKT_secret_key *sk=NULL;
  PKT_signature *sig=NULL;
  PACKET *pkt;
  struct revocation_key revkey;
  size_t fprlen;
  int rc;

  assert(pub_keyblock->pkt->pkttype==PKT_PUBLIC_KEY);
  assert(sec_keyblock->pkt->pkttype==PKT_SECRET_KEY);

  pk=pub_keyblock->pkt->pkt.public_key;

  if(pk->numrevkeys==0 && pk->version==3)
    {
      /* It is legal but bad for compatibility to add a revoker to a
         v3 key as it means that PGP2 will not be able to use that key
         anymore.  Also, PGP may not expect a revoker on a v3 key.
         Don't bother to ask this if the key already has a revoker -
         any damage has already been done at that point. -dms */
      if(opt.expert)
	{
	  tty_printf(_("WARNING: This is a PGP 2.x-style key.  "
		       "Adding a designated revoker may cause\n"
		       "         some versions of PGP to reject this key.\n"));

	  if(!cpr_get_answer_is_yes("keyedit.v3_revoker.okay",
				    _("Are you sure you still want "
				      "to add it? (y/N) ")))
	    return 0;
	}
      else
	{
	  tty_printf(_("You may not add a designated revoker to "
		       "a PGP 2.x-style key.\n"));
	  return 0;
	}
    }

  sk=copy_secret_key(NULL,sec_keyblock->pkt->pkt.secret_key);

  for(;;)
    {
      char *answer;

      if(revoker_pk)
	free_public_key(revoker_pk);

      revoker_pk=xmalloc_clear(sizeof(*revoker_pk));

      tty_printf("\n");

      answer=cpr_get_utf8("keyedit.add_revoker",
			  _("Enter the user ID of the designated revoker: "));
      if(answer[0]=='\0' || answer[0]=='\004')
	{
	  xfree(answer);
	  goto fail;
	}

      /* Note that I'm requesting CERT here, which usually implies
	 primary keys only, but some casual testing shows that PGP and
	 GnuPG both can handle a designated revokation from a
	 subkey. */
      revoker_pk->req_usage=PUBKEY_USAGE_CERT;
      rc=get_pubkey_byname(revoker_pk,answer,NULL,NULL,1);
      if(rc)
	{
	  log_error (_("key \"%s\" not found: %s\n"),answer,g10_errstr(rc));
	  xfree(answer);
	  continue;
	}

      xfree(answer);

      fingerprint_from_pk(revoker_pk,revkey.fpr,&fprlen);
      if(fprlen!=20)
	{
	  log_error(_("cannot appoint a PGP 2.x style key as a "
		      "designated revoker\n"));
	  continue;
	}

      revkey.class=0x80;
      if(sensitive)
	revkey.class|=0x40;
      revkey.algid=revoker_pk->pubkey_algo;

      if(cmp_public_keys(revoker_pk,pk)==0)
	{
	  /* This actually causes no harm (after all, a key that
	     designates itself as a revoker is the same as a
	     regular key), but it's easy enough to check. */
	  log_error(_("you cannot appoint a key as its own "
		      "designated revoker\n"));

	  continue;
	}

      keyid_from_pk(pk,NULL);

      /* Does this revkey already exist? */
      if(!pk->revkey && pk->numrevkeys)
	BUG();
      else
	{
	  int i;

	  for(i=0;i<pk->numrevkeys;i++)
	    {
	      if(memcmp(&pk->revkey[i],&revkey,
			sizeof(struct revocation_key))==0)
		{
		  char buf[50];

		  log_error(_("this key has already been designated "
			      "as a revoker\n"));

		  sprintf(buf,"%08lX%08lX",
			  (ulong)pk->keyid[0],(ulong)pk->keyid[1]);
		  write_status_text(STATUS_ALREADY_SIGNED,buf);

		  break;
		}
	    }

	  if(i<pk->numrevkeys)
	    continue;
	}

      print_pubkey_info(NULL,revoker_pk);
      print_fingerprint(revoker_pk,NULL,2);
      tty_printf("\n");

      tty_printf(_("WARNING: appointing a key as a designated revoker "
		   "cannot be undone!\n"));

      tty_printf("\n");

      if(!cpr_get_answer_is_yes("keyedit.add_revoker.okay",
				_("Are you sure you want to appoint this "
				  "key as a designated revoker? (y/N) ")))
	continue;

      free_public_key(revoker_pk);
      revoker_pk=NULL;
      break;
    }

  /* The 1F signature must be at least v4 to carry the revocation key
     subpacket. */
  rc = make_keysig_packet( &sig, pk, NULL, NULL, sk, 0x1F, 0, 4, 0, 0,
			   keygen_add_revkey,&revkey );
  if( rc )
    {
      log_error("signing failed: %s\n", g10_errstr(rc) );
      goto fail;
    }

  free_secret_key(sk);
  sk=NULL;

  /* insert into secret keyblock */
  pkt = xmalloc_clear( sizeof *pkt );
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = copy_signature(NULL, sig);
  insert_kbnode( sec_keyblock, new_kbnode(pkt), PKT_SIGNATURE );

  /* insert into public keyblock */
  pkt = xmalloc_clear( sizeof *pkt );
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  insert_kbnode( pub_keyblock, new_kbnode(pkt), PKT_SIGNATURE );

  return 1;

 fail:
  if(sk)
    free_secret_key(sk);
  if(sig)
    free_seckey_enc(sig);
  if(revoker_pk)
    free_public_key(revoker_pk);

  return 0;
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
    u32 timestamp=make_timestamp();

    if( count_selected_keys( sec_keyblock ) ) {
	tty_printf(_("Please remove selections from the secret keys.\n"));
	return 0;
    }

    n1 = count_selected_keys( pub_keyblock );
    if( n1 > 1 ) {
	tty_printf(_("Please select at most one subkey.\n"));
	return 0;
    }
    else if( n1 )
	tty_printf(_("Changing expiration time for a subkey.\n"));
    else
      {
	tty_printf(_("Changing expiration time for the primary key.\n"));
	mainkey=1;
	no_primary_warning(pub_keyblock);
      }

    expiredate=ask_expire_interval(timestamp,0,NULL);
    if(expiredate)
      expiredate+=timestamp;

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
		&& ( (mainkey && uid
		      && uid->created && (sig->sig_class&~3) == 0x10)
		     || (!mainkey && sig->sig_class == 0x18)  )
		&& sig->flags.chosen_selfsig )
	      {
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

		/* Note the potential oddity that the expiration date
		   is calculated from the time when this function
		   started ("timestamp"), but the signature is
		   calculated from the time within
		   update_keysig_packet().  On a slow or loaded
		   machine, these two values may not match, making the
		   expiration date off by a second or two. */
		if( mainkey )
		  rc = update_keysig_packet(&newsig, sig, main_pk, uid, NULL,
					    sk, keygen_add_key_expire, main_pk);
		else
		  rc = update_keysig_packet(&newsig, sig, main_pk, NULL, sub_pk,
					    sk, keygen_add_key_expire, sub_pk );
		if( rc ) {
		    log_error("make_keysig_packet failed: %s\n",
						    g10_errstr(rc));
		    free_secret_key( sk );
		    return 0;
		}
		/* replace the packet */
		newpkt = xmalloc_clear( sizeof *newpkt );
		newpkt->pkttype = PKT_SIGNATURE;
		newpkt->pkt.signature = newsig;
		free_packet( node->pkt );
		xfree( node->pkt );
		node->pkt = newpkt;
		if( sn ) {
		    newpkt = xmalloc_clear( sizeof *newpkt );
		    newpkt->pkttype = PKT_SIGNATURE;
		    newpkt->pkt.signature = copy_signature( NULL, newsig );
		    free_packet( sn->pkt );
		    xfree( sn->pkt );
		    sn->pkt = newpkt;
		}
		sub_pk = NULL;
	    }
	}
    }

    free_secret_key( sk );
    update_trust=1;
    return 1;
}

static int
menu_backsign(KBNODE pub_keyblock,KBNODE sec_keyblock)
{
  int rc,modified=0;
  PKT_public_key *main_pk;
  PKT_secret_key *main_sk,*sub_sk=NULL;
  KBNODE node;

  assert(pub_keyblock->pkt->pkttype==PKT_PUBLIC_KEY);
  assert(sec_keyblock->pkt->pkttype==PKT_SECRET_KEY);

  merge_keys_and_selfsig(pub_keyblock);
  main_pk=pub_keyblock->pkt->pkt.public_key;
  main_sk=copy_secret_key(NULL,sec_keyblock->pkt->pkt.secret_key);
  keyid_from_pk(main_pk,NULL);

  for(node=pub_keyblock;node;node=node->next)
    {
      PKT_public_key *sub_pk=NULL;
      KBNODE node2,sig_pk=NULL,sig_sk=NULL;
      char *passphrase;

      if(sub_sk)
	{
	  free_secret_key(sub_sk);
	  sub_sk=NULL;
	}

      /* Find a signing subkey with no backsig */
      if(node->pkt->pkttype==PKT_PUBLIC_SUBKEY)
	{
	  if(node->pkt->pkt.public_key->pubkey_usage&PUBKEY_USAGE_SIG)
	    {
	      if(node->pkt->pkt.public_key->backsig)
		tty_printf(_("signing subkey %s is already cross-certified\n"),
			   keystr_from_pk(node->pkt->pkt.public_key));
	      else
		sub_pk=node->pkt->pkt.public_key;
	    }
	  else
	    tty_printf(_("subkey %s does not sign and so does"
			 " not need to be cross-certified\n"),
		       keystr_from_pk(node->pkt->pkt.public_key));
	}

      if(!sub_pk)
	continue;

      /* Find the selected selfsig on this subkey */
      for(node2=node->next;
	  node2 && node2->pkt->pkttype==PKT_SIGNATURE;
	  node2=node2->next)
	if(node2->pkt->pkt.signature->version>=4
	   && node2->pkt->pkt.signature->flags.chosen_selfsig)
	  {
	    sig_pk=node2;
	    break;
	  }

      if(!sig_pk)
	continue;

      /* Find the secret subkey that matches the public subkey */
      for(node2=sec_keyblock;node2;node2=node2->next)
	if(node2->pkt->pkttype==PKT_SECRET_SUBKEY
	   && !cmp_public_secret_key(sub_pk,node2->pkt->pkt.secret_key))
	  {
	    sub_sk=copy_secret_key(NULL,node2->pkt->pkt.secret_key);
	    break;
	  }

      if(!sub_sk)
	{
	  tty_printf(_("no secret subkey for public subkey %s - ignoring\n"),
		     keystr_from_pk(sub_pk));
	  continue;
	}

      /* Now finally find the matching selfsig on the secret subkey.
	 We can't use chosen_selfsig here (it's not set for secret
	 keys), so we just pick the selfsig with the right class.
	 This is what menu_expire does as well. */
      for(node2=node2->next;
	  node2 && node2->pkt->pkttype!=PKT_SECRET_SUBKEY;
	  node2=node2->next)
	if(node2->pkt->pkttype==PKT_SIGNATURE
	   && node2->pkt->pkt.signature->version>=4
	   && node2->pkt->pkt.signature->keyid[0]==sig_pk->pkt->pkt.signature->keyid[0]
	   && node2->pkt->pkt.signature->keyid[1]==sig_pk->pkt->pkt.signature->keyid[1]
	   && node2->pkt->pkt.signature->sig_class==sig_pk->pkt->pkt.signature->sig_class)
	  {
	    sig_sk=node2;
	    break;
	  }

      /* Now we can get to work.  We have a main key and secret part,
	 a signing subkey with signature and secret part possibly with
	 signature. */

      passphrase=get_last_passphrase();
      set_next_passphrase(passphrase);
      xfree(passphrase);

      rc=make_backsig(sig_pk->pkt->pkt.signature,main_pk,sub_pk,sub_sk);
      if(rc==0)
	{
	  PKT_signature *newsig;
	  PACKET *newpkt;

	  passphrase=get_last_passphrase();
	  set_next_passphrase(passphrase);
	  xfree(passphrase);

	  rc=update_keysig_packet(&newsig,sig_pk->pkt->pkt.signature,main_pk,
				  NULL,sub_pk,main_sk,NULL,NULL);
	  if(rc==0)
	    {
	      /* Put the new sig into place on the pubkey */
	      newpkt=xmalloc_clear(sizeof(*newpkt));
	      newpkt->pkttype=PKT_SIGNATURE;
	      newpkt->pkt.signature=newsig;
	      free_packet(sig_pk->pkt);
	      xfree(sig_pk->pkt);
	      sig_pk->pkt=newpkt;

	      if(sig_sk)
		{
		  /* Put the new sig into place on the seckey */
		  newpkt=xmalloc_clear(sizeof(*newpkt));
		  newpkt->pkttype=PKT_SIGNATURE;
		  newpkt->pkt.signature=copy_signature(NULL,newsig);
		  free_packet(sig_sk->pkt);
		  xfree(sig_sk->pkt);
		  sig_sk->pkt=newpkt;
		}

	      modified=1;
	    }
	  else
	    {
	      log_error("update_keysig_packet failed: %s\n",g10_errstr(rc));
	      break;
	    }
	}
      else
	{
	  log_error("make_backsig failed: %s\n",g10_errstr(rc));
	  break;
	}
    }

  set_next_passphrase(NULL);

  free_secret_key(main_sk);
  if(sub_sk)
    free_secret_key(sub_sk);

  return modified;
}


static int
change_primary_uid_cb ( PKT_signature *sig, void *opaque )
{
    byte buf[1];

    /* first clear all primary uid flags so that we are sure none are
     * lingering around */
    delete_sig_subpkt (sig->hashed,   SIGSUBPKT_PRIMARY_UID);
    delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PRIMARY_UID);

    /* if opaque is set,we want to set the primary id */
    if (opaque) { 
        buf[0] = 1;
        build_sig_subpkt (sig, SIGSUBPKT_PRIMARY_UID, buf, 1 );
    }

    return 0;
}


/*
 * Set the primary uid flag for the selected UID.  We will also reset
 * all other primary uid flags.  For this to work with have to update
 * all the signature timestamps.  If we would do this with the current
 * time, we lose quite a lot of information, so we use a a kludge to
 * do this: Just increment the timestamp by one second which is
 * sufficient to updated a signature during import.
 */
static int
menu_set_primary_uid ( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    PKT_secret_key *sk;    /* copy of the main sk */
    PKT_public_key *main_pk;
    PKT_user_id *uid;
    KBNODE node;
    u32 keyid[2];
    int selected;
    int attribute = 0;
    int modified = 0;

    if ( count_selected_uids (pub_keyblock) != 1 ) {
	tty_printf(_("Please select exactly one user ID.\n"));
	return 0;
    }

    node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
    sk = copy_secret_key( NULL, node->pkt->pkt.secret_key);

    /* Now we can actually change the self signature(s) */
    main_pk = NULL;
    uid = NULL;
    selected = 0;

    /* Is our selected uid an attribute packet? */
    for ( node=pub_keyblock; node; node = node->next )
      if (node->pkt->pkttype == PKT_USER_ID && node->flag & NODFLG_SELUID)
	attribute = (node->pkt->pkt.user_id->attrib_data!=NULL);

    for ( node=pub_keyblock; node; node = node->next ) {
	if ( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
            break; /* ready */

	if ( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
	    main_pk = node->pkt->pkt.public_key;
	    keyid_from_pk( main_pk, keyid );
	}
	else if ( node->pkt->pkttype == PKT_USER_ID ) {
	    uid = node->pkt->pkt.user_id;
       	    selected = node->flag & NODFLG_SELUID;
        }
	else if ( main_pk && uid && node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    if ( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
		 && (uid && (sig->sig_class&~3) == 0x10)
		 && attribute == (uid->attrib_data!=NULL)
		 && sig->flags.chosen_selfsig )
	      {
	      if(sig->version < 4) {
		char *user=utf8_to_native(uid->name,strlen(uid->name),0);

		log_info(_("skipping v3 self-signature on user ID \"%s\"\n"),
			 user);
		xfree(user);
	      }
	      else {
	        /* This is a selfsignature which is to be replaced.
		   We can just ignore v3 signatures because they are
		   not able to carry the primary ID flag.  We also
		   ignore self-sigs on user IDs that are not of the
		   same type that we are making primary.  That is, if
		   we are making a user ID primary, we alter user IDs.
		   If we are making an attribute packet primary, we
		   alter attribute packets. */

                /* FIXME: We must make sure that we only have one
                   self-signature per user ID here (not counting
                   revocations) */
		PKT_signature *newsig;
		PACKET *newpkt;
                const byte *p;
                int action;

                /* see whether this signature has the primary UID flag */
                p = parse_sig_subpkt (sig->hashed,
                                      SIGSUBPKT_PRIMARY_UID, NULL );
                if ( !p )
                    p = parse_sig_subpkt (sig->unhashed,
                                          SIGSUBPKT_PRIMARY_UID, NULL );
                if ( p && *p ) /* yes */
                    action = selected? 0 : -1;
                else /* no */
                    action = selected? 1 : 0;

                if (action) {
                    int rc = update_keysig_packet (&newsig, sig,
					       main_pk, uid, NULL,
                                               sk,
                                               change_primary_uid_cb,
                                               action > 0? "x":NULL );
                    if( rc ) {
                        log_error ("update_keysig_packet failed: %s\n",
                                   g10_errstr(rc));
                        free_secret_key( sk );
                        return 0;
                    }
                    /* replace the packet */
                    newpkt = xmalloc_clear( sizeof *newpkt );
                    newpkt->pkttype = PKT_SIGNATURE;
                    newpkt->pkt.signature = newsig;
                    free_packet( node->pkt );
                    xfree( node->pkt );
                    node->pkt = newpkt;
                    modified = 1;
		}
	      }
	    }
	}
    }

    free_secret_key( sk );
    return modified;
}


/* 
 * Set preferences to new values for the selected user IDs
 */
static int
menu_set_preferences (KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    PKT_secret_key *sk;    /* copy of the main sk */
    PKT_public_key *main_pk;
    PKT_user_id *uid;
    KBNODE node;
    u32 keyid[2];
    int selected, select_all;
    int modified = 0;

    no_primary_warning(pub_keyblock);

    select_all = !count_selected_uids (pub_keyblock);

    node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
    sk = copy_secret_key( NULL, node->pkt->pkt.secret_key);

    /* Now we can actually change the self signature(s) */
    main_pk = NULL;
    uid = NULL;
    selected = 0;
    for ( node=pub_keyblock; node; node = node->next ) {
	if ( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
            break; /* ready */

	if ( node->pkt->pkttype == PKT_PUBLIC_KEY ) {
	    main_pk = node->pkt->pkt.public_key;
	    keyid_from_pk( main_pk, keyid );
	}
	else if ( node->pkt->pkttype == PKT_USER_ID ) {
	    uid = node->pkt->pkt.user_id;
       	    selected = select_all || (node->flag & NODFLG_SELUID);
        }
	else if ( main_pk && uid && selected
                  && node->pkt->pkttype == PKT_SIGNATURE ) {
	    PKT_signature *sig = node->pkt->pkt.signature;
	    if ( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
		 && (uid && (sig->sig_class&~3) == 0x10)
		 && sig->flags.chosen_selfsig ) {
	      if( sig->version < 4 ) {
		char *user=utf8_to_native(uid->name,strlen(uid->name),0);

		log_info(_("skipping v3 self-signature on user ID \"%s\"\n"),
			 user);
		xfree(user);
	      }
	      else {
		/* This is a selfsignature which is to be replaced 
                 * We have to ignore v3 signatures because they are
                 * not able to carry the preferences */
		PKT_signature *newsig;
		PACKET *newpkt;
                int rc;

                rc = update_keysig_packet (&newsig, sig,
                                           main_pk, uid, NULL,
                                           sk,
                                           keygen_upd_std_prefs,
                                           NULL );
                if( rc ) {
                    log_error ("update_keysig_packet failed: %s\n",
                               g10_errstr(rc));
                    free_secret_key( sk );
                    return 0;
                }
                /* replace the packet */
                newpkt = xmalloc_clear( sizeof *newpkt );
                newpkt->pkttype = PKT_SIGNATURE;
                newpkt->pkt.signature = newsig;
                free_packet( node->pkt );
                xfree( node->pkt );
                node->pkt = newpkt;
                modified = 1;
	      }
            }
	}
    }
    
    free_secret_key( sk );
    return modified;
}


static int
menu_set_keyserver_url (const char *url,
			KBNODE pub_keyblock, KBNODE sec_keyblock )
{
  PKT_secret_key *sk;    /* copy of the main sk */
  PKT_public_key *main_pk;
  PKT_user_id *uid;
  KBNODE node;
  u32 keyid[2];
  int selected, select_all;
  int modified = 0;
  char *answer,*uri;

  no_primary_warning(pub_keyblock);

  if(url)
    answer=xstrdup(url);
  else
    {
      answer=cpr_get_utf8("keyedit.add_keyserver",
			  _("Enter your preferred keyserver URL: "));
      if(answer[0]=='\0' || answer[0]=='\004')
	{
	  xfree(answer);
	  return 0;
	}
    }

  if(ascii_strcasecmp(answer,"none")==0)
    uri=NULL;
  else
    {
      struct keyserver_spec *keyserver=NULL;
      /* Sanity check the format */
      keyserver=parse_keyserver_uri(answer,1,NULL,0);
      xfree(answer);
      if(!keyserver)
	{
	  log_info(_("could not parse keyserver URL\n"));
	  return 0;
	}
      uri=xstrdup(keyserver->uri);
      free_keyserver_spec(keyserver);
    }

  select_all = !count_selected_uids (pub_keyblock);

  node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
  sk = copy_secret_key( NULL, node->pkt->pkt.secret_key);

  /* Now we can actually change the self signature(s) */
  main_pk = NULL;
  uid = NULL;
  selected = 0;
  for ( node=pub_keyblock; node; node = node->next )
    {
      if ( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	break; /* ready */

      if ( node->pkt->pkttype == PKT_PUBLIC_KEY )
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk( main_pk, keyid );
	}
      else if ( node->pkt->pkttype == PKT_USER_ID )
	{
	  uid = node->pkt->pkt.user_id;
	  selected = select_all || (node->flag & NODFLG_SELUID);
	}
      else if ( main_pk && uid && selected
		&& node->pkt->pkttype == PKT_SIGNATURE )
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  if ( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	       && (uid && (sig->sig_class&~3) == 0x10)
	       && sig->flags.chosen_selfsig)
	    {
	      char *user=utf8_to_native(uid->name,strlen(uid->name),0);
	      if( sig->version < 4 )
		log_info(_("skipping v3 self-signature on user ID \"%s\"\n"),
			 user);
	      else
		{
		  /* This is a selfsignature which is to be replaced
		   * We have to ignore v3 signatures because they are
		   * not able to carry the subpacket. */
		  PKT_signature *newsig;
		  PACKET *newpkt;
		  int rc;
		  const byte *p;
		  size_t plen;

		  p=parse_sig_subpkt(sig->hashed,SIGSUBPKT_PREF_KS,&plen);
		  if(p && plen)
		    {
		      tty_printf("Current preferred keyserver for user"
				 " ID \"%s\": ",user);
		      tty_print_utf8_string(p,plen);
		      tty_printf("\n");
		      if(!cpr_get_answer_is_yes("keyedit.confirm_keyserver",
			 uri?_("Are you sure you want to replace it? (y/N) "):
			     _("Are you sure you want to delete it? (y/N) ")))
			continue;
		    }
		  else if(uri==NULL)
		    {
		      /* There is no current keyserver URL, so there
			 is no point in trying to un-set it. */
		      continue;
		    }

		  rc = update_keysig_packet (&newsig, sig,
					     main_pk, uid, NULL,
					     sk,
					     keygen_add_keyserver_url, uri );
		  if( rc )
		    {
		      log_error ("update_keysig_packet failed: %s\n",
				 g10_errstr(rc));
		      free_secret_key( sk );
		      xfree(uri);
		      return 0;
		    }
		  /* replace the packet */
		  newpkt = xmalloc_clear( sizeof *newpkt );
		  newpkt->pkttype = PKT_SIGNATURE;
		  newpkt->pkt.signature = newsig;
		  free_packet( node->pkt );
		  xfree( node->pkt );
		  node->pkt = newpkt;
		  modified = 1;
		}

	      xfree(user);
	    }
	}
    }

  xfree(uri);
  free_secret_key( sk );
  return modified;
}

static int
menu_set_notation(const char *string,KBNODE pub_keyblock,KBNODE sec_keyblock)
{
  PKT_secret_key *sk;    /* copy of the main sk */
  PKT_public_key *main_pk;
  PKT_user_id *uid;
  KBNODE node;
  u32 keyid[2];
  int selected, select_all;
  int modified = 0;
  char *answer;
  struct notation *notation;

  no_primary_warning(pub_keyblock);

  if(string)
    answer=xstrdup(string);
  else
    {
      answer=cpr_get_utf8("keyedit.add_notation",
			  _("Enter the notation: "));
      if(answer[0]=='\0' || answer[0]=='\004')
	{
	  xfree(answer);
	  return 0;
	}
    }

  if(ascii_strcasecmp(answer,"none")==0
     || ascii_strcasecmp(answer,"-")==0)
    notation=NULL; /* delete them all */
  else
    {
      notation=string_to_notation(answer,0);
      if(!notation)
	{
	  xfree(answer);
	  return 0;
	}
    }

  xfree(answer);

  select_all = !count_selected_uids (pub_keyblock);

  node = find_kbnode( sec_keyblock, PKT_SECRET_KEY );
  sk = copy_secret_key( NULL, node->pkt->pkt.secret_key);

  /* Now we can actually change the self signature(s) */
  main_pk = NULL;
  uid = NULL;
  selected = 0;
  for ( node=pub_keyblock; node; node = node->next )
    {
      if ( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	break; /* ready */

      if ( node->pkt->pkttype == PKT_PUBLIC_KEY )
	{
	  main_pk = node->pkt->pkt.public_key;
	  keyid_from_pk( main_pk, keyid );
	}
      else if ( node->pkt->pkttype == PKT_USER_ID )
	{
	  uid = node->pkt->pkt.user_id;
	  selected = select_all || (node->flag & NODFLG_SELUID);
	}
      else if ( main_pk && uid && selected
		&& node->pkt->pkttype == PKT_SIGNATURE )
	{
	  PKT_signature *sig = node->pkt->pkt.signature;
	  if ( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1]
	       && (uid && (sig->sig_class&~3) == 0x10)
	       && sig->flags.chosen_selfsig)
	    {
	      char *user=utf8_to_native(uid->name,strlen(uid->name),0);
	      if( sig->version < 4 )
		log_info(_("skipping v3 self-signature on user ID \"%s\"\n"),
			 user);
	      else
		{
		  PKT_signature *newsig;
		  PACKET *newpkt;
		  int rc,skip=0,addonly=1;

		  if(sig->flags.notation)
		    {
		      tty_printf("Current notations for user ID \"%s\":\n",
				 user);
		      tty_print_notations(-9,sig);
		    }
		  else
		    {
		      tty_printf("No notations on user ID \"%s\"\n",user);
		      if(notation==NULL)
			{
			  /* There are no current notations, so there
			     is no point in trying to un-set them. */
			  continue;
			}
		    }

		  if(notation)
		    {
		      struct notation *n;
		      int deleting=0;

		      notation->next=sig_to_notation(sig);

		      for(n=notation->next;n;n=n->next)
			if(strcmp(n->name,notation->name)==0)
			  {
			    if(notation->value)
			      {
				if(strcmp(n->value,notation->value)==0)
				  {
				    if(notation->flags.ignore)
				      {
					/* Value match with a delete
					   flag. */
					n->flags.ignore=1;
					deleting=1;
				      }
				    else
				      {
					/* Adding the same notation
					   twice, so don't add it at
					   all. */
					skip=1;
					tty_printf("Skipping notation:"
						   " %s=%s\n",
						   notation->name,
						   notation->value);
					break;
				      }
				  }
			      }
			    else
			      {
				/* No value, so it means delete. */
				n->flags.ignore=1;
				deleting=1;
			      }

			    if(n->flags.ignore)
			      {
				tty_printf("Removing notation: %s=%s\n",
					   n->name,n->value);
				addonly=0;
			      }
			  }

		      if(!notation->flags.ignore && !skip)
			tty_printf("Adding notation: %s=%s\n",
				   notation->name,notation->value);

		      /* We tried to delete, but had no matches */
		      if(notation->flags.ignore && !deleting)
			continue;
		    }
		  else
		    {
		      tty_printf("Removing all notations\n");
		      addonly=0;
		    }

		  if(skip
		     || (!addonly
			 && !cpr_get_answer_is_yes("keyedit.confirm_notation",
						   _("Proceed? (y/N) "))))
		    continue;

		  rc = update_keysig_packet (&newsig, sig,
					     main_pk, uid, NULL,
					     sk,
					     keygen_add_notations, notation );
		  if( rc )
		    {
		      log_error ("update_keysig_packet failed: %s\n",
				 g10_errstr(rc));
		      free_secret_key( sk );
		      free_notation(notation);
		      xfree(user);
		      return 0;
		    }

		  /* replace the packet */
		  newpkt = xmalloc_clear( sizeof *newpkt );
		  newpkt->pkttype = PKT_SIGNATURE;
		  newpkt->pkt.signature = newsig;
		  free_packet( node->pkt );
		  xfree( node->pkt );
		  node->pkt = newpkt;
		  modified = 1;

		  if(notation)
		    {
		      /* Snip off the notation list from the sig */
		      free_notation(notation->next);
		      notation->next=NULL;
		    }

		  xfree(user);
		}
	    }
	}
    }

  free_notation(notation);
  free_secret_key( sk );
  return modified;
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

/* Search in the keyblock for a uid that matches namehash */
static int
menu_select_uid_namehash( KBNODE keyblock, const char *namehash )
{
  byte hash[NAMEHASH_LEN];
  KBNODE node;
  int i;

  assert(strlen(namehash)==NAMEHASH_LEN*2);

  for(i=0;i<NAMEHASH_LEN;i++)
    hash[i]=hextobyte(&namehash[i*2]);

  for(node=keyblock->next;node;node=node->next)
    {
      if(node->pkt->pkttype==PKT_USER_ID)
	{
	  namehash_from_uid(node->pkt->pkt.user_id);
	  if(memcmp(node->pkt->pkt.user_id->namehash,hash,NAMEHASH_LEN)==0)
	    {
	      if(node->flag&NODFLG_SELUID)
		node->flag &= ~NODFLG_SELUID;
	      else
		node->flag |= NODFLG_SELUID;

	      break;
	    }
	}
    }

    if(!node)
      {
	tty_printf(_("No user ID with hash %s\n"),namehash);
	return 0;
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
	    tty_printf(_("No subkey with index %d\n"), idx );
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

/* returns how many real (i.e. not attribute) uids are unmarked */
static int
real_uids_left( KBNODE keyblock )
{
  KBNODE node;
  int real=0;

  for(node=keyblock;node;node=node->next)
    if(node->pkt->pkttype==PKT_USER_ID && !(node->flag&NODFLG_SELUID) &&
       !node->pkt->pkt.user_id->attrib_data)
      real++;

  return real;
}

/*
 * Ask whether the signature should be revoked.  If the user commits this,
 * flag bit MARK_A is set on the signature and the user ID.
 */
static void
ask_revoke_sig( KBNODE keyblock, KBNODE node )
{
    int doit=0;
    PKT_user_id *uid;
    PKT_signature *sig = node->pkt->pkt.signature;
    KBNODE unode = find_prev_kbnode( keyblock, node, PKT_USER_ID );

    if( !unode ) {
	log_error("Oops: no user ID for signature\n");
	return;
    }

    uid=unode->pkt->pkt.user_id;

    if(opt.with_colons)
      {
	if(uid->attrib_data)
	  printf("uat:::::::::%u %lu",uid->numattribs,uid->attrib_len);
	else
	  {
	    printf("uid:::::::::");
	    print_string (stdout, uid->name, uid->len, ':');
	  }

	printf("\n");

	print_and_check_one_sig_colon(keyblock,node,NULL,NULL,NULL,NULL,1);
      }
    else
      {
	char *p=utf8_to_native(unode->pkt->pkt.user_id->name,
			 unode->pkt->pkt.user_id->len,0);
	tty_printf(_("user ID: \"%s\"\n"),p);
	xfree(p);

	tty_printf(_("signed by your key %s on %s%s%s\n"),
		   keystr(sig->keyid),datestr_from_sig(sig),
		   sig->flags.exportable?"":_(" (non-exportable)"),"");
      }
    if(sig->flags.expired)
      {
	tty_printf(_("This signature expired on %s.\n"),
		   expirestr_from_sig(sig));
	/* Use a different question so we can have different help text */
	doit=cpr_get_answer_is_yes("ask_revoke_sig.expired",
			_("Are you sure you still want to revoke it? (y/N) "));
      }
    else
      doit=cpr_get_answer_is_yes("ask_revoke_sig.one",
	      _("Create a revocation certificate for this signature? (y/N) "));

    if(doit) {
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
    int rc, any, skip=1, all=!count_selected_uids(keyblock);
    struct revocation_reason_info *reason = NULL;

    assert(keyblock->pkt->pkttype==PKT_PUBLIC_KEY);

    /* FIXME: detect duplicates here  */
    tty_printf(_("You have signed these user IDs on key %s:\n"),
	       keystr_from_pk(keyblock->pkt->pkt.public_key));
    for( node = keyblock; node; node = node->next ) {
	node->flag &= ~(NODFLG_SELSIG | NODFLG_MARK_A);
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    if( node->flag&NODFLG_SELUID || all ) {
	      PKT_user_id *uid = node->pkt->pkt.user_id;
	      /* Hmmm: Should we show only UIDs with a signature? */
	      tty_printf("     ");
	      tty_print_utf8_string( uid->name, uid->len );
	      tty_printf("\n");
	      skip=0;
	    }
	    else
	      skip=1;
	}
	else if( !skip && node->pkt->pkttype == PKT_SIGNATURE
		&& ((sig = node->pkt->pkt.signature),
                     !seckey_available(sig->keyid)  ) )
	  {
	    if( (sig->sig_class&~3) == 0x10 )
	      {
		tty_printf("   ");
		tty_printf(_("signed by your key %s on %s%s%s\n"),
			   keystr(sig->keyid), datestr_from_sig(sig),
			   sig->flags.exportable?"":_(" (non-exportable)"),
			   sig->flags.revocable?"":_(" (non-revocable)"));
		if(sig->flags.revocable)
		  node->flag |= NODFLG_SELSIG;
	      }
	    else if( sig->sig_class == 0x30 )
	      {
		tty_printf("   ");
		tty_printf(_("revoked by your key %s on %s\n"),
			   keystr(sig->keyid),datestr_from_sig(sig));
	      }
	  }
    }

    tty_printf("\n");

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
	    tty_printf("   ");
	    tty_printf(_("signed by your key %s on %s%s%s\n"),
 		       keystr(sig->keyid), datestr_from_sig(sig),"",
		       sig->flags.exportable?"":_(" (non-exportable)") );
	}
    }
    if( !any )
	return 0; /* none selected */

    if( !cpr_get_answer_is_yes("ask_revoke_sig.okay",
	 _("Really create the revocation certificates? (y/N) ")) )
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
	attrib.non_exportable=!node->pkt->pkt.signature->flags.exportable;

	node->flag &= ~NODFLG_MARK_A;
	sk = xmalloc_secure_clear( sizeof *sk );
	if( get_seckey( sk, node->pkt->pkt.signature->keyid ) ) {
	    log_info(_("no secret key\n"));
	    continue;
	}
	rc = make_keysig_packet( &sig, primary_pk,
				       unode->pkt->pkt.user_id,
				       NULL,
				       sk,
				       0x30, 0, 0, 0, 0,
				       sign_mk_attrib,
				       &attrib );
	free_secret_key(sk);
	if( rc ) {
	    log_error(_("signing failed: %s\n"), g10_errstr(rc));
	    release_revocation_reason_info( reason );
	    return changed;
	}
	changed = 1; /* we changed the keyblock */
	update_trust = 1;
	/* Are we revoking our own uid? */
	if(primary_pk->keyid[0]==sig->keyid[0] &&
	   primary_pk->keyid[1]==sig->keyid[1])
	  unode->pkt->pkt.user_id->is_revoked=1;
	pkt = xmalloc_clear( sizeof *pkt );
	pkt->pkttype = PKT_SIGNATURE;
	pkt->pkt.signature = sig;
	insert_kbnode( unode, new_kbnode(pkt), 0 );
	goto reloop;
    }

    release_revocation_reason_info( reason );
    return changed;
}

/* Revoke a user ID (i.e. revoke a user ID selfsig).  Return true if
   keyblock changed. */
static int
menu_revuid( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
  PKT_public_key *pk = pub_keyblock->pkt->pkt.public_key;
  PKT_secret_key *sk = copy_secret_key( NULL,
					sec_keyblock->pkt->pkt.secret_key );
  KBNODE node;
  int changed = 0;
  int rc;
  struct revocation_reason_info *reason = NULL;

  /* Note that this is correct as per the RFCs, but nevertheless
     somewhat meaningless in the real world.  1991 did define the 0x30
     sig class, but PGP 2.x did not actually implement it, so it would
     probably be safe to use v4 revocations everywhere. -ds */

  for( node = pub_keyblock; node; node = node->next )
    if(pk->version>3 || (node->pkt->pkttype==PKT_USER_ID &&
			 node->pkt->pkt.user_id->selfsigversion>3))
      {
	if((reason = ask_revocation_reason( 0, 1, 4 )))
	  break;
	else
	  goto leave;
      }

 reloop: /* (better this way because we are modifing the keyring) */
  for( node = pub_keyblock; node; node = node->next )
    if(node->pkt->pkttype == PKT_USER_ID && (node->flag & NODFLG_SELUID))
      {
	PKT_user_id *uid=node->pkt->pkt.user_id;

	if(uid->is_revoked)
	  {
	    char *user=utf8_to_native(uid->name,uid->len,0);
	    log_info(_("user ID \"%s\" is already revoked\n"),user);
	    xfree(user);
	  }
	else
	  {
	    PACKET *pkt;
	    PKT_signature *sig;
	    struct sign_attrib attrib;
	    u32 timestamp=make_timestamp();

	    if(uid->created>=timestamp)
	      {
		/* Okay, this is a problem.  The user ID selfsig was
		   created in the future, so we need to warn the user and
		   set our revocation timestamp one second after that so
		   everything comes out clean. */

		log_info(_("WARNING: a user ID signature is dated %d"
			   " seconds in the future\n"),uid->created-timestamp);

		timestamp=uid->created+1;
	      }

	    memset( &attrib, 0, sizeof attrib );
	    attrib.reason = reason;

	    node->flag &= ~NODFLG_SELUID;

	    rc = make_keysig_packet( &sig, pk, uid, NULL, sk, 0x30, 0,
				     (reason==NULL)?3:0, timestamp, 0,
				     sign_mk_attrib, &attrib );
	    if( rc )
	      {
		log_error(_("signing failed: %s\n"), g10_errstr(rc));
		goto leave;
	      }
	    else
	      {
		pkt = xmalloc_clear( sizeof *pkt );
		pkt->pkttype = PKT_SIGNATURE;
		pkt->pkt.signature = sig;
		insert_kbnode( node, new_kbnode(pkt), 0 );

		/* If the trustdb has an entry for this key+uid then the
		   trustdb needs an update. */
		if(!update_trust
		   && (get_validity(pk,uid)&TRUST_MASK)>=TRUST_UNDEFINED)
		  update_trust=1;

		changed = 1;
		node->pkt->pkt.user_id->is_revoked=1;

		goto reloop;
	      }
	  }
      }

  if(changed)
    commit_kbnode( &pub_keyblock );

 leave:
  free_secret_key(sk);
  release_revocation_reason_info( reason );
  return changed;
}

/****************
 * Revoke the whole key.
 */
static int
menu_revkey( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
  PKT_public_key *pk=pub_keyblock->pkt->pkt.public_key;
  PKT_secret_key *sk;
  int rc,changed = 0;
  struct revocation_reason_info *reason;
  PACKET *pkt;
  PKT_signature *sig;

  if(pk->is_revoked)
    {
      tty_printf(_("Key %s is already revoked.\n"),keystr_from_pk(pk));
      return 0;
    }

  reason = ask_revocation_reason( 1, 0, 0 );
  /* user decided to cancel */
  if( !reason )
    return 0;

  sk = copy_secret_key( NULL, sec_keyblock->pkt->pkt.secret_key );
  rc = make_keysig_packet( &sig, pk, NULL, NULL, sk,
			   0x20, 0, opt.force_v4_certs?4:0, 0, 0,
			   revocation_reason_build_cb, reason );
  free_secret_key(sk);
  if( rc )
    {
      log_error(_("signing failed: %s\n"), g10_errstr(rc));
      goto scram;
    }

  changed = 1; /* we changed the keyblock */

  pkt = xmalloc_clear( sizeof *pkt );
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  insert_kbnode( pub_keyblock, new_kbnode(pkt), 0 );
  commit_kbnode( &pub_keyblock );

  update_trust=1;

 scram:
  release_revocation_reason_info( reason );
  return changed;
}

static int
menu_revsubkey( KBNODE pub_keyblock, KBNODE sec_keyblock )
{
    PKT_public_key *mainpk;
    KBNODE node;
    int changed = 0;
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

	    if(subpk->is_revoked)
	      {
		tty_printf(_("Subkey %s is already revoked.\n"),
			   keystr_from_pk(subpk));
		continue;
	      }

	    memset( &attrib, 0, sizeof attrib );
	    attrib.reason = reason;

	    node->flag &= ~NODFLG_SELKEY;
	    sk = copy_secret_key( NULL, sec_keyblock->pkt->pkt.secret_key );
	    rc = make_keysig_packet( &sig, mainpk, NULL, subpk, sk,
                                     0x28, 0, 0, 0, 0,
				     sign_mk_attrib, &attrib );
	    free_secret_key(sk);
	    if( rc ) {
		log_error(_("signing failed: %s\n"), g10_errstr(rc));
		release_revocation_reason_info( reason );
		return changed;
	    }
	    changed = 1; /* we changed the keyblock */

	    pkt = xmalloc_clear( sizeof *pkt );
	    pkt->pkttype = PKT_SIGNATURE;
	    pkt->pkt.signature = sig;
	    insert_kbnode( node, new_kbnode(pkt), 0 );
	    goto reloop;
	}
    }
    commit_kbnode( &pub_keyblock );
    /*commit_kbnode( &sec_keyblock );*/

    /* No need to set update_trust here since signing keys no longer
       are used to certify other keys, so there is no change in trust
       when revoking/removing them */

    release_revocation_reason_info( reason );
    return changed;
}

/* Note that update_ownertrust is going to mark the trustdb dirty when
   enabling or disabling a key.  This is arguably sub-optimal as
   disabled keys are still counted in the web of trust, but perhaps
   not worth adding extra complexity to change. -ds */
static int
enable_disable_key( KBNODE keyblock, int disable )
{
    PKT_public_key *pk = find_kbnode( keyblock, PKT_PUBLIC_KEY )
			    ->pkt->pkt.public_key;
    unsigned int trust, newtrust;

    trust = newtrust = get_ownertrust (pk);
    newtrust &= ~TRUST_FLAG_DISABLED;
    if( disable )
	newtrust |= TRUST_FLAG_DISABLED;
    if( trust == newtrust )
	return 0; /* already in that state */
    update_ownertrust(pk, newtrust );
    return 0;
}


static void
menu_showphoto( KBNODE keyblock )
{
  KBNODE node;
  int select_all = !count_selected_uids(keyblock);
  int count=0;
  PKT_public_key *pk=NULL;

  /* Look for the public key first.  We have to be really, really,
     explicit as to which photo this is, and what key it is a UID on
     since people may want to sign it. */

  for( node = keyblock; node; node = node->next )
    {
      if( node->pkt->pkttype == PKT_PUBLIC_KEY )
	pk = node->pkt->pkt.public_key;
      else if( node->pkt->pkttype == PKT_USER_ID )
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  count++;

	  if((select_all || (node->flag & NODFLG_SELUID)) &&
	     uid->attribs!=NULL)
	    {
	      int i;

	      for(i=0;i<uid->numattribs;i++)
		{
		  byte type;
		  u32 size;

		  if(uid->attribs[i].type==ATTRIB_IMAGE &&
		     parse_image_header(&uid->attribs[i],&type,&size))
		    {
		      tty_printf(_("Displaying %s photo ID of size %ld for "
				   "key %s (uid %d)\n"),
				 image_type_to_string(type,1),
				 (ulong)size,keystr_from_pk(pk),count);
		      show_photos(&uid->attribs[i],1,pk,NULL);
		    }
		}
	    }
	}
    }
}
