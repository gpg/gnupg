/* pkclist.c
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
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <assert.h>

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "trustdb.h"
#include "ttyio.h"
#include "status.h"
#include "photoid.h"
#include "i18n.h"

#define CONTROL_D ('D' - 'A' + 1)

/****************
 * Show the revocation reason as it is stored with the given signature
 */
static void
do_show_revocation_reason( PKT_signature *sig )
{
    size_t n, nn;
    const byte *p, *pp;
    int seq = 0;
    const char *text;

    while( (p = enum_sig_subpkt (sig->hashed, SIGSUBPKT_REVOC_REASON,
				 &n, &seq, NULL )) ) {
	if( !n )
	    continue; /* invalid - just skip it */

	if( *p == 0 )
	    text = _("No reason specified");
	else if( *p == 0x01 )
	    text = _("Key is superseded");
	else if( *p == 0x02 )
	    text = _("Key has been compromised");
	else if( *p == 0x03 )
	    text = _("Key is no longer used");
	else if( *p == 0x20 )
	    text = _("User ID is no longer valid");
	else
	    text = NULL;

	log_info( _("reason for revocation: ") );
	if( text )
	    fputs( text, log_stream() );
	else
	    fprintf( log_stream(), "code=%02x", *p );
	putc( '\n', log_stream() );
	n--; p++;
	pp = NULL;
	do {
	    /* We don't want any empty lines, so skip them */
	    while( n && *p == '\n' ) {
		p++;
		n--;
	    }
	    if( n ) {
		pp = memchr( p, '\n', n );
		nn = pp? pp - p : n;
		log_info( _("revocation comment: ") );
		print_string( log_stream(), p, nn, 0 );
		putc( '\n', log_stream() );
		p += nn; n -= nn;
	    }
	} while( pp );
    }
}

/* Mode 0: try and find the revocation based on the pk (i.e. check
   subkeys, etc.)  Mode 1: use only the revocation on the main pk */

void
show_revocation_reason( PKT_public_key *pk, int mode )
{
    /* Hmmm, this is not so easy becuase we have to duplicate the code
     * used in the trustbd to calculate the keyflags.  We need to find
     * a clean way to check revocation certificates on keys and
     * signatures.  And there should be no duplicate code.  Because we
     * enter this function only when the trustdb told us that we have
     * a revoked key, we could simply look for a revocation cert and
     * display this one, when there is only one. Let's try to do this
     * until we have a better solution.  */
    KBNODE node, keyblock = NULL;
    byte fingerprint[MAX_FINGERPRINT_LEN];
    size_t fingerlen;
    int rc;

    /* get the keyblock */
    fingerprint_from_pk( pk, fingerprint, &fingerlen );
    rc = get_keyblock_byfprint( &keyblock, fingerprint, fingerlen );
    if( rc ) { /* that should never happen */
	log_debug( "failed to get the keyblock\n");
	return;
    }

    for( node=keyblock; node; node = node->next ) {
        if( (mode && node->pkt->pkttype == PKT_PUBLIC_KEY) ||
	  ( ( node->pkt->pkttype == PKT_PUBLIC_KEY
	      || node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    && !cmp_public_keys( node->pkt->pkt.public_key, pk ) ) )
	    break;
    }
    if( !node ) {
	log_debug("Oops, PK not in keyblock\n");
	release_kbnode( keyblock );
	return;
    }
    /* now find the revocation certificate */
    for( node = node->next; node ; node = node->next ) {
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    break;
	if( node->pkt->pkttype == PKT_SIGNATURE
	    && (node->pkt->pkt.signature->sig_class == 0x20
		|| node->pkt->pkt.signature->sig_class == 0x28 ) ) {
		/* FIXME: we should check the signature here */
		do_show_revocation_reason ( node->pkt->pkt.signature );
		break;
	}
    }

    /* We didn't find it, so check if the whole key is revoked */
    if(!node && !mode)
      show_revocation_reason(pk,1);

    release_kbnode( keyblock );
}


/****************
 * mode: 0 = standard
 *       1 = Without key info and additional menu option 'm'
 *           this does also add an option to set the key to ultimately trusted.
 * Returns: 
 *      -2 = nothing changed - caller should show some additional info
 *      -1 = quit operation
 *       0 = nothing changed
 *       1 = new ownertrust now in new_trust
 */
static int
do_edit_ownertrust (PKT_public_key *pk, int mode,
                    unsigned *new_trust, int defer_help )
{
  char *p;
  u32 keyid[2];
  int changed=0;
  int quit=0;
  int show=0;
  int min_num;
  int did_help=defer_help;
  unsigned int minimum=get_min_ownertrust(pk);

  switch(minimum)
    {
    default:
    case TRUST_UNDEFINED: min_num=1; break;
    case TRUST_NEVER:     min_num=2; break;
    case TRUST_MARGINAL:  min_num=3; break;
    case TRUST_FULLY:     min_num=4; break;
    }

  keyid_from_pk (pk, keyid);
  for(;;) {
    /* A string with valid answers.

       Note to translators: These are the allowed answers in lower and
       uppercase.  Below you will find the matching strings which
       should be translated accordingly and the letter changed to
       match the one in the answer string.
    
         i = please show me more information
         m = back to the main menu
         s = skip this key
	 q = quit
    */
    const char *ans = _("iImMqQsS");

    if( !did_help ) 
      {
        if( !mode ) 
          {
            KBNODE keyblock, un;

            tty_printf(_("No trust value assigned to:\n"));
	    tty_printf("%4u%c/%s %s\n",nbits_from_pk( pk ),
		       pubkey_letter( pk->pubkey_algo ),
                       keystr(keyid), datestr_from_pk( pk ) );
	    p=get_user_id_native(keyid);
	    tty_printf(_("      \"%s\"\n"),p);
	    xfree(p);

            keyblock = get_pubkeyblock (keyid);
            if (!keyblock)
                BUG ();
            for (un=keyblock; un; un = un->next)
	      {
                if (un->pkt->pkttype != PKT_USER_ID )
		  continue;
                if (un->pkt->pkt.user_id->is_revoked )
		  continue;
                if (un->pkt->pkt.user_id->is_expired )
		  continue;
		/* Only skip textual primaries */
                if (un->pkt->pkt.user_id->is_primary
		    && !un->pkt->pkt.user_id->attrib_data )
		  continue;
                
		if((opt.verify_options&VERIFY_SHOW_PHOTOS)
		   && un->pkt->pkt.user_id->attrib_data)
		  show_photos(un->pkt->pkt.user_id->attribs,
			      un->pkt->pkt.user_id->numattribs,pk,NULL);

		p=utf8_to_native(un->pkt->pkt.user_id->name,
				 un->pkt->pkt.user_id->len,0);

		tty_printf(_("  aka \"%s\"\n"),p);
	      }
        
            print_fingerprint (pk, NULL, 2);
            tty_printf("\n");
	    release_kbnode (keyblock);
          }

	if(opt.trust_model==TM_DIRECT)
	  {
	    tty_printf(_("How much do you trust that this key actually "
			 "belongs to the named user?\n"));
	    tty_printf("\n");
	  }
	else
	  {
	    /* This string also used in keyedit.c:trustsig_prompt */
	    tty_printf(_("Please decide how far you trust this user to"
			 " correctly verify other users' keys\n"
			 "(by looking at passports, checking fingerprints from"
			 " different sources, etc.)\n"));
	    tty_printf("\n");
	  }

	if(min_num<=1)
	  tty_printf (_("  %d = I don't know or won't say\n"), 1);
	if(min_num<=2)
	  tty_printf (_("  %d = I do NOT trust\n"), 2);
	if(min_num<=3)
	  tty_printf (_("  %d = I trust marginally\n"), 3);
	if(min_num<=4)
	  tty_printf (_("  %d = I trust fully\n"), 4);
        if (mode)
          tty_printf (_("  %d = I trust ultimately\n"), 5);
#if 0
	/* not yet implemented */
        tty_printf ("  i = please show me more information\n");
#endif
        if( mode )
          tty_printf(_("  m = back to the main menu\n"));
        else
	  {
	    tty_printf(_("  s = skip this key\n"));
	    tty_printf(_("  q = quit\n"));
	  }
        tty_printf("\n");
	if(minimum)
	  tty_printf(_("The minimum trust level for this key is: %s\n\n"),
		     trust_value_to_string(minimum));
        did_help = 1;
      }
    if( strlen(ans) != 8 )
      BUG();
    p = cpr_get("edit_ownertrust.value",_("Your decision? "));
    trim_spaces(p);
    cpr_kill_prompt();
    if( !*p )
      did_help = 0;
    else if( *p && p[1] )
      ;
    else if( !p[1] && ((*p >= '0'+min_num) && *p <= (mode?'5':'4')) ) 
      {
        unsigned int trust;
        switch( *p )
          {
          case '1': trust = TRUST_UNDEFINED; break;
          case '2': trust = TRUST_NEVER    ; break;
          case '3': trust = TRUST_MARGINAL ; break;
          case '4': trust = TRUST_FULLY    ; break;
          case '5': trust = TRUST_ULTIMATE ; break;
          default: BUG();
          }
        if (trust == TRUST_ULTIMATE
            && !cpr_get_answer_is_yes ("edit_ownertrust.set_ultimate.okay",
                                       _("Do you really want to set this key"
                                         " to ultimate trust? (y/N) ")))
          ; /* no */
        else
          {
            *new_trust = trust;
            changed = 1;
            break;
          }
      }
#if 0
    /* not yet implemented */
    else if( *p == ans[0] || *p == ans[1] ) 
      {
        tty_printf(_("Certificates leading to an ultimately trusted key:\n"));
        show = 1;
        break;
      }
#endif
    else if( mode && (*p == ans[2] || *p == ans[3] || *p == CONTROL_D ) ) 
      {
        break ; /* back to the menu */
      }
    else if( !mode && (*p == ans[6] || *p == ans[7] ) )
      {
	break; /* skip */
      }
    else if( !mode && (*p == ans[4] || *p == ans[5] ) )
      {
        quit = 1;
        break ; /* back to the menu */
      }
    xfree(p); p = NULL;
  }
  xfree(p);
  return show? -2: quit? -1 : changed;
}

/* 
 * Display a menu to change the ownertrust of the key PK (which should
 * be a primary key).  
 * For mode values see do_edit_ownertrust ()
 */
int
edit_ownertrust (PKT_public_key *pk, int mode )
{
  unsigned int trust = 0;  /* Needs to be initialized to avoid gcc warning. */
  int no_help = 0;

  for(;;)
    {
      switch ( do_edit_ownertrust (pk, mode, &trust, no_help ) )
        {
        case -1: /* quit */
          return -1;
        case -2: /* show info */
          no_help = 1;
          break;
        case 1: /* trust value set */
          trust &= ~TRUST_FLAG_DISABLED;
          trust |= get_ownertrust (pk) & TRUST_FLAG_DISABLED;
          update_ownertrust (pk, trust );
          return 1;
        default:
          return 0;
        }
    }
}


/****************
 * Check whether we can trust this pk which has a trustlevel of TRUSTLEVEL
 * Returns: true if we trust.
 */
static int
do_we_trust( PKT_public_key *pk, unsigned int trustlevel )
{
  /* We should not be able to get here with a revoked or expired
     key */
  if(trustlevel & TRUST_FLAG_REVOKED
     || trustlevel & TRUST_FLAG_SUB_REVOKED
     || (trustlevel & TRUST_MASK) == TRUST_EXPIRED)
    BUG();

  if( opt.trust_model==TM_ALWAYS )
    {
      if( opt.verbose )
	log_info("No trust check due to `--trust-model always' option\n");
      return 1;
    }

  switch(trustlevel & TRUST_MASK)
    {
    default:
      log_error ("invalid trustlevel %u returned from validation layer\n",
		 trustlevel);
      /* fall thru */
    case TRUST_UNKNOWN: 
    case TRUST_UNDEFINED:
      log_info(_("%s: There is no assurance this key belongs"
		 " to the named user\n"),keystr_from_pk(pk));
      return 0; /* no */

    case TRUST_MARGINAL:
      log_info(_("%s: There is limited assurance this key belongs"
		 " to the named user\n"),keystr_from_pk(pk));
      return 1; /* yes */

    case TRUST_FULLY:
      if( opt.verbose )
	log_info(_("This key probably belongs to the named user\n"));
      return 1; /* yes */

    case TRUST_ULTIMATE:
      if( opt.verbose )
	log_info(_("This key belongs to us\n"));
      return 1; /* yes */
    }

  return 1; /*NOTREACHED*/
}


/****************
 * wrapper around do_we_trust, so we can ask whether to use the
 * key anyway.
 */
static int
do_we_trust_pre( PKT_public_key *pk, unsigned int trustlevel )
{
  int rc;

  rc = do_we_trust( pk, trustlevel );

  if( !opt.batch && !rc )
    {
      print_pubkey_info(NULL,pk);
      print_fingerprint (pk, NULL, 2);
      tty_printf("\n");

      tty_printf(
	       _("It is NOT certain that the key belongs to the person named\n"
		 "in the user ID.  If you *really* know what you are doing,\n"
		 "you may answer the next question with yes.\n"));

      tty_printf("\n");

      if( cpr_get_answer_is_yes("untrusted_key.override",
				_("Use this key anyway? (y/N) "))  )
	rc = 1;

      /* Hmmm: Should we set a flag to tell the user about
       *	 his decision the next time he encrypts for this recipient?
       */
    }

  return rc;
}


/****************
 * Check whether we can trust this signature.
 * Returns: Error if we shall not trust this signatures.
 */
int
check_signatures_trust( PKT_signature *sig )
{
  PKT_public_key *pk = xmalloc_clear( sizeof *pk );
  unsigned int trustlevel;
  int rc=0;

  rc = get_pubkey( pk, sig->keyid );
  if (rc) 
    { /* this should not happen */
      log_error("Ooops; the key vanished  - can't check the trust\n");
      rc = G10ERR_NO_PUBKEY;
      goto leave;
    }

  if ( opt.trust_model==TM_ALWAYS )
    {
      if( !opt.quiet )
        log_info(_("WARNING: Using untrusted key!\n"));
      if (opt.with_fingerprint)
        print_fingerprint (pk, NULL, 1);
      goto leave;
    }

  if(pk->maybe_revoked && !pk->is_revoked)
    log_info(_("WARNING: this key might be revoked (revocation key"
	       " not present)\n"));

  trustlevel = get_validity (pk, NULL);

  if ( (trustlevel & TRUST_FLAG_REVOKED) ) 
    {
      write_status( STATUS_KEYREVOKED );
      if(pk->is_revoked==2)
	log_info(_("WARNING: This key has been revoked by its"
		   " designated revoker!\n"));
      else
	log_info(_("WARNING: This key has been revoked by its owner!\n"));
      log_info(_("         This could mean that the signature is forged.\n"));
      show_revocation_reason( pk, 0 );
    }
  else if ((trustlevel & TRUST_FLAG_SUB_REVOKED) ) 
    {
      write_status( STATUS_KEYREVOKED );
      log_info(_("WARNING: This subkey has been revoked by its owner!\n"));
      show_revocation_reason( pk, 0 );
    }
  
  if ((trustlevel & TRUST_FLAG_DISABLED))
    log_info (_("Note: This key has been disabled.\n"));

  /* If we have PKA information adjust the trustlevel. */
  if (sig->pka_info && sig->pka_info->valid)
    {
      unsigned char fpr[MAX_FINGERPRINT_LEN];
      PKT_public_key *primary_pk;
      size_t fprlen;
      int okay;


      primary_pk = xmalloc_clear (sizeof *primary_pk);
      get_pubkey (primary_pk, pk->main_keyid);
      fingerprint_from_pk (primary_pk, fpr, &fprlen);
      free_public_key (primary_pk);

      if ( fprlen == 20 && !memcmp (sig->pka_info->fpr, fpr, 20) )
        {
          okay = 1;
          write_status_text (STATUS_PKA_TRUST_GOOD, sig->pka_info->email);
          log_info (_("Note: Verified signer's address is `%s'\n"),
                    sig->pka_info->email);
        }
      else
        {
          okay = 0;
          write_status_text (STATUS_PKA_TRUST_BAD, sig->pka_info->email);
          log_info (_("Note: Signer's address `%s' "
                      "does not match DNS entry\n"), sig->pka_info->email);
        }

      switch ( (trustlevel & TRUST_MASK) ) 
        {
        case TRUST_UNKNOWN: 
        case TRUST_UNDEFINED:
        case TRUST_MARGINAL:
          if (okay && opt.verify_options&VERIFY_PKA_TRUST_INCREASE)
            {
              trustlevel = ((trustlevel & ~TRUST_MASK) | TRUST_FULLY);
              log_info (_("trustlevel adjusted to FULL"
                          " due to valid PKA info\n"));
            }
          /* (fall through) */
        case TRUST_FULLY:
          if (!okay)
            {
              trustlevel = ((trustlevel & ~TRUST_MASK) | TRUST_NEVER);
              log_info (_("trustlevel adjusted to NEVER"
                          " due to bad PKA info\n"));
            }
          break;
        }
    }

  /* Now let the user know what up with the trustlevel. */
  switch ( (trustlevel & TRUST_MASK) ) 
    {
    case TRUST_EXPIRED:
      log_info(_("Note: This key has expired!\n"));
      print_fingerprint (pk, NULL, 1);
      break;
        
    default:
      log_error ("invalid trustlevel %u returned from validation layer\n",
                 trustlevel);
      /* fall thru */
    case TRUST_UNKNOWN: 
    case TRUST_UNDEFINED:
      write_status( STATUS_TRUST_UNDEFINED );
      log_info(_("WARNING: This key is not certified with"
                 " a trusted signature!\n"));
      log_info(_("         There is no indication that the "
                 "signature belongs to the owner.\n" ));
      print_fingerprint (pk, NULL, 1);
      break;

    case TRUST_NEVER:
      /* currently we won't get that status */
      write_status( STATUS_TRUST_NEVER );
      log_info(_("WARNING: We do NOT trust this key!\n"));
      log_info(_("         The signature is probably a FORGERY.\n"));
      if (opt.with_fingerprint)
        print_fingerprint (pk, NULL, 1);
      rc = G10ERR_BAD_SIGN;
      break;

    case TRUST_MARGINAL:
      write_status( STATUS_TRUST_MARGINAL );
      log_info(_("WARNING: This key is not certified with"
                 " sufficiently trusted signatures!\n"));
      log_info(_("         It is not certain that the"
                 " signature belongs to the owner.\n" ));
      print_fingerprint (pk, NULL, 1);
      break;

    case TRUST_FULLY:
      write_status( STATUS_TRUST_FULLY );
      if (opt.with_fingerprint)
        print_fingerprint (pk, NULL, 1);
      break;

    case TRUST_ULTIMATE:
      write_status( STATUS_TRUST_ULTIMATE );
      if (opt.with_fingerprint)
        print_fingerprint (pk, NULL, 1);
      break;
    }

 leave:
  free_public_key( pk );
  return rc;
}


void
release_pk_list( PK_LIST pk_list )
{
    PK_LIST pk_rover;

    for( ; pk_list; pk_list = pk_rover ) {
	pk_rover = pk_list->next;
	free_public_key( pk_list->pk );
	xfree( pk_list );
    }
}


static int
key_present_in_pk_list(PK_LIST pk_list, PKT_public_key *pk)
{
    for( ; pk_list; pk_list = pk_list->next)
	if (cmp_public_keys(pk_list->pk, pk) == 0)
	    return 0;

    return -1;
}


/****************
 * Return a malloced string with a default reciepient if there is any
 */
static char *
default_recipient(void)
{
    PKT_secret_key *sk;
    byte fpr[MAX_FINGERPRINT_LEN+1];
    size_t n;
    char *p;
    int i;

    if( opt.def_recipient )
	return xstrdup( opt.def_recipient );
    if( !opt.def_recipient_self )
	return NULL;
    sk = xmalloc_clear( sizeof *sk );
    i = get_seckey_byname( sk, NULL, 0 );
    if( i ) {
	free_secret_key( sk );
	return NULL;
    }
    n = MAX_FINGERPRINT_LEN;
    fingerprint_from_sk( sk, fpr, &n );
    free_secret_key( sk );
    p = xmalloc( 2*n+3 );
    *p++ = '0';
    *p++ = 'x';
    for(i=0; i < n; i++ )
	sprintf( p+2*i, "%02X", fpr[i] );
    p -= 2;
    return p;
}

static int
expand_id(const char *id,STRLIST *into,unsigned int flags)
{
  struct groupitem *groups;
  int count=0;

  for(groups=opt.grouplist;groups;groups=groups->next)
    {
      /* need strcasecmp() here, as this should be localized */
      if(strcasecmp(groups->name,id)==0)
	{
	  STRLIST each,sl;

	  /* this maintains the current utf8-ness */
	  for(each=groups->values;each;each=each->next)
	    {
	      sl=add_to_strlist(into,each->d);
	      sl->flags=flags;
	      count++;
	    }

	  break;
	}
    }

  return count;
}

/* For simplicity, and to avoid potential loops, we only expand once -
   you can't make an alias that points to an alias. */
static STRLIST
expand_group(STRLIST input)
{
  STRLIST sl,output=NULL,rover;

  for(rover=input;rover;rover=rover->next)
    if(expand_id(rover->d,&output,rover->flags)==0)
      {
	/* Didn't find any groups, so use the existing string */
	sl=add_to_strlist(&output,rover->d);
	sl->flags=rover->flags;
      }

  return output;
}


/* This is the central function to collect the keys for recipients.
   It is thus used to prepare a public key encryption. encrypt-to
   keys, default keys and the keys for the actual recipients are all
   collected here.  When not in batch mode and no recipient has been
   passed on the commandline, the function will also ask for
   recipients.

   RCPTS is a string list with the recipients; NULL is an allowed
   value but not very useful.  Group expansion is done on these names;
   they may be in any of the user Id formats we can handle.  The flags
   bits for each string in the string list are used for:
     Bit 0: This is an encrypt-to recipient.
     Bit 1: This is a hidden recipient.

   USE is the desired use for the key - usually PUBKEY_USAGE_ENC.
   RET_PK_LIST.

   On success a list of keys is stored at the address RET_PK_LIST; the
   caller must free this list.  On error the value at this address is
   not changed.
 */
int
build_pk_list( STRLIST rcpts, PK_LIST *ret_pk_list, unsigned int use )
{
  PK_LIST pk_list = NULL;
  PKT_public_key *pk=NULL;
  int rc=0;
  int any_recipients=0;
  STRLIST rov,remusr;
  char *def_rec = NULL;

  /* Try to expand groups if any have been defined. */
  if (opt.grouplist)
    remusr = expand_group (rcpts);
  else
    remusr = rcpts;

  /* Check whether there are any recipients in the list and build the
   * list of the encrypt-to ones (we always trust them). */
  for ( rov = remusr; rov; rov = rov->next ) 
    {
      if ( !(rov->flags & 1) )
        {
          /* This is a regular recipient; i.e. not an encrypt-to
             one. */
          any_recipients = 1;

          /* Hidden recipients are not allowed while in PGP mode,
             issue a warning and switch into GnuPG mode. */
          if ((rov->flags&2) && (PGP2 || PGP6 || PGP7 || PGP8))
            {
              log_info(_("you may not use %s while in %s mode\n"),
                       "--hidden-recipient",
                       compliance_option_string());

              compliance_failure();
            }
        }
      else if ( (use & PUBKEY_USAGE_ENC) && !opt.no_encrypt_to ) 
        {
          /* Encryption has been requested and --encrypt-to has not
             been disabled.  Check this encrypt-to key. */
          pk = xmalloc_clear( sizeof *pk );
          pk->req_usage = use;

          /* We explicitly allow encrypt-to to an disabled key; thus
             we pass 1 as last argument. */
          if ( (rc = get_pubkey_byname ( pk, rov->d, NULL, NULL, 1 )) ) 
            {
              free_public_key ( pk ); pk = NULL;
              log_error (_("%s: skipped: %s\n"), rov->d, g10_errstr(rc) );
              write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                            rov->d, strlen (rov->d), -1);
              goto fail;
            }
          else if ( !(rc=check_pubkey_algo2 (pk->pubkey_algo, use )) ) 
            {
              /* Skip the actual key if the key is already present
               * in the list.  Add it to our list if not. */
              if (key_present_in_pk_list(pk_list, pk) == 0)
                {
                  free_public_key (pk); pk = NULL;
                  log_info (_("%s: skipped: public key already present\n"),
                            rov->d);
                }
              else
                {
                  PK_LIST r;
                  r = xmalloc( sizeof *r );
                  r->pk = pk; pk = NULL;
                  r->next = pk_list;
                  r->flags = (rov->flags&2)?1:0;
                  pk_list = r;

                  /* Hidden encrypt-to recipients are not allowed while
                     in PGP mode, issue a warning and switch into
                     GnuPG mode. */
                  if ((r->flags&1) && (PGP2 || PGP6 || PGP7 || PGP8))
                    {
                      log_info(_("you may not use %s while in %s mode\n"),
                               "--hidden-encrypt-to",
                               compliance_option_string());

                      compliance_failure();
                    }
                }
            }
          else 
            {
              /* The public key is not usable for encryption or not
                 available. */
              free_public_key( pk ); pk = NULL;
              log_error(_("%s: skipped: %s\n"), rov->d, g10_errstr(rc) );
              write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                            rov->d, strlen (rov->d), -1);
              goto fail;
            }
        }
    }

  /* If we don't have any recipients yet and we are not in batch mode
     drop into interactive selection mode. */
  if ( !any_recipients && !opt.batch ) 
    { 
      int have_def_rec;
      char *answer = NULL;
      STRLIST backlog = NULL;

      if (pk_list)
        any_recipients = 1;
      def_rec = default_recipient();
      have_def_rec = !!def_rec;
      if ( !have_def_rec )
        tty_printf(_("You did not specify a user ID. (you may use \"-r\")\n"));

      for (;;) 
        {
          rc = 0;
          xfree(answer);
          if ( have_def_rec )
            {
              /* A default recipient is taken as the first entry. */
              answer = def_rec;
              def_rec = NULL;
            }
          else if (backlog) 
            {
              /* This is part of our trick to expand and display groups. */
              answer = pop_strlist (&backlog);
            }
          else
            {
              /* Show the list of already collected recipients and ask
                 for more. */
              PK_LIST iter;

              tty_printf("\n");
              tty_printf(_("Current recipients:\n"));
              for (iter=pk_list;iter;iter=iter->next)
                {
                  u32 keyid[2];

                  keyid_from_pk(iter->pk,keyid);
                  tty_printf("%4u%c/%s %s \"",
                             nbits_from_pk(iter->pk),
                             pubkey_letter(iter->pk->pubkey_algo),
                             keystr(keyid),
                             datestr_from_pk(iter->pk));

                  if (iter->pk->user_id)
                    tty_print_utf8_string(iter->pk->user_id->name,
                                          iter->pk->user_id->len);
                  else
                    {
                      size_t n;
                      char *p = get_user_id( keyid, &n );
                      tty_print_utf8_string( p, n );
                      xfree(p);
                    }
                  tty_printf("\"\n");
                }

              answer = cpr_get_utf8("pklist.user_id.enter",
                                    _("\nEnter the user ID.  "
                                      "End with an empty line: "));
              trim_spaces(answer);
              cpr_kill_prompt();
            }
          
          if ( !answer || !*answer ) 
            {
              xfree(answer);
              break;  /* No more recipients entered - get out of loop. */
            }

          /* Do group expand here too.  The trick here is to continue
             the loop if any expansion occured.  The code above will
             then list all expanded keys. */
          if (expand_id(answer,&backlog,0))
            continue;

          /* Get and check key for the current name. */
          if (pk)
            free_public_key (pk);
          pk = xmalloc_clear( sizeof *pk );
          pk->req_usage = use;
          rc = get_pubkey_byname( pk, answer, NULL, NULL, 0 );
          if (rc)
            tty_printf(_("No such user ID.\n"));
          else if ( !(rc=check_pubkey_algo2(pk->pubkey_algo, use)) ) 
            {
              if ( have_def_rec )
                {
                  /* No validation for a default recipient. */
                  if (!key_present_in_pk_list(pk_list, pk)) 
                    {
                      free_public_key (pk); pk = NULL;
                      log_info (_("skipped: public key "
                                  "already set as default recipient\n") );
                    }
                  else
                    {
                      PK_LIST r = xmalloc (sizeof *r);
                      r->pk = pk; pk = NULL;
                      r->next = pk_list;
                      r->flags = 0; /* No throwing default ids. */
                      pk_list = r;
                    }
                  any_recipients = 1;
                  continue;
                }
              else
                { /* Check validity of this key. */
                  int trustlevel;
		    
                  trustlevel = get_validity (pk, pk->user_id);
                  if ( (trustlevel & TRUST_FLAG_DISABLED) ) 
                    {
                      tty_printf (_("Public key is disabled.\n") );
                    }
                  else if ( do_we_trust_pre (pk, trustlevel) ) 
                    {
                      /* Skip the actual key if the key is already
                       * present in the list */
                      if (!key_present_in_pk_list(pk_list, pk))
                        {
                          free_public_key(pk); pk = NULL;
                          log_info(_("skipped: public key already set\n") );
                        }
                      else
                        {
                          PK_LIST r;
                          r = xmalloc( sizeof *r );
                          r->pk = pk; pk = NULL;
                          r->next = pk_list;
                          r->flags = 0; /* No throwing interactive ids. */
                          pk_list = r;
                        }
                      any_recipients = 1;
                      continue;
                    }
                }
            }
          xfree(def_rec); def_rec = NULL;
          have_def_rec = 0;
        }
      if ( pk )
        {
          free_public_key( pk );
          pk = NULL;
        }
    }
  else if ( !any_recipients && (def_rec = default_recipient()) ) 
    {
      /* We are in batch mode and have only a default recipient. */
      pk = xmalloc_clear( sizeof *pk );
      pk->req_usage = use;

      /* The default recipient is allowed to be disabled; thus pass 1
         as last argument. */
      rc = get_pubkey_byname (pk, def_rec, NULL, NULL, 1);
      if (rc)
        log_error(_("unknown default recipient \"%s\"\n"), def_rec );
      else if ( !(rc=check_pubkey_algo2(pk->pubkey_algo, use)) ) 
        {
          /* Mark any_recipients here since the default recipient
             would have been used if it wasn't already there.  It
             doesn't really matter if we got this key from the default
             recipient or an encrypt-to. */
          any_recipients = 1;
          if (!key_present_in_pk_list(pk_list, pk))
            log_info (_("skipped: public key already set "
                        "as default recipient\n"));
          else 
            {
              PK_LIST r = xmalloc( sizeof *r );
              r->pk = pk; pk = NULL;
              r->next = pk_list;
              r->flags = 0; /* No throwing default ids. */
              pk_list = r;
            }
        }
      if ( pk )
        {
          free_public_key( pk );
          pk = NULL;
        }
      xfree(def_rec); def_rec = NULL;
    }
  else 
    {
      /* General case: Check all keys. */
      any_recipients = 0;
      for (; remusr; remusr = remusr->next ) 
        {
          if ( (remusr->flags & 1) )
            continue; /* encrypt-to keys are already handled. */

          pk = xmalloc_clear( sizeof *pk );
          pk->req_usage = use;
          if ( (rc = get_pubkey_byname( pk, remusr->d, NULL, NULL, 0 )) ) 
            {
              /* Key not found or other error. */
              free_public_key( pk ); pk = NULL;
              log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
              write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                            remusr->d, strlen (remusr->d),
                                            -1);
              goto fail;
            }
          else if ( !(rc=check_pubkey_algo2(pk->pubkey_algo, use )) ) 
            {
              /* Key found and usable.  Check validity. */
              int trustlevel;
              
              trustlevel = get_validity (pk, pk->user_id);
              if ( (trustlevel & TRUST_FLAG_DISABLED) ) 
                {
                  /*Key has been disabled. */
                  free_public_key(pk); pk = NULL;
                  log_info(_("%s: skipped: public key is disabled\n"),
                           remusr->d);
                  write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                                remusr->d,
                                                strlen (remusr->d),
                                                -1);
                  rc=G10ERR_UNU_PUBKEY;
                  goto fail;
                }
              else if ( do_we_trust_pre( pk, trustlevel ) ) 
                {
                  /* Note: do_we_trust may have changed the trustlevel */

                  /* We have at least one valid recipient. It doesn't
                   * matters if this recipient is already present. */
                  any_recipients = 1;

                  /* Skip the actual key if the key is already present
                   * in the list */
                  if (!key_present_in_pk_list(pk_list, pk)) 
                    {
                      free_public_key(pk); pk = NULL;
                      log_info(_("%s: skipped: public key already present\n"),
                               remusr->d);
                    }
                  else
                    {
                      PK_LIST r;
                      r = xmalloc( sizeof *r );
                      r->pk = pk; pk = NULL;
                      r->next = pk_list;
                      r->flags = (remusr->flags&2)?1:0;
                      pk_list = r;
                    }
                }
              else
                { /* We don't trust this key. */
                  free_public_key( pk ); pk = NULL;
                  write_status_text_and_buffer (STATUS_INV_RECP, "10 ",
                                                remusr->d,
                                                strlen (remusr->d),
                                                -1);
                  rc=G10ERR_UNU_PUBKEY;
                  goto fail;
                }
            }
          else
            {
              /* Key found but not usable for us (e.g. sign-only key). */
              free_public_key( pk ); pk = NULL;
              write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                            remusr->d,
                                            strlen (remusr->d),
                                            -1);
              log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
              goto fail;
            }
        }
    }
  
  if ( !rc && !any_recipients ) 
    {
      log_error(_("no valid addressees\n"));
      write_status_text (STATUS_NO_RECP, "0");
      rc = G10ERR_NO_USER_ID;
    }
  
 fail:

  if ( rc )
    release_pk_list( pk_list );
  else
    *ret_pk_list = pk_list;
  if (opt.grouplist)
    free_strlist(remusr);
  return rc;
}


/* In pgp6 mode, disallow all ciphers except IDEA (1), 3DES (2), and
   CAST5 (3), all hashes except MD5 (1), SHA1 (2), and RIPEMD160 (3),
   and all compressions except none (0) and ZIP (1).  pgp7 and pgp8
   mode expands the cipher list to include AES128 (7), AES192 (8),
   AES256 (9), and TWOFISH (10).  pgp8 adds the SHA-256 hash (8).  For
   a true PGP key all of this is unneeded as they are the only items
   present in the preferences subpacket, but checking here covers the
   weird case of encrypting to a key that had preferences from a
   different implementation which was then used with PGP.  I am not
   completely comfortable with this as the right thing to do, as it
   slightly alters the list of what the user is supposedly requesting.
   It is not against the RFC however, as the preference chosen will
   never be one that the user didn't specify somewhere ("The
   implementation may use any mechanism to pick an algorithm in the
   intersection"), and PGP has no mechanism to fix such a broken
   preference list, so I'm including it. -dms */

int
algo_available( preftype_t preftype, int algo, const union pref_hint *hint )
{
  if( preftype == PREFTYPE_SYM )
    {
      if(PGP6 && (algo != CIPHER_ALGO_IDEA
		  && algo != CIPHER_ALGO_3DES
		  && algo != CIPHER_ALGO_CAST5))
	return 0;
      
      if(PGP7 && (algo != CIPHER_ALGO_IDEA
		  && algo != CIPHER_ALGO_3DES
		  && algo != CIPHER_ALGO_CAST5
		  && algo != CIPHER_ALGO_AES
		  && algo != CIPHER_ALGO_AES192
		  && algo != CIPHER_ALGO_AES256
		  && algo != CIPHER_ALGO_TWOFISH))
	return 0;

      /* PGP8 supports all the ciphers we do.. */

      return algo && !check_cipher_algo( algo );
    }
  else if( preftype == PREFTYPE_HASH )
    {
      if(hint && hint->digest_length)
	{
	  if(hint->digest_length!=20 || opt.flags.dsa2)
	    {
	      /* If --enable-dsa2 is set or the hash isn't 160 bits
		 (which implies DSA2), then we'll accept a hash that
		 is larger than we need.  Otherwise we won't accept
		 any hash that isn't exactly the right size. */
	      if(hint->digest_length > md_digest_length(algo))
		return 0;
	    }
	  else if(hint->digest_length != md_digest_length(algo))
	    return 0;
	}

      if((PGP6 || PGP7) && (algo != DIGEST_ALGO_MD5
			    && algo != DIGEST_ALGO_SHA1
			    && algo != DIGEST_ALGO_RMD160))
	return 0;


      if(PGP8 && (algo != DIGEST_ALGO_MD5
		  && algo != DIGEST_ALGO_SHA1
		  && algo != DIGEST_ALGO_RMD160
		  && algo != DIGEST_ALGO_SHA256))
	return 0;

      return algo && !check_digest_algo( algo );
    }
  else if( preftype == PREFTYPE_ZIP )
    {
      if((PGP6 || PGP7) && (algo != COMPRESS_ALGO_NONE
			    && algo != COMPRESS_ALGO_ZIP))
	return 0;

      /* PGP8 supports all the compression algos we do */

      return !check_compress_algo( algo );
    }
  else
    return 0;
}



/****************
 * Return -1 if we could not find an algorithm.
 */
int
select_algo_from_prefs(PK_LIST pk_list, int preftype,
		       int request, const union pref_hint *hint)
{
    PK_LIST pkr;
    u32 bits[8];
    const prefitem_t *prefs;
    int i, j;
    int compr_hack=0;
    int any;

    if( !pk_list )
	return -1;

    memset( bits, ~0, 8 * sizeof *bits );
    for( pkr = pk_list; pkr; pkr = pkr->next ) {
	u32 mask[8];

	memset( mask, 0, 8 * sizeof *mask );
	if( preftype == PREFTYPE_SYM ) {
	  if( PGP2 &&
	      pkr->pk->version < 4 &&
	      pkr->pk->selfsigversion < 4 )
	    mask[0] |= (1<<1); /* IDEA is implicitly there for v3 keys
				  with v3 selfsigs (rfc2440:12.1) if
				  --pgp2 mode is on.  This doesn't
				  mean it's actually available, of
				  course. */
	  else
	    mask[0] |= (1<<2); /* 3DES is implicitly there for everyone else */
	}
	else if( preftype == PREFTYPE_HASH ) {
	  /* While I am including this code for completeness, note
	     that currently --pgp2 mode locks the hash at MD5, so this
	     function will never even be called.  Even if the hash
	     wasn't locked at MD5, we don't support sign+encrypt in
	     --pgp2 mode, and that's the only time PREFTYPE_HASH is
	     used anyway. -dms */
	  if( PGP2 &&
	      pkr->pk->version < 4 &&
	      pkr->pk->selfsigversion < 4 )
	    mask[0] |= (1<<1); /* MD5 is there for v3 keys with v3
				  selfsigs when --pgp2 is on. */
	  else
	    mask[0] |= (1<<2); /* SHA1 is there for everyone else */
	}
	else if( preftype == PREFTYPE_ZIP )
	  mask[0] |= (1<<0); /* Uncompressed is implicit */

        if (pkr->pk->user_id) /* selected by user ID */
            prefs = pkr->pk->user_id->prefs;
        else
            prefs = pkr->pk->prefs;

	any = 0;
	if( prefs ) {
	    for (i=0; prefs[i].type; i++ ) {
		if( prefs[i].type == preftype ) {
		    mask[prefs[i].value/32] |= 1 << (prefs[i].value%32);
		    any = 1;
		}
	    }
	}

	if( (!prefs || !any) && preftype == PREFTYPE_ZIP ) {
	    mask[0] |= 3; /* asume no_compression and old pgp */
	    compr_hack = 1;
	}

#if 0
	log_debug("pref mask=%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n",
	       (ulong)mask[7], (ulong)mask[6], (ulong)mask[5], (ulong)mask[4],
	     (ulong)mask[3], (ulong)mask[2], (ulong)mask[1], (ulong)mask[0]);
#endif
	for(i=0; i < 8; i++ )
	    bits[i] &= mask[i];
#if 0
	log_debug("pref bits=%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n",
	       (ulong)bits[7], (ulong)bits[6], (ulong)bits[5], (ulong)bits[4],
	     (ulong)bits[3], (ulong)bits[2], (ulong)bits[1], (ulong)bits[0]);
#endif
    }
    /* usable algorithms are now in bits
     * We now use the last key from pk_list to select
     * the algorithm we want to use. there are no
     * preferences for the last key, we select the one
     * corresponding to first set bit.
     */
    i = -1;
    any = 0;

    /* Can we use the requested algorithm? */
    if(request>-1 && (bits[request/32] & (1<<(request%32))) &&
       algo_available(preftype,request,hint))
      return request;

    /* If we have personal prefs set, use them instead of the last key */
    if(preftype==PREFTYPE_SYM && opt.personal_cipher_prefs)
      prefs=opt.personal_cipher_prefs;
    else if(preftype==PREFTYPE_HASH && opt.personal_digest_prefs)
      prefs=opt.personal_digest_prefs;
    else if(preftype==PREFTYPE_ZIP && opt.personal_compress_prefs)
      prefs=opt.personal_compress_prefs;

    if( prefs ) {
	for(j=0; prefs[j].type; j++ ) {
	    if( prefs[j].type == preftype ) {
                if( (bits[prefs[j].value/32] & (1<<(prefs[j].value%32))) ) {
		    if( algo_available( preftype, prefs[j].value, hint ) ) {
			any = 1;
			i = prefs[j].value;
			break;
		    }
		}
	    }
	}
    }
    if( !prefs || !any ) {
	for(j=0; j < 256; j++ )
	    if( (bits[j/32] & (1<<(j%32))) ) {
		if( algo_available( preftype, j, hint ) ) {
		    i = j;
		    break;
		}
	    }
    }

#if 0
    log_debug("prefs of type %d: selected %d\n", preftype, i );
#endif
    if( compr_hack && !i ) {
	/* selected no compression, but we should check whether
	 * algorithm 1 is also available (the ordering is not relevant
	 * in this case). */
	if( bits[0] & (1<<1) )
	    i = 1; /* yep; we can use compression algo 1 */
    }

    /* "If you are building an authentication system, the recipient
       may specify a preferred signing algorithm. However, the signer
       would be foolish to use a weak algorithm simply because the
       recipient requests it." RFC2440:13.  If we settle on MD5, and
       SHA1 is also available, use SHA1 instead.  Of course, if the
       user intentionally chose MD5 (by putting it in their personal
       prefs), then we should do what they say. */

    if(preftype==PREFTYPE_HASH &&
       i==DIGEST_ALGO_MD5 && (bits[0] & (1<<DIGEST_ALGO_SHA1)))
      {
	i=DIGEST_ALGO_SHA1;

	if(opt.personal_digest_prefs)
	  for(j=0; prefs[j].type; j++ )
	    if(opt.personal_digest_prefs[j].type==PREFTYPE_HASH &&
	       opt.personal_digest_prefs[j].value==DIGEST_ALGO_MD5)
	      {
		i=DIGEST_ALGO_MD5;
		break;
	      }
      }

    return i;
}

/*
 * Select the MDC flag from the pk_list.  We can only use MDC if all recipients
 * support this feature 
 */
int
select_mdc_from_pklist (PK_LIST pk_list)
{
    PK_LIST pkr;

    if( !pk_list )
	return 0;

    for (pkr = pk_list; pkr; pkr = pkr->next) {
        int mdc;

        if (pkr->pk->user_id) /* selected by user ID */
            mdc = pkr->pk->user_id->flags.mdc;
        else
            mdc = pkr->pk->mdc_feature;
        if (!mdc)
            return 0; /* at least one recipient does not support it */
    }
    return 1; /* can be used */
}
