/* pkclist.c
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
				 &n, &seq )) ) {
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


static void
show_paths (const PKT_public_key *pk, int only_first )
{
    log_debug("not yet implemented\n");
#if 0    
    void *context = NULL;
    unsigned otrust, validity;
    int last_level, level;

    last_level = 0;
    while( (level=enum_cert_paths( &context, &lid, &otrust, &validity)) != -1){
	char *p;
	int c, rc;
	size_t n;
	u32 keyid[2];
	PKT_public_key *pk ;

	if( level < last_level && only_first )
	    break;
	last_level = level;

	rc = keyid_from_lid( lid, keyid );

	if( rc ) {
	    log_error("ooops: can't get keyid for lid %lu\n", lid);
	    return;
	}

	pk = m_alloc_clear( sizeof *pk );
	rc = get_pubkey( pk, keyid );
	if( rc ) {
	    log_error("key %08lX: public key not found: %s\n",
				    (ulong)keyid[1], g10_errstr(rc) );
	    return;
	}

	tty_printf("%*s%4u%c/%08lX.%lu %s \"",
		  level*2, "",
		  nbits_from_pk( pk ), pubkey_letter( pk->pubkey_algo ),
		  (ulong)keyid[1], lid, datestr_from_pk( pk ) );

	c = trust_letter(otrust);
	if( c )
	    putchar( c );
	else
	    printf( "%02x", otrust );
	putchar('/');
	c = trust_letter(validity);
	if( c )
	    putchar( c );
	else
	    printf( "%02x", validity );
	putchar(' ');

	p = get_user_id( keyid, &n );
	tty_print_utf8_string( p, n ),
	m_free(p);
	tty_printf("\"\n");
	free_public_key( pk );
    }
    enum_cert_paths( &context, NULL, NULL, NULL ); /* release context */
#endif
    tty_printf("\n");
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
  size_t n;
  u32 keyid[2];
  int changed=0;
  int quit=0;
  int show=0;
  int did_help=defer_help;

  keyid_from_pk (pk, keyid);
  for(;;) {
    /* a string with valid answers */
    const char *ans = _("iImMqQsS");

    if( !did_help ) 
      {
        if( !mode ) 
          {
            tty_printf(_("No trust value assigned to:\n"
                         "%4u%c/%08lX %s \""),
                       nbits_from_pk( pk ), pubkey_letter( pk->pubkey_algo ),
                       (ulong)keyid[1], datestr_from_pk( pk ) );
            p = get_user_id( keyid, &n );
            tty_print_utf8_string( p, n ),
              m_free(p);
            tty_printf("\"\n");
            print_fingerprint (pk, NULL, 2);
            tty_printf("\n");
          }
        tty_printf (_(
                     "Please decide how far you trust this user to correctly\n"
                     "verify other users' keys (by looking at passports,\n"
                     "checking fingerprints from different sources...)?\n\n"));
        tty_printf (_(" %d = Don't know\n"), 1);
        tty_printf (_(" %d = I do NOT trust\n"), 2);
        tty_printf (_(" %d = I trust marginally\n"), 3);
        tty_printf (_(" %d = I trust fully\n"), 4);
        if (mode)
          tty_printf (_(" %d = I trust ultimately\n"), 5);
        tty_printf (_(" i = please show me more information\n") );
        if( mode )
          tty_printf(_(" m = back to the main menu\n"));
        else
	  {
	    tty_printf(_(" s = skip this key\n"));
	    tty_printf(_(" q = quit\n"));
	  }
        tty_printf("\n");
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
    else if( !p[1] && (*p >= '1' && *p <= (mode?'5':'4')) ) 
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
                                         " to ultimate trust? ")))
          ; /* no */
        else
          {
            *new_trust = trust;
            changed = 1;
            break;
          }
      }
    else if( *p == ans[0] || *p == ans[1] ) 
      {
        tty_printf(_("Certificates leading to an ultimately trusted key:\n"));
        show = 1;
        break;
      }
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
    m_free(p); p = NULL;
  }
  m_free(p);
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
  unsigned int trust;
  int no_help = 0;

  for(;;)
    {
      switch ( do_edit_ownertrust (pk, mode, &trust, no_help ) )
        {
        case -1: /* quit */
          return -1;
        case -2: /* show info */
          show_paths(pk, 1);
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
do_we_trust( PKT_public_key *pk, unsigned int *trustlevel )
{
    unsigned int trustmask = 0;

    /* FIXME: get_pubkey_byname already checks the validity and won't
     * return keys which are either expired or revoked - so these
     * question here won't get triggered.  We have to find a solution
     * for this.  It might make sense to have a function in getkey.c
     * which does only the basic checks and returns even revoked and
     * expired keys.  This fnction could then also returhn a list of
     * keys if the speicified name is ambiguous
     */
    if( (*trustlevel & TRUST_FLAG_REVOKED) ) {
	log_info(_("key %08lX: key has been revoked!\n"),
					(ulong)keyid_from_pk( pk, NULL) );
	show_revocation_reason( pk, 0 );
	if( opt.batch )
          return 0; /* no */

	if( !cpr_get_answer_is_yes("revoked_key.override",
				    _("Use this key anyway? ")) )
          return 0; /* no */
	trustmask |= TRUST_FLAG_REVOKED;
    }
    if( (*trustlevel & TRUST_FLAG_SUB_REVOKED) ) {
	log_info(_("key %08lX: subkey has been revoked!\n"),
					(ulong)keyid_from_pk( pk, NULL) );
	show_revocation_reason( pk, 0 );
	if( opt.batch )
	    return 0;

	if( !cpr_get_answer_is_yes("revoked_key.override",
				    _("Use this key anyway? ")) )
	    return 0;
	trustmask |= TRUST_FLAG_SUB_REVOKED;
    }
    *trustlevel &= ~trustmask;

    if( opt.always_trust) {
	if( opt.verbose )
	    log_info("No trust check due to --always-trust option\n");
	return 1;
    }

    switch( (*trustlevel & TRUST_MASK) ) {
      case TRUST_EXPIRED:
	log_info(_("%08lX: key has expired\n"),
				    (ulong)keyid_from_pk( pk, NULL) );
	return 0; /* no */

      default:
         log_error ("invalid trustlevel %u returned from validation layer\n",
                    *trustlevel);
         /* fall thru */
      case TRUST_UNKNOWN: 
      case TRUST_UNDEFINED:
        log_info(_("%08lX: There is no indication that this key "
                   "really belongs to the owner\n"),
                 (ulong)keyid_from_pk( pk, NULL) );
	return 0; /* no */

      case TRUST_NEVER:
	log_info(_("%08lX: We do NOT trust this key\n"),
					(ulong)keyid_from_pk( pk, NULL) );
	return 0; /* no */

      case TRUST_MARGINAL:
	log_info(
       _("%08lX: It is not sure that this key really belongs to the owner\n"
	 "but it is accepted anyway\n"), (ulong)keyid_from_pk( pk, NULL) );
	return 1; /* yes */

      case TRUST_FULLY:
	if( opt.verbose )
	    log_info(_("This key probably belongs to the owner\n"));
	return 1; /* yes */

      case TRUST_ULTIMATE:
	if( opt.verbose )
	    log_info(_("This key belongs to us\n"));
	return 1; /* yes */
    }

    return 1; /* yes */
}



/****************
 * wrapper around do_we_trust, so we can ask whether to use the
 * key anyway.
 */
static int
do_we_trust_pre( PKT_public_key *pk, unsigned int trustlevel )
{
    int rc;

    rc = do_we_trust( pk, &trustlevel );

    if( (trustlevel & TRUST_FLAG_REVOKED) && !rc )
	return 0;
    if( (trustlevel & TRUST_FLAG_SUB_REVOKED) && !rc )
	return 0;

    if( !opt.batch && !rc ) {
	char *p;
	u32 keyid[2];
	size_t n;

	keyid_from_pk( pk, keyid);
	tty_printf( "%4u%c/%08lX %s \"",
		  nbits_from_pk( pk ), pubkey_letter( pk->pubkey_algo ),
		  (ulong)keyid[1], datestr_from_pk( pk ) );
	p = get_user_id( keyid, &n );
	tty_print_utf8_string( p, n ),
	m_free(p);
	tty_printf("\"\n");
        print_fingerprint (pk, NULL, 2);
	tty_printf("\n");

	tty_printf(_(
"It is NOT certain that the key belongs to its owner.\n"
"If you *really* know what you are doing, you may answer\n"
"the next question with yes\n\n") );

	if( cpr_get_answer_is_yes("untrusted_key.override",
				  _("Use this key anyway? "))  )
	    rc = 1;

	/* Hmmm: Should we set a flag to tell the user about
	 *	 his decision the next time he encrypts for this recipient?
	 */
    }
    else if( opt.always_trust && !rc ) {
	if( !opt.quiet )
	    log_info(_("WARNING: Using untrusted key!\n"));
	rc = 1;
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
  PKT_public_key *pk = m_alloc_clear( sizeof *pk );
  unsigned int trustlevel;
  int rc=0;

  if ( opt.always_trust)
    {
      if( !opt.quiet )
        log_info(_("WARNING: Using untrusted key!\n"));
      if (opt.with_fingerprint)
        print_fingerprint (pk, NULL, 1);
      goto leave;
    }

  rc = get_pubkey( pk, sig->keyid );
  if (rc) 
    { /* this should not happen */
      log_error("Ooops; the key vanished  - can't check the trust\n");
      rc = G10ERR_NO_PUBKEY;
      goto leave;
    }

  trustlevel = get_validity (pk, NULL);

  if ( (trustlevel & TRUST_FLAG_REVOKED) ) 
    {
      write_status( STATUS_KEYREVOKED );
      log_info(_("WARNING: This key has been revoked by its owner!\n"));
      log_info(_("         This could mean that the signature is forgery.\n"));
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
	m_free( pk_list );
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
	return m_strdup( opt.def_recipient );
    if( !opt.def_recipient_self )
	return NULL;
    sk = m_alloc_clear( sizeof *sk );
    i = get_seckey_byname( sk, NULL, 0 );
    if( i ) {
	free_secret_key( sk );
	return NULL;
    }
    n = MAX_FINGERPRINT_LEN;
    fingerprint_from_sk( sk, fpr, &n );
    free_secret_key( sk );
    p = m_alloc( 2*n+3 );
    *p++ = '0';
    *p++ = 'x';
    for(i=0; i < n; i++ )
	sprintf( p+2*i, "%02X", fpr[i] );
    p -= 2;
    return p;
}


int
build_pk_list( STRLIST remusr, PK_LIST *ret_pk_list, unsigned use )
{
    PK_LIST pk_list = NULL;
    PKT_public_key *pk=NULL;
    int rc=0;
    int any_recipients=0;
    STRLIST rov;
    char *def_rec = NULL;

    /* check whether there are any recipients in the list and build the
     * list of the encrypt-to ones (we always trust them) */
    for( rov = remusr; rov; rov = rov->next ) {
	if( !(rov->flags & 1) )
	    any_recipients = 1;
	else if( (use & PUBKEY_USAGE_ENC) && !opt.no_encrypt_to ) {
	    pk = m_alloc_clear( sizeof *pk );
	    pk->req_usage = use;
	    if( (rc = get_pubkey_byname( pk, rov->d, NULL, NULL )) ) {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), rov->d, g10_errstr(rc) );
                write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                              rov->d, strlen (rov->d), -1);
            }
	    else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, use )) ) {
		/* Skip the actual key if the key is already present
		 * in the list */
		if (key_present_in_pk_list(pk_list, pk) == 0) {
		    free_public_key(pk); pk = NULL;
		    log_info(_("%s: skipped: public key already present\n"),
							    rov->d);
		}
		else {
		    PK_LIST r;
		    r = m_alloc( sizeof *r );
		    r->pk = pk; pk = NULL;
		    r->next = pk_list;
		    r->mark = 0;
		    pk_list = r;
		}
	    }
	    else {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), rov->d, g10_errstr(rc) );
                write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                              rov->d, strlen (rov->d), -1);
	    }
	}
    }

    if( !any_recipients && !opt.batch ) { /* ask */
	int have_def_rec;
	char *answer=NULL;

	def_rec = default_recipient();
	have_def_rec = !!def_rec;
	if( !have_def_rec )
	    tty_printf(_(
		"You did not specify a user ID. (you may use \"-r\")\n"));
	for(;;) {
	    rc = 0;
	    m_free(answer);
	    if( have_def_rec ) {
		answer = def_rec;
		def_rec = NULL;
	    }
	    else {
		answer = cpr_get_utf8("pklist.user_id.enter",
			 _("\nEnter the user ID.  End with an empty line: "));
		trim_spaces(answer);
		cpr_kill_prompt();
	    }
	    if( !answer || !*answer ) {
	        m_free(answer);
		break;
	    }
	    if( pk )
		free_public_key( pk );
	    pk = m_alloc_clear( sizeof *pk );
	    pk->req_usage = use;
	    rc = get_pubkey_byname( pk, answer, NULL, NULL );
	    if( rc )
		tty_printf(_("No such user ID.\n"));
	    else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, use)) ) {
		if( have_def_rec ) {
		    if (key_present_in_pk_list(pk_list, pk) == 0) {
			free_public_key(pk); pk = NULL;
			log_info(_("skipped: public key "
				   "already set as default recipient\n") );
		    }
		    else {
			PK_LIST r = m_alloc( sizeof *r );
			r->pk = pk; pk = NULL;
			r->next = pk_list;
			r->mark = 0;
			pk_list = r;
		    }
		    any_recipients = 1;
		    continue;
		}
		else {
		    int trustlevel;

		    trustlevel = get_validity (pk, NULL);
		    if( (trustlevel & TRUST_FLAG_DISABLED) ) {
			tty_printf(_("Public key is disabled.\n") );
		    }
		    else if( do_we_trust_pre( pk, trustlevel ) ) {
			/* Skip the actual key if the key is already present
			 * in the list */
			if (key_present_in_pk_list(pk_list, pk) == 0) {
			    free_public_key(pk); pk = NULL;
			    log_info(_("skipped: public key already set\n") );
			}
			else {
			    PK_LIST r;
			    char *p;
			    size_t n;
			    u32 keyid[2];

			    keyid_from_pk( pk, keyid);
			    tty_printf("Added %4u%c/%08lX %s \"",
				       nbits_from_pk( pk ),
				       pubkey_letter( pk->pubkey_algo ),
				       (ulong)keyid[1],
				       datestr_from_pk( pk ) );
			    p = get_user_id( keyid, &n );
			    tty_print_utf8_string( p, n );
			    m_free(p);
			    tty_printf("\"\n");

			    r = m_alloc( sizeof *r );
			    r->pk = pk; pk = NULL;
			    r->next = pk_list;
			    r->mark = 0;
			    pk_list = r;
			}
			any_recipients = 1;
			continue;
		    }
		}
	    }
	    m_free(def_rec); def_rec = NULL;
	    have_def_rec = 0;
	}
	if( pk ) {
	    free_public_key( pk );
	    pk = NULL;
	}
    }
    else if( !any_recipients && (def_rec = default_recipient()) ) {
	pk = m_alloc_clear( sizeof *pk );
	pk->req_usage = use;
	rc = get_pubkey_byname( pk, def_rec, NULL, NULL );
	if( rc )
	    log_error(_("unknown default recipient `%s'\n"), def_rec );
	else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, use)) ) {
	  /* Mark any_recipients here since the default recipient
             would have been used if it wasn't already there.  It
             doesn't really matter if we got this key from the default
             recipient or an encrypt-to. */
	  any_recipients = 1;
	  if (key_present_in_pk_list(pk_list, pk) == 0)
	    log_info(_("skipped: public key already set as default recipient\n"));
	  else {
	    PK_LIST r = m_alloc( sizeof *r );
	    r->pk = pk; pk = NULL;
	    r->next = pk_list;
	    r->mark = 0;
	    pk_list = r;
	  }
	}
	if( pk ) {
	    free_public_key( pk );
	    pk = NULL;
	}
	m_free(def_rec); def_rec = NULL;
    }
    else {
	any_recipients = 0;
	for(; remusr; remusr = remusr->next ) {
	    if( (remusr->flags & 1) )
		continue; /* encrypt-to keys are already handled */

	    pk = m_alloc_clear( sizeof *pk );
	    pk->req_usage = use;
	    if( (rc = get_pubkey_byname( pk, remusr->d, NULL, NULL )) ) {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
                write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                              remusr->d, strlen (remusr->d),
                                              -1);
	    }
	    else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, use )) ) {
		int trustlevel;

		trustlevel = get_validity (pk, pk->namehash);
		if( (trustlevel & TRUST_FLAG_DISABLED) ) {
		    free_public_key(pk); pk = NULL;
		    log_info(_("%s: skipped: public key is disabled\n"),
								    remusr->d);
                    write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                                  remusr->d,
                                                  strlen (remusr->d),
                                                  -1);
		}
		else if( do_we_trust_pre( pk, trustlevel ) ) {
		    /* note: do_we_trust may have changed the trustlevel */

		    /* We have at least one valid recipient. It doesn't matters
		     * if this recipient is already present. */
		    any_recipients = 1;

		    /* Skip the actual key if the key is already present
		     * in the list */
		    if (key_present_in_pk_list(pk_list, pk) == 0) {
			free_public_key(pk); pk = NULL;
			log_info(_("%s: skipped: public key already present\n"),
								    remusr->d);
		    }
		    else {
			PK_LIST r;
			r = m_alloc( sizeof *r );
			r->pk = pk; pk = NULL;
			r->next = pk_list;
			r->mark = 0;
			pk_list = r;
		    }
		}
		else { /* we don't trust this pk */
		    free_public_key( pk ); pk = NULL;
                    write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                                  remusr->d,
                                                  strlen (remusr->d),
                                                  -1);
		}
	    }
	    else {
		free_public_key( pk ); pk = NULL;
                write_status_text_and_buffer (STATUS_INV_RECP, "0 ",
                                              remusr->d,
                                              strlen (remusr->d),
                                              -1);
		log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
	    }
	}
    }

    if( !rc && !any_recipients ) {
	log_error(_("no valid addressees\n"));
        write_status_text (STATUS_NO_RECP, "0");
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_pk_list( pk_list );
    else
	*ret_pk_list = pk_list;
    return rc;
}


/* In pgp6 mode, disallow all ciphers except IDEA (1), 3DES (2), and
   CAST5 (3), all hashes except MD5 (1), SHA1 (2), and RIPEMD160 (3),
   and all compressions except none (0) and ZIP (1).  pgp7 mode
   expands the cipher list to include AES128 (7), AES192 (8), AES256
   (9), and TWOFISH (10).  For a true PGP key all of this is unneeded
   as they are the only items present in the preferences subpacket,
   but checking here covers the weird case of encrypting to a key that
   had preferences from a different implementation which was then used
   with PGP.  I am not completely comfortable with this as the right
   thing to do, as it slightly alters the list of what the user is
   supposedly requesting.  It is not against the RFC however, as the
   preference chosen will never be one that the user didn't specify
   somewhere ("The implementation may use any mechanism to pick an
   algorithm in the intersection"), and PGP has no mechanism to fix
   such a broken preference list, so I'm including it. -dms */

static int
algo_available( int preftype, int algo )
{
    if( preftype == PREFTYPE_SYM ) {
        if( opt.pgp6 && ( algo != 1 && algo != 2 && algo != 3) )
	  return 0;

        if( opt.pgp7 && (algo != 1 && algo != 2 && algo != 3 &&
			 algo != 7 && algo != 8 && algo != 9 && algo != 10) )
	  return 0;

	return algo && !check_cipher_algo( algo );
    }
    else if( preftype == PREFTYPE_HASH ) {
        if( (opt.pgp6 || opt.pgp7 ) && ( algo != 1 && algo != 2 && algo != 3) )
	  return 0;

	return algo && !check_digest_algo( algo );
    }
    else if( preftype == PREFTYPE_ZIP ) {
        if ( ( opt.pgp6 || opt.pgp7 ) && ( algo !=0 && algo != 1) )
	  return 0;

	return !algo || algo == 1 || algo == 2;
    }
    else
	return 0;
}



/****************
 * Return -1 if we could not find an algorithm.
 */
int
select_algo_from_prefs( PK_LIST pk_list, int preftype )
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
	  if( pkr->pk->version < 4 &&
	      pkr->pk->selfsigversion < 4 &&
	      opt.pgp2 )
	    mask[0] |= (1<<1); /* IDEA is implicitly there for v3 keys
				  with v3 selfsigs (rfc2440:12.1) if
				  --pgp2 mode is on.  This doesn't
				  mean it's actually available, of
				  course. */
	  else
	    mask[0] |= (1<<2); /* 3DES is implicitly there for everyone else */
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

    /* If we have personal prefs set, use them instead of the last key */
    if(opt.personal_prefs)
      prefs=opt.personal_prefs;

    if( prefs ) {
	for(j=0; prefs[j].type; j++ ) {
	    if( prefs[j].type == preftype ) {
                if( (bits[prefs[j].value/32] & (1<<(prefs[j].value%32))) ) {
		    if( algo_available( preftype, prefs[j].value ) ) {
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
		if( algo_available( preftype, j ) ) {
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
	    i = 1;  /* yep; we can use compression algo 1 */
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
            mdc = pkr->pk->user_id->mdc_feature;
        else
            mdc = pkr->pk->mdc_feature;
        if (!mdc)
            return 0; /* at least on recipeint does not support it */
    }
    return 1; /* can be used */
}
