/* pkclist.c
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
#include "ttyio.h"
#include "status.h"
#include "i18n.h"

/****************
 * Returns true if an ownertrust has changed.
 */
static int
query_ownertrust( ulong lid )
{
    char *p;
    int rc;
    size_t n;
    u32 keyid[2];
    PKT_public_key *pk ;
    int changed=0;

    rc = keyid_from_lid( lid, keyid );
    if( rc ) {
	log_error("ooops: can't get keyid for lid %lu\n", lid);
	return 0;
    }

    pk = m_alloc_clear( sizeof *pk );
    rc = get_pubkey( pk, keyid );
    if( rc ) {
	log_error("key %08lX: public key not found: %s\n",
				(ulong)keyid[1], g10_errstr(rc) );
	return 0;
    }

    tty_printf(_("No owner trust defined for %lu:\n"
	       "%4u%c/%08lX %s \""), lid,
	      nbits_from_pk( pk ), pubkey_letter( pk->pubkey_algo ),
	      (ulong)keyid[1], datestr_from_pk( pk ) );
    p = get_user_id( keyid, &n );
    tty_print_string( p, n ),
    m_free(p);
    tty_printf(_("\"\n\n"
"Please decide how far you trust this user to correctly\n"
"verify other users' keys (by looking at passports,\n"
"checking fingerprints from different sources...)?\n\n"
" 1 = Don't know\n"
" 2 = I do NOT trust\n"
" 3 = I trust marginally\n"
" 4 = I trust fully\n"
" s = please show me more information\n\n") );

    for(;;) {
	p = tty_get(_("Your decision? "));
	trim_spaces(p);
	tty_kill_prompt();
	if( *p && p[1] )
	    ;
	else if( *p == '?' ) {
	    tty_printf(_(
"It's up to you to assign a value here; this value will never be exported\n"
"to any 3rd party.  We need it to implement the web-of-trust; it has nothing\n"
"to do with the (implicitly created) web-of-certificates.\n"));
	}
	else if( !p[1] && (*p >= '1' && *p <= '4') ) {
	    unsigned trust;
	    switch( *p ) {
	      case '1': trust = TRUST_UNDEFINED; break;
	      case '2': trust = TRUST_NEVER    ; break;
	      case '3': trust = TRUST_MARGINAL ; break;
	      case '4': trust = TRUST_FULLY    ; break;
	      default: BUG();
	    }
	    if( !update_ownertrust( lid, trust ) )
		changed++;
	    break;
	}
	else if( *p == 's' || *p == 'S' ) {
	    tty_printf(_("You will see a list of signators etc. here\n"));
	}
	m_free(p); p = NULL;
    }
    m_free(p);
    m_free(pk);
    return changed;
}


/****************
 * Try to add some more owner trusts (interactive)
 * Returns: -1 if no ownertrust were added.
 */
static int
add_ownertrust( PKT_public_key *pk )
{
    int rc;
    void *context = NULL;
    ulong lid;
    unsigned trust;
    int any=0;

    tty_printf(
_("Could not find a valid trust path to the key.  Let's see whether we\n"
  "can assign some missing owner trust values.\n\n"));

    rc = query_trust_record( pk );
    if( rc ) {
	log_error("Ooops: not in trustdb\n");
	return -1;
    }

    lid = pk->local_id;
    while( !(rc=enum_trust_web( &context, &lid )) ) {
	rc = get_ownertrust( lid, &trust );
	if( rc )
	    log_fatal("Ooops: couldn't get owner trust for %lu\n", lid);
	if( trust == TRUST_UNDEFINED || trust == TRUST_EXPIRED ||
	    trust == TRUST_UNKNOWN ) {
	    if( query_ownertrust( lid ) )
		any=1;
	}
    }
    if( rc == -1 )
	rc = 0;
    enum_trust_web( &context, NULL ); /* close */

    if( !any )
	tty_printf(_("No owner trust values changed.\n\n") );

    return rc? rc : any? 0:-1;
}

/****************
 * Check whether we can trust this pk which has a trustlevel of TRUSTLEVEL
 * Returns: true if we trust.
 */
static int
do_we_trust( PKT_public_key *pk, int trustlevel )
{
    int rc;

    if( (trustlevel & TRUST_FLAG_REVOKED) ) {
	char *answer;
	int yes;

	log_info("key has been revoked!\n");
	if( opt.batch )
	    return 0;

	answer = tty_get("Use this key anyway? ");
	tty_kill_prompt();
	yes = answer_is_yes(answer);
	m_free(answer);
	if( !yes )
	    return 0;
    }


    switch( (trustlevel & TRUST_MASK) ) {
      case TRUST_UNKNOWN: /* No pubkey in trustDB: Insert and check again */
	rc = insert_trust_record( pk );
	if( rc ) {
	    log_error("failed to insert it into the trustdb: %s\n",
						      g10_errstr(rc) );
	    return 0; /* no */
	}
	rc = check_trust( pk, &trustlevel );
	if( rc )
	    log_fatal("trust check after insert failed: %s\n",
						      g10_errstr(rc) );
	if( trustlevel == TRUST_UNKNOWN || trustlevel == TRUST_EXPIRED )
	    BUG();
	return do_we_trust( pk, trustlevel );

      case TRUST_EXPIRED:
	log_info("key has expired\n");
	return 0; /* no */

      case TRUST_UNDEFINED:
	if( opt.batch || opt.answer_no )
	    log_info("no info to calculate a trust probability\n");
	else {
	    rc = add_ownertrust( pk );
	    if( !rc ) {
		rc = check_trust( pk, &trustlevel );
		if( rc )
		    log_fatal("trust check after add_ownertrust failed: %s\n",
							      g10_errstr(rc) );
		/* fixme: this is recursive; we should unroll it */
		return do_we_trust( pk, trustlevel );
	    }
	}
	return 0;

      case TRUST_NEVER:
	log_info("We do NOT trust this key\n");
	return 0; /* no */

      case TRUST_MARGINAL:
	log_info("I'm not sure whether this key really belongs to the owner\n"
		 "but I proceed anyway\n");
	return 1; /* yes */

      case TRUST_FULLY:
	if( opt.verbose )
	    log_info("This key probably belongs to the owner\n");
	return 1; /* yes */

      case TRUST_ULTIMATE:
	if( opt.verbose )
	    log_info("This key belongs to us (we have the secret key)\n");
	return 1; /* yes */

      default: BUG();
    }


    /* Eventuell fragen falls der trustlevel nicht ausreichend ist */


    return 1; /* yes */
}


/****************
 * wrapper around do_we_trust, so we can ask whether to use the
 * key anyway.
 */
static int
do_we_trust_pre( PKT_public_key *pk, int trustlevel )
{
    int rc = do_we_trust( pk, trustlevel );

    if( !opt.batch && !rc ) {
	char *answer;

	tty_printf(_(
"It is NOT certain that the key belongs to its owner.\n"
"If you *really* know what you are doing, you may answer\n"
"the next question with yes\n\n") );

	answer = tty_get("Use this key anyway? ");
	tty_kill_prompt();
	if( answer_is_yes(answer) )
	    rc = 1;
	m_free(answer);
    }
    else if( opt.always_trust && !rc ) {
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
    int trustlevel;
    int dont_try = 0;
    int rc=0;

    rc = get_pubkey( pk, sig->keyid );
    if( rc ) { /* this should not happen */
	log_error("Ooops; the key vanished  - can't check the trust\n");
	rc = G10ERR_NO_PUBKEY;
	goto leave;
    }

  retry:
    rc = check_trust( pk, &trustlevel );
    if( rc ) {
	log_error("check trust failed: %s\n", g10_errstr(rc));
	goto leave;
    }

    if( (trustlevel & TRUST_FLAG_REVOKED) ) {
	write_status( STATUS_KEYREVOKED );
	log_info(_("WARNING: This key has been revoked by its owner!\n"));
	log_info(_("         This could mean that the signature is forgery.\n"));
    }


    switch( (trustlevel & TRUST_MASK) ) {
      case TRUST_UNKNOWN: /* No pubkey in trustDB: Insert and check again */
	rc = insert_trust_record( pk );
	if( rc ) {
	    log_error("failed to insert it into the trustdb: %s\n",
						      g10_errstr(rc) );
	    goto leave;
	}
	rc = check_trust( pk, &trustlevel );
	if( rc )
	    log_fatal("trust check after insert failed: %s\n",
						      g10_errstr(rc) );
	if( trustlevel == TRUST_UNKNOWN || trustlevel == TRUST_EXPIRED )
	    BUG();
	goto retry;

      case TRUST_EXPIRED:
	log_info(_("Note: This key has expired!\n"));
	break;

      case TRUST_UNDEFINED:
	if( dont_try || opt.batch || opt.answer_no ) {
	    write_status( STATUS_TRUST_UNDEFINED );
	    log_info(_(
	    "WARNING: This key is not certified with a trusted signature!\n"));
	    log_info(_(
	    "         There is no indication that the "
				    "signature belongs to the owner.\n" ));
	}
	else {
	    rc = add_ownertrust( pk );
	    if( rc ) {
		dont_try = 1;
		rc = 0;
	    }
	    goto retry;
	}
	break;

      case TRUST_NEVER:
	write_status( STATUS_TRUST_NEVER );
	log_info(_("WARNING: We do NOT trust this key!\n"));
	log_info(_("         The signature is probably a FORGERY.\n"));
	rc = G10ERR_BAD_SIGN;
	break;

      case TRUST_MARGINAL:
	write_status( STATUS_TRUST_MARGINAL );
	log_info(_(
	 "WARNING: This key is not certified with sufficiently trusted signatures!\n"
		));
	log_info(_(
	 "         It is not certain that the signature belongs to the owner.\n"
		 ));
	break;

      case TRUST_FULLY:
	write_status( STATUS_TRUST_FULLY );
	break;

      case TRUST_ULTIMATE:
	write_status( STATUS_TRUST_ULTIMATE );
	break;

      default: BUG();
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

int
build_pk_list( STRLIST remusr, PK_LIST *ret_pk_list, unsigned usage )
{
    PK_LIST pk_list = NULL;
    PKT_public_key *pk=NULL;
    int rc=0;

    if( !remusr && !opt.batch ) { /* ask */
	char *answer=NULL;

	tty_printf(_(
		"You did not specify a user ID. (you may use \"-r\")\n\n"));
	for(;;) {
	    rc = 0;
	    m_free(answer);
	    answer = tty_get(_("Enter the user ID: "));
	    trim_spaces(answer);
	    tty_kill_prompt();
	    if( !*answer )
		break;
	    if( pk )
		free_public_key( pk );
	    pk = m_alloc_clear( sizeof *pk );
	    pk->pubkey_usage = usage;
	    rc = get_pubkey_byname( pk, answer );
	    if( rc )
		tty_printf(_("No such user ID.\n"));
	    else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, usage)) ) {
		int trustlevel;

		rc = check_trust( pk, &trustlevel );
		if( rc ) {
		    log_error("error checking pk of '%s': %s\n",
						      answer, g10_errstr(rc) );
		}
		else if( do_we_trust_pre( pk, trustlevel ) ) {
		    PK_LIST r;

		    r = m_alloc( sizeof *r );
		    r->pk = pk; pk = NULL;
		    r->next = pk_list;
		    r->mark = 0;
		    pk_list = r;
		    break;
		}
	    }
	}
	m_free(answer);
	if( pk ) {
	    free_public_key( pk );
	    pk = NULL;
	}
    }
    else {
	for(; remusr; remusr = remusr->next ) {

	    pk = m_alloc_clear( sizeof *pk );
	    pk->pubkey_usage = usage;
	    if( (rc = get_pubkey_byname( pk, remusr->d )) ) {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
	    }
	    else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, usage )) ) {
		int trustlevel;

		rc = check_trust( pk, &trustlevel );
		if( rc ) {
		    free_public_key( pk ); pk = NULL;
		    log_error(_("%s: error checking key: %s\n"),
						      remusr->d, g10_errstr(rc) );
		}
		else if( do_we_trust_pre( pk, trustlevel ) ) {
		    /* note: do_we_trust may have changed the trustlevel */
		    PK_LIST r;

		    r = m_alloc( sizeof *r );
		    r->pk = pk; pk = NULL;
		    r->next = pk_list;
		    r->mark = 0;
		    pk_list = r;
		}
		else { /* we don't trust this pk */
		    free_public_key( pk ); pk = NULL;
		}
	    }
	    else {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
	    }
	}
    }


    if( !rc && !pk_list ) {
	log_error(_("no valid addressees\n"));
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_pk_list( pk_list );
    else
	*ret_pk_list = pk_list;
    return rc;
}


