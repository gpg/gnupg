/* pkclist.c
 *	Copyright (c) 1997 by Werner Koch (dd9jn)
 *
 * This file is part of G10.
 *
 * G10 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * G10 is distributed in the hope that it will be useful,
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
#include "i18n.h"

/****************
 * Returns true if a ownertrust has changed.
 */
static int
query_ownertrust( ulong lid )
{
    char *p;
    int rc;
    size_t n;
    u32 keyid[2];
    PKT_public_cert *pkc ;
    int changed=0;

    rc = keyid_from_trustdb( lid, keyid );
    if( rc ) {
	log_error("ooops: can't get keyid for lid %lu\n", lid);
	return 0;
    }

    pkc = m_alloc_clear( sizeof *pkc );
    rc = get_pubkey( pkc, keyid );
    if( rc ) {
	log_error("keyid %08lX: pubkey not found: %s\n",
				(ulong)keyid[1], g10_errstr(rc) );
	return 0;
    }

    tty_printf(_("No ownertrust defined for %lu:\n"
	       "%4u%c/%08lX %s \""), lid,
	      nbits_from_pkc( pkc ), pubkey_letter( pkc->pubkey_algo ),
	      (ulong)keyid[1], datestr_from_pkc( pkc ) );
    p = get_user_id( keyid, &n );
    tty_print_string( p, n ),
    m_free(p);
    tty_printf(_("\"\n\n"
"Please decide in how far do you trust this user to\n"
"correctly sign other users keys (looking at his passport,\n"
"checking the fingerprints from different sources ...)?\n\n"
" 1 = Don't know\n"
" 2 = I do NOT trust\n"
" 3 = I trust marginally\n"
" 4 = I trust fully\n"
" s = please show me more informations\n\n") );

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
    m_free(pkc);
    return changed;
}


/****************
 * Try to add some more owner trusts (interactive)
 * Returns: -1 if no ownertrust were added.
 */
static int
add_ownertrust( PKT_public_cert *pkc )
{
    int rc;
    void *context = NULL;
    ulong lid;
    unsigned trust;
    int any=0;

    tty_printf(
_("Could not find a valid trust path to the key.  Lets see, wether we\n"
  "can assign some missing owner trust values.\n\n"));

    rc = query_trust_record( pkc );
    if( rc ) {
	log_error("Ooops: not in trustdb\n");
	return -1;
    }

    lid = pkc->local_id;
    while( !(rc=enum_trust_web( &context, &lid )) ) {
	rc = get_ownertrust( lid, &trust );
	if( rc )
	    log_fatal("Ooops: couldn't get ownertrust for %lu\n", lid);
	if( trust == TRUST_UNDEFINED || trust == TRUST_EXPIRED ||
	    trust == TRUST_UNKNOWN ) {
	    if( query_ownertrust( lid ) )
		any=1;
	}
    }
    if( rc == -1 )
	rc = 0;
    enum_trust_web( &context, NULL ); /* close */


    return rc? rc : any? 0:-1;
}


/****************
 * Check wether we can trust this pkc which has a trustlevel of TRUSTLEVEL
 * Returns: true if we trust.
 */
static int
do_we_trust( PKT_public_cert *pkc, int trustlevel )
{
    int rc;

    switch( trustlevel ) {
      case TRUST_UNKNOWN: /* No pubkey in trustDB: Insert and check again */
	rc = insert_trust_record( pkc );
	if( rc ) {
	    log_error("failed to insert it into the trustdb: %s\n",
						      g10_errstr(rc) );
	    return 0; /* no */
	}
	rc = check_trust( pkc, &trustlevel );
	if( rc )
	    log_fatal("trust check after insert failed: %s\n",
						      g10_errstr(rc) );
	if( trustlevel == TRUST_UNKNOWN || trustlevel == TRUST_EXPIRED )
	    BUG();
	return do_we_trust( pkc, trustlevel );

      case TRUST_EXPIRED:
	log_error("trust has expired: NOT yet implemented\n");
	return 0; /* no */

      case TRUST_UNDEFINED:
	if( opt.batch || opt.answer_no )
	    log_info("no info to calculate a trust probability\n");
	else {
	    rc = add_ownertrust( pkc );
	    if( !rc ) {
		rc = check_trust( pkc, &trustlevel );
		if( rc )
		    log_fatal("trust check after add_ownertrust failed: %s\n",
							      g10_errstr(rc) );
		/* FIXME: this is recursive; we better should unroll it */
		return do_we_trust( pkc, trustlevel );
	    }
	}
	return 0; /* no */

      case TRUST_NEVER:
	log_info("We do NOT trust this key\n");
	return 0; /* no */

      case TRUST_MARGINAL:
	log_info("I'm not sure wether this keys really belongs to the owner\n"
		 "but I proceed anyway\n");
	return 1; /* yes */

      case TRUST_FULLY:
	log_info("This key probably belongs to the owner\n");
	return 1; /* yes */

      case TRUST_ULTIMATE:
	log_info("Our own keys is always good.\n");
	return 1; /* yes */

      default: BUG();
    }


    /* Eventuell fragen falls der trustlevel nicht ausreichend ist */


    return 1; /* yes */
}



void
release_pkc_list( PKC_LIST pkc_list )
{
    PKC_LIST pkc_rover;

    for( ; pkc_list; pkc_list = pkc_rover ) {
	pkc_rover = pkc_list->next;
	free_public_cert( pkc_list->pkc );
	m_free( pkc_list );
    }
}

int
build_pkc_list( STRLIST remusr, PKC_LIST *ret_pkc_list )
{
    PKC_LIST pkc_list = NULL;
    int rc;

    if( !remusr ) { /* ask!!! */
	log_bug("ask for public key nyi\n");
    }
    else {
	for(; remusr; remusr = remusr->next ) {
	    PKT_public_cert *pkc;

	    pkc = m_alloc_clear( sizeof *pkc );
	    if( (rc = get_pubkey_byname( pkc, remusr->d )) ) {
		free_public_cert( pkc ); pkc = NULL;
		log_error("skipped '%s': %s\n", remusr->d, g10_errstr(rc) );
	    }
	    else if( !(rc=check_pubkey_algo(pkc->pubkey_algo)) ) {
		int trustlevel;

		rc = check_trust( pkc, &trustlevel );
		if( rc ) {
		    free_public_cert( pkc ); pkc = NULL;
		    log_error("error checking pkc of '%s': %s\n",
						      remusr->d, g10_errstr(rc) );
		}
		else if( do_we_trust( pkc, trustlevel ) ) {
		    /* note: do_we_trust may have changed the trustlevel */
		    PKC_LIST r;

		    r = m_alloc( sizeof *r );
		    r->pkc = pkc; pkc = NULL;
		    r->next = pkc_list;
		    r->mark = 0;
		    pkc_list = r;
		}
		else { /* we don't trust this pkc */
		    free_public_cert( pkc ); pkc = NULL;
		}
	    }
	    else {
		free_public_cert( pkc ); pkc = NULL;
		log_error("skipped '%s': %s\n", remusr->d, g10_errstr(rc) );
	    }
	}
    }


    if( !rc && !pkc_list ) {
	log_error("no valid addressees\n");
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_pkc_list( pkc_list );
    else
	*ret_pkc_list = pkc_list;
    return rc;
}


