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


#define CONTROL_D ('D' - 'A' + 1)


static void
show_paths( ulong lid, int only_first )
{
    void *context = NULL;
    unsigned otrust, validity;
    int last_level, level;

    last_level = 0;
    while( (level=enum_cert_paths( &context, &lid, &otrust, &validity)) != -1){
	char *p;
	int rc;
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
	p = get_user_id( keyid, &n );
	tty_print_string( p, n ),
	m_free(p);
	tty_printf("\"\n");
	free_public_key( pk );
    }
    enum_cert_paths( &context, NULL, NULL, NULL ); /* release context */
    tty_printf("\n");
}




/****************
 * Returns true if an ownertrust has changed.
 */
int
edit_ownertrust( ulong lid, int mode )
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

    if( !mode ) {
	tty_printf(_("No trust value assigned to %lu:\n"
		   "%4u%c/%08lX %s \""), lid,
		  nbits_from_pk( pk ), pubkey_letter( pk->pubkey_algo ),
		  (ulong)keyid[1], datestr_from_pk( pk ) );
	p = get_user_id( keyid, &n );
	tty_print_string( p, n ),
	m_free(p);
	tty_printf("\"\n\n");
    }
    tty_printf(_(
"Please decide how far you trust this user to correctly\n"
"verify other users' keys (by looking at passports,\n"
"checking fingerprints from different sources...)?\n\n"
" 1 = Don't know\n"
" 2 = I do NOT trust\n"
" 3 = I trust marginally\n"
" 4 = I trust fully\n"
" s = please show me more information\n") );
    if( mode )
	tty_printf(_(" m = back to the main menu\n"));
    tty_printf("\n");

    for(;;) {
	/* a string with valid answers */
	char *ans = _("sSmM");

	if( strlen(ans) != 4 )
	    BUG();
	p = cpr_get("edit_ownertrust.value",_("Your decision? "));
	trim_spaces(p);
	cpr_kill_prompt();
	if( *p && p[1] )
	    ;
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
	else if( *p == ans[0] || *p == ans[1] ) {
	    tty_printf(_(
		"Certificates leading to an ultimately trusted key:\n"));
	    show_paths( lid, 1	);
	}
	else if( mode && (*p == ans[2] || *p == ans[3] || *p == CONTROL_D ) ) {
	    break ; /* back to the menu */
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
    unsigned otrust, validity;
    int any=0, changed=0, any_undefined=0;

    tty_printf(
_("Could not find a valid trust path to the key.  Let's see whether we\n"
  "can assign some missing owner trust values.\n\n"));

    rc = query_trust_record( pk );
    if( rc ) {
	log_error("Ooops: not in trustdb\n");
	return -1;
    }

    lid = pk->local_id;
    while( enum_cert_paths( &context, &lid, &otrust, &validity ) != -1 ) {
	any=1;
	if( otrust == TRUST_UNDEFINED || otrust == TRUST_EXPIRED ||
	    otrust == TRUST_UNKNOWN ) {
	    any_undefined=1;
	    if( edit_ownertrust( lid, 0 ) )
		changed=1;
	}
    }
    enum_cert_paths( &context, NULL, NULL, NULL ); /* release context */

    if( !any )
	tty_printf(_("No path leading to one of our keys found.\n\n") );
    else if( !any_undefined )
	tty_printf(_("No certificates with undefined trust found.\n\n") );
    else if( !changed )
	tty_printf(_("No trust values changed.\n\n") );

    return any? 0:-1;
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
	log_info(_("key %08lX: key has been revoked!\n"),
					(ulong)keyid_from_pk( pk, NULL) );
	if( opt.batch )
	    return 0;

	if( !cpr_get_answer_is_yes("revoked_key.override",
				    _("Use this key anyway? ")) )
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
	log_info(_("%08lX: key has expired\n"),
				    (ulong)keyid_from_pk( pk, NULL) );
	return 0; /* no */

      case TRUST_UNDEFINED:
	if( opt.batch || opt.answer_no )
	    log_info(_("%08lX: no info to calculate a trust probability\n"),
					(ulong)keyid_from_pk( pk, NULL) );
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
	tty_printf(_(
"It is NOT certain that the key belongs to its owner.\n"
"If you *really* know what you are doing, you may answer\n"
"the next question with yes\n\n") );

	if( cpr_get_answer_is_yes("untrusted_key.override",
				  _("Use this key anyway? "))  )
	    rc = 1;
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
	    answer = cpr_get_utf8("pklist.user_id.enter",
				   _("Enter the user ID: "));
	    trim_spaces(answer);
	    cpr_kill_prompt();
	    if( !*answer )
		break;
	    if( pk )
		free_public_key( pk );
	    pk = m_alloc_clear( sizeof *pk );
	    pk->pubkey_usage = usage;
	    rc = get_pubkey_byname( NULL, pk, answer, NULL );
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
	    if( (rc = get_pubkey_byname( NULL, pk, remusr->d, NULL )) ) {
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


/****************
 * Return -1 if we could not find an algorithm.
 */
int
select_algo_from_prefs( PK_LIST pk_list, int preftype )
{
    PK_LIST pkr;
    u32 bits[8];
    byte *pref = NULL;
    size_t npref;
    int i, j;
    int compr_hack=0;
    int any;

    if( !pk_list )
	return -1;

    memset( bits, ~0, 8 * sizeof *bits );
    for( pkr = pk_list; pkr; pkr = pkr->next ) {
	u32 mask[8];

	memset( mask, 0, 8 * sizeof *mask );
	if( !pkr->pk->local_id )
	    BUG(); /* if this occurs, we can use get_ownertrust to set it */
	if( preftype == PREFTYPE_SYM )
	    mask[0] |= (1<<2); /* 3DES is implicitly there */
	m_free(pref);
	pref = get_pref_data( pkr->pk->local_id, pkr->pk->namehash, &npref);
	any = 0;
	if( pref ) {
	   #if 0
	    log_hexdump("raw: ", pref, npref );
	   #endif
	    for(i=0; i+1 < npref; i+=2 ) {
		if( pref[i] == preftype ) {
		    mask[pref[i+1]/32] |= 1 << (pref[i+1]%32);
		    any = 1;
		}
	    }
	}
	if( (!pref || !any) && preftype == PREFTYPE_COMPR ) {
	    mask[0] |= 3; /* asume no_compression and old pgp */
	    compr_hack = 1;
	}

      #if 0
	log_debug("mask=%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n",
	       (ulong)mask[7], (ulong)mask[6], (ulong)mask[5], (ulong)mask[4],
	     (ulong)mask[3], (ulong)mask[2], (ulong)mask[1], (ulong)mask[0]);
      #endif
	for(i=0; i < 8; i++ )
	    bits[i] &= mask[i];
      #if 0
	log_debug("bits=%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n",
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
    if( pref ) {
	for(j=0; j+1 < npref; j+=2 ) {
	    if( pref[j] == preftype ) {
		any = 1;
		if( (bits[pref[j+1]/32] & (1<<(pref[j+1]%32))) ) {
		    /* fixme: check whether this algoritm is available */
		    i = pref[j+1];
		    break;
		}
	    }
	}
    }
    if( !pref || !any ) {
	for(j=0; j < 256; j++ )
	    if( (bits[j/32] & (1<<(j%32))) ) {
		/* fixme: check whether this algoritm is available */
		i = j;
		break;
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

    m_free(pref);
    return i;
}


