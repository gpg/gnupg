/* pkclist.c
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

/* fixme: we have nearly the same code in keyedit.c */
static void
print_fpr( PKT_public_key *pk )
{
    byte array[MAX_FINGERPRINT_LEN], *p;
    size_t i, n;

    fingerprint_from_pk( pk, array, &n );
    p = array;
    /* Translators: this shoud fit into 24 bytes to that the fingerprint
     * data is properly aligned with the user ID */
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

static void
fpr_info( PKT_public_key *pk )
{
    byte array[MAX_FINGERPRINT_LEN], *p;
    size_t i, n;
    FILE *fp = log_stream();

    fingerprint_from_pk( pk, array, &n );
    p = array;
    log_info(_("Fingerprint:"));
    if( n == 20 ) {
	for(i=0; i < n ; i++, i++, p += 2 ) {
	    if( i == 10 )
		putc(' ', fp);
	    fprintf(fp, " %02X%02X", *p, p[1] );
	}
    }
    else {
	for(i=0; i < n ; i++, p++ ) {
	    if( i && !(i%8) )
		putc(' ', fp);
	    fprintf(fp, " %02X", *p );
	}
    }
    putc('\n', fp );
}


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

    while( (p = enum_sig_subpkt( sig->hashed_data, SIGSUBPKT_REVOC_REASON,
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

	log_info( _("Reason for revocation: ") );
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
		log_info( _("Revocation comment: ") );
		print_string( log_stream(), p, nn, 0 );
		putc( '\n', log_stream() );
		p += nn; n -= nn;
	    }
	} while( pp );
    }
}


static void
show_revocation_reason( PKT_public_key *pk )
{
    /* Hmmm, this is not so easy becuase we have to duplicate the code
     * used in the trustbd to calculate the keyflags.  We need to find
     * a clean way to check revocation certificates on keys and signatures.
     * And there should be no duplicate code.  Because we enter this function
     * only when the trustdb toldus, taht we have a revoked key, we could
     * simplylook for a revocation cert and display this one, when there is
     * only one. Let's try to do this until we have a better solution.
     */
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
	if( ( node->pkt->pkttype == PKT_PUBLIC_KEY
	      || node->pkt->pkttype == PKT_PUBLIC_SUBKEY )
	    && !cmp_public_keys( node->pkt->pkt.public_key, pk ) )
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
	}
    }

    release_kbnode( keyblock );
}


static void
show_paths( ulong lid, int only_first )
{
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
    tty_printf("\n");
}




/****************
 * Returns true if an ownertrust has changed.
 */
static int
do_edit_ownertrust( ulong lid, int mode, unsigned *new_trust, int defer_help )
{
    char *p;
    int rc;
    size_t n;
    u32 keyid[2];
    PKT_public_key *pk ;
    int changed=0;
    int quit=0;
    int show=0;
    int did_help=defer_help;

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


    for(;;) {
	/* a string with valid answers */
	const char *ans = _("sSmMqQ");

	if( !did_help ) {
	    if( !mode ) {
		tty_printf(_("No trust value assigned to %lu:\n"
			   "%4u%c/%08lX %s \""), lid,
			  nbits_from_pk( pk ), pubkey_letter( pk->pubkey_algo ),
			  (ulong)keyid[1], datestr_from_pk( pk ) );
		p = get_user_id( keyid, &n );
		tty_print_utf8_string( p, n ),
		m_free(p);
		tty_printf("\"\n");
		print_fpr( pk );
		tty_printf("\n");
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
	    else
		tty_printf(_(" q = quit\n"));
	    tty_printf("\n");
	    did_help = 1;
	}
	if( strlen(ans) != 6 )
	    BUG();
	p = cpr_get("edit_ownertrust.value",_("Your decision? "));
	trim_spaces(p);
	cpr_kill_prompt();
	if( !*p )
	    did_help = 0;
	else if( *p && p[1] )
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
            *new_trust = trust;
            changed = 1;
            break;
	}
	else if( *p == ans[0] || *p == ans[1] ) {
	    tty_printf(_(
		"Certificates leading to an ultimately trusted key:\n"));
	    show = 1;
	    break;
	}
	else if( mode && (*p == ans[2] || *p == ans[3] || *p == CONTROL_D ) ) {
	    break ; /* back to the menu */
	}
	else if( !mode && (*p == ans[4] || *p == ans[5] ) ) {
	    quit = 1;
	    break ; /* back to the menu */
	}
	m_free(p); p = NULL;
    }
    m_free(p);
    m_free(pk);
    return show? -2: quit? -1 : changed;
}


int
edit_ownertrust( ulong lid, int mode )
{
    unsigned int trust;
    int no_help = 0;

    for(;;) {
	switch( do_edit_ownertrust( lid, mode, &trust, no_help ) ) {
	  case -1:
	    return 0;
	  case -2:
	    show_paths( lid, 1	);
	    no_help = 1;
	    break;
	  case 1:
	    trust &= ~TRUST_FLAG_DISABLED;
	    trust |= get_ownertrust( lid ) & TRUST_FLAG_DISABLED;
	    if( !update_ownertrust( lid, trust ) )
		return 1;
	    return 0;
	  default:
	    return 0;
	}
    }
}

static int
add_ownertrust_cb( ulong lid )
{
    unsigned trust;
    int rc = do_edit_ownertrust( lid, 0, &trust, 0 );

    if( rc == 1 )
	return trust & TRUST_MASK;
    return rc > 0? 0 : rc;
}

/****************
 * Try to add some more owner trusts (interactive)
 * This function presents all the signator in a certificate
 * chain who have no ownertrust value assigned.
 * Returns: -1 if no ownertrust were added.
 */
static int
add_ownertrust( PKT_public_key *pk, int *quit, unsigned *trustlevel )
{
    int rc;
    unsigned flags = 0;

    *quit = 0;
    *trustlevel = 0;
    tty_printf(
_("Could not find a valid trust path to the key.  Let's see whether we\n"
  "can assign some missing owner trust values.\n\n"));

    rc = check_trust( pk, trustlevel, NULL, add_ownertrust_cb, &flags );

    if( !(flags & 1) )
	tty_printf(_("No path leading to one of our keys found.\n\n") );
    else if( !(flags & 2) )
	tty_printf(_("No certificates with undefined trust found.\n\n") );
    else if( !(flags & 4) )
	tty_printf(_("No trust values changed.\n\n") );

    return (flags & 4)? 0:-1;
}

/****************
 * Check whether we can trust this pk which has a trustlevel of TRUSTLEVEL
 * Returns: true if we trust. Might change the trustlevel
 */
static int
do_we_trust( PKT_public_key *pk, int *trustlevel )
{
    int rc;
    int did_add = 0;
    int trustmask = 0;

  retry:
    if( (*trustlevel & TRUST_FLAG_REVOKED) ) {
	log_info(_("key %08lX: key has been revoked!\n"),
					(ulong)keyid_from_pk( pk, NULL) );
	show_revocation_reason( pk );
	if( opt.batch )
	    return 0;

	if( !cpr_get_answer_is_yes("revoked_key.override",
				    _("Use this key anyway? ")) )
	    return 0;
	trustmask |= TRUST_FLAG_REVOKED;
    }
    else if( (*trustlevel & TRUST_FLAG_SUB_REVOKED) ) {
	log_info(_("key %08lX: subkey has been revoked!\n"),
					(ulong)keyid_from_pk( pk, NULL) );
	show_revocation_reason( pk );
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
	/* The problem with this, is that EXPIRE can't be checked as
	 * this needs to insert a new key into the trustdb first and
	 * we don't want that - IS this still true? */
	return 1;
    }


    switch( (*trustlevel & TRUST_MASK) ) {
      case TRUST_UNKNOWN: /* No pubkey in trustDB: Insert and check again */
	rc = insert_trust_record_by_pk( pk );
	if( rc ) {
	    log_error("failed to insert it into the trustdb: %s\n",
						      g10_errstr(rc) );
	    return 0; /* no */
	}
	rc = check_trust( pk, trustlevel, NULL, NULL, NULL );
	*trustlevel &= ~trustmask;
	if( rc )
	    log_fatal("trust check after insert failed: %s\n",
						      g10_errstr(rc) );
	if( *trustlevel == TRUST_UNKNOWN || *trustlevel == TRUST_EXPIRED ) {
	    log_debug("do_we_trust: oops at %d\n", __LINE__ );
	    return 0;
	}
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
	    int quit;

	    rc = add_ownertrust( pk, &quit, trustlevel );
	    *trustlevel &= ~trustmask;
	    if( !rc && !did_add && !quit ) {
		did_add = 1;
		goto retry;
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

    return 1; /* yes */
}



/****************
 * wrapper around do_we_trust, so we can ask whether to use the
 * key anyway.
 */
static int
do_we_trust_pre( PKT_public_key *pk, int trustlevel )
{
    int rc;

    rc = do_we_trust( pk, &trustlevel );

    if( (trustlevel & TRUST_FLAG_REVOKED) && !rc )
	return 0;
    if( (trustlevel & TRUST_FLAG_SUB_REVOKED) && !rc )
	return 0;
    else if( !opt.batch && !rc ) {
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
	print_fpr( pk );
	tty_printf("\n");

	tty_printf(_(
"It is NOT certain that the key belongs to its owner.\n"
"If you *really* know what you are doing, you may answer\n"
"the next question with yes\n\n") );

	if( cpr_get_answer_is_yes("untrusted_key.override",
				  _("Use this key anyway? "))  )
	    rc = 1;

	/* Hmmm: Should we set a flag to tell the user the user about
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
    int trustlevel;
    int did_add = 0;
    int rc=0;


    if( opt.always_trust ) {
	if( !opt.quiet )
	    log_info(_("WARNING: Using untrusted key!\n"));
	return 0;
    }


    rc = get_pubkey( pk, sig->keyid );
    if( rc ) { /* this should not happen */
	log_error("Ooops; the key vanished  - can't check the trust\n");
	rc = G10ERR_NO_PUBKEY;
	goto leave;
    }

    rc = check_trust( pk, &trustlevel, NULL, NULL, NULL );
    if( rc ) {
	log_error("check trust failed: %s\n", g10_errstr(rc));
	goto leave;
    }

  retry:
    if( (trustlevel & TRUST_FLAG_REVOKED) ) {
	write_status( STATUS_KEYREVOKED );
	log_info(_("WARNING: This key has been revoked by its owner!\n"));
	log_info(_("         This could mean that the signature is forgery.\n"));
	show_revocation_reason( pk );
    }
    else if( (trustlevel & TRUST_FLAG_SUB_REVOKED) ) {
	write_status( STATUS_KEYREVOKED );
	log_info(_("WARNING: This subkey has been revoked by its owner!\n"));
	show_revocation_reason( pk );
    }


    switch( (trustlevel & TRUST_MASK) ) {
      case TRUST_UNKNOWN: /* No pubkey in trustDB: Insert and check again */
	rc = insert_trust_record_by_pk( pk );
	if( rc ) {
	    log_error("failed to insert it into the trustdb: %s\n",
						      g10_errstr(rc) );
	    goto leave;
	}
	rc = check_trust( pk, &trustlevel, NULL, NULL, NULL );
	if( rc )
	    log_fatal("trust check after insert failed: %s\n",
						      g10_errstr(rc) );
	if( trustlevel == TRUST_UNKNOWN || trustlevel == TRUST_EXPIRED )
	    BUG();
	goto retry;

      case TRUST_EXPIRED:
	log_info(_("Note: This key has expired!\n"));
	fpr_info( pk );
	break;

      case TRUST_UNDEFINED:
	if( did_add || opt.batch || opt.answer_no ) {
	    write_status( STATUS_TRUST_UNDEFINED );
	    log_info(_(
	    "WARNING: This key is not certified with a trusted signature!\n"));
	    log_info(_(
	    "         There is no indication that the "
				    "signature belongs to the owner.\n" ));
	    fpr_info( pk );
	}
	else {
	    int quit;
	    rc = add_ownertrust( pk, &quit, &trustlevel );
	    if( rc || quit ) {
		did_add = 1;
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
	fpr_info( pk );
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
	    if( (rc = get_pubkey_byname( NULL, pk, rov->d, NULL )) ) {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), rov->d, g10_errstr(rc) );
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
	    }
	}
    }

    if( !any_recipients && !opt.batch ) { /* ask */
	char *answer=NULL;
	int have_def_rec;

	def_rec = default_recipient();
	have_def_rec = !!def_rec;
	if( !have_def_rec )
	    tty_printf(_(
		"You did not specify a user ID. (you may use \"-r\")\n\n"));
	for(;;) {
	    rc = 0;
	    m_free(answer);
	    if( have_def_rec ) {
		answer = def_rec;
		def_rec = NULL;
	    }
	    else {
		answer = cpr_get_utf8("pklist.user_id.enter",
				       _("Enter the user ID: "));
		trim_spaces(answer);
		cpr_kill_prompt();
	    }
	    if( !*answer )
		break;
	    if( pk )
		free_public_key( pk );
	    pk = m_alloc_clear( sizeof *pk );
	    pk->req_usage = use;
	    rc = get_pubkey_byname( NULL, pk, answer, NULL );
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
		    break;
		}
		else {
		    int trustlevel;

		    rc = check_trust( pk, &trustlevel, pk->namehash,
						       NULL, NULL );
		    if( rc ) {
			log_error("error checking pk of `%s': %s\n",
						     answer, g10_errstr(rc) );
		    }
		    else if( (trustlevel & TRUST_FLAG_DISABLED) ) {
			tty_printf(_("Public key is disabled.\n") );
		    }
		    else if( do_we_trust_pre( pk, trustlevel ) ) {
			/* Skip the actual key if the key is already present
			 * in the list */
			if (key_present_in_pk_list(pk_list, pk) == 0) {
			    free_public_key(pk); pk = NULL;
			    log_info(_("skipped: public key "
				       "already set with --encrypt-to\n") );
			}
			else {
			    PK_LIST r;

			    r = m_alloc( sizeof *r );
			    r->pk = pk; pk = NULL;
			    r->next = pk_list;
			    r->mark = 0;
			    pk_list = r;
			}
			any_recipients = 1;
			break;
		    }
		}
	    }
	    m_free(def_rec); def_rec = NULL;
	    have_def_rec = 0;
	}
	m_free(answer);
	if( pk ) {
	    free_public_key( pk );
	    pk = NULL;
	}
    }
    else if( !any_recipients && (def_rec = default_recipient()) ) {
	pk = m_alloc_clear( sizeof *pk );
	pk->req_usage = use;
	rc = get_pubkey_byname( NULL, pk, def_rec, NULL );
	if( rc )
	    log_error(_("unknown default recipient `%s'\n"), def_rec );
	else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, use)) ) {
	    PK_LIST r = m_alloc( sizeof *r );
	    r->pk = pk; pk = NULL;
	    r->next = pk_list;
	    r->mark = 0;
	    pk_list = r;
	    any_recipients = 1;
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
	    if( (rc = get_pubkey_byname( NULL, pk, remusr->d, NULL )) ) {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
	    }
	    else if( !(rc=check_pubkey_algo2(pk->pubkey_algo, use )) ) {
		int trustlevel;

		rc = check_trust( pk, &trustlevel, pk->namehash, NULL, NULL );
		if( rc ) {
		    free_public_key( pk ); pk = NULL;
		    log_error(_("%s: error checking key: %s\n"),
						      remusr->d, g10_errstr(rc) );
		}
		else if( (trustlevel & TRUST_FLAG_DISABLED) ) {
		    free_public_key(pk); pk = NULL;
		    log_info(_("%s: skipped: public key is disabled\n"),
								    remusr->d);
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
		}
	    }
	    else {
		free_public_key( pk ); pk = NULL;
		log_error(_("%s: skipped: %s\n"), remusr->d, g10_errstr(rc) );
	    }
	}
    }

    if( !rc && !any_recipients ) {
	log_error(_("no valid addressees\n"));
	rc = G10ERR_NO_USER_ID;
    }

    if( rc )
	release_pk_list( pk_list );
    else
	*ret_pk_list = pk_list;
    return rc;
}



static int
algo_available( int preftype, int algo )
{
    if( preftype == PREFTYPE_SYM ) {
	return algo && !check_cipher_algo( algo );
    }
    else if( preftype == PREFTYPE_HASH ) {
	return algo && !check_digest_algo( algo );
    }
    else if( preftype == PREFTYPE_COMPR ) {
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
	if( !pkr->pk->local_id ) { /* try to set the local id */
	    query_trust_info( pkr->pk, NULL );
	    if( !pkr->pk->local_id ) {
		log_debug("select_algo_from_prefs: can't get LID\n");
		continue;
	    }
	}
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
		if( (bits[pref[j+1]/32] & (1<<(pref[j+1]%32))) ) {
		    if( algo_available( preftype, pref[j+1] ) ) {
			any = 1;
			i = pref[j+1];
			break;
		    }
		}
	    }
	}
    }
    if( !pref || !any ) {
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

    m_free(pref);
    return i;
}


