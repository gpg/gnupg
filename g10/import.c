/* import.c
 *	Copyright (C) 1998 Free Software Foundation, Inc.
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
#include "main.h"
#include "i18n.h"


static struct {
    ulong no_user_id;
    ulong imported;
    ulong imported_rsa;
    ulong n_uids;
    ulong n_sigs;
    ulong n_subk;
    ulong unchanged;
    ulong n_revoc;
    ulong secret_read;
    ulong secret_imported;
    ulong secret_dups;
} stats;


static int read_block( IOBUF a, compress_filter_context_t *cfx,
			     PACKET **pending_pkt, KBNODE *ret_root );
static int import_one( const char *fname, KBNODE keyblock, int fast );
static int import_secret_one( const char *fname, KBNODE keyblock );
static int import_revoke_cert( const char *fname, KBNODE node );
static int chk_self_sigs( const char *fname, KBNODE keyblock,
			  PKT_public_key *pk, u32 *keyid );
static int delete_inv_parts( const char *fname, KBNODE keyblock, u32 *keyid );
static int merge_blocks( const char *fname, KBNODE keyblock_orig,
			 KBNODE keyblock, u32 *keyid,
			 int *n_uids, int *n_sigs, int *n_subk );
static int append_uid( KBNODE keyblock, KBNODE node, int *n_sigs,
			     const char *fname, u32 *keyid );
static int append_key( KBNODE keyblock, KBNODE node, int *n_sigs,
			     const char *fname, u32 *keyid );
static int merge_sigs( KBNODE dst, KBNODE src, int *n_sigs,
			     const char *fname, u32 *keyid );
static int merge_keysigs( KBNODE dst, KBNODE src, int *n_sigs,
			     const char *fname, u32 *keyid );


/****************
 * Import the public keys from the given filename. Input may be armored.
 * This function rejects all keys which are not validly self signed on at
 * least one userid. Only user ids which are self signed will be imported.
 * Other signatures are not checked.
 *
 * Actually this function does a merge. It works like this:
 *
 *  - get the keyblock
 *  - check self-signatures and remove all userids and their signatures
 *    without/invalid self-signatures.
 *  - reject the keyblock, if we have no valid userid.
 *  - See whether we have this key already in one of our pubrings.
 *    If not, simply add it to the default keyring.
 *  - Compare the key and the self-signatures of the new and the one in
 *    our keyring.  If they are different something weird is going on;
 *    ask what to do.
 *  - See whether we have only non-self-signature on one user id; if not
 *    ask the user what to do.
 *  - compare the signatures: If we already have this signature, check
 *    that they compare okay; if not, issue a warning and ask the user.
 *    (consider looking at the timestamp and use the newest?)
 *  - Simply add the signature.  Can't verify here because we may not have
 *    the signature's public key yet; verification is done when putting it
 *    into the trustdb, which is done automagically as soon as this pubkey
 *    is used.
 *  - Proceed with next signature.
 *
 *  Key revocation certificates have special handling.
 *
 */
int
import_keys( const char *fname, int fast )
{
    armor_filter_context_t afx;
    compress_filter_context_t cfx;
    PACKET *pending_pkt = NULL;
    IOBUF inp = NULL;
    KBNODE keyblock;
    int rc = 0;
    ulong count=0;

    memset( &afx, 0, sizeof afx);
    memset( &cfx, 0, sizeof cfx);
    afx.only_keyblocks = 1;

    /* fixme: don't use static variables */
    memset( &stats, 0, sizeof( stats ) );

    /* open file */
    inp = iobuf_open(fname);
    if( !fname )
	fname = "[stdin]";
    if( !inp ) {
	log_error_f(fname, _("can't open file: %s\n"), strerror(errno) );
	return G10ERR_OPEN_FILE;
    }


    getkey_disable_caches();

    if( !opt.no_armor ) /* armored reading is not disabled */
	iobuf_push_filter( inp, armor_filter, &afx );

    while( !(rc = read_block( inp, &cfx, &pending_pkt, &keyblock) )) {
	if( keyblock->pkt->pkttype == PKT_PUBLIC_KEY )
	    rc = import_one( fname, keyblock, fast );
	else if( keyblock->pkt->pkttype == PKT_SECRET_KEY )
	    rc = import_secret_one( fname, keyblock );
	else if( keyblock->pkt->pkttype == PKT_SIGNATURE
		 && keyblock->pkt->pkt.signature->sig_class == 0x20 )
	    rc = import_revoke_cert( fname, keyblock );
	else {
	    log_info_f(fname, _("skipping block of type %d\n"),
					    keyblock->pkt->pkttype );
	}
	release_kbnode(keyblock);
	if( rc )
	    break;
	if( !(++count % 100) )
	    log_info(_("%lu keys so far processed\n"), count );
    }
    if( rc == -1 )
	rc = 0;
    else if( rc && rc != G10ERR_INV_KEYRING )
	log_error_f( fname, _("read error: %s\n"), g10_errstr(rc));

    log_info(_("Total number processed: %lu\n"), count );
    if( stats.no_user_id )
	log_info(_("          w/o user IDs: %lu\n"), stats.no_user_id );
    if( stats.imported || stats.imported_rsa ) {
	log_info(_("              imported: %lu"), stats.imported );
	if( stats.imported_rsa )
	    fprintf(stderr, "  (RSA: %lu)", stats.imported_rsa );
	putc('\n', stderr);
    }
    if( stats.unchanged )
	log_info(_("             unchanged: %lu\n"), stats.unchanged );
    if( stats.n_uids )
	log_info(_("          new user IDs: %lu\n"), stats.n_uids );
    if( stats.n_subk )
	log_info(_("           new subkeys: %lu\n"), stats.n_subk );
    if( stats.n_sigs )
	log_info(_("        new signatures: %lu\n"), stats.n_sigs );
    if( stats.n_revoc )
	log_info(_("   new key revocations: %lu\n"), stats.n_revoc );
    if( stats.secret_read )
	log_info(_("      secret keys read: %lu\n"), stats.secret_read );
    if( stats.secret_imported )
	log_info(_("  secret keys imported: %lu\n"), stats.secret_imported );
    if( stats.secret_dups )
	log_info(_(" secret keys unchanged: %lu\n"), stats.secret_dups );


    iobuf_close(inp);
    return rc;
}


/****************
 * Read the next keyblock from stream A, CFX is used to handle
 * compressed keyblocks. PENDING_PKT should be initialzed to NULL
 * and not chnaged form the caller.
 * Retunr: 0 = okay, -1 no more blocks or another errorcode.
 */
static int
read_block( IOBUF a, compress_filter_context_t *cfx,
	    PACKET **pending_pkt, KBNODE *ret_root )
{
    int rc;
    PACKET *pkt;
    KBNODE root = NULL;
    int in_cert;

    if( *pending_pkt ) {
	root = new_kbnode( *pending_pkt );
	*pending_pkt = NULL;
	in_cert = 1;
    }
    else
	in_cert = 0;
    pkt = m_alloc( sizeof *pkt );
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	if( rc ) {  /* ignore errors */
	    if( rc != G10ERR_UNKNOWN_PACKET ) {
		log_error("read_block: read error: %s\n", g10_errstr(rc) );
		rc = G10ERR_INV_KEYRING;
		goto ready;
	    }
	    free_packet( pkt );
	    init_packet(pkt);
	    continue;
	}

	if( !root && pkt->pkttype == PKT_SIGNATURE
		  && pkt->pkt.signature->sig_class == 0x20 ) {
	    /* this is a revocation certificate which is handled
	     * in a special way */
	    root = new_kbnode( pkt );
	    pkt = NULL;
	    goto ready;
	}

	/* make a linked list of all packets */
	switch( pkt->pkttype ) {
	  case PKT_COMPRESSED:
	    if( pkt->pkt.compressed->algorithm < 1
		|| pkt->pkt.compressed->algorithm > 2 ) {
		rc = G10ERR_COMPR_ALGO;
		goto ready;
	    }
	    cfx->algo = pkt->pkt.compressed->algorithm;
	    pkt->pkt.compressed->buf = NULL;
	    iobuf_push_filter( a, compress_filter, cfx );
	    free_packet( pkt );
	    init_packet(pkt);
	    break;


	  case PKT_PUBLIC_KEY:
	  case PKT_SECRET_KEY:
	    if( in_cert ) { /* store this packet */
		*pending_pkt = pkt;
		pkt = NULL;
		goto ready;
	    }
	    in_cert = 1;
	  default:
	    if( in_cert ) {
		if( !root )
		    root = new_kbnode( pkt );
		else
		    add_kbnode( root, new_kbnode( pkt ) );
		pkt = m_alloc( sizeof *pkt );
	    }
	    init_packet(pkt);
	    break;
	}
    }
  ready:
    if( rc == -1 && root )
	rc = 0;

    if( rc )
	release_kbnode( root );
    else
	*ret_root = root;
    free_packet( pkt );
    m_free( pkt );
    return rc;
}


/****************
 * Try to import one keyblock.	Return an error only in serious cases, but
 * never for an invalid keyblock.  It uses log_error to increase the
 * internal errorcount, so that invalid input can be detected by programs
 * which called g10.
 */
static int
import_one( const char *fname, KBNODE keyblock, int fast )
{
    PKT_public_key *pk;
    PKT_public_key *pk_orig;
    KBNODE node, uidnode;
    KBNODE keyblock_orig = NULL;
    KBPOS kbpos;
    u32 keyid[2];
    int rc = 0;
    int new_key = 0;
    int mod_key = 0;

    /* get the key and print some info about it */
    node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
    if( !node )
	BUG();

    pk = node->pkt->pkt.public_key;
    keyid_from_pk( pk, keyid );
    uidnode = find_next_kbnode( keyblock, PKT_USER_ID );

    if( opt.verbose ) {
	log_info_f( fname, "pub  %4u%c/%08lX %s   ",
		  nbits_from_pk( pk ),
		  pubkey_letter( pk->pubkey_algo ),
		  (ulong)keyid[1], datestr_from_pk(pk) );
	if( uidnode )
	    print_string( stderr, uidnode->pkt->pkt.user_id->name,
				  uidnode->pkt->pkt.user_id->len, 0 );
	putc('\n', stderr);
    }
    if( !uidnode ) {
	log_error_f(fname, _("key %08lX: no user id\n"), (ulong)keyid[1]);
	return 0;
    }

    clear_kbnode_flags( keyblock );
    rc = chk_self_sigs( fname, keyblock , pk, keyid );
    if( rc )
	return rc== -1? 0:rc;

    if( !delete_inv_parts( fname, keyblock, keyid ) ) {
	if( !opt.quiet ) {
	    log_info_f( fname, _("key %08lX: no valid user ids\n"),
							(ulong)keyid[1]);
	    log_info(_("this may be caused by a missing self-signature\n"));
	}
	stats.no_user_id++;
	return 0;
    }


    /* do we have this key already in one of our pubrings ? */
    pk_orig = m_alloc_clear( sizeof *pk_orig );
    rc = get_pubkey( pk_orig, keyid );
    if( rc && rc != G10ERR_NO_PUBKEY ) {
	log_error_f( fname, _("key %08lX: public key not found: %s\n"),
				(ulong)keyid[1], g10_errstr(rc));
    }
    else if( rc ) { /* insert this key */
	/* get default resource */
	if( get_keyblock_handle( NULL, 0, &kbpos ) ) {
	    log_error(_("no default public keyring\n"));
	    return G10ERR_GENERAL;
	}
	if( opt.verbose > 1 )
	    log_info_f( fname, _("writing to '%s'\n"),
				keyblock_resource_name(&kbpos) );
	if( (rc=lock_keyblock( &kbpos )) )
	    log_error_f( keyblock_resource_name(&kbpos),
			_("can't lock public keyring: %s\n"), g10_errstr(rc) );
	else if( (rc=insert_keyblock( &kbpos, keyblock )) )
	    log_error_f( keyblock_resource_name(&kbpos),
			_("can't write to keyring: %s\n"), g10_errstr(rc) );
	unlock_keyblock( &kbpos );
	/* we are ready */
	if( !opt.quiet )
	    log_info_f( fname, _("key %08lX: public key imported\n"),
						      (ulong)keyid[1]);
	stats.imported++;
	if( is_RSA( pk->pubkey_algo ) )
	    stats.imported_rsa++;
	new_key = 1;
    }
    else { /* merge */
	int n_uids, n_sigs, n_subk;

	/* Compare the original against the new key; just to be sure nothing
	 * weird is going on */
	if( cmp_public_keys( pk_orig, pk ) ) {
	    log_error_f( fname, _("key %08lX: doesn't match our copy\n"),
							  (ulong)keyid[1]);
	    rc = G10ERR_GENERAL;
	    goto leave;
	}

	/* See whether we have only non-self-signature on one user id; if not
	 * ask the user what to do. <--- fixme */

	/* now read the original keyblock */
	rc = find_keyblock_bypk( &kbpos, pk_orig );
	if( rc ) {
	    log_error_f(fname,
			_("key %08lX: can't locate original keyblock: %s\n"),
				     (ulong)keyid[1], g10_errstr(rc));
	    goto leave;
	}
	rc = read_keyblock( &kbpos, &keyblock_orig );
	if( rc ) {
	    log_error_f(fname,
			_("key %08lX: can't read original keyblock: %s\n"),
					    (ulong)keyid[1], g10_errstr(rc));
	    goto leave;
	}
	/* and try to merge the block */
	clear_kbnode_flags( keyblock_orig );
	clear_kbnode_flags( keyblock );
	n_uids = n_sigs = n_subk = 0;
	rc = merge_blocks( fname, keyblock_orig, keyblock,
				keyid, &n_uids, &n_sigs, &n_subk );
	if( rc )
	    goto leave;
	if( n_uids || n_sigs || n_subk ) {
	    mod_key = 1;
	    /* keyblock_orig has been updated; write */
	    if( opt.verbose > 1 )
		log_info_f(keyblock_resource_name(&kbpos),
				      _("writing keyblock\n"));
	    if( (rc=lock_keyblock( &kbpos )) )
		log_error_f(keyblock_resource_name(&kbpos),
			 _("can't lock public keyring: %s\n"), g10_errstr(rc) );
	    else if( (rc=update_keyblock( &kbpos, keyblock_orig )) )
		log_error_f( keyblock_resource_name(&kbpos),
			    _("can't write keyblock: %s\n"), g10_errstr(rc) );
	    unlock_keyblock( &kbpos );
	    /* we are ready */
	    if( !opt.quiet ) {
		if( n_uids == 1 )
		    log_info_f(fname, _("key %08lX: 1 new user-id\n"),
					     (ulong)keyid[1]);
		else if( n_uids )
		    log_info_f(fname, _("key %08lX: %d new user-ids\n"),
					     (ulong)keyid[1], n_uids );
		if( n_sigs == 1 )
		    log_info_f(fname, _("key %08lX: 1 new signature\n"),
					     (ulong)keyid[1]);
		else if( n_sigs )
		    log_info_f(fname, _("key %08lX: %d new signatures\n"),
					     (ulong)keyid[1], n_sigs );
		if( n_subk == 1 )
		    log_info_f(fname, _("key %08lX: 1 new subkey\n"),
					     (ulong)keyid[1]);
		else if( n_subk )
		    log_info_f(fname, _("key %08lX: %d new subkeys\n"),
					     (ulong)keyid[1], n_subk );
	    }

	    stats.n_uids +=n_uids;
	    stats.n_sigs +=n_sigs;
	    stats.n_subk +=n_subk;
	}
	else {
	    if( !opt.quiet )
		log_info_f(fname, _("key %08lX: not changed\n"),
						    (ulong)keyid[1] );
	    stats.unchanged++;
	}
    }
    if( !rc && !fast ) {
	rc = query_trust_record( new_key? pk : pk_orig );
	if( rc && rc != -1 )
	    log_error("trustdb error: %s\n", g10_errstr(rc) );
	else if( rc == -1 ) { /* not found trustdb */
	    rc = insert_trust_record( new_key? pk : pk_orig );
	    if( rc )
		log_error("key %08lX: trustdb insert failed: %s\n",
					(ulong)keyid[1], g10_errstr(rc) );
	}
	else if( mod_key )
	    rc = update_trust_record( keyblock_orig, 1, NULL );
	else
	    rc = clear_trust_checked_flag( new_key? pk : pk_orig );
    }

  leave:
    release_kbnode( keyblock_orig );
    free_public_key( pk_orig );
    return rc;
}


/****************
 * Ditto for secret keys.  Handling is simpler than for public keys.
 */
static int
import_secret_one( const char *fname, KBNODE keyblock )
{
    PKT_secret_key *sk;
    KBNODE node, uidnode;
    KBPOS kbpos;
    u32 keyid[2];
    int rc = 0;

    /* get the key and print some info about it */
    node = find_kbnode( keyblock, PKT_SECRET_KEY );
    if( !node )
	BUG();

    sk = node->pkt->pkt.secret_key;
    keyid_from_sk( sk, keyid );
    uidnode = find_next_kbnode( keyblock, PKT_USER_ID );

    if( opt.verbose ) {
	log_info_f(fname, "sec  %4u%c/%08lX %s   ",
		  nbits_from_sk( sk ),
		  pubkey_letter( sk->pubkey_algo ),
		  (ulong)keyid[1], datestr_from_sk(sk) );
	if( uidnode )
	    print_string( stderr, uidnode->pkt->pkt.user_id->name,
				  uidnode->pkt->pkt.user_id->len, 0 );
	putc('\n', stderr);
    }
    stats.secret_read++;
    if( !uidnode ) {
	log_error_f(fname, _("key %08lX: no user id\n"), (ulong)keyid[1]);
	return 0;
    }

    clear_kbnode_flags( keyblock );

    /* do we have this key already in one of our secrings ? */
    rc = seckey_available( keyid );
    if( rc == G10ERR_NO_SECKEY ) { /* simply insert this key */
	/* get default resource */
	if( get_keyblock_handle( NULL, 1, &kbpos ) ) {
	    log_error("no default secret keyring\n");
	    return G10ERR_GENERAL;
	}
	if( opt.verbose > 1 )
	    log_info_f(keyblock_resource_name(&kbpos), _("writing keyblock\n"));
	if( (rc=lock_keyblock( &kbpos )) )
	    log_error_f( keyblock_resource_name(&kbpos),
		      _("can't lock secret keyring: %s\n"), g10_errstr(rc) );
	else if( (rc=insert_keyblock( &kbpos, keyblock )) )
	    log_error_f(keyblock_resource_name(&kbpos),
		      _("can't write keyring: %s\n"), g10_errstr(rc) );
	unlock_keyblock( &kbpos );
	/* we are ready */
	log_info_f(fname, _("key %08lX: secret key imported\n"), (ulong)keyid[1]);
	stats.secret_imported++;
    }
    else if( !rc ) { /* we can't merge secret keys */
	log_error_f(fname, _("key %08lX: already in secret keyring\n"),
						(ulong)keyid[1]);
	stats.secret_dups++;
    }
    else
	log_error_f(fname, _("key %08lX: secret key not found: %s\n"),
				(ulong)keyid[1], g10_errstr(rc));

    return rc;
}


/****************
 * Import a revocation certificate; this is a single signature packet.
 */
static int
import_revoke_cert( const char *fname, KBNODE node )
{
    PKT_public_key *pk=NULL;
    KBNODE onode, keyblock = NULL;
    KBPOS kbpos;
    u32 keyid[2];
    int rc = 0;

    assert( !node->next );
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( node->pkt->pkt.signature->sig_class == 0x20 );

    keyid[0] = node->pkt->pkt.signature->keyid[0];
    keyid[1] = node->pkt->pkt.signature->keyid[1];

    pk = m_alloc_clear( sizeof *pk );
    rc = get_pubkey( pk, keyid );
    if( rc == G10ERR_NO_PUBKEY ) {
	log_info_f(fname, _("key %08lX: no public key - "
		 "can't apply revocation certificate\n"), (ulong)keyid[1]);
	rc = 0;
	goto leave;
    }
    else if( rc ) {
	log_error_f(fname, _("key %08lX: public key not found: %s\n"),
				       (ulong)keyid[1], g10_errstr(rc));
	goto leave;
    }

    /* read the original keyblock */
    rc = find_keyblock_bypk( &kbpos, pk );
    if( rc ) {
	log_error_f(fname,
		_("key %08lX: can't locate original keyblock: %s\n"),
					(ulong)keyid[1], g10_errstr(rc));
	goto leave;
    }
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error_f(fname,
		_("key %08lX: can't read original keyblock: %s\n"),
					(ulong)keyid[1], g10_errstr(rc));
	goto leave;
    }


    /* it is okay, that node is not in keyblock because
     * check_key_signature works fine for sig_class 0x20 in this
     * special case. */
    rc = check_key_signature( keyblock, node, NULL);
    if( rc ) {
	log_error_f(fname, _("key %08lX: invalid revocation certificate"
		  ": %s - rejected\n"), (ulong)keyid[1], g10_errstr(rc));
    }


    /* check whether we already have this */
    for(onode=keyblock->next; onode; onode=onode->next ) {
	if( onode->pkt->pkttype == PKT_USER_ID )
	    break;
	else if( onode->pkt->pkttype == PKT_SIGNATURE
		 && onode->pkt->pkt.signature->sig_class == 0x20
		 && keyid[0] == onode->pkt->pkt.signature->keyid[0]
		 && keyid[1] == onode->pkt->pkt.signature->keyid[1] ) {
	    rc = 0;
	    goto leave; /* yes, we already know about it */
	}
    }


    /* insert it */
    insert_kbnode( keyblock, clone_kbnode(node), 0 );

    /* and write the keyblock back */
    if( opt.verbose > 1 )
	log_info_f( keyblock_resource_name(&kbpos), _("writing keyblock\n"));
    if( (rc=lock_keyblock( &kbpos )) )
	log_error_f( keyblock_resource_name(&kbpos),
		    _("can't lock public keyring: %s\n"), g10_errstr(rc) );
    else if( (rc=update_keyblock( &kbpos, keyblock )) )
	log_error_f(keyblock_resource_name(&kbpos),
		    _("can't write keyblock: %s\n"), g10_errstr(rc) );
    unlock_keyblock( &kbpos );
    /* we are ready */
    if( !opt.quiet )
	log_info_f(fname, _("key %08lX: revocation certificate imported\n"),
					(ulong)keyid[1]);
    stats.n_revoc++;

  leave:
    release_kbnode( keyblock );
    free_public_key( pk );
    return rc;
}


/****************
 * loop over the keyblock and check all self signatures.
 * Mark all user-ids with a self-signature by setting flag bit 0.
 * Mark all user-ids with an invalid self-signature by setting bit 1.
 */
static int
chk_self_sigs( const char *fname, KBNODE keyblock,
	       PKT_public_key *pk, u32 *keyid )
{
    KBNODE n, unode;
    PKT_signature *sig;
    int rc;

    for( n=keyblock; (n = find_next_kbnode(n, 0)); ) {
	if( n->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	sig = n->pkt->pkt.signature;
	if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] ) {
	    unode = find_prev_kbnode( keyblock, n, PKT_USER_ID );
	    if( !unode )  {
		log_error_f(fname, _("key %08lX: no user-id for signature\n"),
					(ulong)keyid[1]);
		return -1;  /* the complete keyblock is invalid */
	    }
	    rc = check_key_signature( keyblock, n, NULL);
	    if( rc ) {
		log_error_f( fname,  rc == G10ERR_PUBKEY_ALGO ?
			  _("key %08lX: unsupported public key algorithm\n"):
			  _("key %08lX: invalid self-signature\n"),
				 (ulong)keyid[1]);

		unode->flag |= 2; /* mark as invalid */
	    }
	    unode->flag |= 1; /* mark that signature checked */
	}
    }
    return 0;
}

/****************
 * delete all parts which are invalid and those signatures whose
 * public key algorithm is not available in this implemenation;
 * but consider RSA as valid, because parse/build_packets knows
 * about it.
 * returns: true if at least one valid user-id is left over.
 */
static int
delete_inv_parts( const char *fname, KBNODE keyblock, u32 *keyid )
{
    KBNODE node;
    int nvalid=0, uid_seen=0;

    for(node=keyblock->next; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    uid_seen = 1;
	    if( (node->flag & 2) || !(node->flag & 1) ) {
		if( opt.verbose ) {
		    log_info_f(fname, _("key %08lX: skipped userid '"),
							 (ulong)keyid[1]);
		    print_string( stderr, node->pkt->pkt.user_id->name,
				      node->pkt->pkt.user_id->len, 0 );
		    fputs("'\n", stderr );
		}
		delete_kbnode( node ); /* the user-id */
		/* and all following packets up to the next user-id */
		while( node->next && node->next->pkt->pkttype != PKT_USER_ID ){
		    delete_kbnode( node->next );
		    node = node->next;
		}
	    }
	    else
		nvalid++;
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && check_pubkey_algo( node->pkt->pkt.signature->pubkey_algo)
		 && node->pkt->pkt.signature->pubkey_algo != PUBKEY_ALGO_RSA )
	    delete_kbnode( node ); /* build_packet() can't handle this */
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && node->pkt->pkt.signature->sig_class == 0x20 )  {
	    if( uid_seen ) {
		log_error_f(fname, _("key %08lX: revocation certificate "
				     "at wrong place - skipped\n"),
				    (ulong)keyid[1]);
		delete_kbnode( node );
	    }
	    else {
		int rc = check_key_signature( keyblock, node, NULL);
		if( rc ) {
		    log_error_f(fname, _("key %08lX: invalid revocation "
			      "certificate: %s - skipped\n"),
			      (ulong)keyid[1], g10_errstr(rc));
		    delete_kbnode( node );
		}
	    }
	}
    }

    /* note: because keyblock is the public key, it is never marked
     * for deletion and so keyblock cannot change */
    commit_kbnode( &keyblock );
    return nvalid;
}


/****************
 * compare and merge the blocks
 *
 * o compare the signatures: If we already have this signature, check
 *   that they compare okay; if not, issue a warning and ask the user.
 * o Simply add the signature.	Can't verify here because we may not have
 *   the signature's public key yet; verification is done when putting it
 *   into the trustdb, which is done automagically as soon as this pubkey
 *   is used.
 * Note: We indicate newly inserted packets with flag bit 0
 */
static int
merge_blocks( const char *fname, KBNODE keyblock_orig, KBNODE keyblock,
	      u32 *keyid, int *n_uids, int *n_sigs, int *n_subk )
{
    KBNODE onode, node;
    int rc, found;

    /* 1st: handle revocation certificates */
    for(node=keyblock->next; node; node=node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID )
	    break;
	else if( node->pkt->pkttype == PKT_SIGNATURE
		 && node->pkt->pkt.signature->sig_class == 0x20 )  {
	    /* check whether we already have this */
	    found = 0;
	    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
		if( onode->pkt->pkttype == PKT_USER_ID )
		    break;
		else if( onode->pkt->pkttype == PKT_SIGNATURE
			 && onode->pkt->pkt.signature->sig_class == 0x20
			 && node->pkt->pkt.signature->keyid[0]
			    == onode->pkt->pkt.signature->keyid[0]
			 && node->pkt->pkt.signature->keyid[1]
			    == onode->pkt->pkt.signature->keyid[1] ) {
		    found = 1;
		    break;
		}
	    }
	    if( !found ) {
		KBNODE n2 = clone_kbnode(node);
		insert_kbnode( keyblock_orig, n2, 0 );
		n2->flag |= 1;
		log_info_f(fname, _("key %08lX: revocation certificate added\n"),
					 (ulong)keyid[1]);
	    }
	}
    }

    /* 2nd: try to merge new certificates in */
    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
	if( !(onode->flag & 1) && onode->pkt->pkttype == PKT_USER_ID) {
	    /* find the user id in the imported keyblock */
	    for(node=keyblock->next; node; node=node->next )
		if( node->pkt->pkttype == PKT_USER_ID
		    && !cmp_user_ids( onode->pkt->pkt.user_id,
					  node->pkt->pkt.user_id ) )
		    break;
	    if( node ) { /* found: merge */
		rc = merge_sigs( onode, node, n_sigs, fname, keyid );
		if( rc )
		    return rc;
	    }
	}
    }

    /* 3rd: add new user-ids */
    for(node=keyblock->next; node; node=node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID) {
	    /* do we have this in the original keyblock */
	    for(onode=keyblock_orig->next; onode; onode=onode->next )
		if( onode->pkt->pkttype == PKT_USER_ID
		    && !cmp_user_ids( onode->pkt->pkt.user_id,
				      node->pkt->pkt.user_id ) )
		    break;
	    if( !onode ) { /* this is a new user id: append */
		rc = append_uid( keyblock_orig, node, n_sigs, fname, keyid);
		if( rc )
		    return rc;
		++*n_uids;
	    }
	}
    }

    /* merge subkey certifcates */
    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
	if( !(onode->flag & 1)
	    &&	(   onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
		 || onode->pkt->pkttype == PKT_SECRET_SUBKEY) ) {
	    /* find the subkey in the imported keyblock */
	    for(node=keyblock->next; node; node=node->next ) {
		if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
		    && !cmp_public_keys( onode->pkt->pkt.public_key,
					  node->pkt->pkt.public_key ) )
		    break;
		else if( node->pkt->pkttype == PKT_SECRET_SUBKEY
		    && !cmp_secret_keys( onode->pkt->pkt.secret_key,
					  node->pkt->pkt.secret_key ) )
		    break;
	    }
	    if( node ) { /* found: merge */
		rc = merge_keysigs( onode, node, n_sigs, fname, keyid );
		if( rc )
		    return rc;
	    }
	}
    }

    /*	add new subkeys */
    for(node=keyblock->next; node; node=node->next ) {
	onode = NULL;
	if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    /* do we have this in the original keyblock? */
	    for(onode=keyblock_orig->next; onode; onode=onode->next )
		if( onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
		    && !cmp_public_keys( onode->pkt->pkt.public_key,
					 node->pkt->pkt.public_key ) )
		    break;
	    if( !onode ) { /* this is a new subkey: append */
		rc = append_key( keyblock_orig, node, n_sigs, fname, keyid);
		if( rc )
		    return rc;
		++*n_subk;
	    }
	}
	else if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	    /* do we have this in the original keyblock? */
	    for(onode=keyblock_orig->next; onode; onode=onode->next )
		if( onode->pkt->pkttype == PKT_SECRET_SUBKEY
		    && !cmp_secret_keys( onode->pkt->pkt.secret_key,
					 node->pkt->pkt.secret_key ) )
		    break;
	    if( !onode ) { /* this is a new subkey: append */
		rc = append_key( keyblock_orig, node, n_sigs, fname, keyid);
		if( rc )
		    return rc;
		++*n_subk;
	    }
	}
    }

    return 0;
}


/****************
 * append the userid starting with NODE and all signatures to KEYBLOCK.
 * Mark all new and copied packets by setting flag bit 0.
 */
static int
append_uid( KBNODE keyblock, KBNODE node, int *n_sigs,
					  const char *fname, u32 *keyid )
{
    KBNODE n, n_where=NULL;

    assert(node->pkt->pkttype == PKT_USER_ID );
    if( node->next->pkt->pkttype == PKT_USER_ID ) {
	log_error_f(fname, _("key %08lX: our copy has no self-signature\n"),
						  (ulong)keyid[1]);
	return G10ERR_GENERAL;
    }

    /* find the position */
    for( n = keyblock; n; n_where = n, n = n->next ) {
	if( n->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || n->pkt->pkttype == PKT_SECRET_SUBKEY )
	    break;
    }
    if( !n )
	n_where = NULL;

    /* and append/insert */
    while( node ) {
	/* we add a clone to the original keyblock, because this
	 * one is released first */
	n = clone_kbnode(node);
	if( n_where ) {
	    insert_kbnode( n_where, n, 0 );
	    n_where = n;
	}
	else
	    add_kbnode( keyblock, n );
	n->flag |= 1;
	node->flag |= 1;
	if( n->pkt->pkttype == PKT_SIGNATURE )
	    ++*n_sigs;

	node = node->next;
	if( node && node->pkt->pkttype != PKT_SIGNATURE )
	    break;
    }

    return 0;
}


/****************
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_USER_ID.
 * (how should we handle comment packets here?)
 */
static int
merge_sigs( KBNODE dst, KBNODE src, int *n_sigs,
				    const char *fname, u32 *keyid )
{
    KBNODE n, n2;
    int found=0;

    assert(dst->pkt->pkttype == PKT_USER_ID );
    assert(src->pkt->pkttype == PKT_USER_ID );
    /* at least a self signature comes next to the user-ids */
    assert(src->next->pkt->pkttype != PKT_USER_ID );
    if( dst->next->pkt->pkttype == PKT_USER_ID ) {
	log_error_f(fname, _("key %08lX: our copy has no self-signature\n"),
						  (ulong)keyid[1]);
	return 0;
    }


    for(n=src->next; n && n->pkt->pkttype != PKT_USER_ID; n = n->next ) {
	if( n->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	found = 0;
	for(n2=dst->next; n2 && n2->pkt->pkttype != PKT_USER_ID; n2 = n2->next){
	    if( n2->pkt->pkttype == PKT_SIGNATURE
		&& n->pkt->pkt.signature->keyid[0]
		   == n2->pkt->pkt.signature->keyid[0]
		&& n->pkt->pkt.signature->keyid[1]
		   == n2->pkt->pkt.signature->keyid[1]
		&& n->pkt->pkt.signature->timestamp
		   <= n2->pkt->pkt.signature->timestamp
		&& n->pkt->pkt.signature->sig_class
		   == n2->pkt->pkt.signature->sig_class ) {
		found++;
		break;
	    }
	}
	if( !found ) {
	    /* This signature is new or newer, append N to DST.
	     * We add a clone to the original keyblock, because this
	     * one is released first */
	    n2 = clone_kbnode(n);
	    insert_kbnode( dst, n2, PKT_SIGNATURE );
	    n2->flag |= 1;
	    n->flag |= 1;
	    ++*n_sigs;
	}
    }

    return 0;
}

/****************
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_xxx_SUBKEY.
 */
static int
merge_keysigs( KBNODE dst, KBNODE src, int *n_sigs,
				    const char *fname, u32 *keyid )
{
    KBNODE n, n2;
    int found=0;

    assert(   dst->pkt->pkttype == PKT_PUBLIC_SUBKEY
	   || dst->pkt->pkttype == PKT_SECRET_SUBKEY );

    for(n=src->next; n ; n = n->next ) {
	if( n->pkt->pkttype == PKT_PUBLIC_SUBKEY
	    || n->pkt->pkttype == PKT_PUBLIC_KEY )
	    break;
	if( n->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	found = 0;
	for(n2=dst->next; n2; n2 = n2->next){
	    if( n2->pkt->pkttype == PKT_PUBLIC_SUBKEY
		|| n2->pkt->pkttype == PKT_PUBLIC_KEY )
		break;
	    if( n2->pkt->pkttype == PKT_SIGNATURE
		&& n->pkt->pkt.signature->keyid[0]
		   == n2->pkt->pkt.signature->keyid[0]
		&& n->pkt->pkt.signature->keyid[1]
		   == n2->pkt->pkt.signature->keyid[1]
		&& n->pkt->pkt.signature->timestamp
		   <= n2->pkt->pkt.signature->timestamp
		&& n->pkt->pkt.signature->sig_class
		   == n2->pkt->pkt.signature->sig_class ) {
		found++;
		break;
	    }
	}
	if( !found ) {
	    /* This signature is new or newer, append N to DST.
	     * We add a clone to the original keyblock, because this
	     * one is released first */
	    n2 = clone_kbnode(n);
	    insert_kbnode( dst, n2, PKT_SIGNATURE );
	    n2->flag |= 1;
	    n->flag |= 1;
	    ++*n_sigs;
	}
    }

    return 0;
}

/****************
 * append the subkey starting with NODE and all signatures to KEYBLOCK.
 * Mark all new and copied packets by setting flag bit 0.
 */
static int
append_key( KBNODE keyblock, KBNODE node, int *n_sigs,
					  const char *fname, u32 *keyid )
{
    KBNODE n;

    assert( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
	   || node->pkt->pkttype == PKT_SECRET_SUBKEY );

    while(  node ) {
	/* we add a clone to the original keyblock, because this
	 * one is released first */
	n = clone_kbnode(node);
	add_kbnode( keyblock, n );
	n->flag |= 1;
	node->flag |= 1;
	if( n->pkt->pkttype == PKT_SIGNATURE )
	    ++*n_sigs;

	node = node->next;
	if( node && node->pkt->pkttype != PKT_SIGNATURE )
	    break;
    }

    return 0;
}

