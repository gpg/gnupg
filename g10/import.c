/* import.c
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
#include "main.h"


static int read_block( IOBUF a, compress_filter_context_t *cfx,
			     PACKET **pending_pkt, KBNODE *ret_root );
static int import_one( const char *fname, KBNODE keyblock );
static int import_revoke_cert( const char *fname, KBNODE node );
static int chk_self_sigs( const char *fname, KBNODE keyblock,
			  PKT_public_cert *pkc, u32 *keyid );
static int delete_inv_parts( const char *fname, KBNODE keyblock, u32 *keyid );
static int merge_blocks( const char *fname, KBNODE keyblock_orig,
		       KBNODE keyblock, u32 *keyid, int *n_uids, int *n_sigs );
static int append_uid( KBNODE keyblock, KBNODE node, int *n_sigs,
			     const char *fname, u32 *keyid );
static int merge_sigs( KBNODE dst, KBNODE src, int *n_sigs,
			     const char *fname, u32 *keyid );


/****************
 * Import the public keys from the given filename. Input may be armored.
 * This function rejects all keys which are not validly self signed on at
 * least one userid. Only user ids which are self signed will be imported.
 * Other signatures are not checked.
 *
 * Actually this functtion does a merge. It works like this:
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
import_pubkeys( const char *fname )
{
    armor_filter_context_t afx;
    compress_filter_context_t cfx;
    PACKET *pending_pkt = NULL;
    IOBUF inp = NULL;
    KBNODE keyblock;
    int rc = 0;

    memset( &afx, 0, sizeof afx);
    memset( &cfx, 0, sizeof cfx);

    /* open file */
    inp = iobuf_open(fname);
    if( !fname )
	fname = "[stdin]";
    if( !inp ) {
	log_error("%s: can't open file: %s\n", fname, strerror(errno) );
	return G10ERR_OPEN_FILE;
    }

    if( !opt.no_armor ) /* armored reading is not diabled */
	iobuf_push_filter( inp, armor_filter, &afx );

    while( !(rc = read_block( inp, &cfx, &pending_pkt, &keyblock) )) {
	if( keyblock->pkt->pkttype == PKT_PUBLIC_CERT )
	    rc = import_one( fname, keyblock );
	else if( keyblock->pkt->pkttype == PKT_SIGNATURE
		 && keyblock->pkt->pkt.signature->sig_class == 0x20 )
	    rc = import_revoke_cert( fname, keyblock );
	else
	    log_info("%s: skipping block of type %d\n",
					    fname, keyblock->pkt->pkttype );
	release_kbnode(keyblock);
	if( rc )
	    break;
    }
    if( rc == -1 )
	rc = 0;
    else if( rc )
	log_error("%s: read error: %s\n", fname, g10_errstr(rc));

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
	    if( pkt->pkt.compressed->algorithm == 1 )
		cfx->pgpmode = 1;
	    else if( pkt->pkt.compressed->algorithm != 2  ){
		rc = G10ERR_COMPR_ALGO;
		goto ready;
	    }
	    pkt->pkt.compressed->buf = NULL;
	    iobuf_push_filter( a, compress_filter, cfx );
	    free_packet( pkt );
	    init_packet(pkt);
	    break;


	  case PKT_PUBLIC_CERT:
	  case PKT_SECRET_CERT:
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
import_one( const char *fname, KBNODE keyblock )
{
    PKT_public_cert *pkc;
    PKT_public_cert *pkc_orig;
    KBNODE node, uidnode;
    KBNODE keyblock_orig = NULL;
    KBPOS kbpos;
    u32 keyid[2];
    int rc = 0;

    /* get the key and print some info about it */
    node = find_kbnode( keyblock, PKT_PUBLIC_CERT );
    if( !node ) {
	log_error("%s: Oops; public key not found anymore!\n", fname);
	return G10ERR_GENERAL; /* really serious */
    }

    pkc = node->pkt->pkt.public_cert;
    keyid_from_pkc( pkc, keyid );
    uidnode = find_next_kbnode( keyblock, PKT_USER_ID );

    if( opt.verbose ) {
	log_info("%s: pub  %4u%c/%08lX %s   ", fname,
		  nbits_from_pkc( pkc ),
		  pubkey_letter( pkc->pubkey_algo ),
		  (ulong)keyid[1], datestr_from_pkc(pkc) );
	if( uidnode )
	    print_string( stderr, uidnode->pkt->pkt.user_id->name,
				  uidnode->pkt->pkt.user_id->len, 0 );
	putc('\n', stderr);
    }
    if( !uidnode ) {
	log_error("%s: No user id for key %08lX\n", fname, (ulong)keyid[1]);
	return 0;
    }

    clear_kbnode_flags( keyblock );
    rc = chk_self_sigs( fname, keyblock , pkc, keyid );
    if( rc )
	return rc== -1? 0:rc;

    if( !delete_inv_parts( fname, keyblock, keyid ) ) {
	log_info("%s: key %08lX, no valid user ids\n",
						    fname, (ulong)keyid[1]);
	return 0;
    }

    /* do we have this key already in one of our pubrings ? */
    pkc_orig = m_alloc_clear( sizeof *pkc_orig );
    rc = get_pubkey( pkc_orig, keyid );
    if( rc && rc != G10ERR_NO_PUBKEY ) {
	log_error("%s: key %08lX, public key not found: %s\n",
				fname, (ulong)keyid[1], g10_errstr(rc));
    }
    else if( rc ) { /* insert this key */
	/* get default resource */
	if( get_keyblock_handle( NULL, 0, &kbpos ) ) {
	    log_error("no default public keyring\n");
	    return G10ERR_GENERAL;
	}
	if( opt.verbose > 1 )
	    log_info("%s: writing to '%s'\n",
				fname, keyblock_resource_name(&kbpos) );
	if( (rc=lock_keyblock( &kbpos )) )
	    log_error("can't lock public keyring '%s': %s\n",
			     keyblock_resource_name(&kbpos), g10_errstr(rc) );
	else if( (rc=insert_keyblock( &kbpos, keyblock )) )
	    log_error("%s: can't write to '%s': %s\n", fname,
			     keyblock_resource_name(&kbpos), g10_errstr(rc) );
	unlock_keyblock( &kbpos );
	/* we are ready */
	log_info("%s: key %08lX imported\n", fname, (ulong)keyid[1]);
    }
    else { /* merge */
	int n_uids, n_sigs;

	/* Compare the original against the new key; just to be sure nothing
	 * weird is going on */
	if( cmp_public_certs( pkc_orig, pkc ) ) {
	    log_error("%s: key %08lX, doesn't match our copy\n",
						    fname, (ulong)keyid[1]);
	    rc = G10ERR_GENERAL;
	    goto leave;
	}

	/* See whether we have only non-self-signature on one user id; if not
	 * ask the user what to do. <--- fixme */

	/* now read the original keyblock */
	rc = find_keyblock_bypkc( &kbpos, pkc_orig );
	if( rc ) {
	    log_error("%s: key %08lX, can't locate original keyblock: %s\n",
				     fname, (ulong)keyid[1], g10_errstr(rc));
	    goto leave;
	}
	rc = read_keyblock( &kbpos, &keyblock_orig );
	if( rc ) {
	    log_error("%s: key %08lX, can't read original keyblock: %s\n",
				     fname, (ulong)keyid[1], g10_errstr(rc));
	    goto leave;
	}
	/* and try to merge the block */
	clear_kbnode_flags( keyblock_orig );
	clear_kbnode_flags( keyblock );
	n_uids = n_sigs = 0;
	rc = merge_blocks( fname, keyblock_orig, keyblock,
				keyid, &n_uids, &n_sigs );
	if( rc )
	    goto leave;
	if( n_uids || n_sigs ) { /* keyblock_orig has been updated; write */
	    if( opt.verbose > 1 )
		log_info("%s: writing to '%s'\n",
				    fname, keyblock_resource_name(&kbpos) );
	    if( (rc=lock_keyblock( &kbpos )) )
		log_error("can't lock public keyring '%s': %s\n",
				 keyblock_resource_name(&kbpos), g10_errstr(rc) );
	    else if( (rc=update_keyblock( &kbpos, keyblock )) )
		log_error("%s: can't write to '%s': %s\n", fname,
				 keyblock_resource_name(&kbpos), g10_errstr(rc) );
	    unlock_keyblock( &kbpos );
	    /* we are ready */
	    if( n_uids == 1 )
		log_info("%s: key %08lX, 1 new user-id\n",
					 fname, (ulong)keyid[1]);
	    else if( n_uids )
		log_info("%s: key %08lX, %d new user-ids\n",
					 fname, (ulong)keyid[1], n_uids );
	    if( n_sigs == 1 )
		log_info("%s: key %08lX, 1 new signature\n",
					 fname, (ulong)keyid[1]);
	    else if( n_sigs )
		log_info("%s: key %08lX, %d new signatures\n",
					 fname, (ulong)keyid[1], n_sigs );
	}
	else
	    log_info("%s: key %08lX, not changed\n", fname, (ulong)keyid[1] );
    }

  leave:
    release_kbnode( keyblock_orig );
    free_public_cert( pkc_orig );
    return rc;
}


/****************
 * Import a revocation certificate; this is a single signature packet.
 */
static int
import_revoke_cert( const char *fname, KBNODE node )
{
    PKT_public_cert *pkc=NULL;
    KBNODE onode, keyblock = NULL;
    KBPOS kbpos;
    u32 keyid[2];
    int rc = 0;

    assert( !node->next );
    assert( node->pkt->pkttype == PKT_SIGNATURE );
    assert( node->pkt->pkt.signature->sig_class == 0x20 );

    keyid[0] = node->pkt->pkt.signature->keyid[0];
    keyid[1] = node->pkt->pkt.signature->keyid[1];

    pkc = m_alloc_clear( sizeof *pkc );
    rc = get_pubkey( pkc, keyid );
    if( rc == G10ERR_NO_PUBKEY ) {
	log_info("%s: key %08lX, no public key - "
		 "can't apply revocation certificate\n",
				fname, (ulong)keyid[1]);
	rc = 0;
	goto leave;
    }
    else if( rc ) {
	log_error("%s: key %08lX, public key not found: %s\n",
				fname, (ulong)keyid[1], g10_errstr(rc));
	goto leave;
    }

    /* read the original keyblock */
    rc = find_keyblock_bypkc( &kbpos, pkc );
    if( rc ) {
	log_error("%s: key %08lX, can't locate original keyblock: %s\n",
				 fname, (ulong)keyid[1], g10_errstr(rc));
	goto leave;
    }
    rc = read_keyblock( &kbpos, &keyblock );
    if( rc ) {
	log_error("%s: key %08lX, can't read original keyblock: %s\n",
				 fname, (ulong)keyid[1], g10_errstr(rc));
	goto leave;
    }


    /* it is okay, that node is not in keyblock because
     * check_key_signature works fine for sig_class 0x20 in this
     * special case. */
    rc = check_key_signature( keyblock, node, NULL);
    if( rc ) {
	log_error("%s: key %08lX, invalid revocation certificate"
		  ": %s - rejected\n",
		  fname, (ulong)keyid[1], g10_errstr(rc));
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
	log_info("%s: writing to '%s'\n",
			    fname, keyblock_resource_name(&kbpos) );
    if( (rc=lock_keyblock( &kbpos )) )
	log_error("can't lock public keyring '%s': %s\n",
			 keyblock_resource_name(&kbpos), g10_errstr(rc) );
    else if( (rc=update_keyblock( &kbpos, keyblock )) )
	log_error("%s: can't write to '%s': %s\n", fname,
			 keyblock_resource_name(&kbpos), g10_errstr(rc) );
    unlock_keyblock( &kbpos );
    /* we are ready */
    log_info("%s: key %08lX, added revocation certificate\n",
				 fname, (ulong)keyid[1]);

  leave:
    release_kbnode( keyblock );
    free_public_cert( pkc );
    return rc;
}


/****************
 * loop over the keyblock and check all self signatures.
 * Mark all user-ids with a self-signature by setting flag bit 0.
 * Mark all user-ids with an invalid self-signature by setting bit 1.
 */
static int
chk_self_sigs( const char *fname, KBNODE keyblock,
	       PKT_public_cert *pkc, u32 *keyid )
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
		log_error("%s: key %08lX, no user-id for signature\n",
					fname, (ulong)keyid[1]);
		return -1;  /* the complete keyblock is invalid */
	    }
	    rc = check_key_signature( keyblock, n, NULL);
	    if( rc ) {
		log_error( rc == G10ERR_PUBKEY_ALGO ?
			  "%s: key %08lX, unsupported public key algorithm\n":
			  "%s: key %08lX, invalid self-signature\n",
			  fname, (ulong)keyid[1]);

		unode->flag |= 2; /* mark as invalid */
	    }
	    unode->flag |= 1; /* mark that user-id checked */
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
		    log_info("%s: key %08lX, removed userid '",
						  fname, (ulong)keyid[1]);
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
		log_error("%s: key %08lX, revocation certificate at wrong "
			   "place - removed\n", fname, (ulong)keyid[1]);
		delete_kbnode( node );
	    }
	    else {
		int rc = check_key_signature( keyblock, node, NULL);
		if( rc ) {
		    log_error("%s: key %08lX, invalid revocation certificate"
			      ": %s - removed\n",
			      fname, (ulong)keyid[1], g10_errstr(rc));
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
 *   FIXME: add the check that we don't have duplicate signatures and the
 *   warning in cases where the old/new signatures don't match.
 * o Simply add the signature.	Can't verify here because we may not have
 *   the signature's public key yet; verification is done when putting it
 *   into the trustdb, which is done automagically as soon as this pubkey
 *   is used.
 * Note: We indicate newly inserted packets with flag bit 0
 */
static int
merge_blocks( const char *fname, KBNODE keyblock_orig, KBNODE keyblock,
				   u32 *keyid, int *n_uids, int *n_sigs )
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
		node->flag |= 1;
		log_info("%s: key %08lX, added revocation certificate\n",
					 fname, (ulong)keyid[1]);
	    }
	}
    }

    /* 2nd: try to merge new ones in */
    for(onode=keyblock_orig->next; onode; onode=onode->next ) {
	if( !(onode->flag & 1) && onode->pkt->pkttype == PKT_USER_ID) {
	    /* find the user id in the imported keyblock */
	    for(node=keyblock->next; node; node=node->next )
		if( !(node->flag & 1)
		    && node->pkt->pkttype == PKT_USER_ID
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
	if( !(node->flag & 1) && node->pkt->pkttype == PKT_USER_ID) {
	    /* do we have this in the original keyblock */
	    for(onode=keyblock_orig->next; onode; onode=onode->next )
		if( !(onode->flag & 1)
		    && onode->pkt->pkttype == PKT_USER_ID
		    && cmp_user_ids( onode->pkt->pkt.user_id,
				     node->pkt->pkt.user_id ) )
		    break;
	    if( !node ) { /* this is a new user id: append */
		rc = append_uid( keyblock_orig, node, n_sigs, fname, keyid);
		if( rc )
		    return rc;
		++*n_uids;
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
    KBNODE n;

    assert(node->pkt->pkttype == PKT_USER_ID );
    /* at lease a self signature comes next to the user-id */
    if( node->next->pkt->pkttype == PKT_USER_ID ) {
	log_error("%s: key %08lX, our copy has no self-signature\n",
						  fname, (ulong)keyid[1]);
	return G10ERR_GENERAL;
    }

    for( ;node && node->pkt->pkttype != PKT_USER_ID; node = node->next ) {
	/* we add a clone to the original keyblock, because this
	 * one is released first */
	n = clone_kbnode(node);
	add_kbnode( keyblock, n );
	node->flag |= 1;
	n->flag |= 1;
	if( n->pkt->pkttype == PKT_SIGNATURE )
	    ++*n_sigs;
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
	log_error("%s: key %08lX, our copy has no self-signature\n",
						  fname, (ulong)keyid[1]);
	return 0;
    }


    for(n=src->next; n && n->pkt->pkttype != PKT_USER_ID; n = n->next ) {
	if( n->pkt->pkttype != PKT_SIGNATURE )
	    continue;
	found = 0;
	for(n2=dst->next; n2 && n2->pkt->pkttype != PKT_USER_ID; n2 = n2->next)
	    if( n2->pkt->pkttype == PKT_SIGNATURE
		&& n->pkt->pkt.signature->keyid[0]
		   == n2->pkt->pkt.signature->keyid[0]
		&& n->pkt->pkt.signature->keyid[1]
		   == n2->pkt->pkt.signature->keyid[1] ) {
	    found++;
	    break;
	}

	if( found ) { /* we already have this signature */
	    /* Hmmm: should we compare the timestamp etc?
	     * but then we have first to see whether this signature is valid
	     * - or simply add it in such a case and let trustdb logic
	     * decide whether to remove the old one
	     */
	    continue;
	}

	/* This signature is new, append N to DST it.
	 * We add a clone to the original keyblock, because this
	 * one is released first */
	n2 = clone_kbnode(n);
	insert_kbnode( dst, n2, PKT_USER_ID );
	n2->flag |= 1;
	n->flag |= 1;
	++*n_sigs;
    }

    return 0;
}

