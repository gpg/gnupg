/* import.c
 *	Copyright (c) 1998 by Werner Koch (dd9jn)
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
#include "main.h"


static int read_block( IOBUF a, compress_filter_context_t *cfx,
			     PACKET **pending_pkt, KBNODE *ret_root );
static int import_one( const char *fname, KBNODE keyblock );
static int chk_self_sigs( const char *fname, KBNODE keyblock,
			  PKT_public_cert *pkc, u32 *keyid );
static int delete_inv_parts( const char *fname, KBNODE keyblock, u32 *keyid );


/****************
 * Import the public keys from the given filename. Input may be armored.
 * This function rejects alls keys which are not valid self signed on at
 * least one userid. Only user ids which are self signed will be imported.
 * Other signatures are not not checked.
 *
 * Actually this functtion does a merge. It works like this:
 *   FIXME: add handling for revocation certs
 *
 *  - get the keyblock
 *  - check self-signatures and remove all userids and their signatures
 *    without/invalid self-signatures.
 *  - reject the keyblock, if we have no valid userid.
 *  - See wether we have this key already in one of our pubrings.
 *    If not, simply add it to the default keyring.
 *  - Compare the key and the self-signatures of the new and the one in
 *    our keyring.  If they are differen something weird is going on;
 *    ask what to do.
 *  - See wether we have only non-self-signature on one user id; if not
 *    ask the user what to do.
 *  - compare the signatures: If we already have this signature, check
 *    that they compare okay; if not, issue a warning and ask the user.
 *    (consider to look at the timestamp and use the newest?)
 *  - Simply add the signature.  Can't verify here because we may not have
 *    the signatures public key yet; verification is done when putting it
 *    into the trustdb, which is done automagically as soon as this pubkey
 *    is used.
 *  - Proceed with next signature.
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
    int in_cert = 0;

    if( *pending_pkt ) {
	root = new_kbnode( *pending_pkt );
	*pending_pkt = NULL;
    }
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
	    if( !root )
		root = new_kbnode( pkt );
	    else
		add_kbnode( root, new_kbnode( pkt ) );
	    pkt = m_alloc( sizeof *pkt );
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
    KBPOS kbpos;
    u32 keyid[2];
    int rc = 0;

    /* get the key and print some infos about it */
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
				  uidnode->pkt->pkt.user_id->len );
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
	log_info("%s: key %08lX, no valid user ids left over\n",
						    fname, (ulong)keyid[1]);
	return 0;
    }

    /* do we have this key already in one of our pubrings ? */
    pkc_orig = m_alloc( sizeof *pkc_orig );
    rc = get_pubkey( pkc_orig, keyid );
    if( rc && rc != G10ERR_NO_PUBKEY ) {
	log_error("%s: key %08lX, public key not found: %s\n",
				fname, (ulong)keyid[1], g10_errstr(rc));
    }
    else if( rc ) { /* inset this key */
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
	if( opt.verbose )
	    log_info("%s: key %08lX imported\n", fname, (ulong)keyid[1]);
    }
    else {
       /* merge
	* o Compare the key and the self-signatures of the new and the one in
	*   our keyring.  If they are different something weird is going on;
	*   ask what to do.
	* o See wether we have only non-self-signature on one user id; if not
	*   ask the user what to do.
	* o compare the signatures: If we already have this signature, check
	*   that they compare okay; if not, issue a warning and ask the user.
	*   (consider to look at the timestamp and use the newest?)
	* o Simply add the signature.  Can't verify here because we may not have
	*   the signatures public key yet; verification is done when putting it
	*   into the trustdb, which is done automagically as soon as this pubkey
	*   is used.
	*/
	log_error("nyi\n");
    }

    free_public_cert( pkc_orig );
    return rc;
}

/****************
 * loop over the keyblock an check all self signatures.
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
		log_error("%s: key %08lX, invalid self-signature\n",
					fname, (ulong)keyid[1]);
		unode->flag |= 2; /* mark as invalid */
	    }
	    unode->flag |= 1; /* mark that user-id checked */
	}
    }
    return 0;
}

/****************
 * delete all parts which are invalid.
 * returns: true if at least one valid user-id is left over.
 */
static int
delete_inv_parts( const char *fname, KBNODE keyblock, u32 *keyid )
{
    KBNODE node;
    int nvalid=0;

    for(node=keyblock->next; node; node = node->next ) {
	if( node->pkt->pkttype == PKT_USER_ID ) {
	    if( (node->flag & 2) || !(node->flag & 1) ) {
		log_info("%s: key %08lX, removed userid '",
						  fname, (ulong)keyid[1]);
		print_string( stderr, node->pkt->pkt.user_id->name,
				      node->pkt->pkt.user_id->len );
		fputs("'\n", stderr );
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
    }

    /* note: because keyblock is the public key, ist is never marked
     * for deletion and so the keyblock cannot chnage */
    commit_kbnode( &keyblock );
    return nvalid;
}
