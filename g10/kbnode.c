/* kbnode.c -  keyblock node utility functions
 * Copyright (C) 1998, 1999, 2000, 2001, 2002,
 *               2005 Free Software Foundation, Inc.
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "keydb.h"

#define USE_UNUSED_NODES 1

static KBNODE unused_nodes;

static KBNODE
alloc_node(void)
{
    KBNODE n;

    n = unused_nodes;
    if( n )
	unused_nodes = n->next;
    else
	n = xmalloc( sizeof *n );
    n->next = NULL;
    n->pkt = NULL;
    n->flag = 0;
    n->private_flag=0;
    n->recno = 0;
    return n;
}

static void
free_node( KBNODE n )
{
    if( n ) {
#if USE_UNUSED_NODES
	n->next = unused_nodes;
	unused_nodes = n;
#else
	xfree( n );
#endif
    }
}



KBNODE
new_kbnode( PACKET *pkt )
{
    KBNODE n = alloc_node();
    n->pkt = pkt;
    return n;
}


KBNODE
clone_kbnode( KBNODE node )
{
    KBNODE n = alloc_node();

    n->pkt = node->pkt;
    n->private_flag = node->private_flag | 2; /* mark cloned */
    return n;
}


void
release_kbnode( KBNODE n )
{
    KBNODE n2;

    while( n ) {
	n2 = n->next;
	if( !is_cloned_kbnode(n) ) {
	    free_packet( n->pkt );
	    xfree( n->pkt );
	}
	free_node( n );
	n = n2;
    }
}


/****************
 * Delete NODE.
 * Note: This only works with walk_kbnode!!
 */
void
delete_kbnode( KBNODE node )
{
    node->private_flag |= 1;
}

/****************
 * Append NODE to ROOT.  ROOT must exist!
 */
void
add_kbnode( KBNODE root, KBNODE node )
{
    KBNODE n1;

    for(n1=root; n1->next; n1 = n1->next)
	;
    n1->next = node;
}

/****************
 * Insert NODE into the list after root but before a packet which is not of
 * type PKTTYPE
 * (only if PKTTYPE != 0)
 */
void
insert_kbnode( KBNODE root, KBNODE node, int pkttype )
{
    if( !pkttype ) {
	node->next = root->next;
	root->next = node;
    }
    else {
	KBNODE n1;

	for(n1=root; n1->next;	n1 = n1->next)
	    if( pkttype != n1->next->pkt->pkttype ) {
		node->next = n1->next;
		n1->next = node;
		return;
	    }
	/* no such packet, append */
	node->next = NULL;
	n1->next = node;
    }
}


/****************
 * Find the previous node (if PKTTYPE = 0) or the previous node
 * with pkttype PKTTYPE in the list starting with ROOT of NODE.
 */
KBNODE
find_prev_kbnode( KBNODE root, KBNODE node, int pkttype )
{
    KBNODE n1;

    for (n1=NULL; root && root != node; root = root->next ) {
        if (!pkttype ||root->pkt->pkttype == pkttype)
            n1 = root;
    }
    return n1;
}

/****************
 * Ditto, but find the next packet.  The behaviour is trivial if
 * PKTTYPE is 0 but if it is specified, the next node with a packet
 * of this type is returned.  The function has some knowledge about
 * the valid ordering of packets: e.g. if the next signature packet
 * is requested, the function will not return one if it encounters
 * a user-id.
 */
KBNODE
find_next_kbnode( KBNODE node, int pkttype )
{
    for( node=node->next ; node; node = node->next ) {
	if( !pkttype )
	    return node;
	else if( pkttype == PKT_USER_ID 
		 && (	node->pkt->pkttype == PKT_PUBLIC_KEY
		     || node->pkt->pkttype == PKT_SECRET_KEY ) )
	    return NULL;
	else if( pkttype == PKT_SIGNATURE
		 && (	node->pkt->pkttype == PKT_USER_ID
		     || node->pkt->pkttype == PKT_PUBLIC_KEY
		     || node->pkt->pkttype == PKT_SECRET_KEY ) )
	    return NULL;
	else if( node->pkt->pkttype == pkttype )
	    return node;
    }
    return NULL;
}


KBNODE
find_kbnode( KBNODE node, int pkttype )
{
    for( ; node; node = node->next ) {
	if( node->pkt->pkttype == pkttype )
	    return node;
    }
    return NULL;
}



/****************
 * Walk through a list of kbnodes. This function returns
 * the next kbnode for each call; before using the function the first
 * time, the caller must set CONTEXT to NULL (This has simply the effect
 * to start with ROOT).
 */
KBNODE
walk_kbnode( KBNODE root, KBNODE *context, int all )
{
    KBNODE n;

    do {
	if( !*context ) {
	    *context = root;
	    n = root;
	}
	else {
	    n = (*context)->next;
	    *context = n;
	}
    } while( !all && n && is_deleted_kbnode(n) );

    return n;
}

void
clear_kbnode_flags( KBNODE n )
{
    for( ; n; n = n->next ) {
	n->flag = 0;
    }
}


/****************
 * Commit changes made to the kblist at ROOT. Note that ROOT my change,
 * and it is therefore passed by reference.
 * The function has the effect of removing all nodes marked as deleted.
 * returns true if any node has been changed
 */
int
commit_kbnode( KBNODE *root )
{
    KBNODE n, nl;
    int changed = 0;

    for( n = *root, nl=NULL; n; n = nl->next ) {
	if( is_deleted_kbnode(n) ) {
	    if( n == *root )
		*root = nl = n->next;
	    else
		nl->next = n->next;
	    if( !is_cloned_kbnode(n) ) {
		free_packet( n->pkt );
		xfree( n->pkt );
	    }
	    free_node( n );
	    changed = 1;
	}
	else
	    nl = n;
    }
    return changed;
}

void
remove_kbnode( KBNODE *root, KBNODE node )
{
    KBNODE n, nl;

    for( n = *root, nl=NULL; n; n = nl->next ) {
	if( n == node ) {
	    if( n == *root )
		*root = nl = n->next;
	    else
		nl->next = n->next;
	    if( !is_cloned_kbnode(n) ) {
		free_packet( n->pkt );
		xfree( n->pkt );
	    }
	    free_node( n );
	}
	else
	    nl = n;
    }
}


/****************
 * Move NODE behind right after WHERE or to the beginning if WHERE is NULL.
 */
void
move_kbnode( KBNODE *root, KBNODE node, KBNODE where )
{
    KBNODE tmp, prev;

    if( !root || !*root || !node )
	return;  /* sanity check */
    for( prev = *root; prev && prev->next != node; prev = prev->next )
	;
    if( !prev )
	return; /* node is not in the list */

    if( !where ) {  /* move node before root */
	if( node == *root ) /* move to itself */
	    return;
	prev->next = node->next;
	node->next = *root;
	*root = node;
	return;
    }
    /* move it after where */
    if( node == where )
	return;
    tmp = node->next;
    node->next = where->next;
    where->next = node;
    prev->next = tmp;
}




void
dump_kbnode( KBNODE node )
{
    for(; node; node = node->next ) {
	const char *s;
	switch( node->pkt->pkttype ) {
	  case 0:		s="empty"; break;
	  case PKT_PUBLIC_KEY:	s="public-key"; break;
	  case PKT_SECRET_KEY:	s="secret-key"; break;
	  case PKT_SECRET_SUBKEY: s= "secret-subkey"; break;
	  case PKT_PUBKEY_ENC:	s="public-enc"; break;
	  case PKT_SIGNATURE:	s="signature"; break;
	  case PKT_ONEPASS_SIG: s="onepass-sig"; break;
	  case PKT_USER_ID:	s="user-id"; break;
	  case PKT_PUBLIC_SUBKEY: s="public-subkey"; break;
	  case PKT_COMMENT:	s="comment"; break;
	  case PKT_RING_TRUST:	s="trust"; break;
	  case PKT_PLAINTEXT:	s="plaintext"; break;
	  case PKT_COMPRESSED:	s="compressed"; break;
	  case PKT_ENCRYPTED:	s="encrypted"; break;
          case PKT_GPG_CONTROL: s="gpg-control"; break;
	  default:		s="unknown"; break;
	}
	fprintf(stderr, "node %p %02x/%02x type=%s",
		node, node->flag, node->private_flag, s);
	if( node->pkt->pkttype == PKT_USER_ID ) {
            PKT_user_id *uid = node->pkt->pkt.user_id;
	    fputs("  \"", stderr);
	    print_string( stderr, uid->name, uid->len, 0 );
	    fprintf (stderr, "\" %c%c%c%c\n",
                     uid->is_expired? 'e':'.',
                     uid->is_revoked? 'r':'.',
                     uid->created?    'v':'.',
                     uid->is_primary? 'p':'.' );
	}
	else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	    fprintf(stderr, "  class=%02x keyid=%08lX ts=%lu\n",
		   node->pkt->pkt.signature->sig_class,
		   (ulong)node->pkt->pkt.signature->keyid[1],
                   (ulong)node->pkt->pkt.signature->timestamp);
	}
	else if( node->pkt->pkttype == PKT_GPG_CONTROL ) {
	    fprintf(stderr, " ctrl=%d len=%u\n",
                    node->pkt->pkt.gpg_control->control,
                    (unsigned int)node->pkt->pkt.gpg_control->datalen);
	}
	else if( node->pkt->pkttype == PKT_PUBLIC_KEY
		 || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
            PKT_public_key *pk = node->pkt->pkt.public_key;
	    fprintf(stderr, "  keyid=%08lX a=%d u=%d %c%c%c%c\n",
                    (ulong)keyid_from_pk( pk, NULL ),
                    pk->pubkey_algo, pk->pubkey_usage,
                    pk->has_expired? 'e':'.',  
                    pk->is_revoked?  'r':'.',  
                    pk->is_valid?    'v':'.',
                    pk->mdc_feature? 'm':'.');
	}
	else
	    fputs("\n", stderr);
    }
}
