/* kbnode.c -  keyblock node utility functions
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
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "packet.h"
#include "keydb.h"



KBNODE
new_kbnode( PACKET *pkt )
{
    KBNODE n = m_alloc( sizeof *n );
    n->next = NULL;
    n->pkt = pkt;
    n->flag = 0;
    n->private_flag=0; /* kludge to delete a node */
    return n;
}


void
release_kbnode( KBNODE n )
{
    KBNODE n2;

    while( n ) {
	n2 = n->next;
	free_packet( n->pkt );
	m_free( n );
	n = n2;
    }
}


/****************
 * Delete NODE from ROOT, ROOT must exist!
 * Note: This does only work with walk_kbnode!!
 */
void
delete_kbnode( KBNODE root, KBNODE node )
{
    node->private_flag |= 1;
}

/****************
 * Append NODE to ROOT, ROOT must exist!
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
 * Insert NODE into the list after root but before a packet with type PKTTYPE
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
	    if( pkttype == n1->next->pkt->pkttype ) {
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

    for(n1=NULL ; root && root != node; root = root->next )
	if( !pkttype || root->pkt->pkttype == pkttype )
	    n1 = root;
    return n1;
}

/****************
 * Ditto, but find the next package.  The behaviour is trivial if
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
		 && (	node->pkt->pkttype == PKT_PUBLIC_CERT
		     || node->pkt->pkttype == PKT_SECRET_CERT ) )
	    return NULL;
	else if( pkttype == PKT_SIGNATURE
		 && (	node->pkt->pkttype == PKT_USER_ID
		     || node->pkt->pkttype == PKT_PUBLIC_CERT
		     || node->pkt->pkttype == PKT_SECRET_CERT ) )
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
 * Walk through a list of kbnodes. This functions returns
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
	    return root;
	}

	n = *context;
	if( n->next ) {
	    n = n->next;
	    *context = n;
	}
    } while( !all && n && (n->private_flag & 1) );

    return n;
}

void
clear_kbnode_flags( KBNODE n )
{
    for( ; n; n = n->next ) {
	n->flag = 0;
    }
}

