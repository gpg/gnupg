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
    n->child = NULL;
    n->flag = 0;
    return n;
}


void
release_kbnode( KBNODE n )
{
    KBNODE n2;

    while( n ) {
	n2 = n->next;
	release_kbnode( n->child );
	free_packet( n->pkt );
	m_free( n );
	n = n2;
    }
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
 * Append NODE to ROOT as child of ROOT
 */
void
add_kbnode_as_child( KBNODE root, KBNODE node )
{
    KBNODE n1;

    if( !(n1=root->child) )
	root->child = node;
    else {
	for( ; n1->next; n1 = n1->next)
	    ;
	n1->next = node;
    }
}

/****************
 * Return the parent node of KBNODE from the tree with ROOT
 */
KBNODE
find_kbparent( KBNODE root, KBNODE node )
{
    KBNODE n, n2;

    for( ; root; root = root->child) {
	for( n = root; n; n = n->next) {
	    for( n2 = n->child; n2; n2 = n2->next ) {
		if( n2 == node )
		    return n;
	    }
	}
    }
    return NULL;
}


/****************
 * Walk through a tree of kbnodes. This functions returns
 * the next kbnode for each call; before using the function the first
 * time, the caller must set CONTEXT to NULL (This has simply the effect
 * to start with ROOT).
 */
KBNODE
walk_kbtree( KBNODE root, KBNODE *context )
{
    KBNODE n;

    if( !*context ) {
	*context = root;
	return root;
    }

    n = *context;
    if( n->child ) {
	n = n->child;
	*context = n;
    }
    else if( n->next ) {
	n = n->next;
	*context = n;
    }
    else if( (n = find_kbparent( root, n )) ) {
	n = n->next;
	*context = n;
    }
    return n;
}

void
clear_kbnode_flags( KBNODE n )
{
    for( ; n; n = n->next ) {
	clear_kbnode_flags( n->child );
	n->flag = 0;
    }
}
