/* mpiutil.ac  -  Utility functions for MPI
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
#include <assert.h>

#include "mpi.h"
#include "mpi-internal.h"
#include "memory.h"
#include "g10lib.h"

/****************
 * Note:  It was a bad idea to use the number of limbs to allocate
 *	  because on a alpha the limbs are large but we normally need
 *	  integers of n bits - So we should chnage this to bits (or bytes).
 *
 *	  But mpi_alloc is used in a lot of places :-)
 */
MPI
mpi_alloc( unsigned nlimbs )
{
    MPI a;

    if( DBG_MEMORY )
	log_debug("mpi_alloc(%u)\n", nlimbs*BITS_PER_MPI_LIMB );
    a = g10_xmalloc( sizeof *a );
    a->d = nlimbs? mpi_alloc_limb_space( nlimbs, 0 ) : NULL;
    a->alloced = nlimbs;
    a->nlimbs = 0;
    a->sign = 0;
    a->flags = 0;
    a->nbits = 0;
    return a;
}

void
mpi_m_check( MPI a )
{
    g10_check_heap(a);
    g10_check_heap(a->d);
}

MPI
mpi_alloc_secure( unsigned nlimbs )
{
    MPI a;

    if( DBG_MEMORY )
	log_debug("mpi_alloc_secure(%u)\n", nlimbs*BITS_PER_MPI_LIMB );
    a = g10_xmalloc( sizeof *a );
    a->d = nlimbs? mpi_alloc_limb_space( nlimbs, 1 ) : NULL;
    a->alloced = nlimbs;
    a->flags = 1;
    a->nlimbs = 0;
    a->sign = 0;
    a->nbits = 0;
    return a;
}



mpi_ptr_t
mpi_alloc_limb_space( unsigned nlimbs, int secure )
{
    size_t len = nlimbs * sizeof(mpi_limb_t);
    mpi_ptr_t p;

    if( DBG_MEMORY )
	log_debug("mpi_alloc_limb_space(%u)\n", (unsigned)len*8 );

    p = secure? g10_xmalloc_secure( len ) : g10_xmalloc( len );

    return p;
}

void
mpi_free_limb_space( mpi_ptr_t a )
{
    if( !a )
	return;
    if( DBG_MEMORY )
	log_debug("mpi_free_limb_space\n" );

    g10_free(a);
}


void
mpi_assign_limb_space( MPI a, mpi_ptr_t ap, unsigned nlimbs )
{
    mpi_free_limb_space(a->d);
    a->d = ap;
    a->alloced = nlimbs;
}



/****************
 * Resize the array of A to NLIMBS. the additional space is cleared
 * (set to 0) [done by g10_realloc()]
 */
void
mpi_resize( MPI a, unsigned nlimbs )
{
    if( nlimbs <= a->alloced )
	return; /* no need to do it */
    /* Note: a->secure is not used - instead the realloc functions
     * take care of it. Maybe we should drop a->secure completely
     * and rely on a mpi_is_secure function, which would be
     * a wrapper around g10_is_secure
     */
    if( a->d )
	a->d = g10_xrealloc(a->d, nlimbs * sizeof(mpi_limb_t) );
    else  /* FIXME: It may not be allocted in secure memory */
	a->d = g10_xcalloc( nlimbs , sizeof(mpi_limb_t) );
    a->alloced = nlimbs;
}

void
mpi_clear( MPI a )
{
    a->nlimbs = 0;
    a->nbits = 0;
    a->flags = 0;
}


void
mpi_free( MPI a )
{
    if( !a )
	return;
    if( DBG_MEMORY )
	log_debug("mpi_free\n" );
    if( a->flags & 4 )
	g10_free( a->d );
    else {
	mpi_free_limb_space(a->d);
    }
    if( a->flags & ~7 )
	log_bug("invalid flag value in mpi\n");
    g10_free(a);
}


void
mpi_set_secure( MPI a )
{
    mpi_ptr_t ap, bp;

    if( (a->flags & 1) )
	return;
    a->flags |= 1;
    ap = a->d;
    if( !a->nlimbs ) {
	assert(!ap);
	return;
    }
    bp = mpi_alloc_limb_space( a->nlimbs, 1 );
    MPN_COPY( bp, ap, a->nlimbs );
    a->d = bp;
    mpi_free_limb_space(ap);
}


MPI
mpi_set_opaque( MPI a, void *p, int len )
{
    if( !a ) {
	a = mpi_alloc(0);
    }

    if( a->flags & 4 )
	g10_free( a->d );
    else {
	mpi_free_limb_space(a->d);
    }

    a->d = p;
    a->alloced = 0;
    a->nlimbs = 0;
    a->nbits = len;
    a->flags = 4;
    return a;
}


void *
mpi_get_opaque( MPI a, int *len )
{
    if( !(a->flags & 4) )
	log_bug("mpi_get_opaque on normal mpi\n");
    if( len )
	*len = a->nbits;
    return a->d;
}


/****************
 * Note: This copy function should not interpret the MPI
 *	 but copy it transparently.
 */
MPI
mpi_copy( MPI a )
{
    int i;
    MPI b;

    if( a && (a->flags & 4) ) {
	void *p = g10_is_secure(a->d)? g10_xmalloc_secure( a->nbits )
				     : g10_xmalloc( a->nbits );
	memcpy( p, a->d, a->nbits );
	b = mpi_set_opaque( NULL, p, a->nbits );
    }
    else if( a ) {
	b = mpi_is_secure(a)? mpi_alloc_secure( a->nlimbs )
			    : mpi_alloc( a->nlimbs );
	b->nlimbs = a->nlimbs;
	b->sign = a->sign;
	b->flags  = a->flags;
	b->nbits = a->nbits;
	for(i=0; i < b->nlimbs; i++ )
	    b->d[i] = a->d[i];
    }
    else
	b = NULL;
    return b;
}


/****************
 * This function allocates an MPI which is optimized to hold
 * a value as large as the one given in the arhgument and allocates it
 * with the same flags as A.
 */
MPI
mpi_alloc_like( MPI a )
{
    MPI b;

    if( a && (a->flags & 4) ) {
	void *p = g10_is_secure(a->d)? g10_malloc_secure( a->nbits )
				     : g10_malloc( a->nbits );
	memcpy( p, a->d, a->nbits );
	b = mpi_set_opaque( NULL, p, a->nbits );
    }
    else if( a ) {
	b = mpi_is_secure(a)? mpi_alloc_secure( a->nlimbs )
			    : mpi_alloc( a->nlimbs );
	b->nlimbs = 0;
	b->sign = 0;
	b->flags = a->flags;
	b->nbits = 0;
    }
    else
	b = NULL;
    return b;
}


void
mpi_set( MPI w, MPI u)
{
    mpi_ptr_t wp, up;
    mpi_size_t usize = u->nlimbs;
    int usign = u->sign;

    RESIZE_IF_NEEDED(w, usize);
    wp = w->d;
    up = u->d;
    MPN_COPY( wp, up, usize );
    w->nlimbs = usize;
    w->nbits = u->nbits;
    w->flags = u->flags;
    w->sign = usign;
}


void
mpi_set_ui( MPI w, unsigned long u)
{
    RESIZE_IF_NEEDED(w, 1);
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
    w->nbits = 0;
    w->flags = 0;
}


MPI
mpi_alloc_set_ui( unsigned long u)
{
    MPI w = mpi_alloc(1);
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
    return w;
}


void
mpi_swap( MPI a, MPI b)
{
    struct gcry_mpi tmp;

    tmp = *a; *a = *b; *b = tmp;
}

