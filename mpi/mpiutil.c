/* mpiutil.c  -  Utility functions for MPI
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
#include <assert.h>

#include "mpi.h"
#include "mpi-internal.h"
#include "memory.h"
#include "util.h"


#ifdef M_DEBUG
  #undef mpi_alloc
  #undef mpi_alloc_secure
  #undef mpi_free
#endif

typedef struct unused_obj {
    struct unused_obj *next;
    unsigned length;
    union {
	MPI mpi;
	mpi_limb_t *limb;
    } u;
} *unused_obj_t;

static unused_obj_t unused_objs;
static unused_obj_t unused_mpis;
static unused_obj_t unused_limbs;


MPI
#ifdef M_DEBUG
mpi_debug_alloc( unsigned nlimbs, const char *info )
#else
mpi_alloc( unsigned nlimbs )
#endif
{
    MPI a;

    if( unused_mpis ) {
	unused_obj_t u;

	if( DBG_MEMORY )
	    log_debug("mpi_alloc(%lu) reusing\n", nlimbs*BITS_PER_MPI_LIMB );
	a = unused_mpis->u.mpi;
	u = unused_mpis;
	unused_mpis = unused_mpis->next;
	u->next = unused_objs;
	unused_objs = u;
    }
    else {
	if( DBG_MEMORY )
	    log_debug("mpi_alloc(%lu) new\n", nlimbs*BITS_PER_MPI_LIMB );
      #ifdef M_DEBUG
	a = m_debug_alloc( sizeof *a, info );
      #else
	a = m_alloc( sizeof *a );
      #endif
    }
  #ifdef M_DEBUG
    a->d = mpi_debug_alloc_limb_space( nlimbs, info );
  #else
    a->d = mpi_alloc_limb_space( nlimbs );
  #endif
    a->alloced = nlimbs;
    a->nlimbs = 0;
    a->sign = 0;
    return a;
}

void
mpi_m_check( MPI a )
{
    m_check(a);
    m_check(a->d);
}

MPI
#ifdef M_DEBUG
mpi_debug_alloc_secure( unsigned nlimbs, const char *info )
#else
mpi_alloc_secure( unsigned nlimbs )
#endif
{
    MPI a;

    a = m_alloc( sizeof *a );
  #ifdef M_DEBUG
    a->d = m_debug_alloc_secure( nlimbs * sizeof(mpi_limb_t), info );
  #else
    a->d = m_alloc_secure( nlimbs * sizeof(mpi_limb_t) );
  #endif
    a->alloced = nlimbs;
    a->nlimbs = 0;
    a->sign = 0;
    return a;
}


mpi_ptr_t
#ifdef M_DEBUG
mpi_debug_alloc_limb_space( unsigned nlimbs, const char *info )
#else
mpi_alloc_limb_space( unsigned nlimbs )
#endif
{
    unused_obj_t u;
    size_t len = nlimbs * sizeof(mpi_limb_t);

    for(u=unused_limbs; u; u = u->next )
	if( u->length >= len ) {
	    u->length = 0;
	    if( DBG_MEMORY )
		log_debug("mpi_alloc_limb_space(%lu) reusing\n", len*8 );
	    return u->u.limb;
	}
    if( DBG_MEMORY )
	log_debug("mpi_alloc_limb_space(%u) new\n", len*8 );
  #ifdef M_DEBUG
    return m_debug_alloc( len, info );
  #else
    return m_alloc( len );
  #endif
}

void
#ifdef M_DEBUG
mpi_debug_free_limb_space( mpi_ptr_t a, const char *info )
#else
mpi_free_limb_space( mpi_ptr_t a )
#endif
{
    unused_obj_t u;

    if( !a )
	return;
    if( DBG_MEMORY )
	log_debug("mpi_free_limb_space of size %lu\n", (ulong)m_size(a)*8 );
    for(u=unused_limbs; u; u = u->next )
	if( !u->length ) {
	    u->length = m_size(a);
	    u->u.limb = a;
	    return;
	}

    if( (u=unused_objs) )
	unused_objs = unused_objs->next;
    else
	u = m_alloc( sizeof *u );
    u->length = m_size(a);
    u->u.limb = a;
    u->next = unused_limbs;
    unused_limbs = u;
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
 * (set to 0) [done by m_realloc()]
 */
void
#ifdef M_DEBUG
mpi_debug_resize( MPI a, unsigned nlimbs, const char *info )
#else
mpi_resize( MPI a, unsigned nlimbs )
#endif
{
    if( nlimbs <= a->alloced )
	return; /* no need to do it */
  #ifdef M_DEBUG
    if( a->d )
	a->d = m_debug_realloc(a->d, nlimbs * sizeof(mpi_limb_t), info );
    else
	a->d = m_debug_alloc_clear( nlimbs * sizeof(mpi_limb_t), info );
  #else
    if( a->d )
	a->d = m_realloc(a->d, nlimbs * sizeof(mpi_limb_t) );
    else
	a->d = m_alloc_clear( nlimbs * sizeof(mpi_limb_t) );
  #endif
    a->alloced = nlimbs;
}

void
mpi_clear( MPI a )
{
    a->nlimbs = 0;
}


void
#ifdef M_DEBUG
mpi_debug_free( MPI a, const char *info )
#else
mpi_free( MPI a )
#endif
{
    unused_obj_t u;

    if( !a )
	return;
    if( DBG_MEMORY )
	log_debug("mpi_free\n" );
  #ifdef M_DEBUG
    mpi_debug_free_limb_space(a->d, info);
  #else
    mpi_free_limb_space(a->d);
  #endif

    if( (u=unused_objs) )
	unused_objs = unused_objs->next;
    else
	u = m_alloc( sizeof *u );
    u->u.mpi = a;
    u->next = unused_mpis;
    unused_mpis = u;
}


MPI
#ifdef M_DEBUG
mpi_debug_copy( MPI a, const char *info )
#else
mpi_copy( MPI a )
#endif
{
    int i;
    MPI b;

    if( a ) {
      #ifdef M_DEBUG
	b = mpi_debug_alloc( a->nlimbs, info );
      #else
	b = mpi_alloc( a->nlimbs );
      #endif
	b->nlimbs = a->nlimbs;
	for(i=0; i < b->nlimbs; i++ )
	    b->d[i] = a->d[i];
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
    w->sign = usign;
}


void
mpi_set_ui( MPI w, unsigned long u)
{
    RESIZE_IF_NEEDED(w, 1);
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
}


MPI
mpi_alloc_set_ui( unsigned long u)
{
  #ifdef M_DEBUG
    MPI w = mpi_debug_alloc(1,"alloc_set_ui");
  #else
    MPI w = mpi_alloc(1);
  #endif
    w->d[0] = u;
    w->nlimbs = u? 1:0;
    w->sign = 0;
    return w;
}


void
mpi_swap( MPI a, MPI b)
{
    MPI x;

    x = a; a = b; b = x;
}


