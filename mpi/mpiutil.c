/* mpiutil.ac  -  Utility functions for MPI
 * Copyright (C) 1998, 1999 Free Software Foundation, Inc.
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

#include "mpi.h"
#include "mpi-internal.h"
#include "memory.h"
#include "util.h"


#ifdef M_DEBUG
#undef mpi_alloc
#undef mpi_alloc_secure
#undef mpi_free
#endif

/****************
 * Note:  It was a bad idea to use the number of limbs to allocate
 *	  because on a alpha the limbs are large but we normally need
 *	  integers of n bits - So we should chnage this to bits (or bytes).
 *
 *	  But mpi_alloc is used in a lot of places :-)
 */
MPI
#ifdef M_DEBUG
mpi_debug_alloc( unsigned nlimbs, const char *info )
#else
mpi_alloc( unsigned nlimbs )
#endif
{
    MPI a;

    if( DBG_MEMORY )
	log_debug("mpi_alloc(%u)\n", nlimbs*BITS_PER_MPI_LIMB );
#ifdef M_DEBUG
    a = m_debug_alloc( sizeof *a, info );
    a->d = nlimbs? mpi_debug_alloc_limb_space( nlimbs, 0, info ) : NULL;
#else
    a = xmalloc( sizeof *a );
    a->d = nlimbs? mpi_alloc_limb_space( nlimbs, 0 ) : NULL;
#endif
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

    if( DBG_MEMORY )
	log_debug("mpi_alloc_secure(%u)\n", nlimbs*BITS_PER_MPI_LIMB );
#ifdef M_DEBUG
    a = m_debug_alloc( sizeof *a, info );
    a->d = nlimbs? mpi_debug_alloc_limb_space( nlimbs, 1, info ) : NULL;
#else
    a = xmalloc( sizeof *a );
    a->d = nlimbs? mpi_alloc_limb_space( nlimbs, 1 ) : NULL;
#endif
    a->alloced = nlimbs;
    a->flags = 1;
    a->nlimbs = 0;
    a->sign = 0;
    a->nbits = 0;
    return a;
}


#if 0
static void *unused_limbs_5;
static void *unused_limbs_32;
static void *unused_limbs_64;
#endif

mpi_ptr_t
#ifdef M_DEBUG
mpi_debug_alloc_limb_space( unsigned nlimbs, int secure, const char *info )
#else
mpi_alloc_limb_space( unsigned nlimbs, int secure )
#endif
{
    size_t len = nlimbs * sizeof(mpi_limb_t);
    mpi_ptr_t p;

    if( DBG_MEMORY )
	log_debug("mpi_alloc_limb_space(%u)\n", (unsigned)len*8 );
#if 0
    if( !secure ) {
	if( nlimbs == 5 && unused_limbs_5 ) {  /* DSA 160 bits */
	    p = unused_limbs_5;
	    unused_limbs_5 = *p;
	    return p;
	}
	else if( nlimbs == 32 && unused_limbs_32 ) {  /* DSA 1024 bits */
	    p = unused_limbs_32;
	    unused_limbs_32 = *p;
	    return p;
	}
	else if( nlimbs == 64 && unused_limbs_64 ) {  /* DSA 2*1024 bits */
	    p = unused_limbs_64;
	    unused_limbs_64 = *p;
	    return p;
	}
    }
#endif

#ifdef M_DEBUG
    p = secure? m_debug_alloc_secure(len, info):m_debug_alloc( len, info );
#else
    p = secure? xmalloc_secure( len ):xmalloc( len );
#endif

    return p;
}

void
#ifdef M_DEBUG
mpi_debug_free_limb_space( mpi_ptr_t a, const char *info )
#else
mpi_free_limb_space( mpi_ptr_t a )
#endif
{
    if( !a )
	return;
    if( DBG_MEMORY )
	log_debug("mpi_free_limb_space of size %lu\n", (ulong)m_size(a)*8 );

#if 0
    if( !m_is_secure(a) ) {
	size_t nlimbs = m_size(a) / 4 ;
	void *p = a;

	if( nlimbs == 5 ) {  /* DSA 160 bits */
	    *a = unused_limbs_5;
	    unused_limbs_5 = a;
	    return;
	}
	else if( nlimbs == 32 ) {  /* DSA 1024 bits */
	    *a = unused_limbs_32;
	    unused_limbs_32 = a;
	    return;
	}
	else if( nlimbs == 64 ) {  /* DSA 2*1024 bits */
	    *a = unused_limbs_64;
	    unused_limbs_64 = a;
	    return;
	}
    }
#endif

    xfree(a);
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
 * (set to 0) [done by xrealloc()]
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
    /* Note: a->secure is not used - instead the realloc functions
     * take care of it. Maybe we should drop a->secure completely
     * and rely on a mpi_is_secure function, which would be
     * a wrapper around m_is_secure
     */
#ifdef M_DEBUG
    if( a->d )
	a->d = m_debug_realloc(a->d, nlimbs * sizeof(mpi_limb_t), info );
    else
	a->d = m_debug_alloc_clear( nlimbs * sizeof(mpi_limb_t), info );
#else
    if( a->d )
	a->d = xrealloc(a->d, nlimbs * sizeof(mpi_limb_t) );
    else
	a->d = xmalloc_clear( nlimbs * sizeof(mpi_limb_t) );
#endif
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
#ifdef M_DEBUG
mpi_debug_free( MPI a, const char *info )
#else
mpi_free( MPI a )
#endif
{
    if( !a )
	return;
    if( DBG_MEMORY )
	log_debug("mpi_free\n" );
    if( a->flags & 4 )
	xfree( a->d );
    else {
#ifdef M_DEBUG
	mpi_debug_free_limb_space(a->d, info);
#else
	mpi_free_limb_space(a->d);
#endif
    }
    if( a->flags & ~7 )
	log_bug("invalid flag value in mpi\n");
    xfree(a);
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
#ifdef M_DEBUG
    bp = mpi_debug_alloc_limb_space( a->nlimbs, 1, "set_secure" );
#else
    bp = mpi_alloc_limb_space( a->nlimbs, 1 );
#endif
    MPN_COPY( bp, ap, a->nlimbs );
    a->d = bp;
#ifdef M_DEBUG
    mpi_debug_free_limb_space(ap, "set_secure");
#else
    mpi_free_limb_space(ap);
#endif
}


MPI
mpi_set_opaque( MPI a, void *p, unsigned int len )
{
    if( !a ) {
#ifdef M_DEBUG
	a = mpi_debug_alloc(0,"alloc_opaque");
#else
	a = mpi_alloc(0);
#endif
    }

    if( a->flags & 4 )
	xfree( a->d );
    else {
#ifdef M_DEBUG
	mpi_debug_free_limb_space(a->d, "alloc_opaque");
#else
	mpi_free_limb_space(a->d);
#endif
    }

    a->d = p;
    a->alloced = 0;
    a->nlimbs = 0;
    a->nbits = len;
    a->flags = 4;
    return a;
}


void *
mpi_get_opaque( MPI a, unsigned int *len )
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
#ifdef M_DEBUG
mpi_debug_copy( MPI a, const char *info )
#else
mpi_copy( MPI a )
#endif
{
    int i;
    MPI b;

    if( a && (a->flags & 4) ) {
	void *p = m_is_secure(a->d)? xmalloc_secure( a->nbits )
				   : xmalloc( a->nbits );
	memcpy( p, a->d, a->nbits );
	b = mpi_set_opaque( NULL, p, a->nbits );
    }
    else if( a ) {
#ifdef M_DEBUG
	b = mpi_is_secure(a)? mpi_debug_alloc_secure( a->nlimbs, info )
			    : mpi_debug_alloc( a->nlimbs, info );
#else
	b = mpi_is_secure(a)? mpi_alloc_secure( a->nlimbs )
			    : mpi_alloc( a->nlimbs );
#endif
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
 * a value as large as the one given in the argument and allocates it
 * with the same flags as A.
 */
MPI
#ifdef M_DEBUG
mpi_debug_alloc_like( MPI a, const char *info )
#else
mpi_alloc_like( MPI a )
#endif
{
    MPI b;

    if( a && (a->flags & 4) ) {
	void *p = m_is_secure(a->d)? xmalloc_secure( a->nbits )
				   : xmalloc( a->nbits );
	memcpy( p, a->d, a->nbits );
	b = mpi_set_opaque( NULL, p, a->nbits );
    }
    else if( a ) {
#ifdef M_DEBUG
	b = mpi_is_secure(a)? mpi_debug_alloc_secure( a->nlimbs, info )
			    : mpi_debug_alloc( a->nlimbs, info );
#else
	b = mpi_is_secure(a)? mpi_alloc_secure( a->nlimbs )
			    : mpi_alloc( a->nlimbs );
#endif
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
    struct gcry_mpi tmp;

    tmp = *a; *a = *b; *b = tmp;
}


int
mpi_get_nlimbs (MPI a)
{
  return a->nlimbs;
}


int 
mpi_is_neg (MPI a)
{
  return a->sign;
}


/* Return the number of limbs to store an MPI which is specified by
   the number of bytes to represent it. */
unsigned int
mpi_nlimb_hint_from_nbytes (unsigned int nbytes)
{
  return (nbytes+BYTES_PER_MPI_LIMB-1) / BYTES_PER_MPI_LIMB;
}

/* Return the number of limbs to store an MPI which is specified by
   the number of bytes to represent it. */
unsigned int
mpi_nlimb_hint_from_nbits (unsigned int nbits)
{
  return (nbits+BITS_PER_MPI_LIMB-1) / BITS_PER_MPI_LIMB;
}

unsigned int
mpi_get_flags (MPI a)
{
  return a->flags;
}
