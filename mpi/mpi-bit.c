/* mpi-bit.c  -  MPI bit level fucntions
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
#include <assert.h>
#include "mpi-internal.h"
#include "longlong.h"


#ifdef MPI_INTERNAL_NEED_CLZ_TAB
#ifdef __STDC__
const
#endif
unsigned char
__clz_tab[] =
{
  0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
};
#endif


#define A_LIMB_1 ((mpi_limb_t)1)


/****************
 * Sometimes we have MSL (most significant limbs) which are 0;
 * this is for some reasons not good, so this function removes them.
 */
void
mpi_normalize( MPI a )
{
    if( mpi_is_opaque (a) )
	return;

    for( ; a->nlimbs && !a->d[a->nlimbs-1]; a->nlimbs-- )
	;
}



/****************
 * Return the number of bits in A.
 */
unsigned
mpi_get_nbits( MPI a )
{
    unsigned n;

    mpi_normalize( a );
    if( a->nlimbs ) {
	mpi_limb_t alimb = a->d[a->nlimbs-1];
	if( alimb )
	    count_leading_zeros( n, alimb );
	else
	    n = BITS_PER_MPI_LIMB;
	n = BITS_PER_MPI_LIMB - n + (a->nlimbs-1) * BITS_PER_MPI_LIMB;
    }
    else
	n = 0;
    return n;
}


/****************
 * Test whether bit N is set.
 */
int
mpi_test_bit( MPI a, unsigned n )
{
    unsigned limbno, bitno;
    mpi_limb_t limb;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs )
	return 0; /* too far left: this is a 0 */
    limb = a->d[limbno];
    return (limb & (A_LIMB_1 << bitno))? 1: 0;
}


/****************
 * Set bit N of A.
 */
void
mpi_set_bit( MPI a, unsigned n )
{
    unsigned limbno, bitno;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs ) { /* resize */
	if( a->alloced >= limbno )
	    mpi_resize(a, limbno+1 );
	a->nlimbs = limbno+1;
    }
    a->d[limbno] |= (A_LIMB_1<<bitno);
}

/****************
 * Set bit N of A. and clear all bits above
 */
void
mpi_set_highbit( MPI a, unsigned n )
{
    unsigned limbno, bitno;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs ) { /* resize */
	if( a->alloced >= limbno )
	    mpi_resize(a, limbno+1 );
	a->nlimbs = limbno+1;
    }
    a->d[limbno] |= (A_LIMB_1<<bitno);
    for( bitno++; bitno < BITS_PER_MPI_LIMB; bitno++ )
	a->d[limbno] &= ~(A_LIMB_1 << bitno);
    a->nlimbs = limbno+1;
}

/****************
 * clear bit N of A and all bits above
 */
void
mpi_clear_highbit( MPI a, unsigned n )
{
    unsigned limbno, bitno;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs )
	return; /* not allocated, so need to clear bits :-) */

    for( ; bitno < BITS_PER_MPI_LIMB; bitno++ )
	a->d[limbno] &= ~(A_LIMB_1 << bitno);
    a->nlimbs = limbno+1;
}

/****************
 * Clear bit N of A.
 */
void
mpi_clear_bit( MPI a, unsigned n )
{
    unsigned limbno, bitno;

    limbno = n / BITS_PER_MPI_LIMB;
    bitno  = n % BITS_PER_MPI_LIMB;

    if( limbno >= a->nlimbs )
	return; /* don't need to clear this bit, it's to far to left */
    a->d[limbno] &= ~(A_LIMB_1 << bitno);
}


/****************
 * Shift A by N bits to the right
 * FIXME: should use alloc_limb if X and A are same.
 */
void
mpi_rshift( MPI x, MPI a, unsigned n )
{
    mpi_ptr_t xp;
    mpi_size_t xsize;

    xsize = a->nlimbs;
    x->sign = a->sign;
    RESIZE_IF_NEEDED(x, xsize);
    xp = x->d;

    if( xsize ) {
	mpihelp_rshift( xp, a->d, xsize, n);
	MPN_NORMALIZE( xp, xsize);
    }
    x->nlimbs = xsize;
}


/****************
 * Shift A by COUNT limbs to the left
 * This is used only within the MPI library
 */
void
mpi_lshift_limbs( MPI a, unsigned int count )
{
    mpi_ptr_t ap = a->d;
    int n = a->nlimbs;
    int i;

    if( !count || !n )
	return;

    RESIZE_IF_NEEDED( a, n+count );

    for( i = n-1; i >= 0; i-- )
	ap[i+count] = ap[i];
    for(i=0; i < count; i++ )
	ap[i] = 0;
    a->nlimbs += count;
}


/****************
 * Shift A by COUNT limbs to the right
 * This is used only within the MPI library
 */
void
mpi_rshift_limbs( MPI a, unsigned int count )
{
    mpi_ptr_t ap = a->d;
    mpi_size_t n = a->nlimbs;
    unsigned int i;

    if( count >= n ) {
	a->nlimbs = 0;
	return;
    }

    for( i = 0; i < n - count; i++ )
	ap[i] = ap[i+count];
    ap[i] = 0;
    a->nlimbs -= count;
}


