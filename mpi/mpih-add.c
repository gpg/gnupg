/* mpihelp-add.c  -  MPI helper functions
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

#include "mpi-internal.h"

/****************
 * Add to S1_PTR with size S1_SIZE the limb S2_LIMB and
 * store the result in RES_PTR. Return the carry
 * S1_SIZE must be > 0.
 */
/*_EXTERN_INLINE */
mpi_limb_t
mpihelp_add_1( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
	       mpi_size_t s1_size, mpi_limb_t s2_limb)
{
    mpi_limb_t x;

    x = *s1_ptr++;
    s2_limb += x;
    *res_ptr++ = s2_limb;
    if( s2_limb < x ) { /* sum is less than the left operand: handle carry */
	while( --s1_size ) {
	    x = *s1_ptr++ + 1;	/* add carry */
	    *res_ptr++ = x;	/* and store */
	    if( x )		/* not 0 (no overflow): we can stop */
		goto leave;
	}
	return 1; /* return carry (size of s1 to small) */
    }

  leave:
    if( res_ptr != s1_ptr ) { /* not the same variable */
	mpi_size_t i;	       /* copy the rest */
	for( i=0; i < s1_size-1; i++ )
	    res_ptr[i] = s1_ptr[i];
    }
    return 0; /* no carry */
}


/* FIXME: this should be done in assembly */
mpi_limb_t
mpihelp_add_n( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
	       mpi_ptr_t s2_ptr, mpi_size_t size)
{
    mpi_limb_t x, y, cy;
    mpi_size_t j;

    /* The loop counter and index J goes from -SIZE to -1.  This way
       the loop becomes faster.  */
    j = -size;

    /* Offset the base pointers to compensate for the negative indices. */
    s1_ptr -= j;
    s2_ptr -= j;
    res_ptr -= j;

    cy = 0;
    do {
	y = s2_ptr[j];
	x = s1_ptr[j];
	y += cy;		  /* add previous carry to one addend */
	cy = y < cy? 1:0;	  /* get out carry from that addition */
	y += x; 		  /* add other addend */
	cy += y < x? 1:0;	  /* get out carry from that add, combine */
	res_ptr[j] = y;
    } while( ++j );

    return cy;
}


/*_EXTERN_INLINE*/
mpi_limb_t
mpihelp_add(mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr, mpi_size_t s1_size,
			       mpi_ptr_t s2_ptr, mpi_size_t s2_size)
{
    mpi_limb_t cy = 0;

    if( s2_size )
	cy = mpihelp_add_n( res_ptr, s1_ptr, s2_ptr, s2_size );

    if( s1_size - s2_size )
	cy = mpihelp_add_1( res_ptr + s2_size, s1_ptr + s2_size,
			    s1_size - s2_size, cy);
    return cy;
}

