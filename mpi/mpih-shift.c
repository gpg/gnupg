/* mpihelp-shift.c  -  MPI helper functions
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

/* Shift U (pointed to by UP and USIZE digits long) CNT bits to the left
 * and store the USIZE least significant digits of the result at WP.
 * Return the bits shifted out from the most significant digit.
 *
 * Argument constraints:
 * 1. 0 < CNT < BITS_PER_MP_LIMB
 * 2. If the result is to be written over the input, WP must be >= UP.
 */

mpi_limb_t
mpihelp_lshift( mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize,
					    unsigned int cnt)
{
    mpi_limb_t high_limb, low_limb;
    unsigned sh_1, sh_2;
    mpi_size_t i;
    mpi_limb_t retval;

    sh_1 = cnt;
    wp += 1;
    sh_2 = BITS_PER_MPI_LIMB - sh_1;
    i = usize - 1;
    low_limb = up[i];
    retval = low_limb >> sh_2;
    high_limb = low_limb;
    while( --i >= 0 ) {
	low_limb = up[i];
	wp[i] = (high_limb << sh_1) | (low_limb >> sh_2);
	high_limb = low_limb;
    }
    wp[i] = high_limb << sh_1;

    return retval;
}


/* Shift U (pointed to by UP and USIZE limbs long) CNT bits to the right
 * and store the USIZE least significant limbs of the result at WP.
 * The bits shifted out to the right are returned.
 *
 * Argument constraints:
 * 1. 0 < CNT < BITS_PER_MP_LIMB
 * 2. If the result is to be written over the input, WP must be <= UP.
 */

mpi_limb_t
mpihelp_rshift( mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize, unsigned cnt)
{
    mpi_limb_t high_limb, low_limb;
    unsigned sh_1, sh_2;
    mpi_size_t i;
    mpi_limb_t retval;

    sh_1 = cnt;
    wp -= 1;
    sh_2 = BITS_PER_MPI_LIMB - sh_1;
    high_limb = up[0];
    retval = high_limb << sh_2;
    low_limb = high_limb;
    for( i=1; i < usize; i++) {
	high_limb = up[i];
	wp[i] = (low_limb >> sh_1) | (high_limb << sh_2);
	low_limb = high_limb;
    }
    wp[i] = low_limb >> sh_1;

    return retval;
}

