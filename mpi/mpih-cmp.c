/* mpihelp-sub.c  -  MPI helper functions
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
 * Compare OP1_PTR/OP1_SIZE with OP2_PTR/OP2_SIZE.
 * There are no restrictions on the relative sizes of
 * the two arguments.
 * Return 1 if OP1 > OP2, 0 if they are equal, and -1 if OP1 < OP2.
 */
int
mpihelp_cmp( mpi_ptr_t op1_ptr, mpi_ptr_t op2_ptr, mpi_size_t size )
{
    mpi_size_t i;
    mpi_limb_t op1_word, op2_word;

    for( i = size - 1; i >= 0 ; i--) {
	op1_word = op1_ptr[i];
	op2_word = op2_ptr[i];
	if( op1_word != op2_word )
	    goto diff;
    }
    return 0;

  diff:
    /* This can *not* be simplified to
     *	 op2_word - op2_word
     * since that expression might give signed overflow.  */
    return (op1_word > op2_word) ? 1 : -1;
}

