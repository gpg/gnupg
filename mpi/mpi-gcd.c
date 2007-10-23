/* mpi-gcd.c  -  MPI functions
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
#include "mpi-internal.h"

/****************
 * Find the greatest common divisor G of A and B.
 * Return: true if this 1, false in all other cases
 */
int
mpi_gcd( MPI g, MPI xa, MPI xb )
{
    MPI a, b;

    a = mpi_copy(xa);
    b = mpi_copy(xb);

    /* TAOCP Vol II, 4.5.2, Algorithm A */
    a->sign = 0;
    b->sign = 0;
    while( mpi_cmp_ui( b, 0 ) ) {
	mpi_fdiv_r( g, a, b ); /* g used as temorary variable */
	mpi_set(a,b);
	mpi_set(b,g);
    }
    mpi_set(g, a);

    mpi_free(a);
    mpi_free(b);
    return !mpi_cmp_ui( g, 1);
}



