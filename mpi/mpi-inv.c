/* mpi-inv.c  -  MPI functions
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
 * Calculate the multiplicative inverse X of U mod V
 * That is: Find the solution for
 *		1 = (u*x) mod v
 * This has only a unique solution if U and V are relatively prime.
 * Returns 0 if a solution was found.
 */
int
mpi_inv_mod( MPI x, MPI u, MPI v )
{
  #if 0
    /* Extended Euclid's algorithm (See TAOPC Vol II, 4.52. Alg X) */
    MPI u1, u2, u3, v1, v2, v3, q, t1, t2, t3;

    u1 = mpi_alloc_set_ui(1);
    u2 = mpi_alloc_set_ui(0);
    u3 = mpi_copy(u);
    v1 = mpi_alloc_set_ui(0);
    v2 = mpi_alloc_set_ui(1);
    v3 = mpi_copy(v);
    q  = mpi_alloc( mpi_get_nlimbs(u) );
    t1 = mpi_alloc( mpi_get_nlimbs(u) );
    t2 = mpi_alloc( mpi_get_nlimbs(u) );
    t3 = mpi_alloc( mpi_get_nlimbs(u) );
    while( mpi_cmp_ui( v3, 0 ) ) {
      /*log_debug("----------------------\n");
	log_mpidump("q =", u1);
	log_mpidump("u1=", u1);
	log_mpidump("u2=", u2);
	log_mpidump("u3=", u3);
	log_mpidump("v1=", v1);
	log_mpidump("v2=", v2);
	log_mpidump("v3=", v3); */
	mpi_fdiv_q( q, u3, v3 );
	mpi_mul(t1, v1, q); mpi_mul(t2, v2, q); mpi_mul(t3, v3, q);
	mpi_sub(t1, u1, t1); mpi_sub(t2, u2, t2); mpi_sub(t3, u3, t3);

	mpi_set(u1, v1); mpi_set(u2, v2); mpi_set(u3, v3);
	mpi_set(v1, t1); mpi_set(v2, t2); mpi_set(v3, t3);
    }
    mpi_set(x, u3);

    mpi_free(u1);
    mpi_free(u2);
    mpi_free(u3);
    mpi_free(v1);
    mpi_free(v2);
    mpi_free(v3);
    mpi_free(q);
    mpi_free(t1);
    mpi_free(t2);
    mpi_free(t3);
  #endif

    /*****************************
     *	1. Init:   g0 = u  g1 = v  v0  = 0   v1 = 1
     *	2. Test:   if g1 is 0 terminate. Result = v0 < 0: v0 + n
     *						    else: v0
     *	3. Divide: div,rem = g0 / g1
     *		   t1 = v0 - div * v1
     *		   v0 = v1
     *		   v1 = t1
     *		   g0 = g1
     *		   g1 = rem
     *	   continue with step 2.
     */
    MPI g0, g1, v0, v1, div, rem, t1;

    g0 = mpi_copy(v);
    g1 = mpi_copy(u);
    v0 = mpi_alloc_set_ui( 0 );
    v1 = mpi_alloc_set_ui( 1 );
    div = mpi_alloc(mpi_get_nlimbs(v));
    rem = mpi_alloc(mpi_get_nlimbs(v));
    t1	= mpi_alloc(mpi_get_nlimbs(v));
    while( mpi_cmp_ui( g1, 0) ) {
	mpi_fdiv_qr(div, rem, g0, g1);
	mpi_mul(t1, div, v1);
	mpi_sub(t1, v0, t1);
	mpi_set(v0, v1);
	mpi_set(v1, t1);
	mpi_set(g0, g1);
	mpi_set(g1, rem);

    }
    if( mpi_cmp_ui( v0, 0) < 0 )
	mpi_add( x, v0, v);
    else
	mpi_set( x, v0);

    mpi_free(g0);
    mpi_free(g1);
    mpi_free(v0);
    mpi_free(v1);
    mpi_free(div);
    mpi_free(rem);
    mpi_free(t1);
    return 0;
}



