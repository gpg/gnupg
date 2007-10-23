/* mpi-mpow.c  -  MPI functions
 * Copyright (C) 1998, 1999, 2000 Free Software Foundation, Inc.
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
#include "longlong.h"
#include <assert.h>

static int
build_index( MPI *exparray, int k, int i, int t )
{
    int j, bitno;
    int idx = 0;

    bitno = t-i;
    for(j=k-1; j >= 0; j-- ) {
	idx <<= 1;
	if( mpi_test_bit( exparray[j], bitno ) )
	    idx |= 1;
    }
    return idx;
}

/****************
 * RES = (BASE[0] ^ EXP[0]) *  (BASE[1] ^ EXP[1]) * ... * mod M
 */
void
mpi_mulpowm( MPI res, MPI *basearray, MPI *exparray, MPI m)
{
    int k;	/* number of elements */
    int t;	/* bit size of largest exponent */
    int i, j, idx;
    MPI *G;	/* table with precomputed values of size 2^k */
    MPI tmp;

    for(k=0; basearray[k]; k++ )
	;
    assert(k);
    for(t=0, i=0; (tmp=exparray[i]); i++ ) {
	j = mpi_get_nbits(tmp);
	if( j > t )
	    t = j;
    }
    assert(i==k);
    assert(t);
    assert( k < 10 );

    G = xmalloc_clear( (1<<k) * sizeof *G );
    /* and calculate */
    tmp =  mpi_alloc( mpi_get_nlimbs(m)+1 );
    mpi_set_ui( res, 1 );
    for(i = 1; i <= t; i++ ) {
	mpi_mulm(tmp, res, res, m );
	idx = build_index( exparray, k, i, t );
	assert( idx >= 0 && idx < (1<<k) );
	if( !G[idx] ) {
	    if( !idx )
		 G[0] = mpi_alloc_set_ui( 1 );
	    else {
		for(j=0; j < k; j++ ) {
		    if( (idx & (1<<j) ) ) {
			if( !G[idx] )
			    G[idx] = mpi_copy( basearray[j] );
			else
			    mpi_mulm( G[idx], G[idx], basearray[j], m );
		    }
		}
		if( !G[idx] )
		    G[idx] = mpi_alloc(0);
	    }
	}
	mpi_mulm(res, tmp, G[idx], m );
    }

    /* cleanup */
    mpi_free(tmp);
    for(i=0; i < (1<<k); i++ )
	mpi_free(G[i]);
    xfree(G);
}
