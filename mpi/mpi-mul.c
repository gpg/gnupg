/* mpi-mul.c  -  MPI functions
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


void
mpi_mul_ui( MPI prod, MPI mult, unsigned long small_mult )
{
    mpi_size_t size, prod_size;
    mpi_ptr_t  prod_ptr;
    mpi_limb_t cy;
    int sign;

    size = mult->nlimbs;
    sign = mult->sign;

    if( !size || !small_mult ) {
	prod->nlimbs = 0;
	prod->sign = 0;
	return;
    }

    prod_size = size + 1;
    if( prod->alloced < prod_size )
	mpi_resize( prod, prod_size );
    prod_ptr = prod->d;

    cy = mpihelp_mul_1( prod_ptr, mult->d, size, (mpi_limb_t)small_mult );
    if( cy )
	prod_ptr[size++] = cy;
    prod->nlimbs = size;
    prod->sign = sign;
}


void
mpi_mul_2exp( MPI w, MPI u, unsigned long cnt)
{
    mpi_size_t usize, wsize, limb_cnt;
    mpi_ptr_t wp;
    mpi_limb_t wlimb;
    int usign, wsign;

    usize = u->nlimbs;
    usign = u->sign;

    if( !usize ) {
	w->nlimbs = 0;
	w->sign = 0;
	return;
    }

    limb_cnt = cnt / BITS_PER_MPI_LIMB;
    wsize = usize + limb_cnt + 1;
    if( w->alloced < wsize )
	mpi_resize(w, wsize );
    wp = w->d;
    wsize = usize + limb_cnt;
    wsign = usign;

    cnt %= BITS_PER_MPI_LIMB;
    if( cnt ) {
	wlimb = mpihelp_lshift( wp + limb_cnt, u->d, usize, cnt );
	if( wlimb ) {
	    wp[wsize] = wlimb;
	    wsize++;
	}
    }
    else {
	MPN_COPY_DECR( wp + limb_cnt, u->d, usize );
    }

    /* Zero all whole limbs at low end.  Do it here and not before calling
     * mpn_lshift, not to lose for U == W.  */
    MPN_ZERO( wp, limb_cnt );

    w->nlimbs = wsize;
    w->sign = wsign;
}



void
mpi_mul( MPI w, MPI u, MPI v)
{
    mpi_size_t usize, vsize, wsize;
    mpi_ptr_t up, vp, wp;
    mpi_limb_t cy;
    int usign, vsign, sign_product;
    int assign_wp=0;
    mpi_ptr_t tmp_limb=NULL;

    if( u->nlimbs < v->nlimbs ) { /* Swap U and V. */
	usize = v->nlimbs;
	usign = v->sign;
	up    = v->d;
	vsize = u->nlimbs;
	vsign = u->sign;
	vp    = u->d;
    }
    else {
	usize = u->nlimbs;
	usign = u->sign;
	up    = u->d;
	vsize = v->nlimbs;
	vsign = v->sign;
	vp    = v->d;
    }
    sign_product = usign ^ vsign;
    wp = w->d;

    /* Ensure W has space enough to store the result.  */
    wsize = usize + vsize;
    if( w->alloced < wsize ) {
	if( wp == up || wp == vp ) {
	    wp = mpi_alloc_limb_space( wsize );
	    assign_wp = 1;
	}
	else {
	    mpi_resize(w, wsize );
	    wp = w->d;
	}
    }
    else { /* Make U and V not overlap with W.	*/
	if( wp == up ) {
	    /* W and U are identical.  Allocate temporary space for U.	*/
	    up = tmp_limb = mpi_alloc_limb_space( usize );
	    /* Is V identical too?  Keep it identical with U.  */
	    if( wp == vp )
		vp = up;
	    /* Copy to the temporary space.  */
	    MPN_COPY( up, wp, usize );
	}
	else if( wp == vp ) {
	    /* W and V are identical.  Allocate temporary space for V.	*/
	    vp = tmp_limb = mpi_alloc_limb_space( vsize );
	    /* Copy to the temporary space.  */
	    MPN_COPY( vp, wp, vsize );
	}
    }

    if( !vsize )
	wsize = 0;
    else {
	cy = mpihelp_mul( wp, up, usize, vp, vsize );
	wsize -= cy? 0:1;
    }

    if( assign_wp )
	mpi_assign_limb_space( w, wp, wsize );
    w->nlimbs = wsize;
    w->sign = sign_product;
    if( tmp_limb )
	mpi_free_limb_space( tmp_limb );
}


