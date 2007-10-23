/* mpi-mul.c  -  MPI functions
 *	Copyright (C) 1994, 1996 Free Software Foundation, Inc.
 *	Copyright (C) 1998, 2001 Free Software Foundation, Inc.
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
 *
 * Note: This code is heavily based on the GNU MP Library.
 *	 Actually it's the same code with only minor changes in the
 *	 way the data is stored; this is to support the abstraction
 *	 of an optional secure memory allocation which may be used
 *	 to avoid revealing of sensitive data due to paging etc.
 *	 The GNU MP Library itself is published under the LGPL;
 *	 however I decided to publish this code under the plain GPL.
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
    int usign, vsign, usecure, vsecure, sign_product;
    int assign_wp=0;
    mpi_ptr_t tmp_limb=NULL;


    if( u->nlimbs < v->nlimbs ) { /* Swap U and V. */
	usize = v->nlimbs;
	usign = v->sign;
	usecure = mpi_is_secure(v);
	up    = v->d;
	vsize = u->nlimbs;
	vsign = u->sign;
	vsecure = mpi_is_secure(u);
	vp    = u->d;
    }
    else {
	usize = u->nlimbs;
	usign = u->sign;
	usecure = mpi_is_secure(u);
	up    = u->d;
	vsize = v->nlimbs;
	vsign = v->sign;
	vsecure = mpi_is_secure(v);
	vp    = v->d;
    }
    sign_product = usign ^ vsign;
    wp = w->d;

    /* Ensure W has space enough to store the result.  */
    wsize = usize + vsize;
    if ( !mpi_is_secure (w) && (mpi_is_secure (u) || mpi_is_secure (v)) ) {
        /* w is not allocated in secure space but u or v is.  To make sure
         * that no temporray results are stored in w, we temporary use 
         * a newly allocated limb space for w */
        wp = mpi_alloc_limb_space( wsize, 1 );
        assign_wp = 2; /* mark it as 2 so that we can later copy it back to
                        * mormal memory */
    }
    else if( w->alloced < wsize ) {
	if( wp == up || wp == vp ) {
	    wp = mpi_alloc_limb_space( wsize, mpi_is_secure(w) );
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
	    up = tmp_limb = mpi_alloc_limb_space( usize, usecure  );
	    /* Is V identical too?  Keep it identical with U.  */
	    if( wp == vp )
		vp = up;
	    /* Copy to the temporary space.  */
	    MPN_COPY( up, wp, usize );
	}
	else if( wp == vp ) {
	    /* W and V are identical.  Allocate temporary space for V.	*/
	    vp = tmp_limb = mpi_alloc_limb_space( vsize, vsecure );
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

    if( assign_wp ) {
        if (assign_wp == 2) {
            /* copy the temp wp from secure memory back to normal memory */
	    mpi_ptr_t tmp_wp = mpi_alloc_limb_space (wsize, 0);
	    MPN_COPY (tmp_wp, wp, wsize);
            mpi_free_limb_space (wp);
            wp = tmp_wp;
        }
	mpi_assign_limb_space( w, wp, wsize );
    }
    w->nlimbs = wsize;
    w->sign = sign_product;
    if( tmp_limb )
	mpi_free_limb_space( tmp_limb );
}


void
mpi_mulm( MPI w, MPI u, MPI v, MPI m)
{
    mpi_mul(w, u, v);
    mpi_fdiv_r( w, w, m );
}

