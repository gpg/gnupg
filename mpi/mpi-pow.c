/* mpi-pow.c  -  MPI functions
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
#include "longlong.h"
#include <assert.h>


/****************
 * RES = BASE ^ EXP mod MOD
 */
void
mpi_powm( MPI res, MPI base, MPI exp, MPI mod)
{
    mpi_ptr_t  rp, ep, mp, bp;
    mpi_size_t esize, msize, bsize, rsize;
    int        esign, msign, bsign, rsign;
    mpi_size_t size;
    int mod_shift_cnt;
    int negative_result;
    mpi_ptr_t mp_marker=NULL, bp_marker=NULL, ep_marker=NULL;
    mpi_ptr_t xp_marker=NULL;
    int assign_rp=0;

    esize = exp->nlimbs;
    msize = mod->nlimbs;
    size = 2 * msize;
    esign = exp->sign;
    msign = mod->sign;

    rp = res->d;
    ep = exp->d;

    if( !msize )
	msize = 1 / msize;	    /* provoke a signal */

    if( !esize ) {
	/* Exponent is zero, result is 1 mod MOD, i.e., 1 or 0
	 * depending on if MOD equals 1.  */
	rp[0] = 1;
	res->nlimbs = (msize == 1 && mod->d[0] == 1) ? 0 : 1;
	res->sign = 0;
	goto leave;
    }

    /* Normalize MOD (i.e. make its most significant bit set) as required by
     * mpn_divrem.  This will make the intermediate values in the calculation
     * slightly larger, but the correct result is obtained after a final
     * reduction using the original MOD value.	*/
    mp = mp_marker = mpi_alloc_limb_space(msize);
    count_leading_zeros( mod_shift_cnt, mod->d[msize-1] );
    if( mod_shift_cnt )
	mpihelp_lshift( mp, mod->d, msize, mod_shift_cnt );
    else
	MPN_COPY( mp, mod->d, msize );

    bsize = base->nlimbs;
    bsign = base->sign;
    if( bsize > msize ) { /* The base is larger than the module. Reduce it. */
	/* Allocate (BSIZE + 1) with space for remainder and quotient.
	 * (The quotient is (bsize - msize + 1) limbs.)  */
	bp = bp_marker = mpi_alloc_limb_space( bsize + 1);
	MPN_COPY( bp, base->d, bsize );
	/* We don't care about the quotient, store it above the remainder,
	 * at BP + MSIZE.  */
	mpihelp_divrem( bp + msize, 0, bp, bsize, mp, msize );
	bsize = msize;
	/* Canonicalize the base, since we are going to multiply with it
	 * quite a few times.  */
	MPN_NORMALIZE( bp, bsize );
    }
    else
	bp = base->d;

    if( !bsize ) {
	res->nlimbs = 0;
	res->sign = 0;
	goto leave;
    }

    if( res->alloced < size ) {
	/* We have to allocate more space for RES.  If any of the input
	 * parameters are identical to RES, defer deallocation of the old
	 * space.  */
	if( rp == ep || rp == mp || rp == bp ) {
	    rp = mpi_alloc_limb_space( size );
	    assign_rp = 1;
	}
	else {
	    mpi_resize( res, size );
	    rp = res->d;
	}
    }
    else { /* Make BASE, EXP and MOD not overlap with RES.  */
	if( rp == bp ) {
	    /* RES and BASE are identical.  Allocate temp. space for BASE.  */
	    assert( !bp_marker );
	    bp = bp_marker = mpi_alloc_limb_space( bsize );
	    MPN_COPY(bp, rp, bsize);
	}
	if( rp == ep ) {
	    /* RES and EXP are identical.  Allocate temp. space for EXP.  */
	    ep = ep_marker = mpi_alloc_limb_space( esize );
	    MPN_COPY(ep, rp, esize);
	}
	if( rp == mp ) {
	    /* RES and MOD are identical.  Allocate temporary space for MOD.*/
	    assert( !mp_marker );
	    mp = mp_marker = mpi_alloc_limb_space( msize );
	    MPN_COPY(mp, rp, msize);
	}
    }

    MPN_COPY( rp, bp, bsize );
    rsize = bsize;
    rsign = bsign;

    {
	mpi_size_t i;
	mpi_ptr_t xp = xp_marker = mpi_alloc_limb_space( 2 * (msize + 1) );
	int c;
	mpi_limb_t e;
	mpi_limb_t carry_limb;

	negative_result = (ep[0] & 1) && base->sign;

	i = esize - 1;
	e = ep[i];
	count_leading_zeros (c, e);
	e = (e << c) << 1;     /* shift the exp bits to the left, lose msb */
	c = BITS_PER_MPI_LIMB - 1 - c;

	/* Main loop.
	 *
	 * Make the result be pointed to alternately by XP and RP.  This
	 * helps us avoid block copying, which would otherwise be necessary
	 * with the overlap restrictions of mpihelp_divmod. With 50% probability
	 * the result after this loop will be in the area originally pointed
	 * by RP (==RES->d), and with 50% probability in the area originally
	 * pointed to by XP.
	 */
	for(;;) {
	    while( c ) {
		mpi_ptr_t tp;
		mpi_size_t xsize;

		mpihelp_mul_n(xp, rp, rp, rsize);
		xsize = 2 * rsize;
		if( xsize > msize ) {
		    mpihelp_divrem(xp + msize, 0, xp, xsize, mp, msize);
		    xsize = msize;
		}

		tp = rp; rp = xp; xp = tp;
		rsize = xsize;

		if( (mpi_limb_signed_t)e < 0 ) {
		    mpihelp_mul( xp, rp, rsize, bp, bsize );
		    xsize = rsize + bsize;
		    if( xsize > msize ) {
			mpihelp_divrem(xp + msize, 0, xp, xsize, mp, msize);
			xsize = msize;
		    }

		    tp = rp; rp = xp; xp = tp;
		    rsize = xsize;
		}
		e <<= 1;
		c--;
	    }

	    i--;
	    if( i < 0 )
		break;
	    e = ep[i];
	    c = BITS_PER_MPI_LIMB;
	}

	/* We shifted MOD, the modulo reduction argument, left MOD_SHIFT_CNT
	 * steps.  Adjust the result by reducing it with the original MOD.
	 *
	 * Also make sure the result is put in RES->d (where it already
	 * might be, see above).
	 */
	if( mod_shift_cnt ) {
	    carry_limb = mpihelp_lshift( res->d, rp, rsize, mod_shift_cnt);
	    rp = res->d;
	    if( carry_limb ) {
		rp[rsize] = carry_limb;
		rsize++;
	    }
	}
	else {
	    MPN_COPY( res->d, rp, rsize);
	    rp = res->d;
	}

	if( rsize >= msize ) {
	    mpihelp_divrem(rp + msize, 0, rp, rsize, mp, msize);
	    rsize = msize;
	}

	/* Remove any leading zero words from the result.  */
	if( mod_shift_cnt )
	    mpihelp_rshift( rp, rp, rsize, mod_shift_cnt);
	MPN_NORMALIZE (rp, rsize);
    }

    if( negative_result && rsize ) {
	if( mod_shift_cnt )
	    mpihelp_rshift( mp, mp, msize, mod_shift_cnt);
	mpihelp_sub( rp, mp, msize, rp, rsize);
	rsize = msize;
	rsign = msign;
	MPN_NORMALIZE(rp, rsize);
    }
    res->nlimbs = rsize;
    res->sign = rsign;

  leave:
    if( assign_rp ) mpi_assign_limb_space( res, rp, size );
    if( mp_marker ) mpi_free_limb_space( mp_marker );
    if( bp_marker ) mpi_free_limb_space( bp_marker );
    if( ep_marker ) mpi_free_limb_space( ep_marker );
    if( xp_marker ) mpi_free_limb_space( xp_marker );
}

