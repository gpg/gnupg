/* mpihelp-mul.c  -  MPI helper functions
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

/* If KARATSUBA_THRESHOLD is not already defined, define it to a
 * value which is good on most machines.  */
#ifndef KARATSUBA_THRESHOLD
    #define KARATSUBA_THRESHOLD 32
#endif

/* The code can't handle KARATSUBA_THRESHOLD smaller than 2.  */
#if KARATSUBA_THRESHOLD < 2
    #undef KARATSUBA_THRESHOLD
    #define KARATSUBA_THRESHOLD 2
#endif


#define MPN_MUL_N_RECURSE(prodp, up, vp, size, tspace) \
    do {						\
	if( (size) < KARATSUBA_THRESHOLD )		\
	    mul_n_basecase (prodp, up, vp, size);	\
	else						\
	    mul_n (prodp, up, vp, size, tspace);	\
    } while (0);

#define MPN_SQR_N_RECURSE(prodp, up, size, tspace) \
    do {					    \
	if ((size) < KARATSUBA_THRESHOLD)	    \
	    sqr_n_basecase (prodp, up, size);	    \
	else					    \
	    sqr_n (prodp, up, size, tspace);	    \
    } while (0);



mpi_limb_t
mpihelp_addmul_1( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
		  mpi_size_t s1_size, mpi_limb_t s2_limb)
{
    mpi_limb_t cy_limb;
    mpi_size_t j;
    mpi_limb_t prod_high, prod_low;
    mpi_limb_t x;

    /* The loop counter and index J goes from -SIZE to -1.  This way
     * the loop becomes faster.  */
    j = -s1_size;
    res_ptr -= j;
    s1_ptr -= j;

    cy_limb = 0;
    do {
	umul_ppmm( prod_high, prod_low, s1_ptr[j], s2_limb );

	prod_low += cy_limb;
	cy_limb = (prod_low < cy_limb?1:0) + prod_high;

	x = res_ptr[j];
	prod_low = x + prod_low;
	cy_limb += prod_low < x?1:0;
	res_ptr[j] = prod_low;
    } while ( ++j );
    return cy_limb;
}


mpi_limb_t
mpihelp_submul_1( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr,
		  mpi_size_t s1_size, mpi_limb_t s2_limb)
{
    mpi_limb_t cy_limb;
    mpi_size_t j;
    mpi_limb_t prod_high, prod_low;
    mpi_limb_t x;

    /* The loop counter and index J goes from -SIZE to -1.  This way
     * the loop becomes faster.  */
    j = -s1_size;
    res_ptr -= j;
    s1_ptr -= j;

    cy_limb = 0;
    do {
	umul_ppmm( prod_high, prod_low, s1_ptr[j], s2_limb);

	prod_low += cy_limb;
	cy_limb = (prod_low < cy_limb?1:0) + prod_high;

	x = res_ptr[j];
	prod_low = x - prod_low;
	cy_limb += prod_low > x?1:0;
	res_ptr[j] = prod_low;
    } while( ++j );

    return cy_limb;
}

mpi_limb_t
mpihelp_mul_1( mpi_ptr_t res_ptr, mpi_ptr_t s1_ptr, mpi_size_t s1_size,
						    mpi_limb_t s2_limb)
{
    mpi_limb_t cy_limb;
    mpi_size_t j;
    mpi_limb_t prod_high, prod_low;

    /* The loop counter and index J goes from -S1_SIZE to -1.  This way
     * the loop becomes faster.  */
    j = -s1_size;

    /* Offset the base pointers to compensate for the negative indices.  */
    s1_ptr -= j;
    res_ptr -= j;

    cy_limb = 0;
    do {
	umul_ppmm( prod_high, prod_low, s1_ptr[j], s2_limb );
	prod_low += cy_limb;
	cy_limb = (prod_low < cy_limb?1:0) + prod_high;
	res_ptr[j] = prod_low;
    } while( ++j );

    return cy_limb;
}


/* Multiply the natural numbers u (pointed to by UP) and v (pointed to by VP),
 * both with SIZE limbs, and store the result at PRODP.  2 * SIZE limbs are
 * always stored.  Return the most significant limb.
 *
 * Argument constraints:
 * 1. PRODP != UP and PRODP != VP, i.e. the destination
 *    must be distinct from the multiplier and the multiplicand.
 *
 *
 * Handle simple cases with traditional multiplication.
 *
 * This is the most critical code of multiplication.  All multiplies rely
 * on this, both small and huge.  Small ones arrive here immediately.  Huge
 * ones arrive here as this is the base case for Karatsuba's recursive
 * algorithm below.
 */

static mpi_limb_t
mul_n_basecase( mpi_ptr_t prodp, mpi_ptr_t up,
				 mpi_ptr_t vp, mpi_size_t size)
{
    mpi_size_t i;
    mpi_limb_t cy;
    mpi_limb_t v_limb;

    /* Multiply by the first limb in V separately, as the result can be
     * stored (not added) to PROD.  We also avoid a loop for zeroing.  */
    v_limb = vp[0];
    if( v_limb <= 1 ) {
	if( v_limb == 1 )
	    MPN_COPY( prodp, up, size );
	else
	    MPN_ZERO( prodp, size );
	cy = 0;
    }
    else
	cy = mpihelp_mul_1( prodp, up, size, v_limb );

    prodp[size] = cy;
    prodp++;

    /* For each iteration in the outer loop, multiply one limb from
     * U with one limb from V, and add it to PROD.  */
    for( i = 1; i < size; i++ ) {
	v_limb = vp[i];
	if( v_limb <= 1 ) {
	    cy = 0;
	    if( v_limb == 1 )
	       cy = mpihelp_add_n(prodp, prodp, up, size);
	}
	else
	    cy = mpihelp_addmul_1(prodp, up, size, v_limb);

	prodp[size] = cy;
	prodp++;
    }

    return cy;
}


static void
mul_n( mpi_ptr_t prodp, mpi_ptr_t up, mpi_ptr_t vp,
			mpi_size_t size, mpi_ptr_t tspace )
{
    if( size & 1 ) {
      /* The size is odd, the code code below doesn't handle that.
       * Multiply the least significant (size - 1) limbs with a recursive
       * call, and handle the most significant limb of S1 and S2
       * separately.
       * A slightly faster way to do this would be to make the Karatsuba
       * code below behave as if the size were even, and let it check for
       * odd size in the end.  I.e., in essence move this code to the end.
       * Doing so would save us a recursive call, and potentially make the
       * stack grow a lot less.
       */
      mpi_size_t esize = size - 1;	 /* even size */
      mpi_limb_t cy_limb;

      MPN_MUL_N_RECURSE( prodp, up, vp, esize, tspace );
      cy_limb = mpihelp_addmul_1( prodp + esize, up, esize, vp[esize] );
      prodp[esize + esize] = cy_limb;
      cy_limb = mpihelp_addmul_1( prodp + esize, vp, size, up[esize] );
      prodp[esize + size] = cy_limb;
    }
    else {
	/* Anatolij Alekseevich Karatsuba's divide-and-conquer algorithm.
	 *
	 * Split U in two pieces, U1 and U0, such that
	 * U = U0 + U1*(B**n),
	 * and V in V1 and V0, such that
	 * V = V0 + V1*(B**n).
	 *
	 * UV is then computed recursively using the identity
	 *
	 *	  2n   n	  n			n
	 * UV = (B  + B )U V  +  B (U -U )(V -V )  +  (B + 1)U V
	 *		  1 1	     1	0   0  1	      0 0
	 *
	 * Where B = 2**BITS_PER_MP_LIMB.
	 */
	mpi_size_t hsize = size >> 1;
	mpi_limb_t cy;
	int negflg;

	/* Product H.	   ________________  ________________
	 *		  |_____U1 x V1____||____U0 x V0_____|
	 * Put result in upper part of PROD and pass low part of TSPACE
	 * as new TSPACE.
	 */
	MPN_MUL_N_RECURSE(prodp + size, up + hsize, vp + hsize, hsize, tspace);

	/* Product M.	   ________________
	 *		  |_(U1-U0)(V0-V1)_|
	 */
	if( mpihelp_cmp(up + hsize, up, hsize) >= 0 ) {
	    mpihelp_sub_n(prodp, up + hsize, up, hsize);
	    negflg = 0;
	}
	else {
	    mpihelp_sub_n(prodp, up, up + hsize, hsize);
	    negflg = 1;
	}
	if( mpihelp_cmp(vp + hsize, vp, hsize) >= 0 ) {
	    mpihelp_sub_n(prodp + hsize, vp + hsize, vp, hsize);
	    negflg ^= 1;
	}
	else {
	    mpihelp_sub_n(prodp + hsize, vp, vp + hsize, hsize);
	    /* No change of NEGFLG.  */
	}
	/* Read temporary operands from low part of PROD.
	 * Put result in low part of TSPACE using upper part of TSPACE
	 * as new TSPACE.
	 */
	MPN_MUL_N_RECURSE(tspace, prodp, prodp + hsize, hsize, tspace + size);

	/* Add/copy product H. */
	MPN_COPY (prodp + hsize, prodp + size, hsize);
	cy = mpihelp_add_n( prodp + size, prodp + size,
			    prodp + size + hsize, hsize);

	/* Add product M (if NEGFLG M is a negative number) */
	if(negflg)
	    cy -= mpihelp_sub_n(prodp + hsize, prodp + hsize, tspace, size);
	else
	    cy += mpihelp_add_n(prodp + hsize, prodp + hsize, tspace, size);

	/* Product L.	   ________________  ________________
	 *		  |________________||____U0 x V0_____|
	 * Read temporary operands from low part of PROD.
	 * Put result in low part of TSPACE using upper part of TSPACE
	 * as new TSPACE.
	 */
	MPN_MUL_N_RECURSE(tspace, up, vp, hsize, tspace + size);

	/* Add/copy Product L (twice) */

	cy += mpihelp_add_n(prodp + hsize, prodp + hsize, tspace, size);
	if( cy )
	  mpihelp_add_1(prodp + hsize + size, prodp + hsize + size, hsize, cy);

	MPN_COPY(prodp, tspace, hsize);
	cy = mpihelp_add_n(prodp + hsize, prodp + hsize, tspace + hsize, hsize);
	if( cy )
	    mpihelp_add_1(prodp + size, prodp + size, size, 1);
    }
}


static void
sqr_n_basecase( mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size )
{
    mpi_size_t i;
    mpi_limb_t cy_limb;
    mpi_limb_t v_limb;

    /* Multiply by the first limb in V separately, as the result can be
     * stored (not added) to PROD.  We also avoid a loop for zeroing.  */
    v_limb = up[0];
    if( v_limb <= 1 ) {
	if( v_limb == 1 )
	    MPN_COPY( prodp, up, size );
	else
	    MPN_ZERO(prodp, size);
	cy_limb = 0;
    }
    else
	cy_limb = mpihelp_mul_1( prodp, up, size, v_limb );

    prodp[size] = cy_limb;
    prodp++;

    /* For each iteration in the outer loop, multiply one limb from
     * U with one limb from V, and add it to PROD.  */
    for( i=1; i < size; i++) {
	v_limb = up[i];
	if( v_limb <= 1 ) {
	    cy_limb = 0;
	    if( v_limb == 1 )
		cy_limb = mpihelp_add_n(prodp, prodp, up, size);
	}
	else
	    cy_limb = mpihelp_addmul_1(prodp, up, size, v_limb);

	prodp[size] = cy_limb;
	prodp++;
    }
}


static void
sqr_n( mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t size, mpi_ptr_t tspace)
{
    if( size & 1 ) {
	/* The size is odd, the code code below doesn't handle that.
	 * Multiply the least significant (size - 1) limbs with a recursive
	 * call, and handle the most significant limb of S1 and S2
	 * separately.
	 * A slightly faster way to do this would be to make the Karatsuba
	 * code below behave as if the size were even, and let it check for
	 * odd size in the end.  I.e., in essence move this code to the end.
	 * Doing so would save us a recursive call, and potentially make the
	 * stack grow a lot less.
	 */
	mpi_size_t esize = size - 1;	   /* even size */
	mpi_limb_t cy_limb;

	MPN_SQR_N_RECURSE( prodp, up, esize, tspace );
	cy_limb = mpihelp_addmul_1( prodp + esize, up, esize, up[esize] );
	prodp[esize + esize] = cy_limb;
	cy_limb = mpihelp_addmul_1( prodp + esize, up, size, up[esize] );

	prodp[esize + size] = cy_limb;
    }
    else {
	mpi_size_t hsize = size >> 1;
	mpi_limb_t cy;

	/* Product H.	   ________________  ________________
	 *		  |_____U1 x U1____||____U0 x U0_____|
	 * Put result in upper part of PROD and pass low part of TSPACE
	 * as new TSPACE.
	 */
	MPN_SQR_N_RECURSE(prodp + size, up + hsize, hsize, tspace);

	/* Product M.	   ________________
	 *		  |_(U1-U0)(U0-U1)_|
	 */
	if( mpihelp_cmp( up + hsize, up, hsize) >= 0 )
	    mpihelp_sub_n( prodp, up + hsize, up, hsize);
	else
	    mpihelp_sub_n (prodp, up, up + hsize, hsize);

	/* Read temporary operands from low part of PROD.
	 * Put result in low part of TSPACE using upper part of TSPACE
	 * as new TSPACE.  */
	MPN_SQR_N_RECURSE(tspace, prodp, hsize, tspace + size);

	/* Add/copy product H  */
	MPN_COPY(prodp + hsize, prodp + size, hsize);
	cy = mpihelp_add_n(prodp + size, prodp + size,
			   prodp + size + hsize, hsize);

	/* Add product M (if NEGFLG M is a negative number).  */
	cy -= mpihelp_sub_n (prodp + hsize, prodp + hsize, tspace, size);

	/* Product L.	   ________________  ________________
	 *		  |________________||____U0 x U0_____|
	 * Read temporary operands from low part of PROD.
	 * Put result in low part of TSPACE using upper part of TSPACE
	 * as new TSPACE.  */
	MPN_SQR_N_RECURSE (tspace, up, hsize, tspace + size);

	/* Add/copy Product L (twice).	*/
	cy += mpihelp_add_n (prodp + hsize, prodp + hsize, tspace, size);
	if( cy )
	    mpihelp_add_1(prodp + hsize + size, prodp + hsize + size,
							    hsize, cy);

	MPN_COPY(prodp, tspace, hsize);
	cy = mpihelp_add_n (prodp + hsize, prodp + hsize, tspace + hsize, hsize);
	if( cy )
	    mpihelp_add_1 (prodp + size, prodp + size, size, 1);
    }
}


/* This should be made into an inline function in gmp.h.  */
void
mpihelp_mul_n( mpi_ptr_t prodp, mpi_ptr_t up, mpi_ptr_t vp, mpi_size_t size)
{
    if( up == vp ) {
	if( size < KARATSUBA_THRESHOLD )
	    sqr_n_basecase( prodp, up, size );
	else {
	    mpi_ptr_t tspace;
	    tspace = mpi_alloc_limb_space( 2 * size );
	    sqr_n( prodp, up, size, tspace );
	    mpi_free_limb_space( tspace );
	}
    }
    else {
	if( size < KARATSUBA_THRESHOLD )
	    mul_n_basecase( prodp, up, vp, size );
	else {
	    mpi_ptr_t tspace;
	    tspace = mpi_alloc_limb_space( 2 * size );
	    mul_n (prodp, up, vp, size, tspace);
	    mpi_free_limb_space( tspace );
	}
    }
}


/* Multiply the natural numbers u (pointed to by UP, with USIZE limbs)
 * and v (pointed to by VP, with VSIZE limbs), and store the result at
 * PRODP.  USIZE + VSIZE limbs are always stored, but if the input
 * operands are normalized.  Return the most significant limb of the
 * result.
 *
 * NOTE: The space pointed to by PRODP is overwritten before finished
 * with U and V, so overlap is an error.
 *
 * Argument constraints:
 * 1. USIZE >= VSIZE.
 * 2. PRODP != UP and PRODP != VP, i.e. the destination
 *    must be distinct from the multiplier and the multiplicand.
 */

mpi_limb_t
mpihelp_mul( mpi_ptr_t prodp, mpi_ptr_t up, mpi_size_t usize,
			      mpi_ptr_t vp, mpi_size_t vsize)
{
    mpi_ptr_t prod_endp = prodp + usize + vsize - 1;
    mpi_limb_t cy;
    mpi_ptr_t tspace;

    if( vsize < KARATSUBA_THRESHOLD ) {
	mpi_size_t i;
	mpi_limb_t v_limb;

	if( !vsize )
	    return 0;

	/* Multiply by the first limb in V separately, as the result can be
	 * stored (not added) to PROD.	We also avoid a loop for zeroing.  */
	v_limb = vp[0];
	if( v_limb <= 1 ) {
	    if( v_limb == 1 )
		MPN_COPY( prodp, up, usize );
	    else
		MPN_ZERO( prodp, usize );
	    cy = 0;
	}
	else
	    cy = mpihelp_mul_1( prodp, up, usize, v_limb );

	prodp[usize] = cy;
	prodp++;

	/* For each iteration in the outer loop, multiply one limb from
	 * U with one limb from V, and add it to PROD.	*/
	for( i = 1; i < vsize; i++ ) {
	    v_limb = vp[i];
	    if( v_limb <= 1 ) {
		cy = 0;
		if( v_limb == 1 )
		   cy = mpihelp_add_n(prodp, prodp, up, usize);
	    }
	    else
		cy = mpihelp_addmul_1(prodp, up, usize, v_limb);

	    prodp[usize] = cy;
	    prodp++;
	}

	return cy;
    }

    tspace = mpi_alloc_limb_space( 2 * vsize );
    MPN_MUL_N_RECURSE( prodp, up, vp, vsize, tspace );

    prodp += vsize;
    up += vsize;
    usize -= vsize;
    if( usize >= vsize ) {
	mpi_ptr_t tp = mpi_alloc_limb_space( 2 * vsize );
	do {
	    MPN_MUL_N_RECURSE( tp, up, vp, vsize, tspace );
	    cy = mpihelp_add_n( prodp, prodp, tp, vsize );
	    mpihelp_add_1( prodp + vsize, tp + vsize, vsize, cy );
	    prodp += vsize;
	    up += vsize;
	    usize -= vsize;
	} while( usize >= vsize );
	mpi_free_limb_space( tp );
    }

    if( usize ) {
	mpihelp_mul( tspace, vp, vsize, up, usize );
	cy = mpihelp_add_n( prodp, prodp, tspace, vsize);
	mpihelp_add_1( prodp + vsize, tspace + vsize, usize, cy );
    }

    mpi_free_limb_space( tspace );
    return *prod_endp;
}


