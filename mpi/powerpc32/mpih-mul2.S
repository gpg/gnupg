/* PowerPC-32 addmul_1 -- Multiply a limb vector with a limb and add
 *			  the result to a second limb vector.
 * Copyright (C) 1993, 1994, 1995, 1997, 1998 Free Software Foundation, Inc.
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

#include "sysdep.h"
#include "asm-syntax.h"


#ifndef USE_PPC_PATCHES

/*******************
 * mpi_limb_t
 * mpihelp_addmul_1( mpi_ptr_t res_ptr,      (r3)
 *		     mpi_ptr_t s1_ptr,	     (r4)
 *		     mpi_size_t s1_size,     (r5)
 *		     mpi_limb_t s2_limb)     (r6)
 *
 * This is a fairly straightforward implementation.  The timing of the PC601
 * is hard to understand, so I will wait to optimize this until I have some
 * hardware to play with.
 *
 * The code trivially generalizes to 64 bit limbs for the PC620.
 */


	.toc
	.csect .mpihelp_addmul_1[PR]
	.align 2
	.globl mpihelp_addmul_1
	.globl .mpihelp_addmul_1
	.csect mpihelp_addmul_1[DS]
mpihelp_addmul_1:
	.long .mpihelp_addmul_1[PR], TOC[tc0], 0
	.csect .mpihelp_addmul_1[PR]
.mpihelp_addmul_1:
	mtctr	5

	lwz	0,0(4)
	mullw	7,0,6
	mulhwu	10,0,6
	lwz	9,0(3)
	addc	8,7,9
	addi	3,3,-4
	bdz	Lend

Loop:	lwzu	0,4(4)
	stwu	8,4(3)
	mullw	8,0,6
	adde	7,8,10
	mulhwu	10,0,6
	lwz	9,4(3)
	addze	10,10
	addc	8,7,9
	bdnz	Loop

Lend:	stw	8,4(3)
	addze	3,10
	blr

#else

/* mp_limb_t mpn_addmul_1 (mp_ptr res_ptr, mp_srcptr s1_ptr,
			   mp_size_t s1_size, mp_limb_t s2_limb)
   Calculate res+s1*s2 and put result back in res; return carry.  */
ENTRY(mpihelp_addmul_1)
       mtctr   %r5

       lwz     %r0,0(%r4)
       mullw   %r7,%r0,%r6
       mulhwu  %r10,%r0,%r6
       lwz     %r9,0(%r3)
       addc    %r8,%r7,%r9
       addi    %r3,%r3,-4	       /* adjust res_ptr */
       bdz     1f

0:     lwzu    %r0,4(%r4)
       stwu    %r8,4(%r3)
       mullw   %r8,%r0,%r6
       adde    %r7,%r8,%r10
       mulhwu  %r10,%r0,%r6
       lwz     %r9,4(%r3)
       addze   %r10,%r10
       addc    %r8,%r7,%r9
       bdnz    0b

1:     stw     %r8,4(%r3)
       addze   %r3,%r10
       blr
END(mpihelp_addmul_1)
#endif
