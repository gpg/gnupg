/* PowerPC-32 submul_1 -- Multiply a limb vector with a limb and subtract
 *			  the result from a second limb vector.
 *
 * Copyright (C) 1995, 1998 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/*******************
 * mpi_limb_t
 * mpihelp_submul_1( mpi_ptr_t res_ptr,      (r3)
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
	.csect .mpihelp_submul_1[PR]
	.align 2
	.globl mpihelp_submul_1
	.globl .mpihelp_submul_1
	.csect mpihelp_submul_1[DS]
mpihelp_submul_1:
	.long .mpihelp_submul_1[PR], TOC[tc0], 0
	.csect .mpihelp_submul_1[PR]
.mpihelp_submul_1:
	mtctr	5

	lwz	0,0(4)
	mullw	7,0,6
	mulhwu	10,0,6
	lwz	9,0(3)
	subfc	8,7,9
	addc	7,7,8		# invert cy (r7 is junk)
	addi	3,3,-4
	bdz	Lend

Loop:	lwzu	0,4(4)
	stwu	8,4(3)
	mullw	8,0,6
	adde	7,8,10
	mulhwu	10,0,6
	lwz	9,4(3)
	addze	10,10
	subfc	8,7,9
	addc	7,7,8		# invert cy (r7 is junk)
	bdnz	Loop

Lend:	stw	8,4(3)
	addze	3,10
	blr


