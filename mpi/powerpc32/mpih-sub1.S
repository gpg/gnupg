/* PowerPC-32  sub_n -- Subtract two limb vectors of the same length > 0
 *			and store difference in a third limb vector.
 *
 * Copyright (C) 1992, 1994, 1995, 1998 Free Software Foundation, Inc.
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
 *  mpi_limb_t
 *  mpihelp_sub_n( mpi_ptr_t res_ptr,	(r3)
 *		   mpi_ptr_t s1_ptr,	(r4)
 *		   mpi_ptr_t s2_ptr,	(r5)
 *		   mpi_size_t size)	(r6)
 */

	.toc
	.extern mpihelp_sub_n[DS]
	.extern .mpihelp_sub_n
.csect [PR]
	.align 2
	.globl mpihelp_sub_n
	.globl .mpihelp_sub_n
	.csect mpihelp_sub_n[DS]
mpihelp_sub_n:
	.long .mpihelp_sub_n, TOC[tc0], 0
	.csect [PR]
.mpihelp_sub_n:
	mtctr	6		# copy size into CTR
	lwz	8,0(4)		# load least significant s1 limb
	lwz	0,0(5)		# load least significant s2 limb
	addi	3,3,-4		# offset res_ptr, it's updated before used
	subfc	7,0,8		# add least significant limbs, set cy
	bdz	Lend		# If done, skip loop
Loop:	lwzu	8,4(4)		# load s1 limb and update s1_ptr
	lwzu	0,4(5)		# load s2 limb and update s2_ptr
	stwu	7,4(3)		# store previous limb in load latency slot
	subfe	7,0,8		# add new limbs with cy, set cy
	bdnz	Loop		# decrement CTR and loop back
Lend:	stw	7,4(3)		# store ultimate result limb
	subfe	3,0,0		# load !cy into ...
	subfic	3,3,0		# ... return value register
	blr


