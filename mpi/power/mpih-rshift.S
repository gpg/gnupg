/* IBM POWER rshift
 *
 *      Copyright (C) 1992, 1994, 1999 Free Software Foundation, Inc.
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


/*
# INPUT PARAMETERS
# res_ptr	r3
# s_ptr 	r4
# size		r5
# cnt		r6
*/

	.toc
	.extern mpihelp_rshift[DS]
	.extern .mpihelp_rshift
.csect [PR]
	.align 2
	.globl mpihelp_rshift
	.globl .mpihelp_rshift
	.csect mpihelp_rshift[DS]
mpihelp_rshift:
	.long .mpihelp_rshift, TOC[tc0], 0
	.csect [PR]
.mpihelp_rshift:
	sfi	8,6,32
	mtctr	5		# put limb count in CTR loop register
	l	0,0(4)		# read least significant limb
	ai	9,3,-4		# adjust res_ptr since it's offset in the stu:s
	sle	3,0,8		# compute carry limb, and init MQ register
	bdz	Lend2		# if just one limb, skip loop
	lu	0,4(4)		# read 2:nd least significant limb
	sleq	7,0,8		# compute least significant limb of result
	bdz	Lend		# if just two limb, skip loop
Loop:	lu	0,4(4)		# load next higher limb
	stu	7,4(9)		# store previous result during read latency
	sleq	7,0,8		# compute result limb
	bdn	Loop		# loop back until CTR is zero
Lend:	stu	7,4(9)		# store 2:nd most significant limb
Lend2:	sre	7,0,6		# compute most significant limb
	st	7,4(9)		# store it
	br


