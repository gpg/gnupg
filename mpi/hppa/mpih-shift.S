/* hppa   rshift, lshift
 *	Copyright (C) 1992, 1994 Free Software Foundation, Inc.
 *	Copyright (C) 1998 Free Software Foundation, Inc.
 *
 * This file is part of GNUPG.
 *
 * GNUPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * Note: This code is heavily based on the GNU MP Library.
 *	 Actually it's the same code with only minor changes in the
 *	 way the data is stored; this is to support the abstraction
 *	 of an optional secure memory allocation which may be used
 *	 to avoid revealing of sensitive data due to paging etc.
 *	 The GNU MP Library itself is published under the LGPL;
 *	 however I decided to publish this code under the plain GPL.
 */



/*******************
 * mpi_limb_t
 * mpihelp_lshift( mpi_ptr_t wp,	(gr26)
 *		   mpi_ptr_t up,	(gr25)
 *		   mpi_size_t usize,	(gr24)
 *		   unsigned cnt)	(gr23)
 */

	.code
	.export 	mpihelp_lshift
mpihelp_lshift
	.proc
	.callinfo	frame=64,no_calls
	.entry

	sh2add		%r24,%r25,%r25
	sh2add		%r24,%r26,%r26
	ldws,mb 	-4(0,%r25),%r22
	subi		32,%r23,%r1
	mtsar		%r1
	addib,= 	-1,%r24,L$0004
	vshd		%r0,%r22,%r28		; compute carry out limb
	ldws,mb 	-4(0,%r25),%r29
	addib,= 	-1,%r24,L$0002
	vshd		%r22,%r29,%r20

L$loop	ldws,mb 	-4(0,%r25),%r22
	stws,mb 	%r20,-4(0,%r26)
	addib,= 	-1,%r24,L$0003
	vshd		%r29,%r22,%r20
	ldws,mb 	-4(0,%r25),%r29
	stws,mb 	%r20,-4(0,%r26)
	addib,<>	-1,%r24,L$loop
	vshd		%r22,%r29,%r20

L$0002	stws,mb 	%r20,-4(0,%r26)
	vshd		%r29,%r0,%r20
	bv		0(%r2)
	stw		%r20,-4(0,%r26)
L$0003	stws,mb 	%r20,-4(0,%r26)
L$0004	vshd		%r22,%r0,%r20
	bv		0(%r2)
	stw		%r20,-4(0,%r26)

	.exit
	.procend



/*******************
 * mpi_limb_t
 * mpihelp_rshift( mpi_ptr_t wp,       (gr26)
 *		   mpi_ptr_t up,       (gr25)
 *		   mpi_size_t usize,   (gr24)
 *		   unsigned cnt)       (gr23)
 */

	.code
	.export 	mpihelp_rshift
mpihelp_rshift
	.proc
	.callinfo	frame=64,no_calls
	.entry

	ldws,ma 	4(0,%r25),%r22
	mtsar		%r23
	addib,= 	-1,%r24,L$r004
	vshd		%r22,%r0,%r28		; compute carry out limb
	ldws,ma 	4(0,%r25),%r29
	addib,= 	-1,%r24,L$r002
	vshd		%r29,%r22,%r20

L$roop	ldws,ma 	4(0,%r25),%r22
	stws,ma 	%r20,4(0,%r26)
	addib,= 	-1,%r24,L$r003
	vshd		%r22,%r29,%r20
	ldws,ma 	4(0,%r25),%r29
	stws,ma 	%r20,4(0,%r26)
	addib,<>	-1,%r24,L$roop
	vshd		%r29,%r22,%r20

L$r002	stws,ma 	%r20,4(0,%r26)
	vshd		%r0,%r29,%r20
	bv		0(%r2)
	stw		%r20,0(0,%r26)
L$r003	stws,ma 	%r20,4(0,%r26)
L$r004	vshd		%r0,%r22,%r20
	bv		0(%r2)
	stw		%r20,0(0,%r26)

	.exit
	.procend

