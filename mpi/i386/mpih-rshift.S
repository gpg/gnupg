/* i80386   rshift
 *
 *      Copyright (C) 1992, 1994, 1998, 
 *                    2001, 2002 Free Software Foundation, Inc.
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


#include "sysdep.h"
#include "asm-syntax.h"


/*******************
 * mpi_limb_t
 * mpihelp_rshift( mpi_ptr_t wp,	(sp + 4)
 *		   mpi_ptr_t up,	(sp + 8)
 *		   mpi_size_t usize,	(sp + 12)
 *		   unsigned cnt)	(sp + 16)
 */

.text
	ALIGN (3)
	.globl C_SYMBOL_NAME(mpihelp_rshift)
C_SYMBOL_NAME(mpihelp_rshift:)
	pushl	%edi
	pushl	%esi
	pushl	%ebx

	movl	16(%esp),%edi		/* wp */
	movl	20(%esp),%esi		/* up */
	movl	24(%esp),%edx		/* usize */
	movl	28(%esp),%ecx		/* cnt */

	leal	-4(%edi,%edx,4),%edi
	leal	(%esi,%edx,4),%esi
	negl	%edx

	movl	(%esi,%edx,4),%ebx	/* read least significant limb */
	xorl	%eax,%eax
	shrdl	%ebx,%eax		/* compute carry limb */
	incl	%edx
	jz	Lend2
	pushl	%eax			/* push carry limb onto stack */
	testb	$1,%dl
	jnz	L2			/* enter loop in the middle */
	movl	%ebx,%eax

	ALIGN (3)
Loop2:	movl	 (%esi,%edx,4),%ebx	 /* load next higher limb */
	shrdl	%ebx,%eax		/* compute result limb */
	movl	%eax,(%edi,%edx,4)	/* store it */
	incl	%edx
L2:	movl	(%esi,%edx,4),%eax
	shrdl	%eax,%ebx
	movl	%ebx,(%edi,%edx,4)
	incl	%edx
	jnz	Loop2

	shrl	%cl,%eax		/* compute most significant limb */
	movl	%eax,(%edi)		/* store it */

	popl	%eax			/* pop carry limb */

	popl	%ebx
	popl	%esi
	popl	%edi
	ret

Lend2:	shrl	%cl,%ebx		/* compute most significant limb */
	movl	%ebx,(%edi)		/* store it */

	popl	%ebx
	popl	%esi
	popl	%edi
	ret

