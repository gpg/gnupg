
; i80586 addmul_1 -- Multiply a limb vector with a limb and add
; the result to a second limb vector.
;
;      Copyright (C) 1992, 1994, 1995, 1996, 1998,
;                    2001 Free Software Foundation, Inc.
;
; This file is part of GnuPG.
;
; GnuPG is free software; you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation; either version 2 of the License, or
; (at your option) any later version.
;
; GnuPG is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software
; Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
;
; Modified versions of the GPG i586 assembler for use with NASM.  This 
; file is part of a native port of Gnu PG for use with Microsoft Visual 
; Studio .net. Ported by Brian Gladman <brg@gladman.uk.net> March 2002.

%define res_ptr	edi
%define s1_ptr	esi
%define size	ecx
%define s2_limb ebp

	global _mpihelp_addmul_1
	
	section	.text
	align	8

_mpihelp_addmul_1:
	push	edi
	push	esi
	push	ebx
	push	ebp
	mov		res_ptr,[esp+20]
	mov		s1_ptr,[esp+24]
	mov		size,[esp+28]
	mov		s2_limb,[esp+32]
	lea		res_ptr,[res_ptr+4*size]
	lea		s1_ptr,[s1_ptr+4*size]
	neg		size
	xor		ebx,ebx
	
	align	8
.1:
	adc		ebx,0
	mov		eax,[s1_ptr+4*size]
	mul		s2_limb
	add		eax,ebx
	mov		ebx,[res_ptr+4*size]
	adc		edx,0
	add		ebx,eax
	mov		[res_ptr+4*size],ebx
	inc		size
	mov		ebx,edx
	jnz		short .1
	adc		ebx,0
	mov		eax,ebx
	pop		ebp
	pop		ebx
	pop		esi
	pop		edi
	ret

	end
