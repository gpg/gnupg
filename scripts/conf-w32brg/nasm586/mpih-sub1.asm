
; i80586 sub_n -- Sub two limb vectors of the same length > 0 and store
; sum in a third limb vector.
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

	global	_mpihelp_sub_n

	section	.text
	align	8
	
_mpihelp_sub_n:
    push    edi
    push    esi
    push    ebx
    push    ebp
    mov     edi,[20+esp]
    mov     esi,[24+esp]
    mov     ebp,[28+esp]
    mov     ecx,[32+esp]
    mov     ebx,[ebp]
    dec     ecx
    mov     edx,ecx
    shr     ecx,3
    and     edx,7
    test    ecx,ecx
    jz      short .2
    push    edx
    
    align	8
.1:	mov     eax,[28+edi]
    lea     edi,[32+edi]     
	mov     eax,[esi]
    mov     edx,[4+esi]
    sbb     eax,ebx
    mov     ebx,[4+ebp]
    sbb     edx,ebx
    mov     ebx,[8+ebp]
    mov     [-32+edi],eax
    mov     [-28+edi],edx
	mov     eax,[8+esi]
    mov     edx,[12+esi]
    sbb     eax,ebx
    mov     ebx,[12+ebp]
    sbb     edx,ebx
    mov     ebx,[16+ebp]
    mov     [-24+edi],eax
    mov     [-20+edi],edx
	mov     eax,[16+esi]
    mov     edx,[20+esi]
    sbb     eax,ebx
    mov     ebx,[20+ebp]
    sbb     edx,ebx
    mov     ebx,[24+ebp]
    mov     [-16+edi],eax
    mov     [-12+edi],edx
	mov     eax,[24+esi]
    mov     edx,[28+esi]
    sbb     eax,ebx
    mov     ebx,[28+ebp]
    sbb     edx,ebx
    mov     ebx,[32+ebp]
    mov     [-8+edi],eax
    mov     [-4+edi],edx
    lea     esi,[32+esi]
    lea     ebp,[32+ebp]
    dec     ecx
    jnz     short .1
    pop     edx
.2: dec     edx
	js      short .4
    inc     edx
.3:	lea     edi,[4+edi]
    mov     eax,[esi]
    sbb     eax,ebx
    mov     ebx,[4+ebp]
    mov     [-4+edi],eax
    lea     esi,[4+esi]
    lea     ebp,[4+ebp]
    dec     edx
    jnz     short .3
.4:	mov     eax,[esi]
    sbb     eax,ebx
    mov     [edi],eax
    sbb     eax,eax
    neg     eax
    pop     ebp
    pop     ebx
    pop     esi
    pop     edi
    ret

	end
