
; 80586 lshift
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

	global	_mpihelp_lshift

	section	.text
	align	8

_mpihelp_lshift:
	push    edi
	push    esi
	push    ebx
	push    ebp
	mov     edi,[20+esp]
	mov     esi,[24+esp]
	mov     ebp,[28+esp]
	mov     ecx,[32+esp]
	cmp		ecx,1
    jne     short .1
    lea     eax,[4+esi]
    cmp     eax,edi
    jnc     .6
    lea     eax,[esi+ebp*4]
    cmp     edi,eax
    jnc     .6

.1: lea     edi,[-4+edi+ebp*4]
    lea     esi,[-4+esi+ebp*4]

    mov     edx,[esi]
    sub     esi, 4
    xor     eax,eax
    shld    eax,edx,cl
    push    eax
    dec     ebp
    push    ebp
    shr     ebp,3
    jz      short .3
    mov     eax, [edi]
    
    align	4
.2: mov     eax,[-28+edi]
    mov     ebx,edx
    mov     eax,[esi]
    mov     edx,[-4+esi]
    shld    ebx,eax,cl
    shld    eax,edx,cl
    mov     [edi],ebx
    mov     [-4+edi],eax
    mov     ebx,[-8+esi]
    mov     eax,[-12+esi]
    shld    edx,ebx,cl
    shld    ebx,eax,cl
    mov     [-8+edi],edx
    mov     [-12+edi],ebx
    mov     edx,[-16+esi]
    mov     ebx,[-20+esi]
    shld    eax,edx,cl
    shld    edx,ebx,cl
    mov     [-16+edi],eax
    mov     [-20+edi],edx
    mov     eax,[-24+esi]
    mov     edx,[-28+esi]
    shld    ebx,eax,cl
    shld    eax,edx,cl
    mov     [-24+edi],ebx
    mov     [-28+edi],eax
    sub     esi,32
    sub     edi,32
    dec     ebp
    jnz     short .2

.3: pop     ebp
    and     ebp,7
    jz      short .5
.4: mov     eax,[esi]
    shld    edx,eax,cl
    mov     [edi],edx
    mov     edx,eax
    sub     esi,4
    sub     edi,4
    dec     ebp
    jnz     short .4

.5: shl     edx,cl
    mov     [edi],edx
    pop     eax
    pop     ebp
    pop     ebx
    pop     esi
    pop     edi
    ret

.6:	mov     edx,[esi]
    add     esi,4
    dec     ebp
    push    ebp
    shr     ebp,3
    add     edx,edx
    inc     ebp
    dec     ebp
    jz      short .8
    mov     eax, [edi]
    
    align	4
.7: mov     eax,[28+edi]
    mov     ebx,edx
    mov     eax,[esi]
    mov     edx,[4+esi]
    adc     eax,eax
    mov     [edi],ebx
    adc     edx,edx
    mov     [4+edi],eax
    mov     ebx,[8+esi]
    mov     eax,[12+esi]
    adc     ebx,ebx
    mov     [8+edi],edx
    adc     eax,eax
    mov     [12+edi],ebx
    mov     edx,[16+esi]
    mov     ebx,[20+esi]
    adc     edx,edx
    mov     [16+edi],eax
    adc     ebx,ebx
    mov     [20+edi],edx
    mov     eax,[24+esi]
    mov     edx,[28+esi]
    adc     eax,eax
    mov     [24+edi],ebx
    adc     edx,edx
    mov     [28+edi],eax
    lea     esi,[32+esi]
    lea     edi,[32+edi]
    dec     ebp
    jnz     short .7

.8: pop     ebp
    sbb     eax,eax
    and     ebp,7
    jz      short .10
    add     eax,eax
.9: mov     ebx,edx
    mov     edx,[esi]
    adc     edx,edx
    mov     [edi],ebx
    lea     esi,[4+esi]
    lea     edi,[4+edi]
    dec     ebp
    jnz     short .9
    jmp     short .11
.10:add     eax,eax
.11:mov     [edi],edx
    sbb     eax,eax
    neg     eax

    pop     ebp
    pop     ebx
    pop     esi
    pop     edi
    ret

	end
