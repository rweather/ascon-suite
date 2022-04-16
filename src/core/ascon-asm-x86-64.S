#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_X86_64)
/*
 * Copyright (C) 2022 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

	.intel_syntax noprefix
	.text
	.p2align 4,,15
	.globl	ascon_permute
	.type	ascon_permute, @function
ascon_permute:
	.cfi_startproc
	push	rbx
	push	r12
	push	r13
	mov	rax, [rdi]
	mov	rcx, [rdi + 8]
	mov	rdx, [rdi + 16]
	mov	r8, [rdi + 24]
	mov	r9, [rdi + 32]
	not	rdx
	cmp	rsi, 12
	jge	.L13
	lea	rbx, [rip + .L14]
	movsxd	rsi, [rbx + rsi*4]
	add	rsi, rbx
	jmp	rsi
.L13:
	jmp	.L12
	.section	.rodata
	.align	4
	.L14:
	.long	.L0-.L14
	.long	.L1-.L14
	.long	.L2-.L14
	.long	.L3-.L14
	.long	.L4-.L14
	.long	.L5-.L14
	.long	.L6-.L14
	.long	.L7-.L14
	.long	.L8-.L14
	.long	.L9-.L14
	.long	.L10-.L14
	.long	.L11-.L14
	.text
	.p2align	4,,10
	.p2align	3
.L0:
	xor	rdx, -241
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L1:
	xor	rdx, -226
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L2:
	xor	rdx, -211
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L3:
	xor	rdx, -196
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L4:
	xor	rdx, -181
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L5:
	xor	rdx, -166
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L6:
	xor	rdx, -151
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L7:
	xor	rdx, -136
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L8:
	xor	rdx, -121
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L9:
	xor	rdx, -106
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L10:
	xor	rdx, -91
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L11:
	xor	rdx, -76
	xor	rax, r9
	xor	r9, r8
	xor	rdx, rcx
	mov	rbx, rax
	mov	rsi, rcx
	mov	r10, rdx
	mov	r11, r8
	mov	r12, r9
	not	rbx
	not	rsi
	not	r10
	not	r11
	not	r12
	and	rbx, rcx
	and	rsi, rdx
	and	r10, r8
	and	r11, r9
	and	r12, rax
	xor	rax, rsi
	xor	rcx, r10
	xor	rdx, r11
	xor	r8, r12
	xor	r9, rbx
	xor	rcx, rax
	xor	rax, r9
	xor	r8, rdx
	mov	rbx, rax
	mov	rsi, rax
	mov	r10, rcx
	mov	r11, rcx
	mov	r12, rdx
	mov	r13, rdx
	ror	rbx, 19
	ror	rsi, 28
	ror	r10, 61
	ror	r11, 39
	ror	r12, 1
	ror	r13, 6
	xor	rax, rbx
	xor	rax, rsi
	xor	rcx, r10
	xor	rcx, r11
	xor	rdx, r12
	xor	rdx, r13
	mov	rbx, r8
	mov	rsi, r8
	mov	r10, r9
	mov	r11, r9
	ror	rbx, 10
	ror	rsi, 17
	ror	r10, 7
	ror	r11, 41
	xor	r8, rbx
	xor	r8, rsi
	xor	r9, r10
	xor	r9, r11
.L12:
	not	rdx
	mov	[rdi], rax
	mov	[rdi + 8], rcx
	mov	[rdi + 16], rdx
	mov	[rdi + 24], r8
	mov	[rdi + 32], r9
	pop	r13
	pop	r12
	pop	rbx
	ret
	.cfi_endproc
	.size	ascon_permute, .-ascon_permute
	.p2align 4,,15
	.globl	ascon_backend_free
	.type	ascon_backend_free, @function
ascon_backend_free:
	.cfi_startproc
	mov	rax, 0
	mov	rcx, 0
	mov	rsi, 0
	mov	r8, 0
	mov	r9, 0
	mov	r10, 0
	mov	r11, 0
	ret
	.cfi_endproc
	.size	ascon_backend_free, .-ascon_backend_free

#endif
