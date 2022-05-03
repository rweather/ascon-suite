#include "ascon-masked-backend.h"
#if defined(ASCON_MASKED_X2_BACKEND_X86_64)
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
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_x2_permute
	.def	ascon_x2_permute;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_x2_permute
ascon_x2_permute:
#else
	.globl	ascon_x2_permute
	.type	ascon_x2_permute, @function
ascon_x2_permute:
	.cfi_startproc
#endif
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rax, [rdx]
	push	rdx
	mov	rcx, [rdi + 64]
	not	rcx
	mov	r8, rsi
	sub	rsi, 15
	shl	rsi, 4
	sub	rsi, r8
	sub	rsi, 1
	jmp	.L1
.L0:
	push	rsi
	xor	rcx, rsi
	mov	r8, [rdi]
	mov	r9, [rdi + 128]
	xor	r8, r9
	mov	r10, [rdi + 96]
	xor	r9, r10
	mov	r11, [rdi + 32]
	xor	rcx, r11
	mov	r12, r8
	mov	r13, [rdi + 8]
	mov	r14, [rdi + 136]
	xor	r13, r14
	mov	r15, [rdi + 104]
	xor	r14, r15
	mov	rbx, [rdi + 72]
	mov	rbp, [rdi + 40]
	xor	rbx, rbp
	mov	rsi, r13
	mov	[rdi + 128], r9
	mov	rdx, rax
	ror	rdx, 11
	mov	r10, r8
	mov	r9, rbp
	not	r10
	ror	r9, 53
	and	r9, r10
	xor	rax, r9
	and	r10, r11
	xor	rax, r10
	mov	r9, r13
	mov	r10, r11
	and	r9, rbp
	ror	r10, 11
	xor	rdx, r9
	and	r10, r13
	xor	rdx, r10
	mov	r10, r11
	mov	r9, rbx
	not	r10
	ror	r9, 53
	and	r9, r10
	xor	r8, r9
	and	r10, rcx
	xor	r8, r10
	mov	r9, rbp
	mov	r10, rcx
	and	r9, rbx
	ror	r10, 11
	xor	r13, r9
	and	r10, rbp
	xor	r13, r10
	mov	r10, rcx
	mov	r9, r15
	not	r10
	ror	r9, 53
	and	r9, r10
	xor	r11, r9
	mov	[rdi + 136], r14
	mov	r14, [rdi + 96]
	and	r10, r14
	xor	r11, r10
	mov	r9, rbx
	mov	r10, r14
	and	r9, r15
	ror	r10, 11
	xor	rbp, r9
	and	r10, rbx
	xor	rbp, r10
	mov	r10, r14
	mov	[rdi], r8
	mov	r8, [rdi + 136]
	mov	r9, r8
	not	r10
	ror	r9, 53
	and	r9, r10
	xor	rcx, r9
	mov	[rdi + 8], r13
	mov	r13, [rdi + 128]
	and	r10, r13
	xor	rcx, r10
	mov	r9, r15
	mov	r10, r13
	and	r9, r8
	ror	r10, 11
	xor	rbx, r9
	and	r10, r15
	xor	rbx, r10
	mov	r10, r13
	mov	r9, rsi
	not	r10
	ror	r9, 53
	and	r9, r10
	xor	r14, r9
	and	r10, r12
	xor	r14, r10
	mov	r9, r8
	mov	r10, r12
	and	r9, rsi
	ror	r10, 11
	xor	r15, r9
	and	r10, r8
	xor	r15, r10
	xor	r13, rax
	mov	r9, [rdi]
	xor	r11, r9
	xor	r9, r13
	xor	r14, rcx
	xor	r8, rdx
	mov	r10, [rdi + 8]
	xor	rbp, r10
	xor	r10, r8
	xor	r15, rbx
	mov	[rdi + 32], r11
	mov	r12, r10
	mov	rdx, rbp
	mov	rsi, r10
	mov	r11, rbp
	ror	r12, 19
	ror	rdx, 61
	ror	rsi, 28
	ror	r11, 39
	xor	r10, r12
	xor	rbp, rdx
	xor	r10, rsi
	xor	rbp, r11
	mov	r12, rbx
	mov	rdx, r15
	mov	rsi, rbx
	mov	r11, r15
	ror	r12, 1
	ror	rdx, 10
	ror	rsi, 6
	ror	r11, 17
	xor	rbx, r12
	xor	r15, rdx
	xor	rbx, rsi
	xor	r15, r11
	mov	r12, r8
	mov	rdx, r9
	mov	rsi, r8
	mov	r11, r9
	ror	r12, 7
	ror	rdx, 19
	ror	rsi, 41
	ror	r11, 28
	xor	r8, r12
	xor	r9, rdx
	xor	r8, rsi
	xor	r9, r11
	mov	[rdi + 128], r13
	mov	r13, [rdi + 32]
	mov	r12, r13
	mov	rdx, rcx
	mov	rsi, r13
	mov	r11, rcx
	ror	r12, 61
	ror	rdx, 1
	ror	rsi, 39
	ror	r11, 6
	xor	r13, r12
	xor	rcx, rdx
	xor	r13, rsi
	xor	rcx, r11
	mov	r12, r14
	mov	[rdi + 8], r10
	mov	r10, [rdi + 128]
	mov	rdx, r10
	mov	rsi, r14
	mov	r11, r10
	ror	r12, 10
	ror	rdx, 7
	ror	rsi, 17
	ror	r11, 41
	xor	r14, r12
	xor	r10, rdx
	xor	r14, rsi
	xor	r10, r11
	mov	[rdi], r9
	mov	[rdi + 32], r13
	mov	[rdi + 96], r14
	mov	[rdi + 128], r10
	mov	[rdi + 40], rbp
	mov	[rdi + 72], rbx
	mov	[rdi + 104], r15
	mov	[rdi + 136], r8
	pop	rsi
	add	rsi, 15
.L1:
	cmp	rsi, -61
	jl	.L0
	pop	r8
	mov	[r8], rax
	not	rcx
	mov	[rdi + 64], rcx
	mov	rax, 0
	mov	rcx, 0
	mov	rsi, 0
	mov	r8, 0
	mov	r9, 0
	mov	r10, 0
	mov	r11, 0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_x2_permute, .-ascon_x2_permute
#endif

#endif
