#include "ascon-masked-backend.h"
#if defined(ASCON_MASKED_X3_BACKEND_X86_64)
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
	.globl	ascon_x3_permute
	.type	ascon_x3_permute, @function
ascon_x3_permute:
	.cfi_startproc
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rax, [rdx]
	mov	rcx, [rdx + 8]
	push	rdx
	mov	r8, [rdi + 64]
	not	r8
	mov	r9, rsi
	sub	rsi, 15
	shl	rsi, 4
	sub	rsi, r9
	sub	rsi, 1
	jmp	.L1
.L0:
	push	rsi
	xor	r8, rsi
	mov	r9, [rdi]
	mov	r10, [rdi + 128]
	xor	r9, r10
	mov	r11, [rdi + 96]
	xor	r10, r11
	mov	r12, [rdi + 32]
	xor	r8, r12
	mov	r13, r9
	mov	r14, [rdi + 8]
	mov	r15, [rdi + 136]
	xor	r14, r15
	mov	rbx, [rdi + 104]
	xor	r15, rbx
	mov	rbp, [rdi + 72]
	mov	rsi, [rdi + 40]
	xor	rbp, rsi
	mov	rdx, r14
	mov	r11, [rdi + 16]
	mov	[rdi + 128], r10
	mov	r10, [rdi + 144]
	xor	r11, r10
	mov	r12, [rdi + 112]
	xor	r10, r12
	mov	[rdi], r9
	mov	r9, [rdi + 80]
	mov	rbx, [rdi + 48]
	xor	r9, rbx
	mov	[rdi + 136], r15
	mov	r15, r11
	mov	[rdi + 72], rbp
	mov	[rdi + 8], r14
	mov	rsi, rax
	mov	rbp, rcx
	ror	rsi, 22
	ror	rbp, 11
	xor	rsi, rbp
	mov	[rdi + 144], r10
	mov	r10, [rdi]
	mov	rbp, r10
	mov	rbx, [rdi + 40]
	mov	r14, rbx
	mov	[rdi + 80], r9
	mov	r9, [rdi + 48]
	mov	r12, r9
	not	rbp
	ror	r14, 53
	ror	r12, 42
	mov	[rdi + 16], r11
	mov	r11, [rdi + 32]
	and	rbp, r11
	and	r14, r10
	and	r12, r10
	xor	rax, rbp
	xor	rax, r14
	xor	rax, r12
	mov	rbx, [rdi + 8]
	mov	rbp, rbx
	mov	r14, r11
	mov	r12, r9
	not	rbp
	ror	r14, 11
	ror	r12, 53
	mov	r10, [rdi + 40]
	and	rbp, r10
	and	r14, rbx
	and	r12, rbx
	xor	rcx, rbp
	xor	rcx, r14
	xor	rcx, r12
	mov	rbp, r11
	mov	r14, r10
	mov	r12, r9
	not	rbp
	ror	rbp, 22
	ror	r14, 11
	mov	rbx, [rdi + 16]
	and	rbp, rbx
	and	r14, rbx
	or	r12, rbx
	xor	rsi, rbp
	xor	rsi, r14
	xor	rsi, r12
	mov	rbp, r11
	mov	r10, [rdi + 72]
	mov	r14, r10
	mov	r9, [rdi + 80]
	mov	r12, r9
	not	rbp
	ror	r14, 53
	ror	r12, 42
	and	rbp, r8
	and	r14, r11
	and	r12, r11
	mov	rbx, [rdi]
	xor	rbx, rbp
	xor	rbx, r14
	xor	rbx, r12
	mov	r10, [rdi + 40]
	mov	rbp, r10
	mov	r14, r8
	mov	r12, r9
	not	rbp
	ror	r14, 11
	ror	r12, 53
	mov	r11, [rdi + 72]
	and	rbp, r11
	and	r14, r10
	and	r12, r10
	mov	[rdi], rbx
	mov	rbx, [rdi + 8]
	xor	rbx, rbp
	xor	rbx, r14
	xor	rbx, r12
	mov	rbp, r8
	mov	r14, r11
	mov	r12, r9
	not	rbp
	ror	rbp, 22
	ror	r14, 11
	mov	r10, [rdi + 48]
	and	rbp, r10
	and	r14, r10
	or	r12, r10
	mov	[rdi + 8], rbx
	mov	rbx, [rdi + 16]
	xor	rbx, rbp
	xor	rbx, r14
	xor	rbx, r12
	mov	rbp, r8
	mov	r11, [rdi + 104]
	mov	r14, r11
	mov	r9, [rdi + 112]
	mov	r12, r9
	not	rbp
	ror	r14, 53
	ror	r12, 42
	mov	r10, [rdi + 96]
	and	rbp, r10
	and	r14, r8
	and	r12, r8
	mov	[rdi + 16], rbx
	mov	rbx, [rdi + 32]
	xor	rbx, rbp
	xor	rbx, r14
	xor	rbx, r12
	mov	r11, [rdi + 72]
	mov	rbp, r11
	mov	r14, r10
	mov	r12, r9
	not	rbp
	ror	r14, 11
	ror	r12, 53
	mov	[rdi + 32], rbx
	mov	rbx, [rdi + 104]
	and	rbp, rbx
	and	r14, r11
	and	r12, r11
	mov	r10, [rdi + 40]
	xor	r10, rbp
	xor	r10, r14
	xor	r10, r12
	mov	r9, [rdi + 96]
	mov	rbp, r9
	mov	r14, rbx
	mov	r11, [rdi + 112]
	mov	r12, r11
	not	rbp
	ror	rbp, 22
	ror	r14, 11
	mov	[rdi + 40], r10
	mov	r10, [rdi + 80]
	and	rbp, r10
	and	r14, r10
	or	r12, r10
	mov	r9, [rdi + 48]
	xor	r9, rbp
	xor	r9, r14
	xor	r9, r12
	mov	rbx, [rdi + 96]
	mov	rbp, rbx
	mov	r11, [rdi + 136]
	mov	r14, r11
	mov	r10, [rdi + 144]
	mov	r12, r10
	not	rbp
	ror	r14, 53
	ror	r12, 42
	mov	[rdi + 48], r9
	mov	r9, [rdi + 128]
	and	rbp, r9
	and	r14, rbx
	and	r12, rbx
	xor	r8, rbp
	xor	r8, r14
	xor	r8, r12
	mov	r11, [rdi + 104]
	mov	rbp, r11
	mov	r14, r9
	mov	r12, r10
	not	rbp
	ror	r14, 11
	ror	r12, 53
	mov	rbx, [rdi + 136]
	and	rbp, rbx
	and	r14, r11
	and	r12, r11
	mov	r9, [rdi + 72]
	xor	r9, rbp
	xor	r9, r14
	xor	r9, r12
	mov	r10, [rdi + 128]
	mov	rbp, r10
	mov	r14, rbx
	mov	r11, [rdi + 144]
	mov	r12, r11
	not	rbp
	ror	rbp, 22
	ror	r14, 11
	mov	[rdi + 72], r9
	mov	r9, [rdi + 112]
	and	rbp, r9
	and	r14, r9
	or	r12, r9
	mov	r10, [rdi + 80]
	xor	r10, rbp
	xor	r10, r14
	xor	r10, r12
	mov	rbx, [rdi + 128]
	mov	rbp, rbx
	mov	r14, rdx
	mov	r12, r15
	not	rbp
	ror	r14, 53
	ror	r12, 42
	and	rbp, r13
	and	r14, rbx
	and	r12, rbx
	mov	r11, [rdi + 96]
	xor	r11, rbp
	xor	r11, r14
	xor	r11, r12
	mov	r9, [rdi + 136]
	mov	rbp, r9
	mov	r14, r13
	mov	r12, r15
	not	rbp
	ror	r14, 11
	ror	r12, 53
	and	rbp, rdx
	and	r14, r9
	and	r12, r9
	mov	[rdi + 80], r10
	mov	r10, [rdi + 104]
	xor	r10, rbp
	xor	r10, r14
	xor	r10, r12
	mov	rbp, r13
	mov	r14, rdx
	mov	r12, r15
	not	rbp
	ror	rbp, 22
	ror	r14, 11
	mov	rbx, [rdi + 144]
	and	rbp, rbx
	and	r14, rbx
	or	r12, rbx
	mov	[rdi + 96], r11
	mov	r11, [rdi + 112]
	xor	r11, rbp
	xor	r11, r14
	xor	r11, r12
	mov	r12, [rdi + 128]
	xor	r12, rax
	mov	r13, [rdi + 32]
	mov	r14, [rdi]
	xor	r13, r14
	xor	r14, r12
	mov	r15, [rdi + 96]
	xor	r15, r8
	xor	r9, rcx
	mov	rbp, [rdi + 40]
	mov	rdx, [rdi + 8]
	xor	rbp, rdx
	xor	rdx, r9
	mov	rbx, [rdi + 72]
	xor	r10, rbx
	mov	[rdi + 112], r11
	mov	r11, [rdi + 144]
	xor	r11, rsi
	mov	[rdi + 32], r13
	mov	r13, [rdi + 48]
	mov	[rdi + 128], r12
	mov	r12, [rdi + 16]
	xor	r13, r12
	xor	r12, r11
	mov	[rdi], r14
	mov	r14, [rdi + 112]
	mov	[rdi + 96], r15
	mov	r15, [rdi + 80]
	xor	r14, r15
	mov	[rdi + 40], rbp
	mov	[rdi + 136], r9
	mov	[rdi + 8], rdx
	mov	rsi, r12
	mov	r9, r13
	mov	rbp, r12
	mov	rdx, r13
	ror	rsi, 19
	ror	r9, 61
	ror	rbp, 28
	ror	rdx, 39
	xor	r12, rsi
	xor	r13, r9
	xor	r12, rbp
	xor	r13, rdx
	mov	rsi, r15
	mov	r9, r14
	mov	rbp, r15
	mov	rdx, r14
	ror	rsi, 1
	ror	r9, 10
	ror	rbp, 6
	ror	rdx, 17
	xor	r15, rsi
	xor	r14, r9
	xor	r15, rbp
	xor	r14, rdx
	mov	rsi, r11
	mov	rbx, [rdi + 8]
	mov	r9, rbx
	mov	rbp, r11
	mov	rdx, rbx
	ror	rsi, 7
	ror	r9, 19
	ror	rbp, 41
	ror	rdx, 28
	xor	r11, rsi
	xor	rbx, r9
	xor	r11, rbp
	xor	rbx, rdx
	mov	[rdi + 104], r10
	mov	r10, [rdi + 40]
	mov	rsi, r10
	mov	[rdi + 16], r12
	mov	r12, [rdi + 72]
	mov	r9, r12
	mov	rbp, r10
	mov	rdx, r12
	ror	rsi, 61
	ror	r9, 1
	ror	rbp, 39
	ror	rdx, 6
	xor	r10, rsi
	xor	r12, r9
	xor	r10, rbp
	xor	r12, rdx
	mov	[rdi + 48], r13
	mov	r13, [rdi + 104]
	mov	rsi, r13
	mov	[rdi + 80], r15
	mov	r15, [rdi + 136]
	mov	r9, r15
	mov	rbp, r13
	mov	rdx, r15
	ror	rsi, 10
	ror	r9, 7
	ror	rbp, 17
	ror	rdx, 41
	xor	r13, rsi
	xor	r15, r9
	xor	r13, rbp
	xor	r15, rdx
	mov	[rdi + 112], r14
	mov	r14, [rdi]
	mov	rsi, r14
	mov	[rdi + 144], r11
	mov	r11, [rdi + 32]
	mov	r9, r11
	mov	rbp, r14
	mov	rdx, r11
	ror	rsi, 19
	ror	r9, 61
	ror	rbp, 28
	ror	rdx, 39
	xor	r14, rsi
	xor	r11, r9
	xor	r14, rbp
	xor	r11, rdx
	mov	rsi, r8
	mov	[rdi + 8], rbx
	mov	rbx, [rdi + 96]
	mov	r9, rbx
	mov	rbp, r8
	mov	rdx, rbx
	ror	rsi, 1
	ror	r9, 10
	ror	rbp, 6
	ror	rdx, 17
	xor	r8, rsi
	xor	rbx, r9
	xor	r8, rbp
	xor	rbx, rdx
	mov	[rdi + 40], r10
	mov	r10, [rdi + 128]
	mov	rsi, r10
	mov	rbp, r10
	ror	rsi, 7
	ror	rbp, 41
	xor	r10, rsi
	xor	r10, rbp
	mov	[rdi], r14
	mov	[rdi + 32], r11
	mov	[rdi + 96], rbx
	mov	[rdi + 128], r10
	mov	[rdi + 72], r12
	mov	[rdi + 104], r13
	mov	[rdi + 136], r15
	pop	rsi
	add	rsi, 15
.L1:
	cmp	rsi, -61
	jl	.L0
	pop	r9
	mov	[r9], rax
	mov	[r9 + 8], rcx
	not	r8
	mov	[rdi + 64], r8
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
	.cfi_endproc
	.size	ascon_x3_permute, .-ascon_x3_permute

#endif
