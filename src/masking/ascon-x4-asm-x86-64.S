#include "ascon-masked-backend.h"
#if defined(ASCON_MASKED_X4_BACKEND_X86_64)
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
	.globl	ascon_x4_permute
	.def	ascon_x4_permute;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_x4_permute
ascon_x4_permute:
#else
	.globl	ascon_x4_permute
	.type	ascon_x4_permute, @function
ascon_x4_permute:
	.cfi_startproc
#endif
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rax, [rdx]
	mov	rcx, [rdx + 8]
	mov	r8, [rdx + 16]
	push	rdx
	mov	r9, [rdi + 64]
	not	r9
	mov	r10, rsi
	sub	rsi, 15
	shl	rsi, 4
	sub	rsi, r10
	sub	rsi, 1
	jmp	.L1
.L0:
	push	rsi
	mov	r10, [rdi]
	mov	r11, [rdi + 128]
	xor	r10, r11
	xor	r9, rsi
	mov	r12, [rdi + 96]
	xor	r11, r12
	mov	r13, [rdi + 32]
	xor	r9, r13
	mov	r14, r10
	mov	r15, [rdi + 8]
	mov	rbx, [rdi + 136]
	xor	r15, rbx
	mov	rbp, [rdi + 104]
	xor	rbx, rbp
	mov	rsi, [rdi + 72]
	mov	rdx, [rdi + 40]
	xor	rsi, rdx
	mov	r12, r15
	mov	[rdi + 128], r11
	mov	r11, [rdi + 16]
	mov	r13, [rdi + 144]
	xor	r11, r13
	mov	[rdi], r10
	mov	r10, [rdi + 112]
	xor	r13, r10
	mov	rbp, [rdi + 80]
	mov	[rdi + 136], rbx
	mov	rbx, [rdi + 48]
	xor	rbp, rbx
	mov	rdx, r11
	mov	[rdi + 72], rsi
	mov	rsi, [rdi + 24]
	mov	[rdi + 8], r15
	mov	r15, [rdi + 152]
	xor	rsi, r15
	mov	r10, [rdi + 120]
	xor	r15, r10
	mov	[rdi + 144], r13
	mov	r13, [rdi + 88]
	mov	rbx, [rdi + 56]
	xor	r13, rbx
	mov	[rdi + 80], rbp
	mov	rbp, rsi
	mov	[rdi + 16], r11
	mov	[rdi + 152], r15
	mov	r11, rax
	mov	r10, rcx
	mov	r15, r8
	ror	r11, 33
	ror	r10, 22
	ror	r15, 11
	xor	r11, r10
	xor	r11, r15
	mov	[rdi + 88], r13
	mov	r13, [rdi]
	mov	r10, r13
	mov	[rdi + 24], rsi
	mov	rsi, [rdi + 8]
	mov	r15, rsi
	mov	r13, [rdi + 16]
	mov	rbx, r13
	not	r10
	ror	r15, 53
	ror	rbx, 42
	mov	rsi, [rdi + 32]
	and	r10, rsi
	and	r15, rsi
	and	rbx, rsi
	xor	rax, r10
	xor	rax, r15
	xor	rax, rbx
	mov	r13, [rdi + 24]
	mov	r10, r13
	mov	rsi, [rdi]
	mov	r15, rsi
	mov	r13, [rdi + 8]
	mov	rbx, r13
	ror	r10, 31
	not	r15
	mov	rsi, [rdi + 32]
	and	r10, rsi
	ror	r15, 11
	mov	r13, [rdi + 40]
	and	rbx, r13
	and	r15, r13
	xor	rax, r10
	xor	rcx, r15
	xor	rcx, rbx
	mov	rsi, [rdi + 16]
	mov	r10, rsi
	mov	r13, [rdi + 24]
	mov	r15, r13
	mov	rsi, [rdi]
	mov	rbx, rsi
	ror	r10, 53
	not	rbx
	ror	r15, 42
	ror	rbx, 22
	mov	r13, [rdi + 40]
	and	r10, r13
	and	r15, r13
	mov	rsi, [rdi + 48]
	and	rbx, rsi
	xor	rcx, r10
	xor	rcx, r15
	xor	r8, rbx
	mov	r13, [rdi + 8]
	mov	r10, r13
	mov	rsi, [rdi + 16]
	mov	r15, rsi
	mov	r13, [rdi + 24]
	mov	rbx, r13
	ror	r10, 11
	ror	rbx, 53
	mov	rsi, [rdi + 48]
	and	r10, rsi
	and	r15, rsi
	and	rbx, rsi
	xor	r8, r10
	xor	r8, r15
	xor	r8, rbx
	mov	r13, [rdi]
	mov	r10, r13
	mov	rsi, [rdi + 8]
	mov	r15, rsi
	mov	r13, [rdi + 16]
	mov	rbx, r13
	not	r10
	ror	r15, 22
	ror	rbx, 11
	ror	r10, 33
	mov	rsi, [rdi + 56]
	and	r15, rsi
	and	rbx, rsi
	and	r10, rsi
	xor	r11, r15
	xor	r11, rbx
	xor	r11, r10
	mov	r13, [rdi + 24]
	mov	r15, r13
	and	r15, rsi
	xor	r11, r15
	mov	r13, [rdi + 32]
	mov	r10, r13
	mov	rsi, [rdi + 40]
	mov	r15, rsi
	mov	r13, [rdi + 48]
	mov	rbx, r13
	not	r10
	ror	r15, 53
	ror	rbx, 42
	and	r10, r9
	and	r15, r9
	and	rbx, r9
	mov	rsi, [rdi]
	xor	rsi, r10
	xor	rsi, r15
	xor	rsi, rbx
	mov	r13, [rdi + 56]
	mov	r10, r13
	mov	[rdi], rsi
	mov	rsi, [rdi + 32]
	mov	r15, rsi
	mov	r13, [rdi + 40]
	mov	rbx, r13
	ror	r10, 31
	not	r15
	and	r10, r9
	ror	r15, 11
	mov	rsi, [rdi + 72]
	and	rbx, rsi
	and	r15, rsi
	mov	r13, [rdi]
	xor	r13, r10
	mov	rsi, [rdi + 8]
	xor	rsi, r15
	xor	rsi, rbx
	mov	[rdi], r13
	mov	r13, [rdi + 48]
	mov	r10, r13
	mov	[rdi + 8], rsi
	mov	rsi, [rdi + 56]
	mov	r15, rsi
	mov	r13, [rdi + 32]
	mov	rbx, r13
	ror	r10, 53
	not	rbx
	ror	r15, 42
	ror	rbx, 22
	mov	rsi, [rdi + 72]
	and	r10, rsi
	and	r15, rsi
	mov	r13, [rdi + 80]
	and	rbx, r13
	mov	rsi, [rdi + 8]
	xor	rsi, r10
	xor	rsi, r15
	mov	r13, [rdi + 16]
	xor	r13, rbx
	mov	[rdi + 8], rsi
	mov	rsi, [rdi + 40]
	mov	r10, rsi
	mov	[rdi + 16], r13
	mov	r13, [rdi + 48]
	mov	r15, r13
	mov	rsi, [rdi + 56]
	mov	rbx, rsi
	ror	r10, 11
	ror	rbx, 53
	mov	r13, [rdi + 80]
	and	r10, r13
	and	r15, r13
	and	rbx, r13
	mov	rsi, [rdi + 16]
	xor	rsi, r10
	xor	rsi, r15
	xor	rsi, rbx
	mov	r13, [rdi + 32]
	mov	r10, r13
	mov	[rdi + 16], rsi
	mov	rsi, [rdi + 40]
	mov	r15, rsi
	mov	r13, [rdi + 48]
	mov	rbx, r13
	not	r10
	ror	r15, 22
	ror	rbx, 11
	ror	r10, 33
	mov	rsi, [rdi + 88]
	and	r15, rsi
	and	rbx, rsi
	and	r10, rsi
	mov	r13, [rdi + 24]
	xor	r13, r15
	xor	r13, rbx
	xor	r13, r10
	mov	rsi, [rdi + 56]
	mov	r15, rsi
	mov	[rdi + 24], r13
	mov	r13, [rdi + 88]
	and	r15, r13
	mov	rsi, [rdi + 24]
	xor	rsi, r15
	mov	r10, r9
	mov	r13, [rdi + 72]
	mov	r15, r13
	mov	[rdi + 24], rsi
	mov	rsi, [rdi + 80]
	mov	rbx, rsi
	not	r10
	ror	r15, 53
	ror	rbx, 42
	mov	r13, [rdi + 96]
	and	r10, r13
	and	r15, r13
	and	rbx, r13
	mov	rsi, [rdi + 32]
	xor	rsi, r10
	xor	rsi, r15
	xor	rsi, rbx
	mov	r13, [rdi + 88]
	mov	r10, r13
	mov	r15, r9
	mov	[rdi + 32], rsi
	mov	rsi, [rdi + 72]
	mov	rbx, rsi
	ror	r10, 31
	not	r15
	mov	r13, [rdi + 96]
	and	r10, r13
	ror	r15, 11
	mov	rsi, [rdi + 104]
	and	rbx, rsi
	and	r15, rsi
	mov	r13, [rdi + 32]
	xor	r13, r10
	mov	rsi, [rdi + 40]
	xor	rsi, r15
	xor	rsi, rbx
	mov	[rdi + 32], r13
	mov	r13, [rdi + 80]
	mov	r10, r13
	mov	[rdi + 40], rsi
	mov	rsi, [rdi + 88]
	mov	r15, rsi
	mov	rbx, r9
	ror	r10, 53
	not	rbx
	ror	r15, 42
	ror	rbx, 22
	mov	r13, [rdi + 104]
	and	r10, r13
	and	r15, r13
	mov	rsi, [rdi + 112]
	and	rbx, rsi
	mov	r13, [rdi + 40]
	xor	r13, r10
	xor	r13, r15
	mov	rsi, [rdi + 48]
	xor	rsi, rbx
	mov	[rdi + 40], r13
	mov	r13, [rdi + 72]
	mov	r10, r13
	mov	[rdi + 48], rsi
	mov	rsi, [rdi + 80]
	mov	r15, rsi
	mov	r13, [rdi + 88]
	mov	rbx, r13
	ror	r10, 11
	ror	rbx, 53
	mov	rsi, [rdi + 112]
	and	r10, rsi
	and	r15, rsi
	and	rbx, rsi
	mov	r13, [rdi + 48]
	xor	r13, r10
	xor	r13, r15
	xor	r13, rbx
	mov	r10, r9
	mov	rsi, [rdi + 72]
	mov	r15, rsi
	mov	[rdi + 48], r13
	mov	r13, [rdi + 80]
	mov	rbx, r13
	not	r10
	ror	r15, 22
	ror	rbx, 11
	ror	r10, 33
	mov	rsi, [rdi + 120]
	and	r15, rsi
	and	rbx, rsi
	and	r10, rsi
	mov	r13, [rdi + 56]
	xor	r13, r15
	xor	r13, rbx
	xor	r13, r10
	mov	rsi, [rdi + 88]
	mov	r15, rsi
	mov	[rdi + 56], r13
	mov	r13, [rdi + 120]
	and	r15, r13
	mov	rsi, [rdi + 56]
	xor	rsi, r15
	mov	r13, [rdi + 96]
	mov	r10, r13
	mov	[rdi + 56], rsi
	mov	rsi, [rdi + 104]
	mov	r15, rsi
	mov	r13, [rdi + 112]
	mov	rbx, r13
	not	r10
	ror	r15, 53
	ror	rbx, 42
	mov	rsi, [rdi + 128]
	and	r10, rsi
	and	r15, rsi
	and	rbx, rsi
	xor	r9, r10
	xor	r9, r15
	xor	r9, rbx
	mov	r13, [rdi + 120]
	mov	r10, r13
	mov	rsi, [rdi + 96]
	mov	r15, rsi
	mov	r13, [rdi + 104]
	mov	rbx, r13
	ror	r10, 31
	not	r15
	mov	rsi, [rdi + 128]
	and	r10, rsi
	ror	r15, 11
	mov	r13, [rdi + 136]
	and	rbx, r13
	and	r15, r13
	xor	r9, r10
	mov	rsi, [rdi + 72]
	xor	rsi, r15
	xor	rsi, rbx
	mov	r13, [rdi + 112]
	mov	r10, r13
	mov	[rdi + 72], rsi
	mov	rsi, [rdi + 120]
	mov	r15, rsi
	mov	r13, [rdi + 96]
	mov	rbx, r13
	ror	r10, 53
	not	rbx
	ror	r15, 42
	ror	rbx, 22
	mov	rsi, [rdi + 136]
	and	r10, rsi
	and	r15, rsi
	mov	r13, [rdi + 144]
	and	rbx, r13
	mov	rsi, [rdi + 72]
	xor	rsi, r10
	xor	rsi, r15
	mov	r13, [rdi + 80]
	xor	r13, rbx
	mov	[rdi + 72], rsi
	mov	rsi, [rdi + 104]
	mov	r10, rsi
	mov	[rdi + 80], r13
	mov	r13, [rdi + 112]
	mov	r15, r13
	mov	rsi, [rdi + 120]
	mov	rbx, rsi
	ror	r10, 11
	ror	rbx, 53
	mov	r13, [rdi + 144]
	and	r10, r13
	and	r15, r13
	and	rbx, r13
	mov	rsi, [rdi + 80]
	xor	rsi, r10
	xor	rsi, r15
	xor	rsi, rbx
	mov	r13, [rdi + 96]
	mov	r10, r13
	mov	[rdi + 80], rsi
	mov	rsi, [rdi + 104]
	mov	r15, rsi
	mov	r13, [rdi + 112]
	mov	rbx, r13
	not	r10
	ror	r15, 22
	ror	rbx, 11
	ror	r10, 33
	mov	rsi, [rdi + 152]
	and	r15, rsi
	and	rbx, rsi
	and	r10, rsi
	mov	r13, [rdi + 88]
	xor	r13, r15
	xor	r13, rbx
	xor	r13, r10
	mov	rsi, [rdi + 120]
	mov	r15, rsi
	mov	[rdi + 88], r13
	mov	r13, [rdi + 152]
	and	r15, r13
	mov	rsi, [rdi + 88]
	xor	rsi, r15
	mov	r13, [rdi + 128]
	mov	r10, r13
	mov	[rdi + 88], rsi
	mov	rsi, [rdi + 136]
	mov	r15, rsi
	mov	r13, [rdi + 144]
	mov	rbx, r13
	not	r10
	ror	r15, 53
	ror	rbx, 42
	and	r10, r14
	and	r15, r14
	and	rbx, r14
	mov	rsi, [rdi + 96]
	xor	rsi, r10
	xor	rsi, r15
	xor	rsi, rbx
	mov	r13, [rdi + 152]
	mov	r10, r13
	mov	[rdi + 96], rsi
	mov	rsi, [rdi + 128]
	mov	r15, rsi
	mov	r13, [rdi + 136]
	mov	rbx, r13
	ror	r10, 31
	not	r15
	and	r10, r14
	ror	r15, 11
	and	rbx, r12
	and	r15, r12
	mov	rsi, [rdi + 96]
	xor	rsi, r10
	mov	r13, [rdi + 104]
	xor	r13, r15
	xor	r13, rbx
	mov	[rdi + 96], rsi
	mov	rsi, [rdi + 144]
	mov	r10, rsi
	mov	[rdi + 104], r13
	mov	r13, [rdi + 152]
	mov	r15, r13
	mov	rsi, [rdi + 128]
	mov	rbx, rsi
	ror	r10, 53
	not	rbx
	ror	r15, 42
	ror	rbx, 22
	and	r10, r12
	and	r15, r12
	and	rbx, rdx
	mov	r13, [rdi + 104]
	xor	r13, r10
	xor	r13, r15
	mov	rsi, [rdi + 112]
	xor	rsi, rbx
	mov	[rdi + 104], r13
	mov	r13, [rdi + 136]
	mov	r10, r13
	mov	[rdi + 112], rsi
	mov	rsi, [rdi + 144]
	mov	r15, rsi
	mov	r13, [rdi + 152]
	mov	rbx, r13
	ror	r10, 11
	ror	rbx, 53
	and	r10, rdx
	and	r15, rdx
	and	rbx, rdx
	mov	rsi, [rdi + 112]
	xor	rsi, r10
	xor	rsi, r15
	xor	rsi, rbx
	mov	r13, [rdi + 128]
	mov	r10, r13
	mov	[rdi + 112], rsi
	mov	rsi, [rdi + 136]
	mov	r15, rsi
	mov	r13, [rdi + 144]
	mov	rbx, r13
	not	r10
	ror	r15, 22
	ror	rbx, 11
	ror	r10, 33
	and	r15, rbp
	and	rbx, rbp
	and	r10, rbp
	mov	rsi, [rdi + 120]
	xor	rsi, r15
	xor	rsi, rbx
	xor	rsi, r10
	mov	r13, [rdi + 152]
	mov	r15, r13
	and	r15, rbp
	xor	rsi, r15
	mov	r10, [rdi + 128]
	xor	r10, rax
	mov	r12, [rdi + 32]
	mov	r14, [rdi]
	xor	r12, r14
	xor	r14, r10
	mov	r15, [rdi + 96]
	xor	r15, r9
	mov	rbx, [rdi + 136]
	xor	rbx, rcx
	mov	rbp, [rdi + 40]
	mov	rdx, [rdi + 8]
	xor	rbp, rdx
	xor	rdx, rbx
	mov	r13, [rdi + 104]
	mov	[rdi + 120], rsi
	mov	rsi, [rdi + 72]
	xor	r13, rsi
	mov	[rdi + 32], r12
	mov	r12, [rdi + 144]
	xor	r12, r8
	mov	[rdi + 128], r10
	mov	r10, [rdi + 48]
	mov	[rdi], r14
	mov	r14, [rdi + 16]
	xor	r10, r14
	xor	r14, r12
	mov	[rdi + 96], r15
	mov	r15, [rdi + 112]
	mov	[rdi + 40], rbp
	mov	rbp, [rdi + 80]
	xor	r15, rbp
	mov	[rdi + 136], rbx
	mov	rbx, [rdi + 152]
	xor	rbx, r11
	mov	[rdi + 8], rdx
	mov	rdx, [rdi + 56]
	mov	rsi, [rdi + 24]
	xor	rdx, rsi
	xor	rsi, rbx
	mov	[rdi + 104], r13
	mov	r13, [rdi + 120]
	mov	[rdi + 48], r10
	mov	r10, [rdi + 88]
	xor	r13, r10
	mov	[rdi + 144], r12
	mov	[rdi + 16], r14
	mov	r11, rsi
	mov	r14, rdx
	mov	r12, rsi
	mov	rbp, rdx
	ror	r11, 19
	ror	r14, 61
	ror	r12, 28
	ror	rbp, 39
	xor	rsi, r11
	xor	rdx, r14
	xor	rsi, r12
	xor	rdx, rbp
	mov	r11, r10
	mov	r14, r13
	mov	r12, r10
	mov	rbp, r13
	ror	r11, 1
	ror	r14, 10
	ror	r12, 6
	ror	rbp, 17
	xor	r10, r11
	xor	r13, r14
	xor	r10, r12
	xor	r13, rbp
	mov	r11, rbx
	mov	[rdi + 112], r15
	mov	r15, [rdi + 16]
	mov	r14, r15
	mov	r12, rbx
	mov	rbp, r15
	ror	r11, 7
	ror	r14, 19
	ror	r12, 41
	ror	rbp, 28
	xor	rbx, r11
	xor	r15, r14
	xor	rbx, r12
	xor	r15, rbp
	mov	[rdi + 24], rsi
	mov	rsi, [rdi + 48]
	mov	r11, rsi
	mov	[rdi + 56], rdx
	mov	rdx, [rdi + 80]
	mov	r14, rdx
	mov	r12, rsi
	mov	rbp, rdx
	ror	r11, 61
	ror	r14, 1
	ror	r12, 39
	ror	rbp, 6
	xor	rsi, r11
	xor	rdx, r14
	xor	rsi, r12
	xor	rdx, rbp
	mov	[rdi + 88], r10
	mov	r10, [rdi + 112]
	mov	r11, r10
	mov	[rdi + 120], r13
	mov	r13, [rdi + 144]
	mov	r14, r13
	mov	r12, r10
	mov	rbp, r13
	ror	r11, 10
	ror	r14, 7
	ror	r12, 17
	ror	rbp, 41
	xor	r10, r11
	xor	r13, r14
	xor	r10, r12
	xor	r13, rbp
	mov	[rdi + 152], rbx
	mov	rbx, [rdi + 8]
	mov	r11, rbx
	mov	[rdi + 16], r15
	mov	r15, [rdi + 40]
	mov	r14, r15
	mov	r12, rbx
	mov	rbp, r15
	ror	r11, 19
	ror	r14, 61
	ror	r12, 28
	ror	rbp, 39
	xor	rbx, r11
	xor	r15, r14
	xor	rbx, r12
	xor	r15, rbp
	mov	[rdi + 48], rsi
	mov	rsi, [rdi + 72]
	mov	r11, rsi
	mov	[rdi + 80], rdx
	mov	rdx, [rdi + 104]
	mov	r14, rdx
	mov	r12, rsi
	mov	rbp, rdx
	ror	r11, 1
	ror	r14, 10
	ror	r12, 6
	ror	rbp, 17
	xor	rsi, r11
	xor	rdx, r14
	xor	rsi, r12
	xor	rdx, rbp
	mov	[rdi + 112], r10
	mov	r10, [rdi + 136]
	mov	r11, r10
	mov	[rdi + 144], r13
	mov	r13, [rdi]
	mov	r14, r13
	mov	r12, r10
	mov	rbp, r13
	ror	r11, 7
	ror	r14, 19
	ror	r12, 41
	ror	rbp, 28
	xor	r10, r11
	xor	r13, r14
	xor	r10, r12
	xor	r13, rbp
	mov	[rdi + 8], rbx
	mov	rbx, [rdi + 32]
	mov	r11, rbx
	mov	r14, r9
	mov	r12, rbx
	mov	rbp, r9
	ror	r11, 61
	ror	r14, 1
	ror	r12, 39
	ror	rbp, 6
	xor	rbx, r11
	xor	r9, r14
	xor	rbx, r12
	xor	r9, rbp
	mov	[rdi + 40], r15
	mov	r15, [rdi + 96]
	mov	r11, r15
	mov	[rdi + 72], rsi
	mov	rsi, [rdi + 128]
	mov	r14, rsi
	mov	r12, r15
	mov	rbp, rsi
	ror	r11, 10
	ror	r14, 7
	ror	r12, 17
	ror	rbp, 41
	xor	r15, r11
	xor	rsi, r14
	xor	r15, r12
	xor	rsi, rbp
	mov	[rdi], r13
	mov	[rdi + 32], rbx
	mov	[rdi + 96], r15
	mov	[rdi + 128], rsi
	mov	[rdi + 104], rdx
	mov	[rdi + 136], r10
	pop	rsi
	add	rsi, 15
.L1:
	cmp	rsi, -61
	jl	.L0
	pop	r10
	mov	[r10], rax
	mov	[r10 + 8], rcx
	mov	[r10 + 16], r8
	not	r9
	mov	[rdi + 64], r9
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
	.size	ascon_x4_permute, .-ascon_x4_permute
#endif

#endif
