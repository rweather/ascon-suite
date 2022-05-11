#include "ascon-masked-backend.h"
#if defined(ASCON_MASKED_X3_BACKEND_X86_64) && ASCON_MASKED_MAX_SHARES >= 3
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

	.text
#if ASCON_MASKED_MAX_SHARES >= 4
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_x3_permute
	.def	ascon_x3_permute;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_x3_permute
ascon_x3_permute:
#else
	.globl	ascon_x3_permute
	.type	ascon_x3_permute, @function
ascon_x3_permute:
	.cfi_startproc
#endif
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	(%rdx), %rax
	movq	8(%rdx), %rcx
	pushq	%rdx
	movq	64(%rdi), %r8
	notq	%r8
	movq	%rsi, %r9
	subq	$15, %rsi
	shlq	$4, %rsi
	subq	%r9, %rsi
	subq	$1, %rsi
	jmp	.L1
.L0:
	pushq	%rsi
	movq	(%rdi), %r9
	movq	128(%rdi), %r10
	xorq	%r10, %r9
	xorq	%rsi, %r8
	movq	96(%rdi), %r11
	xorq	%r11, %r10
	movq	32(%rdi), %r12
	xorq	%r12, %r8
	movq	%r9, %r13
	movq	8(%rdi), %r14
	movq	136(%rdi), %r15
	xorq	%r15, %r14
	movq	104(%rdi), %rbx
	xorq	%rbx, %r15
	movq	72(%rdi), %rbp
	movq	40(%rdi), %rsi
	xorq	%rsi, %rbp
	movq	%r14, %rdx
	movq	16(%rdi), %r11
	movq	%r10, 128(%rdi)
	movq	144(%rdi), %r10
	xorq	%r10, %r11
	movq	112(%rdi), %r12
	xorq	%r12, %r10
	movq	%r9, (%rdi)
	movq	80(%rdi), %r9
	movq	48(%rdi), %rbx
	xorq	%rbx, %r9
	movq	%r15, 136(%rdi)
	movq	%r11, %r15
	movq	%rbp, 72(%rdi)
	movq	%r14, 8(%rdi)
	movq	%rax, %rsi
	movq	%rcx, %rbp
	rorq	$22, %rsi
	rorq	$11, %rbp
	xorq	%rbp, %rsi
	movq	%r10, 144(%rdi)
	movq	(%rdi), %r10
	movq	%r10, %rbp
	movq	40(%rdi), %rbx
	movq	%rbx, %r14
	movq	%r9, 80(%rdi)
	movq	48(%rdi), %r9
	movq	%r9, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	movq	%r11, 16(%rdi)
	movq	32(%rdi), %r11
	andq	%r11, %rbp
	andq	%r10, %r14
	andq	%r10, %r12
	xorq	%rbp, %rax
	xorq	%r14, %rax
	xorq	%r12, %rax
	movq	8(%rdi), %rbx
	movq	%rbx, %rbp
	movq	%r11, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	40(%rdi), %r10
	andq	%r10, %rbp
	andq	%rbx, %r14
	andq	%rbx, %r12
	xorq	%rbp, %rcx
	xorq	%r14, %rcx
	xorq	%r12, %rcx
	movq	%r11, %rbp
	movq	%r10, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	16(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%rbx, %r14
	orq	%rbx, %r12
	xorq	%rbp, %rsi
	xorq	%r14, %rsi
	xorq	%r12, %rsi
	movq	%r11, %rbp
	movq	72(%rdi), %r10
	movq	%r10, %r14
	movq	80(%rdi), %r9
	movq	%r9, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	andq	%r8, %rbp
	andq	%r11, %r14
	andq	%r11, %r12
	movq	(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	40(%rdi), %r10
	movq	%r10, %rbp
	movq	%r8, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	72(%rdi), %r11
	andq	%r11, %rbp
	andq	%r10, %r14
	andq	%r10, %r12
	movq	%rbx, (%rdi)
	movq	8(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	%r8, %rbp
	movq	%r11, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	48(%rdi), %r10
	andq	%r10, %rbp
	andq	%r10, %r14
	orq	%r10, %r12
	movq	%rbx, 8(%rdi)
	movq	16(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	%r8, %rbp
	movq	104(%rdi), %r11
	movq	%r11, %r14
	movq	112(%rdi), %r9
	movq	%r9, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	movq	96(%rdi), %r10
	andq	%r10, %rbp
	andq	%r8, %r14
	andq	%r8, %r12
	movq	%rbx, 16(%rdi)
	movq	32(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	72(%rdi), %r11
	movq	%r11, %rbp
	movq	%r10, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	%rbx, 32(%rdi)
	movq	104(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%r11, %r14
	andq	%r11, %r12
	movq	40(%rdi), %r10
	xorq	%rbp, %r10
	xorq	%r14, %r10
	xorq	%r12, %r10
	movq	96(%rdi), %r9
	movq	%r9, %rbp
	movq	%rbx, %r14
	movq	112(%rdi), %r11
	movq	%r11, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	%r10, 40(%rdi)
	movq	80(%rdi), %r10
	andq	%r10, %rbp
	andq	%r10, %r14
	orq	%r10, %r12
	movq	48(%rdi), %r9
	xorq	%rbp, %r9
	xorq	%r14, %r9
	xorq	%r12, %r9
	movq	96(%rdi), %rbx
	movq	%rbx, %rbp
	movq	136(%rdi), %r11
	movq	%r11, %r14
	movq	144(%rdi), %r10
	movq	%r10, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	movq	%r9, 48(%rdi)
	movq	128(%rdi), %r9
	andq	%r9, %rbp
	andq	%rbx, %r14
	andq	%rbx, %r12
	xorq	%rbp, %r8
	xorq	%r14, %r8
	xorq	%r12, %r8
	movq	104(%rdi), %r11
	movq	%r11, %rbp
	movq	%r9, %r14
	movq	%r10, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	136(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%r11, %r14
	andq	%r11, %r12
	movq	72(%rdi), %r9
	xorq	%rbp, %r9
	xorq	%r14, %r9
	xorq	%r12, %r9
	movq	128(%rdi), %r10
	movq	%r10, %rbp
	movq	%rbx, %r14
	movq	144(%rdi), %r11
	movq	%r11, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	%r9, 72(%rdi)
	movq	112(%rdi), %r9
	andq	%r9, %rbp
	andq	%r9, %r14
	orq	%r9, %r12
	movq	80(%rdi), %r10
	xorq	%rbp, %r10
	xorq	%r14, %r10
	xorq	%r12, %r10
	movq	128(%rdi), %rbx
	movq	%rbx, %rbp
	movq	%rdx, %r14
	movq	%r15, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	andq	%r13, %rbp
	andq	%rbx, %r14
	andq	%rbx, %r12
	movq	96(%rdi), %r11
	xorq	%rbp, %r11
	xorq	%r14, %r11
	xorq	%r12, %r11
	movq	136(%rdi), %r9
	movq	%r9, %rbp
	movq	%r13, %r14
	movq	%r15, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	andq	%rdx, %rbp
	andq	%r9, %r14
	andq	%r9, %r12
	movq	%r10, 80(%rdi)
	movq	104(%rdi), %r10
	xorq	%rbp, %r10
	xorq	%r14, %r10
	xorq	%r12, %r10
	movq	%r13, %rbp
	movq	%rdx, %r14
	movq	%r15, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	144(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%rbx, %r14
	orq	%rbx, %r12
	movq	%r11, 96(%rdi)
	movq	112(%rdi), %r11
	xorq	%rbp, %r11
	xorq	%r14, %r11
	xorq	%r12, %r11
	movq	128(%rdi), %r12
	xorq	%rax, %r12
	movq	32(%rdi), %r13
	movq	(%rdi), %r14
	xorq	%r14, %r13
	xorq	%r12, %r14
	movq	96(%rdi), %r15
	xorq	%r8, %r15
	xorq	%rcx, %r9
	movq	40(%rdi), %rbp
	movq	8(%rdi), %rdx
	xorq	%rdx, %rbp
	xorq	%r9, %rdx
	movq	72(%rdi), %rbx
	xorq	%rbx, %r10
	movq	%r11, 112(%rdi)
	movq	144(%rdi), %r11
	xorq	%rsi, %r11
	movq	%r13, 32(%rdi)
	movq	48(%rdi), %r13
	movq	%r12, 128(%rdi)
	movq	16(%rdi), %r12
	xorq	%r12, %r13
	xorq	%r11, %r12
	movq	%r14, (%rdi)
	movq	112(%rdi), %r14
	movq	%r15, 96(%rdi)
	movq	80(%rdi), %r15
	xorq	%r15, %r14
	movq	%rbp, 40(%rdi)
	movq	%r9, 136(%rdi)
	movq	%rdx, 8(%rdi)
	movq	%r12, %rsi
	movq	%r13, %r9
	movq	%r12, %rbp
	movq	%r13, %rdx
	rorq	$19, %rsi
	rorq	$61, %r9
	rorq	$28, %rbp
	rorq	$39, %rdx
	xorq	%rsi, %r12
	xorq	%r9, %r13
	xorq	%rbp, %r12
	xorq	%rdx, %r13
	movq	%r15, %rsi
	movq	%r14, %r9
	movq	%r15, %rbp
	movq	%r14, %rdx
	rorq	$1, %rsi
	rorq	$10, %r9
	rorq	$6, %rbp
	rorq	$17, %rdx
	xorq	%rsi, %r15
	xorq	%r9, %r14
	xorq	%rbp, %r15
	xorq	%rdx, %r14
	movq	%r11, %rsi
	movq	8(%rdi), %rbx
	movq	%rbx, %r9
	movq	%r11, %rbp
	movq	%rbx, %rdx
	rorq	$7, %rsi
	rorq	$19, %r9
	rorq	$41, %rbp
	rorq	$28, %rdx
	xorq	%rsi, %r11
	xorq	%r9, %rbx
	xorq	%rbp, %r11
	xorq	%rdx, %rbx
	movq	%r10, 104(%rdi)
	movq	40(%rdi), %r10
	movq	%r10, %rsi
	movq	%r12, 16(%rdi)
	movq	72(%rdi), %r12
	movq	%r12, %r9
	movq	%r10, %rbp
	movq	%r12, %rdx
	rorq	$61, %rsi
	rorq	$1, %r9
	rorq	$39, %rbp
	rorq	$6, %rdx
	xorq	%rsi, %r10
	xorq	%r9, %r12
	xorq	%rbp, %r10
	xorq	%rdx, %r12
	movq	%r13, 48(%rdi)
	movq	104(%rdi), %r13
	movq	%r13, %rsi
	movq	%r15, 80(%rdi)
	movq	136(%rdi), %r15
	movq	%r15, %r9
	movq	%r13, %rbp
	movq	%r15, %rdx
	rorq	$10, %rsi
	rorq	$7, %r9
	rorq	$17, %rbp
	rorq	$41, %rdx
	xorq	%rsi, %r13
	xorq	%r9, %r15
	xorq	%rbp, %r13
	xorq	%rdx, %r15
	movq	%r14, 112(%rdi)
	movq	(%rdi), %r14
	movq	%r14, %rsi
	movq	%r11, 144(%rdi)
	movq	32(%rdi), %r11
	movq	%r11, %r9
	movq	%r14, %rbp
	movq	%r11, %rdx
	rorq	$19, %rsi
	rorq	$61, %r9
	rorq	$28, %rbp
	rorq	$39, %rdx
	xorq	%rsi, %r14
	xorq	%r9, %r11
	xorq	%rbp, %r14
	xorq	%rdx, %r11
	movq	%r8, %rsi
	movq	%rbx, 8(%rdi)
	movq	96(%rdi), %rbx
	movq	%rbx, %r9
	movq	%r8, %rbp
	movq	%rbx, %rdx
	rorq	$1, %rsi
	rorq	$10, %r9
	rorq	$6, %rbp
	rorq	$17, %rdx
	xorq	%rsi, %r8
	xorq	%r9, %rbx
	xorq	%rbp, %r8
	xorq	%rdx, %rbx
	movq	%r10, 40(%rdi)
	movq	128(%rdi), %r10
	movq	%r10, %rsi
	movq	%r10, %rbp
	rorq	$7, %rsi
	rorq	$41, %rbp
	xorq	%rsi, %r10
	xorq	%rbp, %r10
	movq	%r14, (%rdi)
	movq	%r11, 32(%rdi)
	movq	%rbx, 96(%rdi)
	movq	%r10, 128(%rdi)
	movq	%r12, 72(%rdi)
	movq	%r13, 104(%rdi)
	movq	%r15, 136(%rdi)
	popq	%rsi
	addq	$15, %rsi
.L1:
	cmpq	$-61, %rsi
	jl	.L0
	popq	%r9
	movq	%rax, (%r9)
	movq	%rcx, 8(%r9)
	notq	%r8
	movq	%r8, 64(%rdi)
	movq	$0, %rax
	movq	$0, %rcx
	movq	$0, %rsi
	movq	$0, %r8
	movq	$0, %r9
	movq	$0, %r10
	movq	$0, %r11
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	popq	%rbp
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_x3_permute, .-ascon_x3_permute
#endif
#elif ASCON_MASKED_MAX_SHARES >= 3
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_x3_permute
	.def	ascon_x3_permute;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_x3_permute
ascon_x3_permute:
#else
	.globl	ascon_x3_permute
	.type	ascon_x3_permute, @function
ascon_x3_permute:
	.cfi_startproc
#endif
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	(%rdx), %rax
	movq	8(%rdx), %rcx
	pushq	%rdx
	movq	48(%rdi), %r8
	notq	%r8
	movq	%rsi, %r9
	subq	$15, %rsi
	shlq	$4, %rsi
	subq	%r9, %rsi
	subq	$1, %rsi
	jmp	.L1
.L0:
	pushq	%rsi
	movq	(%rdi), %r9
	movq	96(%rdi), %r10
	xorq	%r10, %r9
	xorq	%rsi, %r8
	movq	72(%rdi), %r11
	xorq	%r11, %r10
	movq	24(%rdi), %r12
	xorq	%r12, %r8
	movq	%r9, %r13
	movq	8(%rdi), %r14
	movq	104(%rdi), %r15
	xorq	%r15, %r14
	movq	80(%rdi), %rbx
	xorq	%rbx, %r15
	movq	56(%rdi), %rbp
	movq	32(%rdi), %rsi
	xorq	%rsi, %rbp
	movq	%r14, %rdx
	movq	16(%rdi), %r11
	movq	%r10, 96(%rdi)
	movq	112(%rdi), %r10
	xorq	%r10, %r11
	movq	88(%rdi), %r12
	xorq	%r12, %r10
	movq	%r9, (%rdi)
	movq	64(%rdi), %r9
	movq	40(%rdi), %rbx
	xorq	%rbx, %r9
	movq	%r15, 104(%rdi)
	movq	%r11, %r15
	movq	%rbp, 56(%rdi)
	movq	%r14, 8(%rdi)
	movq	%rax, %rsi
	movq	%rcx, %rbp
	rorq	$22, %rsi
	rorq	$11, %rbp
	xorq	%rbp, %rsi
	movq	%r10, 112(%rdi)
	movq	(%rdi), %r10
	movq	%r10, %rbp
	movq	32(%rdi), %rbx
	movq	%rbx, %r14
	movq	%r9, 64(%rdi)
	movq	40(%rdi), %r9
	movq	%r9, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	movq	%r11, 16(%rdi)
	movq	24(%rdi), %r11
	andq	%r11, %rbp
	andq	%r10, %r14
	andq	%r10, %r12
	xorq	%rbp, %rax
	xorq	%r14, %rax
	xorq	%r12, %rax
	movq	8(%rdi), %rbx
	movq	%rbx, %rbp
	movq	%r11, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	32(%rdi), %r10
	andq	%r10, %rbp
	andq	%rbx, %r14
	andq	%rbx, %r12
	xorq	%rbp, %rcx
	xorq	%r14, %rcx
	xorq	%r12, %rcx
	movq	%r11, %rbp
	movq	%r10, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	16(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%rbx, %r14
	orq	%rbx, %r12
	xorq	%rbp, %rsi
	xorq	%r14, %rsi
	xorq	%r12, %rsi
	movq	%r11, %rbp
	movq	56(%rdi), %r10
	movq	%r10, %r14
	movq	64(%rdi), %r9
	movq	%r9, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	andq	%r8, %rbp
	andq	%r11, %r14
	andq	%r11, %r12
	movq	(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	32(%rdi), %r10
	movq	%r10, %rbp
	movq	%r8, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	56(%rdi), %r11
	andq	%r11, %rbp
	andq	%r10, %r14
	andq	%r10, %r12
	movq	%rbx, (%rdi)
	movq	8(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	%r8, %rbp
	movq	%r11, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	40(%rdi), %r10
	andq	%r10, %rbp
	andq	%r10, %r14
	orq	%r10, %r12
	movq	%rbx, 8(%rdi)
	movq	16(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	%r8, %rbp
	movq	80(%rdi), %r11
	movq	%r11, %r14
	movq	88(%rdi), %r9
	movq	%r9, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	movq	72(%rdi), %r10
	andq	%r10, %rbp
	andq	%r8, %r14
	andq	%r8, %r12
	movq	%rbx, 16(%rdi)
	movq	24(%rdi), %rbx
	xorq	%rbp, %rbx
	xorq	%r14, %rbx
	xorq	%r12, %rbx
	movq	56(%rdi), %r11
	movq	%r11, %rbp
	movq	%r10, %r14
	movq	%r9, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	%rbx, 24(%rdi)
	movq	80(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%r11, %r14
	andq	%r11, %r12
	movq	32(%rdi), %r10
	xorq	%rbp, %r10
	xorq	%r14, %r10
	xorq	%r12, %r10
	movq	72(%rdi), %r9
	movq	%r9, %rbp
	movq	%rbx, %r14
	movq	88(%rdi), %r11
	movq	%r11, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	%r10, 32(%rdi)
	movq	64(%rdi), %r10
	andq	%r10, %rbp
	andq	%r10, %r14
	orq	%r10, %r12
	movq	40(%rdi), %r9
	xorq	%rbp, %r9
	xorq	%r14, %r9
	xorq	%r12, %r9
	movq	72(%rdi), %rbx
	movq	%rbx, %rbp
	movq	104(%rdi), %r11
	movq	%r11, %r14
	movq	112(%rdi), %r10
	movq	%r10, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	movq	%r9, 40(%rdi)
	movq	96(%rdi), %r9
	andq	%r9, %rbp
	andq	%rbx, %r14
	andq	%rbx, %r12
	xorq	%rbp, %r8
	xorq	%r14, %r8
	xorq	%r12, %r8
	movq	80(%rdi), %r11
	movq	%r11, %rbp
	movq	%r9, %r14
	movq	%r10, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	movq	104(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%r11, %r14
	andq	%r11, %r12
	movq	56(%rdi), %r9
	xorq	%rbp, %r9
	xorq	%r14, %r9
	xorq	%r12, %r9
	movq	96(%rdi), %r10
	movq	%r10, %rbp
	movq	%rbx, %r14
	movq	112(%rdi), %r11
	movq	%r11, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	%r9, 56(%rdi)
	movq	88(%rdi), %r9
	andq	%r9, %rbp
	andq	%r9, %r14
	orq	%r9, %r12
	movq	64(%rdi), %r10
	xorq	%rbp, %r10
	xorq	%r14, %r10
	xorq	%r12, %r10
	movq	96(%rdi), %rbx
	movq	%rbx, %rbp
	movq	%rdx, %r14
	movq	%r15, %r12
	notq	%rbp
	rorq	$53, %r14
	rorq	$42, %r12
	andq	%r13, %rbp
	andq	%rbx, %r14
	andq	%rbx, %r12
	movq	72(%rdi), %r11
	xorq	%rbp, %r11
	xorq	%r14, %r11
	xorq	%r12, %r11
	movq	104(%rdi), %r9
	movq	%r9, %rbp
	movq	%r13, %r14
	movq	%r15, %r12
	notq	%rbp
	rorq	$11, %r14
	rorq	$53, %r12
	andq	%rdx, %rbp
	andq	%r9, %r14
	andq	%r9, %r12
	movq	%r10, 64(%rdi)
	movq	80(%rdi), %r10
	xorq	%rbp, %r10
	xorq	%r14, %r10
	xorq	%r12, %r10
	movq	%r13, %rbp
	movq	%rdx, %r14
	movq	%r15, %r12
	notq	%rbp
	rorq	$22, %rbp
	rorq	$11, %r14
	movq	112(%rdi), %rbx
	andq	%rbx, %rbp
	andq	%rbx, %r14
	orq	%rbx, %r12
	movq	%r11, 72(%rdi)
	movq	88(%rdi), %r11
	xorq	%rbp, %r11
	xorq	%r14, %r11
	xorq	%r12, %r11
	movq	96(%rdi), %r12
	xorq	%rax, %r12
	movq	24(%rdi), %r13
	movq	(%rdi), %r14
	xorq	%r14, %r13
	xorq	%r12, %r14
	movq	72(%rdi), %r15
	xorq	%r8, %r15
	xorq	%rcx, %r9
	movq	32(%rdi), %rbp
	movq	8(%rdi), %rdx
	xorq	%rdx, %rbp
	xorq	%r9, %rdx
	movq	56(%rdi), %rbx
	xorq	%rbx, %r10
	movq	%r11, 88(%rdi)
	movq	112(%rdi), %r11
	xorq	%rsi, %r11
	movq	%r13, 24(%rdi)
	movq	40(%rdi), %r13
	movq	%r12, 96(%rdi)
	movq	16(%rdi), %r12
	xorq	%r12, %r13
	xorq	%r11, %r12
	movq	%r14, (%rdi)
	movq	88(%rdi), %r14
	movq	%r15, 72(%rdi)
	movq	64(%rdi), %r15
	xorq	%r15, %r14
	movq	%rbp, 32(%rdi)
	movq	%r9, 104(%rdi)
	movq	%rdx, 8(%rdi)
	movq	%r12, %rsi
	movq	%r13, %r9
	movq	%r12, %rbp
	movq	%r13, %rdx
	rorq	$19, %rsi
	rorq	$61, %r9
	rorq	$28, %rbp
	rorq	$39, %rdx
	xorq	%rsi, %r12
	xorq	%r9, %r13
	xorq	%rbp, %r12
	xorq	%rdx, %r13
	movq	%r15, %rsi
	movq	%r14, %r9
	movq	%r15, %rbp
	movq	%r14, %rdx
	rorq	$1, %rsi
	rorq	$10, %r9
	rorq	$6, %rbp
	rorq	$17, %rdx
	xorq	%rsi, %r15
	xorq	%r9, %r14
	xorq	%rbp, %r15
	xorq	%rdx, %r14
	movq	%r11, %rsi
	movq	8(%rdi), %rbx
	movq	%rbx, %r9
	movq	%r11, %rbp
	movq	%rbx, %rdx
	rorq	$7, %rsi
	rorq	$19, %r9
	rorq	$41, %rbp
	rorq	$28, %rdx
	xorq	%rsi, %r11
	xorq	%r9, %rbx
	xorq	%rbp, %r11
	xorq	%rdx, %rbx
	movq	%r10, 80(%rdi)
	movq	32(%rdi), %r10
	movq	%r10, %rsi
	movq	%r12, 16(%rdi)
	movq	56(%rdi), %r12
	movq	%r12, %r9
	movq	%r10, %rbp
	movq	%r12, %rdx
	rorq	$61, %rsi
	rorq	$1, %r9
	rorq	$39, %rbp
	rorq	$6, %rdx
	xorq	%rsi, %r10
	xorq	%r9, %r12
	xorq	%rbp, %r10
	xorq	%rdx, %r12
	movq	%r13, 40(%rdi)
	movq	80(%rdi), %r13
	movq	%r13, %rsi
	movq	%r15, 64(%rdi)
	movq	104(%rdi), %r15
	movq	%r15, %r9
	movq	%r13, %rbp
	movq	%r15, %rdx
	rorq	$10, %rsi
	rorq	$7, %r9
	rorq	$17, %rbp
	rorq	$41, %rdx
	xorq	%rsi, %r13
	xorq	%r9, %r15
	xorq	%rbp, %r13
	xorq	%rdx, %r15
	movq	%r14, 88(%rdi)
	movq	(%rdi), %r14
	movq	%r14, %rsi
	movq	%r11, 112(%rdi)
	movq	24(%rdi), %r11
	movq	%r11, %r9
	movq	%r14, %rbp
	movq	%r11, %rdx
	rorq	$19, %rsi
	rorq	$61, %r9
	rorq	$28, %rbp
	rorq	$39, %rdx
	xorq	%rsi, %r14
	xorq	%r9, %r11
	xorq	%rbp, %r14
	xorq	%rdx, %r11
	movq	%r8, %rsi
	movq	%rbx, 8(%rdi)
	movq	72(%rdi), %rbx
	movq	%rbx, %r9
	movq	%r8, %rbp
	movq	%rbx, %rdx
	rorq	$1, %rsi
	rorq	$10, %r9
	rorq	$6, %rbp
	rorq	$17, %rdx
	xorq	%rsi, %r8
	xorq	%r9, %rbx
	xorq	%rbp, %r8
	xorq	%rdx, %rbx
	movq	%r10, 32(%rdi)
	movq	96(%rdi), %r10
	movq	%r10, %rsi
	movq	%r10, %rbp
	rorq	$7, %rsi
	rorq	$41, %rbp
	xorq	%rsi, %r10
	xorq	%rbp, %r10
	movq	%r14, (%rdi)
	movq	%r11, 24(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%r10, 96(%rdi)
	movq	%r12, 56(%rdi)
	movq	%r13, 80(%rdi)
	movq	%r15, 104(%rdi)
	popq	%rsi
	addq	$15, %rsi
.L1:
	cmpq	$-61, %rsi
	jl	.L0
	popq	%r9
	movq	%rax, (%r9)
	movq	%rcx, 8(%r9)
	notq	%r8
	movq	%r8, 48(%rdi)
	movq	$0, %rax
	movq	$0, %rcx
	movq	$0, %rsi
	movq	$0, %r8
	movq	$0, %r9
	movq	$0, %r10
	movq	$0, %r11
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	popq	%rbp
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_x3_permute, .-ascon_x3_permute
#endif
#endif

#endif
