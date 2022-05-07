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
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	(%rdx), %rax
	movq	8(%rdx), %rcx
	movq	16(%rdx), %r8
	pushq	%rdx
	movq	64(%rdi), %r9
	notq	%r9
	movq	%rsi, %r10
	subq	$15, %rsi
	shlq	$4, %rsi
	subq	%r10, %rsi
	subq	$1, %rsi
	jmp	.L1
.L0:
	pushq	%rsi
	movq	(%rdi), %r10
	movq	128(%rdi), %r11
	xorq	%r11, %r10
	xorq	%rsi, %r9
	movq	96(%rdi), %r12
	xorq	%r12, %r11
	movq	32(%rdi), %r13
	xorq	%r13, %r9
	movq	%r10, %r14
	movq	8(%rdi), %r15
	movq	136(%rdi), %rbx
	xorq	%rbx, %r15
	movq	104(%rdi), %rbp
	xorq	%rbp, %rbx
	movq	72(%rdi), %rsi
	movq	40(%rdi), %rdx
	xorq	%rdx, %rsi
	movq	%r15, %r12
	movq	%r11, 128(%rdi)
	movq	16(%rdi), %r11
	movq	144(%rdi), %r13
	xorq	%r13, %r11
	movq	%r10, (%rdi)
	movq	112(%rdi), %r10
	xorq	%r10, %r13
	movq	80(%rdi), %rbp
	movq	%rbx, 136(%rdi)
	movq	48(%rdi), %rbx
	xorq	%rbx, %rbp
	movq	%r11, %rdx
	movq	%rsi, 72(%rdi)
	movq	24(%rdi), %rsi
	movq	%r15, 8(%rdi)
	movq	152(%rdi), %r15
	xorq	%r15, %rsi
	movq	120(%rdi), %r10
	xorq	%r10, %r15
	movq	%r13, 144(%rdi)
	movq	88(%rdi), %r13
	movq	56(%rdi), %rbx
	xorq	%rbx, %r13
	movq	%rbp, 80(%rdi)
	movq	%rsi, %rbp
	movq	%r11, 16(%rdi)
	movq	%r15, 152(%rdi)
	movq	%rax, %r11
	movq	%rcx, %r10
	movq	%r8, %r15
	rorq	$33, %r11
	rorq	$22, %r10
	rorq	$11, %r15
	xorq	%r10, %r11
	xorq	%r15, %r11
	movq	%r13, 88(%rdi)
	movq	(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 24(%rdi)
	movq	8(%rdi), %rsi
	movq	%rsi, %r15
	movq	16(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$53, %r15
	rorq	$42, %rbx
	movq	32(%rdi), %rsi
	andq	%rsi, %r10
	andq	%rsi, %r15
	andq	%rsi, %rbx
	xorq	%r10, %rax
	xorq	%r15, %rax
	xorq	%rbx, %rax
	movq	24(%rdi), %r13
	movq	%r13, %r10
	movq	(%rdi), %rsi
	movq	%rsi, %r15
	movq	8(%rdi), %r13
	movq	%r13, %rbx
	rorq	$31, %r10
	notq	%r15
	movq	32(%rdi), %rsi
	andq	%rsi, %r10
	rorq	$11, %r15
	movq	40(%rdi), %r13
	andq	%r13, %rbx
	andq	%r13, %r15
	xorq	%r10, %rax
	xorq	%r15, %rcx
	xorq	%rbx, %rcx
	movq	16(%rdi), %rsi
	movq	%rsi, %r10
	movq	24(%rdi), %r13
	movq	%r13, %r15
	movq	(%rdi), %rsi
	movq	%rsi, %rbx
	rorq	$53, %r10
	notq	%rbx
	rorq	$42, %r15
	rorq	$22, %rbx
	movq	40(%rdi), %r13
	andq	%r13, %r10
	andq	%r13, %r15
	movq	48(%rdi), %rsi
	andq	%rsi, %rbx
	xorq	%r10, %rcx
	xorq	%r15, %rcx
	xorq	%rbx, %r8
	movq	8(%rdi), %r13
	movq	%r13, %r10
	movq	16(%rdi), %rsi
	movq	%rsi, %r15
	movq	24(%rdi), %r13
	movq	%r13, %rbx
	rorq	$11, %r10
	rorq	$53, %rbx
	movq	48(%rdi), %rsi
	andq	%rsi, %r10
	andq	%rsi, %r15
	andq	%rsi, %rbx
	xorq	%r10, %r8
	xorq	%r15, %r8
	xorq	%rbx, %r8
	movq	(%rdi), %r13
	movq	%r13, %r10
	movq	8(%rdi), %rsi
	movq	%rsi, %r15
	movq	16(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$22, %r15
	rorq	$11, %rbx
	rorq	$33, %r10
	movq	56(%rdi), %rsi
	andq	%rsi, %r15
	andq	%rsi, %rbx
	andq	%rsi, %r10
	xorq	%r15, %r11
	xorq	%rbx, %r11
	xorq	%r10, %r11
	movq	24(%rdi), %r13
	movq	%r13, %r15
	andq	%rsi, %r15
	xorq	%r15, %r11
	movq	32(%rdi), %r13
	movq	%r13, %r10
	movq	40(%rdi), %rsi
	movq	%rsi, %r15
	movq	48(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$53, %r15
	rorq	$42, %rbx
	andq	%r9, %r10
	andq	%r9, %r15
	andq	%r9, %rbx
	movq	(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	56(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, (%rdi)
	movq	32(%rdi), %rsi
	movq	%rsi, %r15
	movq	40(%rdi), %r13
	movq	%r13, %rbx
	rorq	$31, %r10
	notq	%r15
	andq	%r9, %r10
	rorq	$11, %r15
	movq	72(%rdi), %rsi
	andq	%rsi, %rbx
	andq	%rsi, %r15
	movq	(%rdi), %r13
	xorq	%r10, %r13
	movq	8(%rdi), %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	%r13, (%rdi)
	movq	48(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 8(%rdi)
	movq	56(%rdi), %rsi
	movq	%rsi, %r15
	movq	32(%rdi), %r13
	movq	%r13, %rbx
	rorq	$53, %r10
	notq	%rbx
	rorq	$42, %r15
	rorq	$22, %rbx
	movq	72(%rdi), %rsi
	andq	%rsi, %r10
	andq	%rsi, %r15
	movq	80(%rdi), %r13
	andq	%r13, %rbx
	movq	8(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	movq	16(%rdi), %r13
	xorq	%rbx, %r13
	movq	%rsi, 8(%rdi)
	movq	40(%rdi), %rsi
	movq	%rsi, %r10
	movq	%r13, 16(%rdi)
	movq	48(%rdi), %r13
	movq	%r13, %r15
	movq	56(%rdi), %rsi
	movq	%rsi, %rbx
	rorq	$11, %r10
	rorq	$53, %rbx
	movq	80(%rdi), %r13
	andq	%r13, %r10
	andq	%r13, %r15
	andq	%r13, %rbx
	movq	16(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	32(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 16(%rdi)
	movq	40(%rdi), %rsi
	movq	%rsi, %r15
	movq	48(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$22, %r15
	rorq	$11, %rbx
	rorq	$33, %r10
	movq	88(%rdi), %rsi
	andq	%rsi, %r15
	andq	%rsi, %rbx
	andq	%rsi, %r10
	movq	24(%rdi), %r13
	xorq	%r15, %r13
	xorq	%rbx, %r13
	xorq	%r10, %r13
	movq	56(%rdi), %rsi
	movq	%rsi, %r15
	movq	%r13, 24(%rdi)
	movq	88(%rdi), %r13
	andq	%r13, %r15
	movq	24(%rdi), %rsi
	xorq	%r15, %rsi
	movq	%r9, %r10
	movq	72(%rdi), %r13
	movq	%r13, %r15
	movq	%rsi, 24(%rdi)
	movq	80(%rdi), %rsi
	movq	%rsi, %rbx
	notq	%r10
	rorq	$53, %r15
	rorq	$42, %rbx
	movq	96(%rdi), %r13
	andq	%r13, %r10
	andq	%r13, %r15
	andq	%r13, %rbx
	movq	32(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	88(%rdi), %r13
	movq	%r13, %r10
	movq	%r9, %r15
	movq	%rsi, 32(%rdi)
	movq	72(%rdi), %rsi
	movq	%rsi, %rbx
	rorq	$31, %r10
	notq	%r15
	movq	96(%rdi), %r13
	andq	%r13, %r10
	rorq	$11, %r15
	movq	104(%rdi), %rsi
	andq	%rsi, %rbx
	andq	%rsi, %r15
	movq	32(%rdi), %r13
	xorq	%r10, %r13
	movq	40(%rdi), %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	%r13, 32(%rdi)
	movq	80(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 40(%rdi)
	movq	88(%rdi), %rsi
	movq	%rsi, %r15
	movq	%r9, %rbx
	rorq	$53, %r10
	notq	%rbx
	rorq	$42, %r15
	rorq	$22, %rbx
	movq	104(%rdi), %r13
	andq	%r13, %r10
	andq	%r13, %r15
	movq	112(%rdi), %rsi
	andq	%rsi, %rbx
	movq	40(%rdi), %r13
	xorq	%r10, %r13
	xorq	%r15, %r13
	movq	48(%rdi), %rsi
	xorq	%rbx, %rsi
	movq	%r13, 40(%rdi)
	movq	72(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 48(%rdi)
	movq	80(%rdi), %rsi
	movq	%rsi, %r15
	movq	88(%rdi), %r13
	movq	%r13, %rbx
	rorq	$11, %r10
	rorq	$53, %rbx
	movq	112(%rdi), %rsi
	andq	%rsi, %r10
	andq	%rsi, %r15
	andq	%rsi, %rbx
	movq	48(%rdi), %r13
	xorq	%r10, %r13
	xorq	%r15, %r13
	xorq	%rbx, %r13
	movq	%r9, %r10
	movq	72(%rdi), %rsi
	movq	%rsi, %r15
	movq	%r13, 48(%rdi)
	movq	80(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$22, %r15
	rorq	$11, %rbx
	rorq	$33, %r10
	movq	120(%rdi), %rsi
	andq	%rsi, %r15
	andq	%rsi, %rbx
	andq	%rsi, %r10
	movq	56(%rdi), %r13
	xorq	%r15, %r13
	xorq	%rbx, %r13
	xorq	%r10, %r13
	movq	88(%rdi), %rsi
	movq	%rsi, %r15
	movq	%r13, 56(%rdi)
	movq	120(%rdi), %r13
	andq	%r13, %r15
	movq	56(%rdi), %rsi
	xorq	%r15, %rsi
	movq	96(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 56(%rdi)
	movq	104(%rdi), %rsi
	movq	%rsi, %r15
	movq	112(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$53, %r15
	rorq	$42, %rbx
	movq	128(%rdi), %rsi
	andq	%rsi, %r10
	andq	%rsi, %r15
	andq	%rsi, %rbx
	xorq	%r10, %r9
	xorq	%r15, %r9
	xorq	%rbx, %r9
	movq	120(%rdi), %r13
	movq	%r13, %r10
	movq	96(%rdi), %rsi
	movq	%rsi, %r15
	movq	104(%rdi), %r13
	movq	%r13, %rbx
	rorq	$31, %r10
	notq	%r15
	movq	128(%rdi), %rsi
	andq	%rsi, %r10
	rorq	$11, %r15
	movq	136(%rdi), %r13
	andq	%r13, %rbx
	andq	%r13, %r15
	xorq	%r10, %r9
	movq	72(%rdi), %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	112(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 72(%rdi)
	movq	120(%rdi), %rsi
	movq	%rsi, %r15
	movq	96(%rdi), %r13
	movq	%r13, %rbx
	rorq	$53, %r10
	notq	%rbx
	rorq	$42, %r15
	rorq	$22, %rbx
	movq	136(%rdi), %rsi
	andq	%rsi, %r10
	andq	%rsi, %r15
	movq	144(%rdi), %r13
	andq	%r13, %rbx
	movq	72(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	movq	80(%rdi), %r13
	xorq	%rbx, %r13
	movq	%rsi, 72(%rdi)
	movq	104(%rdi), %rsi
	movq	%rsi, %r10
	movq	%r13, 80(%rdi)
	movq	112(%rdi), %r13
	movq	%r13, %r15
	movq	120(%rdi), %rsi
	movq	%rsi, %rbx
	rorq	$11, %r10
	rorq	$53, %rbx
	movq	144(%rdi), %r13
	andq	%r13, %r10
	andq	%r13, %r15
	andq	%r13, %rbx
	movq	80(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	96(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 80(%rdi)
	movq	104(%rdi), %rsi
	movq	%rsi, %r15
	movq	112(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$22, %r15
	rorq	$11, %rbx
	rorq	$33, %r10
	movq	152(%rdi), %rsi
	andq	%rsi, %r15
	andq	%rsi, %rbx
	andq	%rsi, %r10
	movq	88(%rdi), %r13
	xorq	%r15, %r13
	xorq	%rbx, %r13
	xorq	%r10, %r13
	movq	120(%rdi), %rsi
	movq	%rsi, %r15
	movq	%r13, 88(%rdi)
	movq	152(%rdi), %r13
	andq	%r13, %r15
	movq	88(%rdi), %rsi
	xorq	%r15, %rsi
	movq	128(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 88(%rdi)
	movq	136(%rdi), %rsi
	movq	%rsi, %r15
	movq	144(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$53, %r15
	rorq	$42, %rbx
	andq	%r14, %r10
	andq	%r14, %r15
	andq	%r14, %rbx
	movq	96(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	152(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 96(%rdi)
	movq	128(%rdi), %rsi
	movq	%rsi, %r15
	movq	136(%rdi), %r13
	movq	%r13, %rbx
	rorq	$31, %r10
	notq	%r15
	andq	%r14, %r10
	rorq	$11, %r15
	andq	%r12, %rbx
	andq	%r12, %r15
	movq	96(%rdi), %rsi
	xorq	%r10, %rsi
	movq	104(%rdi), %r13
	xorq	%r15, %r13
	xorq	%rbx, %r13
	movq	%rsi, 96(%rdi)
	movq	144(%rdi), %rsi
	movq	%rsi, %r10
	movq	%r13, 104(%rdi)
	movq	152(%rdi), %r13
	movq	%r13, %r15
	movq	128(%rdi), %rsi
	movq	%rsi, %rbx
	rorq	$53, %r10
	notq	%rbx
	rorq	$42, %r15
	rorq	$22, %rbx
	andq	%r12, %r10
	andq	%r12, %r15
	andq	%rdx, %rbx
	movq	104(%rdi), %r13
	xorq	%r10, %r13
	xorq	%r15, %r13
	movq	112(%rdi), %rsi
	xorq	%rbx, %rsi
	movq	%r13, 104(%rdi)
	movq	136(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 112(%rdi)
	movq	144(%rdi), %rsi
	movq	%rsi, %r15
	movq	152(%rdi), %r13
	movq	%r13, %rbx
	rorq	$11, %r10
	rorq	$53, %rbx
	andq	%rdx, %r10
	andq	%rdx, %r15
	andq	%rdx, %rbx
	movq	112(%rdi), %rsi
	xorq	%r10, %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	movq	128(%rdi), %r13
	movq	%r13, %r10
	movq	%rsi, 112(%rdi)
	movq	136(%rdi), %rsi
	movq	%rsi, %r15
	movq	144(%rdi), %r13
	movq	%r13, %rbx
	notq	%r10
	rorq	$22, %r15
	rorq	$11, %rbx
	rorq	$33, %r10
	andq	%rbp, %r15
	andq	%rbp, %rbx
	andq	%rbp, %r10
	movq	120(%rdi), %rsi
	xorq	%r15, %rsi
	xorq	%rbx, %rsi
	xorq	%r10, %rsi
	movq	152(%rdi), %r13
	movq	%r13, %r15
	andq	%rbp, %r15
	xorq	%r15, %rsi
	movq	128(%rdi), %r10
	xorq	%rax, %r10
	movq	32(%rdi), %r12
	movq	(%rdi), %r14
	xorq	%r14, %r12
	xorq	%r10, %r14
	movq	96(%rdi), %r15
	xorq	%r9, %r15
	movq	136(%rdi), %rbx
	xorq	%rcx, %rbx
	movq	40(%rdi), %rbp
	movq	8(%rdi), %rdx
	xorq	%rdx, %rbp
	xorq	%rbx, %rdx
	movq	104(%rdi), %r13
	movq	%rsi, 120(%rdi)
	movq	72(%rdi), %rsi
	xorq	%rsi, %r13
	movq	%r12, 32(%rdi)
	movq	144(%rdi), %r12
	xorq	%r8, %r12
	movq	%r10, 128(%rdi)
	movq	48(%rdi), %r10
	movq	%r14, (%rdi)
	movq	16(%rdi), %r14
	xorq	%r14, %r10
	xorq	%r12, %r14
	movq	%r15, 96(%rdi)
	movq	112(%rdi), %r15
	movq	%rbp, 40(%rdi)
	movq	80(%rdi), %rbp
	xorq	%rbp, %r15
	movq	%rbx, 136(%rdi)
	movq	152(%rdi), %rbx
	xorq	%r11, %rbx
	movq	%rdx, 8(%rdi)
	movq	56(%rdi), %rdx
	movq	24(%rdi), %rsi
	xorq	%rsi, %rdx
	xorq	%rbx, %rsi
	movq	%r13, 104(%rdi)
	movq	120(%rdi), %r13
	movq	%r10, 48(%rdi)
	movq	88(%rdi), %r10
	xorq	%r10, %r13
	movq	%r12, 144(%rdi)
	movq	%r14, 16(%rdi)
	movq	%rsi, %r11
	movq	%rdx, %r14
	movq	%rsi, %r12
	movq	%rdx, %rbp
	rorq	$19, %r11
	rorq	$61, %r14
	rorq	$28, %r12
	rorq	$39, %rbp
	xorq	%r11, %rsi
	xorq	%r14, %rdx
	xorq	%r12, %rsi
	xorq	%rbp, %rdx
	movq	%r10, %r11
	movq	%r13, %r14
	movq	%r10, %r12
	movq	%r13, %rbp
	rorq	$1, %r11
	rorq	$10, %r14
	rorq	$6, %r12
	rorq	$17, %rbp
	xorq	%r11, %r10
	xorq	%r14, %r13
	xorq	%r12, %r10
	xorq	%rbp, %r13
	movq	%rbx, %r11
	movq	%r15, 112(%rdi)
	movq	16(%rdi), %r15
	movq	%r15, %r14
	movq	%rbx, %r12
	movq	%r15, %rbp
	rorq	$7, %r11
	rorq	$19, %r14
	rorq	$41, %r12
	rorq	$28, %rbp
	xorq	%r11, %rbx
	xorq	%r14, %r15
	xorq	%r12, %rbx
	xorq	%rbp, %r15
	movq	%rsi, 24(%rdi)
	movq	48(%rdi), %rsi
	movq	%rsi, %r11
	movq	%rdx, 56(%rdi)
	movq	80(%rdi), %rdx
	movq	%rdx, %r14
	movq	%rsi, %r12
	movq	%rdx, %rbp
	rorq	$61, %r11
	rorq	$1, %r14
	rorq	$39, %r12
	rorq	$6, %rbp
	xorq	%r11, %rsi
	xorq	%r14, %rdx
	xorq	%r12, %rsi
	xorq	%rbp, %rdx
	movq	%r10, 88(%rdi)
	movq	112(%rdi), %r10
	movq	%r10, %r11
	movq	%r13, 120(%rdi)
	movq	144(%rdi), %r13
	movq	%r13, %r14
	movq	%r10, %r12
	movq	%r13, %rbp
	rorq	$10, %r11
	rorq	$7, %r14
	rorq	$17, %r12
	rorq	$41, %rbp
	xorq	%r11, %r10
	xorq	%r14, %r13
	xorq	%r12, %r10
	xorq	%rbp, %r13
	movq	%rbx, 152(%rdi)
	movq	8(%rdi), %rbx
	movq	%rbx, %r11
	movq	%r15, 16(%rdi)
	movq	40(%rdi), %r15
	movq	%r15, %r14
	movq	%rbx, %r12
	movq	%r15, %rbp
	rorq	$19, %r11
	rorq	$61, %r14
	rorq	$28, %r12
	rorq	$39, %rbp
	xorq	%r11, %rbx
	xorq	%r14, %r15
	xorq	%r12, %rbx
	xorq	%rbp, %r15
	movq	%rsi, 48(%rdi)
	movq	72(%rdi), %rsi
	movq	%rsi, %r11
	movq	%rdx, 80(%rdi)
	movq	104(%rdi), %rdx
	movq	%rdx, %r14
	movq	%rsi, %r12
	movq	%rdx, %rbp
	rorq	$1, %r11
	rorq	$10, %r14
	rorq	$6, %r12
	rorq	$17, %rbp
	xorq	%r11, %rsi
	xorq	%r14, %rdx
	xorq	%r12, %rsi
	xorq	%rbp, %rdx
	movq	%r10, 112(%rdi)
	movq	136(%rdi), %r10
	movq	%r10, %r11
	movq	%r13, 144(%rdi)
	movq	(%rdi), %r13
	movq	%r13, %r14
	movq	%r10, %r12
	movq	%r13, %rbp
	rorq	$7, %r11
	rorq	$19, %r14
	rorq	$41, %r12
	rorq	$28, %rbp
	xorq	%r11, %r10
	xorq	%r14, %r13
	xorq	%r12, %r10
	xorq	%rbp, %r13
	movq	%rbx, 8(%rdi)
	movq	32(%rdi), %rbx
	movq	%rbx, %r11
	movq	%r9, %r14
	movq	%rbx, %r12
	movq	%r9, %rbp
	rorq	$61, %r11
	rorq	$1, %r14
	rorq	$39, %r12
	rorq	$6, %rbp
	xorq	%r11, %rbx
	xorq	%r14, %r9
	xorq	%r12, %rbx
	xorq	%rbp, %r9
	movq	%r15, 40(%rdi)
	movq	96(%rdi), %r15
	movq	%r15, %r11
	movq	%rsi, 72(%rdi)
	movq	128(%rdi), %rsi
	movq	%rsi, %r14
	movq	%r15, %r12
	movq	%rsi, %rbp
	rorq	$10, %r11
	rorq	$7, %r14
	rorq	$17, %r12
	rorq	$41, %rbp
	xorq	%r11, %r15
	xorq	%r14, %rsi
	xorq	%r12, %r15
	xorq	%rbp, %rsi
	movq	%r13, (%rdi)
	movq	%rbx, 32(%rdi)
	movq	%r15, 96(%rdi)
	movq	%rsi, 128(%rdi)
	movq	%rdx, 104(%rdi)
	movq	%r10, 136(%rdi)
	popq	%rsi
	addq	$15, %rsi
.L1:
	cmpq	$-61, %rsi
	jl	.L0
	popq	%r10
	movq	%rax, (%r10)
	movq	%rcx, 8(%r10)
	movq	%r8, 16(%r10)
	notq	%r9
	movq	%r9, 64(%rdi)
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
	.size	ascon_x4_permute, .-ascon_x4_permute
#endif

#endif
