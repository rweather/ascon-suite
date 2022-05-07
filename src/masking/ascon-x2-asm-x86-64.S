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
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	(%rdx), %rax
	pushq	%rdx
	movq	64(%rdi), %rcx
	notq	%rcx
	movq	%rsi, %r8
	subq	$15, %rsi
	shlq	$4, %rsi
	subq	%r8, %rsi
	subq	$1, %rsi
	jmp	.L1
.L0:
	pushq	%rsi
	movq	(%rdi), %r8
	movq	128(%rdi), %r9
	xorq	%r9, %r8
	xorq	%rsi, %rcx
	movq	96(%rdi), %r10
	xorq	%r10, %r9
	movq	32(%rdi), %r11
	xorq	%r11, %rcx
	movq	%r8, %r12
	movq	8(%rdi), %r13
	movq	136(%rdi), %r14
	xorq	%r14, %r13
	movq	104(%rdi), %r15
	xorq	%r15, %r14
	movq	72(%rdi), %rbx
	movq	40(%rdi), %rbp
	xorq	%rbp, %rbx
	movq	%r13, %rsi
	movq	%r9, 128(%rdi)
	movq	%rax, %rdx
	rorq	$11, %rdx
	movq	%r8, %r10
	movq	%rbp, %r9
	notq	%r10
	rorq	$53, %r9
	andq	%r10, %r9
	xorq	%r9, %rax
	andq	%r11, %r10
	xorq	%r10, %rax
	movq	%r13, %r9
	movq	%r11, %r10
	andq	%rbp, %r9
	rorq	$11, %r10
	xorq	%r9, %rdx
	andq	%r13, %r10
	xorq	%r10, %rdx
	movq	%r11, %r10
	movq	%rbx, %r9
	notq	%r10
	rorq	$53, %r9
	andq	%r10, %r9
	xorq	%r9, %r8
	andq	%rcx, %r10
	xorq	%r10, %r8
	movq	%rbp, %r9
	movq	%rcx, %r10
	andq	%rbx, %r9
	rorq	$11, %r10
	xorq	%r9, %r13
	andq	%rbp, %r10
	xorq	%r10, %r13
	movq	%rcx, %r10
	movq	%r15, %r9
	notq	%r10
	rorq	$53, %r9
	andq	%r10, %r9
	xorq	%r9, %r11
	movq	%r14, 136(%rdi)
	movq	96(%rdi), %r14
	andq	%r14, %r10
	xorq	%r10, %r11
	movq	%rbx, %r9
	movq	%r14, %r10
	andq	%r15, %r9
	rorq	$11, %r10
	xorq	%r9, %rbp
	andq	%rbx, %r10
	xorq	%r10, %rbp
	movq	%r14, %r10
	movq	%r8, (%rdi)
	movq	136(%rdi), %r8
	movq	%r8, %r9
	notq	%r10
	rorq	$53, %r9
	andq	%r10, %r9
	xorq	%r9, %rcx
	movq	%r13, 8(%rdi)
	movq	128(%rdi), %r13
	andq	%r13, %r10
	xorq	%r10, %rcx
	movq	%r15, %r9
	movq	%r13, %r10
	andq	%r8, %r9
	rorq	$11, %r10
	xorq	%r9, %rbx
	andq	%r15, %r10
	xorq	%r10, %rbx
	movq	%r13, %r10
	movq	%rsi, %r9
	notq	%r10
	rorq	$53, %r9
	andq	%r10, %r9
	xorq	%r9, %r14
	andq	%r12, %r10
	xorq	%r10, %r14
	movq	%r8, %r9
	movq	%r12, %r10
	andq	%rsi, %r9
	rorq	$11, %r10
	xorq	%r9, %r15
	andq	%r8, %r10
	xorq	%r10, %r15
	xorq	%rax, %r13
	movq	(%rdi), %r9
	xorq	%r9, %r11
	xorq	%r13, %r9
	xorq	%rcx, %r14
	xorq	%rdx, %r8
	movq	8(%rdi), %r10
	xorq	%r10, %rbp
	xorq	%r8, %r10
	xorq	%rbx, %r15
	movq	%r11, 32(%rdi)
	movq	%r10, %r12
	movq	%rbp, %rdx
	movq	%r10, %rsi
	movq	%rbp, %r11
	rorq	$19, %r12
	rorq	$61, %rdx
	rorq	$28, %rsi
	rorq	$39, %r11
	xorq	%r12, %r10
	xorq	%rdx, %rbp
	xorq	%rsi, %r10
	xorq	%r11, %rbp
	movq	%rbx, %r12
	movq	%r15, %rdx
	movq	%rbx, %rsi
	movq	%r15, %r11
	rorq	$1, %r12
	rorq	$10, %rdx
	rorq	$6, %rsi
	rorq	$17, %r11
	xorq	%r12, %rbx
	xorq	%rdx, %r15
	xorq	%rsi, %rbx
	xorq	%r11, %r15
	movq	%r8, %r12
	movq	%r9, %rdx
	movq	%r8, %rsi
	movq	%r9, %r11
	rorq	$7, %r12
	rorq	$19, %rdx
	rorq	$41, %rsi
	rorq	$28, %r11
	xorq	%r12, %r8
	xorq	%rdx, %r9
	xorq	%rsi, %r8
	xorq	%r11, %r9
	movq	%r13, 128(%rdi)
	movq	32(%rdi), %r13
	movq	%r13, %r12
	movq	%rcx, %rdx
	movq	%r13, %rsi
	movq	%rcx, %r11
	rorq	$61, %r12
	rorq	$1, %rdx
	rorq	$39, %rsi
	rorq	$6, %r11
	xorq	%r12, %r13
	xorq	%rdx, %rcx
	xorq	%rsi, %r13
	xorq	%r11, %rcx
	movq	%r14, %r12
	movq	%r10, 8(%rdi)
	movq	128(%rdi), %r10
	movq	%r10, %rdx
	movq	%r14, %rsi
	movq	%r10, %r11
	rorq	$10, %r12
	rorq	$7, %rdx
	rorq	$17, %rsi
	rorq	$41, %r11
	xorq	%r12, %r14
	xorq	%rdx, %r10
	xorq	%rsi, %r14
	xorq	%r11, %r10
	movq	%r9, (%rdi)
	movq	%r13, 32(%rdi)
	movq	%r14, 96(%rdi)
	movq	%r10, 128(%rdi)
	movq	%rbp, 40(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%r15, 104(%rdi)
	movq	%r8, 136(%rdi)
	popq	%rsi
	addq	$15, %rsi
.L1:
	cmpq	$-61, %rsi
	jl	.L0
	popq	%r8
	movq	%rax, (%r8)
	notq	%rcx
	movq	%rcx, 64(%rdi)
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
	.size	ascon_x2_permute, .-ascon_x2_permute
#endif

#endif
