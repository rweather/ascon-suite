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

#if defined(__APPLE__)
	.section __TEXT,__text,regular,pure_instructions
#else
	.text
#endif
#if defined(__APPLE__)
	.p2align 4, 0x90
	.globl	_ascon_permute
_ascon_permute:
	.cfi_startproc
#elif defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.p2align 4,,15
	.globl	ascon_permute
	.def	ascon_permute;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_permute
ascon_permute:
#else
	.p2align 4,,15
	.globl	ascon_permute
	.type	ascon_permute, @function
ascon_permute:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	movq	(%rdi), %rax
	movq	8(%rdi), %rcx
	movq	16(%rdi), %rdx
	movq	24(%rdi), %r8
	movq	32(%rdi), %r9
	notq	%rdx
	cmpq	$12, %rsi
	jge	.L13
	leaq	.L14(%rip), %rbx
	movslq	(%rbx,%rsi,4), %r10
	addq	%rbx, %r10
	jmp	*%r10
.L13:
	jmp	.L12
#if defined(__APPLE__)
	.p2align 2, 0x90
	.data_region jt32
#else
	.section	.rodata
	.align	4
#endif
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
#if defined(__APPLE__)
	.end_data_region
	.section __TEXT,__text,regular,pure_instructions
	.p2align 4, 0x90
#else
	.text
	.p2align	4,,10
	.p2align	3
#endif
.L0:
	xorq	$-241, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L1:
	xorq	$-226, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L2:
	xorq	$-211, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L3:
	xorq	$-196, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L4:
	xorq	$-181, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L5:
	xorq	$-166, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L6:
	xorq	$-151, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L7:
	xorq	$-136, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L8:
	xorq	$-121, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L9:
	xorq	$-106, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L10:
	xorq	$-91, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L11:
	xorq	$-76, %rdx
	xorq	%r9, %rax
	xorq	%rcx, %rdx
	movq	%rax, %rbx
	xorq	%r8, %r9
	movq	%rcx, %r10
	movq	%rdx, %r11
	movq	%r8, %r12
	movq	%r9, %r13
	notq	%rbx
	notq	%r10
	notq	%r11
	notq	%r12
	notq	%r13
	andq	%rcx, %rbx
	andq	%rdx, %r10
	andq	%r8, %r11
	andq	%r9, %r12
	andq	%rax, %r13
	xorq	%r10, %rax
	xorq	%r11, %rcx
	xorq	%r12, %rdx
	xorq	%r13, %r8
	xorq	%rbx, %r9
	xorq	%rax, %rcx
	xorq	%r9, %rax
	xorq	%rdx, %r8
	movq	%rax, %rbx
	movq	%rax, %r10
	movq	%rcx, %r11
	movq	%rcx, %r12
	movq	%rdx, %r13
	movq	%rdx, %rsi
	rorq	$19, %rbx
	rorq	$28, %r10
	rorq	$61, %r11
	rorq	$39, %r12
	rorq	$1, %r13
	rorq	$6, %rsi
	xorq	%rbx, %rax
	xorq	%r11, %rcx
	xorq	%r13, %rdx
	xorq	%r10, %rax
	movq	%r8, %rbx
	movq	%r9, %r11
	xorq	%r12, %rcx
	xorq	%rsi, %rdx
	movq	%r8, %r10
	movq	%r9, %r12
	rorq	$10, %rbx
	rorq	$7, %r11
	rorq	$17, %r10
	xorq	%rbx, %r8
	rorq	$41, %r12
	xorq	%r11, %r9
	xorq	%r10, %r8
	xorq	%r12, %r9
.L12:
	notq	%rdx
	movq	%rax, (%rdi)
	movq	%rcx, 8(%rdi)
	movq	%rdx, 16(%rdi)
	movq	%r8, 24(%rdi)
	movq	%r9, 32(%rdi)
	popq	%r13
	popq	%r12
	popq	%rbx
#if defined(__APPLE__)
	retq
	.cfi_endproc
#elif defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	ret
	.seh_endproc
#else
	ret
	.cfi_endproc
	.size	ascon_permute, .-ascon_permute
#endif
#if defined(__APPLE__)
	.p2align 4, 0x90
	.globl	_ascon_backend_free
_ascon_backend_free:
	.cfi_startproc
#elif defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.p2align 4,,15
	.globl	ascon_backend_free
	.def	ascon_backend_free;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_backend_free
ascon_backend_free:
#else
	.p2align 4,,15
	.globl	ascon_backend_free
	.type	ascon_backend_free, @function
ascon_backend_free:
	.cfi_startproc
#endif
	movq	$0, %rax
	movq	$0, %rcx
	movq	$0, %rsi
	movq	$0, %r8
	movq	$0, %r9
	movq	$0, %r10
	movq	$0, %r11
#if defined(__APPLE__)
	retq
	.cfi_endproc
#elif defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	ret
	.seh_endproc
#else
	ret
	.cfi_endproc
	.size	ascon_backend_free, .-ascon_backend_free
#endif

#endif
