#include "ascon-masked-backend.h"
#if defined(ASCON_MASKED_WORD_BACKEND_X86_64)
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
#if defined(__PIC__)
#define trng_generate_64 ascon_trng_generate_64@PLT
#else
#define trng_generate_64 ascon_trng_generate_64
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_zero
	.def	ascon_masked_word_x2_zero;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_zero
ascon_masked_word_x2_zero:
#else
	.globl	ascon_masked_word_x2_zero
	.type	ascon_masked_word_x2_zero, @function
ascon_masked_word_x2_zero:
	.cfi_startproc
#endif
	pushq	%rbx
	movq	%rdi, %rbx
	movq	%rsi, %rdi
	call	trng_generate_64
	movq	%rax, (%rbx)
	rorq	$11, %rax
	movq	%rax, 8(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 3
	movq	$0, %rcx
	movq	%rcx, 16(%rbx)
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_zero, .-ascon_masked_word_x2_zero
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_load
	.def	ascon_masked_word_x2_load;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_load
ascon_masked_word_x2_load:
#else
	.globl	ascon_masked_word_x2_load
	.type	ascon_masked_word_x2_load, @function
ascon_masked_word_x2_load:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %rcx
	xorq	(%rbp), %rcx
	bswapq	%rcx
	bswapq	%rax
	rorq	$11, %rax
	movq	%rcx, (%rbx)
	movq	%rax, 8(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 3
	movq	$0, %rcx
	movq	%rcx, 16(%rbx)
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_load, .-ascon_masked_word_x2_load
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_load_partial
	.def	ascon_masked_word_x2_load_partial;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_load_partial
ascon_masked_word_x2_load_partial:
#else
	.globl	ascon_masked_word_x2_load_partial
	.type	ascon_masked_word_x2_load_partial, @function
ascon_masked_word_x2_load_partial:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rcx, %rdi
	call	trng_generate_64
	movq	%rax, %rcx
	jmp	.L100
.L101:
	subq	$1, %r12
	movzbl	(%rbp,%r12), %edx
	xorq	%rdx, %rcx
	rorq	$8, %rcx
	rorq	$8, %rax
.L100:
	cmpq	$0, %r12
	jg	.L101
	movq	$0, %rdx
	rorq	$11, %rax
	movq	%rcx, (%rbx)
	movq	%rax, 8(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 3
	movq	$0, %rcx
	movq	%rcx, 16(%rbx)
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_load_partial, .-ascon_masked_word_x2_load_partial
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_load_32
	.def	ascon_masked_word_x2_load_32;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_load_32
ascon_masked_word_x2_load_32:
#else
	.globl	ascon_masked_word_x2_load_32
	.type	ascon_masked_word_x2_load_32, @function
ascon_masked_word_x2_load_32:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rcx, %rdi
	call	trng_generate_64
	movl	(%rbp), %ecx
	xorq	%rax, %rcx
	movl	(%r12), %edx
	rorq	$32, %rdx
	xorq	%rdx, %rcx
	movq	$0, %rdx
	bswapq	%rcx
	bswapq	%rax
	rorq	$11, %rax
	movq	%rcx, (%rbx)
	movq	%rax, 8(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 3
	movq	$0, %rcx
	movq	%rcx, 16(%rbx)
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_load_32, .-ascon_masked_word_x2_load_32
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_store
	.def	ascon_masked_word_x2_store;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_store
ascon_masked_word_x2_store:
#else
	.globl	ascon_masked_word_x2_store
	.type	ascon_masked_word_x2_store, @function
ascon_masked_word_x2_store:
	.cfi_startproc
#endif
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	rorq	$53, %rcx
	bswapq	%rax
	bswapq	%rcx
	xorq	%rcx, %rax
	movq	%rax, (%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_store, .-ascon_masked_word_x2_store
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_store_partial
	.def	ascon_masked_word_x2_store_partial;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_store_partial
ascon_masked_word_x2_store_partial:
#else
	.globl	ascon_masked_word_x2_store_partial
	.type	ascon_masked_word_x2_store_partial, @function
ascon_masked_word_x2_store_partial:
	.cfi_startproc
#endif
	movq	(%rdx), %rax
	movq	8(%rdx), %rcx
	rorq	$53, %rcx
	xorq	%rcx, %rax
	jmp	.L102
.L103:
	rorq	$56, %rax
	movb	%al, (%rdi)
	subq	$1, %rsi
	addq	$1, %rdi
.L102:
	cmpq	$0, %rsi
	jg	.L103
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_store_partial, .-ascon_masked_word_x2_store_partial
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_randomize
	.def	ascon_masked_word_x2_randomize;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_randomize
ascon_masked_word_x2_randomize:
#else
	.globl	ascon_masked_word_x2_randomize
	.type	ascon_masked_word_x2_randomize, @function
ascon_masked_word_x2_randomize:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%rax, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	rorq	$11, %rax
	xorq	%rcx, %rax
	movq	%rax, 8(%rbx)
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_randomize, .-ascon_masked_word_x2_randomize
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_xor
	.def	ascon_masked_word_x2_xor;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_xor
ascon_masked_word_x2_xor:
#else
	.globl	ascon_masked_word_x2_xor
	.type	ascon_masked_word_x2_xor, @function
ascon_masked_word_x2_xor:
	.cfi_startproc
#endif
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	xorq	%rax, (%rdi)
	xorq	%rcx, 8(%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_xor, .-ascon_masked_word_x2_xor
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_replace
	.def	ascon_masked_word_x2_replace;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_replace
ascon_masked_word_x2_replace:
#else
	.globl	ascon_masked_word_x2_replace
	.type	ascon_masked_word_x2_replace, @function
ascon_masked_word_x2_replace:
	.cfi_startproc
#endif
	movq	%rdx, %rcx
	movq	$-1, %rax
	shlq	$3, %rcx
	shrq	%cl, %rax
	movq	%rax, %r8
	notq	%r8
	movq	(%rdi), %rcx
	movq	(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, (%rdi)
	rorq	$11, %rax
	rorq	$11, %r8
	movq	8(%rdi), %rcx
	movq	8(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, 8(%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_replace, .-ascon_masked_word_x2_replace
#endif
#if ASCON_MASKED_MAX_SHARES >= 3
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_from_x3
	.def	ascon_masked_word_x2_from_x3;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_from_x3
ascon_masked_word_x2_from_x3:
#else
	.globl	ascon_masked_word_x2_from_x3
	.type	ascon_masked_word_x2_from_x3, @function
ascon_masked_word_x2_from_x3:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%rax, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	movq	%rax, %rdx
	rorq	$11, %rdx
	xorq	%rdx, %rcx
	movq	16(%rbp), %rdx
	rorq	$53, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 8(%rbx)
	movq	$0, %rcx
#if ASCON_MASKED_MAX_SHARES >= 3
	movq	%rcx, 16(%rbx)
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_from_x3, .-ascon_masked_word_x2_from_x3
#endif
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x2_from_x4
	.def	ascon_masked_word_x2_from_x4;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x2_from_x4
ascon_masked_word_x2_from_x4:
#else
	.globl	ascon_masked_word_x2_from_x4
	.type	ascon_masked_word_x2_from_x4, @function
ascon_masked_word_x2_from_x4:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%rax, %rcx
	movq	16(%rbp), %rdx
	rorq	$42, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	movq	%rax, %rdx
	rorq	$11, %rdx
	xorq	%rdx, %rcx
	movq	24(%rbp), %rdx
	rorq	$42, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 8(%rbx)
	movq	$0, %rcx
#if ASCON_MASKED_MAX_SHARES >= 3
	movq	%rcx, 16(%rbx)
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x2_from_x4, .-ascon_masked_word_x2_from_x4
#endif
#endif
#if ASCON_MASKED_MAX_SHARES >= 3
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_zero
	.def	ascon_masked_word_x3_zero;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_zero
ascon_masked_word_x3_zero:
#else
	.globl	ascon_masked_word_x3_zero
	.type	ascon_masked_word_x3_zero, @function
ascon_masked_word_x3_zero:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rsi, %rdi
	call	trng_generate_64
	movq	%rax, %r12
	movq	%rbp, %rdi
	call	trng_generate_64
	movq	%r12, %rcx
	xorq	%rax, %rcx
	rorq	$11, %r12
	rorq	$22, %rax
	movq	%rcx, (%rbx)
	movq	%r12, 8(%rbx)
	movq	%rax, 16(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	$0, %rcx
	movq	%rcx, 24(%rbx)
#endif
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_zero, .-ascon_masked_word_x3_zero
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_load
	.def	ascon_masked_word_x3_load;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_load
ascon_masked_word_x3_load:
#else
	.globl	ascon_masked_word_x3_load
	.type	ascon_masked_word_x3_load, @function
ascon_masked_word_x3_load:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	%r13, %rcx
	xorq	(%rbp), %rcx
	bswapq	%rcx
	bswapq	%r13
	xorq	%rax, %rcx
	rorq	$11, %r13
	rorq	$22, %rax
	movq	%rcx, (%rbx)
	movq	%r13, 8(%rbx)
	movq	%rax, 16(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	$0, %rcx
	movq	%rcx, 24(%rbx)
#endif
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_load, .-ascon_masked_word_x3_load
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_load_partial
	.def	ascon_masked_word_x3_load_partial;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_load_partial
ascon_masked_word_x3_load_partial:
#else
	.globl	ascon_masked_word_x3_load_partial
	.type	ascon_masked_word_x3_load_partial, @function
ascon_masked_word_x3_load_partial:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rcx, %r13
	movq	%rcx, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r13, %rdi
	call	trng_generate_64
	movq	%r14, %rcx
	jmp	.L104
.L105:
	subq	$1, %r12
	movzbl	(%rbp,%r12), %edx
	xorq	%rdx, %rcx
	rorq	$8, %rcx
	rorq	$8, %r14
.L104:
	cmpq	$0, %r12
	jg	.L105
	movq	$0, %rdx
	xorq	%rax, %rcx
	rorq	$11, %r14
	rorq	$22, %rax
	movq	%rcx, (%rbx)
	movq	%r14, 8(%rbx)
	movq	%rax, 16(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	$0, %rcx
	movq	%rcx, 24(%rbx)
#endif
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_load_partial, .-ascon_masked_word_x3_load_partial
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_load_32
	.def	ascon_masked_word_x3_load_32;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_load_32
ascon_masked_word_x3_load_32:
#else
	.globl	ascon_masked_word_x3_load_32
	.type	ascon_masked_word_x3_load_32, @function
ascon_masked_word_x3_load_32:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rcx, %r13
	movq	%rcx, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r13, %rdi
	call	trng_generate_64
	movl	(%rbp), %ecx
	xorq	%r14, %rcx
	movl	(%r12), %edx
	rorq	$32, %rdx
	xorq	%rdx, %rcx
	movq	$0, %rdx
	bswapq	%rcx
	bswapq	%r14
	xorq	%rax, %rcx
	rorq	$11, %r14
	rorq	$22, %rax
	movq	%rcx, (%rbx)
	movq	%r14, 8(%rbx)
	movq	%rax, 16(%rbx)
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	$0, %rcx
	movq	%rcx, 24(%rbx)
#endif
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_load_32, .-ascon_masked_word_x3_load_32
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_store
	.def	ascon_masked_word_x3_store;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_store
ascon_masked_word_x3_store:
#else
	.globl	ascon_masked_word_x3_store
	.type	ascon_masked_word_x3_store, @function
ascon_masked_word_x3_store:
	.cfi_startproc
#endif
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	movq	16(%rsi), %rdx
	rorq	$53, %rcx
	rorq	$42, %rdx
	bswapq	%rax
	bswapq	%rcx
	bswapq	%rdx
	xorq	%rcx, %rax
	xorq	%rdx, %rax
	movq	%rax, (%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_store, .-ascon_masked_word_x3_store
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_store_partial
	.def	ascon_masked_word_x3_store_partial;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_store_partial
ascon_masked_word_x3_store_partial:
#else
	.globl	ascon_masked_word_x3_store_partial
	.type	ascon_masked_word_x3_store_partial, @function
ascon_masked_word_x3_store_partial:
	.cfi_startproc
#endif
	movq	(%rdx), %rax
	movq	8(%rdx), %rcx
	movq	16(%rdx), %r8
	rorq	$53, %rcx
	rorq	$42, %r8
	xorq	%rcx, %rax
	xorq	%r8, %rax
	jmp	.L106
.L107:
	rorq	$56, %rax
	movb	%al, (%rdi)
	subq	$1, %rsi
	addq	$1, %rdi
.L106:
	cmpq	$0, %rsi
	jg	.L107
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_store_partial, .-ascon_masked_word_x3_store_partial
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_randomize
	.def	ascon_masked_word_x3_randomize;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_randomize
ascon_masked_word_x3_randomize:
#else
	.globl	ascon_masked_word_x3_randomize
	.type	ascon_masked_word_x3_randomize, @function
ascon_masked_word_x3_randomize:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%r13, %rcx
	xorq	%rax, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	rorq	$11, %r13
	xorq	%rcx, %r13
	movq	%r13, 8(%rbx)
	movq	16(%rbp), %rcx
	rorq	$22, %rax
	xorq	%rcx, %rax
	movq	%rax, 16(%rbx)
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_randomize, .-ascon_masked_word_x3_randomize
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_xor
	.def	ascon_masked_word_x3_xor;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_xor
ascon_masked_word_x3_xor:
#else
	.globl	ascon_masked_word_x3_xor
	.type	ascon_masked_word_x3_xor, @function
ascon_masked_word_x3_xor:
	.cfi_startproc
#endif
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	movq	16(%rsi), %rdx
	xorq	%rax, (%rdi)
	xorq	%rcx, 8(%rdi)
	xorq	%rdx, 16(%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_xor, .-ascon_masked_word_x3_xor
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_replace
	.def	ascon_masked_word_x3_replace;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_replace
ascon_masked_word_x3_replace:
#else
	.globl	ascon_masked_word_x3_replace
	.type	ascon_masked_word_x3_replace, @function
ascon_masked_word_x3_replace:
	.cfi_startproc
#endif
	movq	%rdx, %rcx
	movq	$-1, %rax
	shlq	$3, %rcx
	shrq	%cl, %rax
	movq	%rax, %r8
	notq	%r8
	movq	(%rdi), %rcx
	movq	(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, (%rdi)
	rorq	$11, %rax
	rorq	$11, %r8
	movq	8(%rdi), %rcx
	movq	8(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, 8(%rdi)
	rorq	$11, %rax
	rorq	$11, %r8
	movq	16(%rdi), %rcx
	movq	16(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, 16(%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_replace, .-ascon_masked_word_x3_replace
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_from_x2
	.def	ascon_masked_word_x3_from_x2;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_from_x2
ascon_masked_word_x3_from_x2:
#else
	.globl	ascon_masked_word_x3_from_x2
	.type	ascon_masked_word_x3_from_x2, @function
ascon_masked_word_x3_from_x2:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%r13, %rcx
	xorq	%rax, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	movq	%r13, %rdx
	rorq	$11, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 8(%rbx)
	movq	%rax, %rcx
	rorq	$22, %rcx
	movq	%rcx, 16(%rbx)
	movq	$0, %rcx
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_from_x2, .-ascon_masked_word_x3_from_x2
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x3_from_x4
	.def	ascon_masked_word_x3_from_x4;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x3_from_x4
ascon_masked_word_x3_from_x4:
#else
	.globl	ascon_masked_word_x3_from_x4
	.type	ascon_masked_word_x3_from_x4, @function
ascon_masked_word_x3_from_x4:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%r13, %rcx
	xorq	%rax, %rcx
	movq	24(%rbp), %rdx
	rorq	$31, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	movq	%r13, %rdx
	rorq	$11, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 8(%rbx)
	movq	16(%rbp), %rcx
	movq	%rax, %rdx
	rorq	$22, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 16(%rbx)
	movq	$0, %rcx
#if ASCON_MASKED_MAX_SHARES >= 4
	movq	%rcx, 24(%rbx)
#endif
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x3_from_x4, .-ascon_masked_word_x3_from_x4
#endif
#endif
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_zero
	.def	ascon_masked_word_x4_zero;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_zero
ascon_masked_word_x4_zero:
#else
	.globl	ascon_masked_word_x4_zero
	.type	ascon_masked_word_x4_zero, @function
ascon_masked_word_x4_zero:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rsi, %rdi
	call	trng_generate_64
	movq	%rax, %r12
	movq	%rbp, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%rbp, %rdi
	call	trng_generate_64
	movq	%r12, %rcx
	xorq	%r13, %rcx
	xorq	%rax, %rcx
	rorq	$11, %r12
	rorq	$22, %r13
	rorq	$33, %rax
	movq	%rcx, (%rbx)
	movq	%r12, 8(%rbx)
	movq	%r13, 16(%rbx)
	movq	%rax, 24(%rbx)
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_zero, .-ascon_masked_word_x4_zero
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_load
	.def	ascon_masked_word_x4_load;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_load
ascon_masked_word_x4_load:
#else
	.globl	ascon_masked_word_x4_load
	.type	ascon_masked_word_x4_load, @function
ascon_masked_word_x4_load:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r12, %rdi
	call	trng_generate_64
	movq	%r13, %rcx
	xorq	(%rbp), %rcx
	bswapq	%rcx
	bswapq	%r13
	xorq	%r14, %rcx
	xorq	%rax, %rcx
	rorq	$11, %r13
	rorq	$22, %r14
	rorq	$33, %rax
	movq	%rcx, (%rbx)
	movq	%r13, 8(%rbx)
	movq	%r14, 16(%rbx)
	movq	%rax, 24(%rbx)
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_load, .-ascon_masked_word_x4_load
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_load_partial
	.def	ascon_masked_word_x4_load_partial;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_load_partial
ascon_masked_word_x4_load_partial:
#else
	.globl	ascon_masked_word_x4_load_partial
	.type	ascon_masked_word_x4_load_partial, @function
ascon_masked_word_x4_load_partial:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rcx, %r13
	movq	%rcx, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r13, %rdi
	call	trng_generate_64
	movq	%rax, %r15
	movq	%r13, %rdi
	call	trng_generate_64
	movq	%r14, %rcx
	jmp	.L108
.L109:
	subq	$1, %r12
	movzbl	(%rbp,%r12), %edx
	xorq	%rdx, %rcx
	rorq	$8, %rcx
	rorq	$8, %r14
.L108:
	cmpq	$0, %r12
	jg	.L109
	movq	$0, %rdx
	xorq	%r15, %rcx
	xorq	%rax, %rcx
	rorq	$11, %r14
	rorq	$22, %r15
	rorq	$33, %rax
	movq	%rcx, (%rbx)
	movq	%r14, 8(%rbx)
	movq	%r15, 16(%rbx)
	movq	%rax, 24(%rbx)
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_load_partial, .-ascon_masked_word_x4_load_partial
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_load_32
	.def	ascon_masked_word_x4_load_32;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_load_32
ascon_masked_word_x4_load_32:
#else
	.globl	ascon_masked_word_x4_load_32
	.type	ascon_masked_word_x4_load_32, @function
ascon_masked_word_x4_load_32:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rcx, %r13
	movq	%rcx, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r13, %rdi
	call	trng_generate_64
	movq	%rax, %r15
	movq	%r13, %rdi
	call	trng_generate_64
	movl	(%rbp), %ecx
	xorq	%r14, %rcx
	movl	(%r12), %edx
	rorq	$32, %rdx
	xorq	%rdx, %rcx
	movq	$0, %rdx
	bswapq	%rcx
	bswapq	%r14
	xorq	%r15, %rcx
	xorq	%rax, %rcx
	rorq	$11, %r14
	rorq	$22, %r15
	rorq	$33, %rax
	movq	%rcx, (%rbx)
	movq	%r14, 8(%rbx)
	movq	%r15, 16(%rbx)
	movq	%rax, 24(%rbx)
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_load_32, .-ascon_masked_word_x4_load_32
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_store
	.def	ascon_masked_word_x4_store;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_store
ascon_masked_word_x4_store:
#else
	.globl	ascon_masked_word_x4_store
	.type	ascon_masked_word_x4_store, @function
ascon_masked_word_x4_store:
	.cfi_startproc
#endif
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	movq	16(%rsi), %rdx
	movq	24(%rsi), %r8
	rorq	$53, %rcx
	rorq	$42, %rdx
	rorq	$31, %r8
	bswapq	%rax
	bswapq	%rcx
	bswapq	%rdx
	bswapq	%r8
	xorq	%rcx, %rax
	xorq	%rdx, %rax
	xorq	%r8, %rax
	movq	%rax, (%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_store, .-ascon_masked_word_x4_store
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_store_partial
	.def	ascon_masked_word_x4_store_partial;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_store_partial
ascon_masked_word_x4_store_partial:
#else
	.globl	ascon_masked_word_x4_store_partial
	.type	ascon_masked_word_x4_store_partial, @function
ascon_masked_word_x4_store_partial:
	.cfi_startproc
#endif
	movq	(%rdx), %rax
	movq	8(%rdx), %rcx
	movq	16(%rdx), %r8
	movq	24(%rdx), %r9
	rorq	$53, %rcx
	rorq	$42, %r8
	rorq	$31, %r9
	xorq	%rcx, %rax
	xorq	%r8, %rax
	xorq	%r9, %rax
	jmp	.L110
.L111:
	rorq	$56, %rax
	movb	%al, (%rdi)
	subq	$1, %rsi
	addq	$1, %rdi
.L110:
	cmpq	$0, %rsi
	jg	.L111
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_store_partial, .-ascon_masked_word_x4_store_partial
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_randomize
	.def	ascon_masked_word_x4_randomize;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_randomize
ascon_masked_word_x4_randomize:
#else
	.globl	ascon_masked_word_x4_randomize
	.type	ascon_masked_word_x4_randomize, @function
ascon_masked_word_x4_randomize:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r12, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%r13, %rcx
	xorq	%r14, %rcx
	xorq	%rax, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	rorq	$11, %r13
	xorq	%rcx, %r13
	movq	%r13, 8(%rbx)
	movq	16(%rbp), %rcx
	rorq	$22, %r14
	xorq	%rcx, %r14
	movq	%r14, 16(%rbx)
	movq	24(%rbp), %rcx
	rorq	$33, %rax
	xorq	%rcx, %rax
	movq	%rax, 24(%rbx)
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_randomize, .-ascon_masked_word_x4_randomize
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_xor
	.def	ascon_masked_word_x4_xor;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_xor
ascon_masked_word_x4_xor:
#else
	.globl	ascon_masked_word_x4_xor
	.type	ascon_masked_word_x4_xor, @function
ascon_masked_word_x4_xor:
	.cfi_startproc
#endif
	movq	(%rsi), %rax
	movq	8(%rsi), %rcx
	movq	16(%rsi), %rdx
	movq	24(%rsi), %r8
	xorq	%rax, (%rdi)
	xorq	%rcx, 8(%rdi)
	xorq	%rdx, 16(%rdi)
	xorq	%r8, 24(%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_xor, .-ascon_masked_word_x4_xor
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_replace
	.def	ascon_masked_word_x4_replace;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_replace
ascon_masked_word_x4_replace:
#else
	.globl	ascon_masked_word_x4_replace
	.type	ascon_masked_word_x4_replace, @function
ascon_masked_word_x4_replace:
	.cfi_startproc
#endif
	movq	%rdx, %rcx
	movq	$-1, %rax
	shlq	$3, %rcx
	shrq	%cl, %rax
	movq	%rax, %r8
	notq	%r8
	movq	(%rdi), %rcx
	movq	(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, (%rdi)
	rorq	$11, %rax
	rorq	$11, %r8
	movq	8(%rdi), %rcx
	movq	8(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, 8(%rdi)
	rorq	$11, %rax
	rorq	$11, %r8
	movq	16(%rdi), %rcx
	movq	16(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, 16(%rdi)
	rorq	$11, %rax
	rorq	$11, %r8
	movq	24(%rdi), %rcx
	movq	24(%rsi), %r9
	andq	%rax, %rcx
	andq	%r8, %r9
	orq	%r9, %rcx
	movq	%rcx, 24(%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_replace, .-ascon_masked_word_x4_replace
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_from_x2
	.def	ascon_masked_word_x4_from_x2;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_from_x2
ascon_masked_word_x4_from_x2:
#else
	.globl	ascon_masked_word_x4_from_x2
	.type	ascon_masked_word_x4_from_x2, @function
ascon_masked_word_x4_from_x2:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r12, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%r13, %rcx
	xorq	%r14, %rcx
	xorq	%rax, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	movq	%r13, %rdx
	rorq	$11, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 8(%rbx)
	movq	%r14, %rcx
	rorq	$22, %rcx
	movq	%rcx, 16(%rbx)
	movq	%rax, %rcx
	rorq	$33, %rcx
	movq	%rcx, 24(%rbx)
	movq	$0, %rcx
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_from_x2, .-ascon_masked_word_x4_from_x2
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_x4_from_x3
	.def	ascon_masked_word_x4_from_x3;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_x4_from_x3
ascon_masked_word_x4_from_x3:
#else
	.globl	ascon_masked_word_x4_from_x3
	.type	ascon_masked_word_x4_from_x3, @function
ascon_masked_word_x4_from_x3:
	.cfi_startproc
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	movq	%rdi, %rbx
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rdx, %rdi
	call	trng_generate_64
	movq	%rax, %r13
	movq	%r12, %rdi
	call	trng_generate_64
	movq	%rax, %r14
	movq	%r12, %rdi
	call	trng_generate_64
	movq	(%rbp), %rcx
	xorq	%r13, %rcx
	xorq	%r14, %rcx
	xorq	%rax, %rcx
	movq	%rcx, (%rbx)
	movq	8(%rbp), %rcx
	movq	%r13, %rdx
	rorq	$11, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 8(%rbx)
	movq	16(%rbp), %rcx
	movq	%r14, %rdx
	rorq	$22, %rdx
	xorq	%rdx, %rcx
	movq	%rcx, 16(%rbx)
	movq	%rax, %rcx
	rorq	$33, %rcx
	movq	%rcx, 24(%rbx)
	movq	$0, %rcx
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_x4_from_x3, .-ascon_masked_word_x4_from_x3
#endif
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_pad
	.def	ascon_masked_word_pad;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_pad
ascon_masked_word_pad:
#else
	.globl	ascon_masked_word_pad
	.type	ascon_masked_word_pad, @function
ascon_masked_word_pad:
	.cfi_startproc
#endif
	movq	%rsi, %rcx
	shlq	$3, %rcx
	movq	$-9223372036854775808, %rax
	shrq	%cl, %rax
	xorq	%rax, (%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_pad, .-ascon_masked_word_pad
#endif
	.p2align 4,,15
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.globl	ascon_masked_word_separator
	.def	ascon_masked_word_separator;	.scl	3;	.type	32;	.endef
	.seh_proc	ascon_masked_word_separator
ascon_masked_word_separator:
#else
	.globl	ascon_masked_word_separator
	.type	ascon_masked_word_separator, @function
ascon_masked_word_separator:
	.cfi_startproc
#endif
	movq	$1, %rax
	xorq	%rax, (%rdi)
	ret
#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)
	.seh_endproc
#else
	.cfi_endproc
	.size	ascon_masked_word_separator, .-ascon_masked_word_separator
#endif

#endif
