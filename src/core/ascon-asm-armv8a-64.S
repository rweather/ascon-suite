#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_ARMV8A)
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

	.arch	armv8-a
	.text

	.align	2
	.p2align 4,,11
	.global	ascon_permute
	.type	ascon_permute, %function
ascon_permute:
	.cfi_startproc
	ldp	x2, x3, [x0]
	ldp	x4, x5, [x0, 16]
	ldr	x6, [x0, 32]
	mvn	x4, x4
	and	w1, w1, #255
	cmp	w1, #6
	beq	.L6
	cmp	w1, #0
	beq	.L0
	cmp	w1, #4
	beq	.L4
	cmp	w1, #11
	beq	.L11
	cmp	w1, #10
	beq	.L10
	cmp	w1, #9
	beq	.L9
	cmp	w1, #8
	beq	.L8
	cmp	w1, #7
	beq	.L7
	cmp	w1, #5
	beq	.L5
	cmp	w1, #3
	beq	.L3
	cmp	w1, #2
	beq	.L2
	cmp	w1, #1
	beq	.L1
	b	.L12
.L0:
	ldr	x12, =0xffffffffffffff0f
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L1:
	ldr	x12, =0xffffffffffffff1e
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L2:
	ldr	x12, =0xffffffffffffff2d
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L3:
	ldr	x12, =0xffffffffffffff3c
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L4:
	ldr	x12, =0xffffffffffffff4b
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L5:
	ldr	x12, =0xffffffffffffff5a
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L6:
	ldr	x12, =0xffffffffffffff69
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L7:
	ldr	x12, =0xffffffffffffff78
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L8:
	ldr	x12, =0xffffffffffffff87
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L9:
	ldr	x12, =0xffffffffffffff96
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L10:
	ldr	x12, =0xffffffffffffffa5
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L11:
	ldr	x12, =0xffffffffffffffb4
	eor	x4, x4, x12
	eor	x2, x2, x6
	eor	x6, x6, x5
	eor	x4, x4, x3
	mov	x7, x2
	bic	x1, x3, x2
	bic	x9, x4, x3
	eor	x2, x2, x9
	bic	x10, x5, x4
	eor	x3, x3, x10
	bic	x11, x7, x6
	eor	x5, x5, x11
	bic	x12, x6, x5
	eor	x4, x4, x12
	eor	x6, x6, x1
	eor	x3, x3, x2
	eor	x2, x2, x6
	eor	x5, x5, x4
	ror	x1, x2, #19
	ror	x7, x3, #61
	ror	x9, x4, #1
	ror	x10, x5, #10
	ror	x11, x6, #7
	eor	x2, x2, x2, ror #28
	eor	x3, x3, x3, ror #39
	eor	x4, x4, x4, ror #6
	eor	x5, x5, x5, ror #17
	eor	x6, x6, x6, ror #41
	eor	x2, x2, x1
	eor	x3, x3, x7
	eor	x4, x4, x9
	eor	x5, x5, x10
	eor	x6, x6, x11
.L12:
	mvn	x4, x4
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, 16]
	str	x6, [x0, 32]
	ret
	.cfi_endproc
	.size	ascon_permute, .-ascon_permute

	.align	2
	.p2align 4,,11
	.global	ascon_from_regular
	.type	ascon_from_regular, %function
ascon_from_regular:
	.cfi_startproc
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, 16]
	ldr	x5, [x0, 32]
	rev	x1, x1
	rev	x2, x2
	rev	x3, x3
	rev	x4, x4
	rev	x5, x5
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, 16]
	str	x5, [x0, 32]
	ret
	.cfi_endproc
	.size	ascon_from_regular, .-ascon_from_regular

	.align	2
	.p2align 4,,11
	.global	ascon_to_regular
	.type	ascon_to_regular, %function
ascon_to_regular:
	.cfi_startproc
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, 16]
	ldr	x5, [x0, 32]
	rev	x1, x1
	rev	x2, x2
	rev	x3, x3
	rev	x4, x4
	rev	x5, x5
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, 16]
	str	x5, [x0, 32]
	ret
	.cfi_endproc
	.size	ascon_to_regular, .-ascon_to_regular

#endif
