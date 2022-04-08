#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_ARMV6M)
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

	.syntax unified
	.thumb
	.text

	.align	2
	.global	ascon_permute
	.thumb
	.thumb_func
	.type	ascon_permute, %function
ascon_permute:
	push	{r4, r5, r6, r7, lr}
	sub	sp, sp, #44
	str	r0, [sp, #40]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #20]
	ldr	r6, [r0, #28]
	ldr	r7, [r0, #36]
	str	r3, [sp, #4]
	str	r4, [sp, #12]
	str	r5, [sp, #20]
	str	r6, [sp, #28]
	str	r7, [sp, #36]
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #32]
	cmp	r1, #11
	bhi	.L91
	lsls	r1, r1, #2
	adr	r2, .L90
	ldr	r1, [r2, r1]
	mov	pc, r1
	.align	2
.L90:
	.word	.L0
	.word	.L1
	.word	.L2
	.word	.L3
	.word	.L4
	.word	.L5
	.word	.L6
	.word	.L7
	.word	.L8
	.word	.L9
	.word	.L10
	.word	.L11
.L91:
	bl	.L12
.L0:
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L1:
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L2:
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L3:
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L4:
	movs	r0, #6
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L5:
	movs	r0, #3
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L6:
	movs	r0, #6
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L7:
	movs	r0, #3
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L8:
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #6
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L9:
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #6
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L10:
	movs	r0, #12
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #3
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L11:
	movs	r0, #9
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	str	r3, [sp, #0]
	str	r4, [sp, #8]
	str	r5, [sp, #16]
	str	r6, [sp, #24]
	str	r7, [sp, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	movs	r0, #3
	eors	r5, r0
	eors	r3, r7
	eors	r7, r6
	eors	r5, r4
	movs	r1, r3
	mvns	r0, r3
	ands	r0, r4
	mvns	r2, r4
	ands	r2, r5
	eors	r3, r2
	mvns	r2, r5
	ands	r2, r6
	eors	r4, r2
	mvns	r2, r7
	ands	r2, r1
	eors	r6, r2
	mvns	r2, r6
	ands	r2, r7
	eors	r5, r2
	eors	r7, r0
	eors	r4, r3
	eors	r3, r7
	eors	r6, r5
	mvns	r5, r5
	mov	ip, r7
	ldr	r2, [sp, #0]
	movs	r7, #4
	movs	r0, r3
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #5
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r3
	movs	r7, #10
	rors	r0, r0, r7
	eors	r0, r3
	str	r0, [sp, #4]
	movs	r7, #9
	movs	r3, r1
	rors	r3, r3, r7
	eors	r3, r2
	ldr	r2, [sp, #8]
	movs	r7, #11
	movs	r0, r2
	rors	r0, r0, r7
	eors	r0, r2
	movs	r1, r4
	rors	r1, r1, r7
	eors	r1, r4
	movs	r7, #20
	rors	r0, r0, r7
	eors	r0, r4
	str	r0, [sp, #12]
	movs	r7, #19
	movs	r4, r1
	rors	r4, r4, r7
	eors	r4, r2
	ldr	r2, [sp, #16]
	movs	r7, #2
	movs	r0, r5
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #3
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r5
	movs	r7, #1
	rors	r0, r0, r7
	eors	r0, r5
	str	r0, [sp, #20]
	movs	r5, r1
	eors	r5, r2
	ldr	r2, [sp, #24]
	movs	r7, #3
	movs	r0, r6
	rors	r0, r0, r7
	eors	r0, r2
	movs	r7, #4
	movs	r1, r2
	rors	r1, r1, r7
	eors	r1, r6
	movs	r7, #5
	rors	r1, r1, r7
	eors	r1, r6
	str	r1, [sp, #28]
	movs	r6, r0
	rors	r6, r6, r7
	eors	r6, r2
	mov	r7, ip
	mov	ip, r3
	ldr	r2, [sp, #32]
	movs	r3, #17
	movs	r0, r2
	rors	r0, r0, r3
	eors	r0, r2
	movs	r1, r7
	rors	r1, r1, r3
	eors	r1, r7
	movs	r3, #4
	rors	r0, r0, r3
	eors	r0, r7
	str	r0, [sp, #36]
	movs	r3, #3
	movs	r7, r1
	rors	r7, r7, r3
	eors	r7, r2
	mov	r3, ip
.L12:
	ldr	r0, [sp, #40]
	str	r3, [r0, #0]
	str	r4, [r0, #8]
	str	r5, [r0, #16]
	str	r6, [r0, #24]
	str	r7, [r0, #32]
	ldr	r3, [sp, #4]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #36]
	str	r3, [r0, #4]
	str	r4, [r0, #12]
	str	r5, [r0, #20]
	str	r6, [r0, #28]
	str	r7, [r0, #36]
	add	sp, sp, #44
	pop	{r4, r5, r6, r7, pc}
	.size	ascon_permute, .-ascon_permute

	.align	2
	.global	ascon_from_regular
	.thumb
	.thumb_func
	.type	ascon_from_regular, %function
ascon_from_regular:
	push	{r4, r5, r6, lr}
	movs	r6, #5
.L100:
	ldr	r1, [r0]
	ldr	r2, [r0, #4]
	ldr	r5, =0x22222222
	lsrs	r3, r1, #1
	lsrs	r4, r2, #1
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #1
	lsls	r4, r4, #1
	eors	r1, r3
	eors	r2, r4
	ldr	r5, =0x0c0c0c0c
	lsrs	r3, r1, #2
	lsrs	r4, r2, #2
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #2
	lsls	r4, r4, #2
	eors	r1, r3
	eors	r2, r4
	ldr	r5, =0x000f000f
	lsrs	r3, r1, #12
	lsrs	r4, r2, #12
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #12
	lsls	r4, r4, #12
	eors	r1, r3
	eors	r2, r4
	movs	r5, #255
	lsrs	r3, r1, #24
	lsrs	r4, r2, #24
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #24
	lsls	r4, r4, #24
	eors	r1, r3
	eors	r2, r4
	uxth	r3, r2
	lsls	r5, r1, #16
	orrs	r3, r5
	lsrs	r1, r1, #16
	str	r3, [r0]
	lsls	r4, r1, #16
	lsrs	r2, r2, #16
	orrs	r4, r2
	str	r4, [r0, #4]
	adds	r0, r0, #8
	subs	r6, r6, #1
	bne	.L100
	pop	{r4, r5, r6, pc}
	.size	ascon_from_regular, .-ascon_from_regular

	.align	2
	.global	ascon_to_regular
	.thumb
	.thumb_func
	.type	ascon_to_regular, %function
ascon_to_regular:
	push	{r4, r5, r6, lr}
	movs	r6, #5
.L101:
	ldr	r1, [r0]
	ldr	r2, [r0, #4]
	lsrs	r3, r2, #16
	lsls	r3, r3, #16
	uxth	r4, r1
	lsrs	r1, r1, #16
	orrs	r1, r3
	lsls	r2, r2, #16
	orrs	r2, r4
	ldr	r5, =0x0000aaaa
	lsrs	r3, r1, #15
	lsrs	r4, r2, #15
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #15
	lsls	r4, r4, #15
	eors	r1, r3
	eors	r2, r4
	ldr	r5, =0x0000cccc
	lsrs	r3, r1, #14
	lsrs	r4, r2, #14
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #14
	lsls	r4, r4, #14
	eors	r1, r3
	eors	r2, r4
	ldr	r5, =0x0000f0f0
	lsrs	r3, r1, #12
	lsrs	r4, r2, #12
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #12
	lsls	r4, r4, #12
	eors	r1, r3
	eors	r2, r4
	movs	r5, #255
	lsrs	r3, r1, #24
	lsrs	r4, r2, #24
	eors	r3, r1
	eors	r4, r2
	ands	r3, r5
	ands	r4, r5
	eors	r1, r3
	eors	r2, r4
	lsls	r3, r3, #24
	lsls	r4, r4, #24
	eors	r1, r3
	eors	r2, r4
	str	r1, [r0]
	str	r2, [r0, #4]
	adds	r0, r0, #8
	subs	r6, r6, #1
	bne	.L101
	pop	{r4, r5, r6, pc}
	.size	ascon_to_regular, .-ascon_to_regular

#endif
