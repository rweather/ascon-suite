#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_ARMV7M)
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
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r2, [r0, #0]
	ldr	r7, [r0, #4]
	ldr	r3, [r0, #8]
	ldr	r8, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r9, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r10, [r0, #28]
	ldr	r6, [r0, #32]
	ldr	fp, [r0, #36]
	push	{r0}
	cmp	r1, #6
	beq	.L6
	cmp	r1, #0
	beq	.L0
	cmp	r1, #4
	beq	.L4
	cmp	r1, #11
	beq	.L11
	cmp	r1, #10
	beq	.L10
	cmp	r1, #9
	beq	.L9
	cmp	r1, #8
	beq	.L8
	cmp	r1, #7
	beq	.L7
	cmp	r1, #5
	beq	.L5
	cmp	r1, #3
	beq	.L3
	cmp	r1, #2
	beq	.L2
	cmp	r1, #1
	beq	.L1
	b	.L12
.L0:
	eor	r4, r4, #12
	eor	r9, r9, #12
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L1:
	eor	r4, r4, #9
	eor	r9, r9, #12
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L2:
	eor	r4, r4, #12
	eor	r9, r9, #9
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L3:
	eor	r4, r4, #9
	eor	r9, r9, #9
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L4:
	eor	r4, r4, #6
	eor	r9, r9, #12
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L5:
	eor	r4, r4, #3
	eor	r9, r9, #12
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L6:
	eor	r4, r4, #6
	eor	r9, r9, #9
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L7:
	eor	r4, r4, #3
	eor	r9, r9, #9
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L8:
	eor	r4, r4, #12
	eor	r9, r9, #6
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L9:
	eor	r4, r4, #9
	eor	r9, r9, #6
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L10:
	eor	r4, r4, #12
	eor	r9, r9, #3
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L11:
	eor	r4, r4, #9
	eor	r9, r9, #3
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L12:
	pop	{r0}
	str	r2, [r0, #0]
	str	r7, [r0, #4]
	str	r3, [r0, #8]
	str	r8, [r0, #12]
	str	r4, [r0, #16]
	str	r9, [r0, #20]
	str	r5, [r0, #24]
	str	r10, [r0, #28]
	str	r6, [r0, #32]
	str	fp, [r0, #36]
	movs	r1, #0
	movs	r2, #0
	movs	r3, #0
	mov	ip, r1
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	ascon_permute, .-ascon_permute

#endif
