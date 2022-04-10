#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_XTENSA)
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

#ifdef ESP8266
	.section .irom0.text,"ax",@progbits
#else
	.section .text.ascon_permute,"ax",@progbits
#endif
	.align	4
	.literal_position
	.global	ascon_permute
	.type	ascon_permute, @function
ascon_permute:
#ifdef __XTENSA_WINDOWED_ABI__
	entry	sp, 32
	s32i.n	a2, sp, 0
#else
	addi	sp, sp, -32
	s32i.n	a2, sp, 0
	s32i.n	a12, sp, 4
	s32i.n	a13, sp, 8
	s32i.n	a14, sp, 12
	s32i.n	a15, sp, 16
#endif
	l32i.n	a4, a2, 0
	l32i.n	a9, a2, 4
	l32i.n	a5, a2, 8
	l32i.n	a10, a2, 12
	l32i.n	a6, a2, 16
	l32i.n	a11, a2, 20
	l32i.n	a7, a2, 24
	l32i.n	a12, a2, 28
	l32i.n	a8, a2, 32
	l32i.n	a13, a2, 36
	movi.n	a15, -1
	xor	a6, a6, a15
	xor	a11, a11, a15
	beqi	a3, 6, .L6
	beqz	a3, .L0
	beqi	a3, 4, .L4
	movi.n	a3, 11
	beq	a3, a3, .L11
	beqi	a3, 10, .L10
	movi.n	a3, 9
	beq	a3, a3, .L9
	beqi	a3, 8, .L8
	beqi	a3, 7, .L7
	beqi	a3, 5, .L5
	beqi	a3, 3, .L3
	beqi	a3, 2, .L2
	beqi	a3, 1, .L1
	j	.L12
.L0:
	movi.n	a2, -13
	movi.n	a3, -13
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L1:
	movi.n	a2, -10
	movi.n	a3, -13
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L2:
	movi.n	a2, -13
	movi.n	a3, -10
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L3:
	movi.n	a2, -10
	movi.n	a3, -10
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L4:
	movi.n	a2, -7
	movi.n	a3, -13
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L5:
	movi.n	a2, -4
	movi.n	a3, -13
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L6:
	movi.n	a2, -7
	movi.n	a3, -10
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L7:
	movi.n	a2, -4
	movi.n	a3, -10
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L8:
	movi.n	a2, -13
	movi.n	a3, -7
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L9:
	movi.n	a2, -10
	movi.n	a3, -7
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L10:
	movi.n	a2, -13
	movi.n	a3, -4
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L11:
	movi.n	a2, -10
	movi.n	a3, -4
	xor	a6, a6, a2
	xor	a11, a11, a3
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	and	a2, a2, a5
	xor	a14, a5, a15
	and	a14, a14, a6
	xor	a4, a4, a14
	xor	a14, a6, a15
	and	a14, a14, a7
	xor	a5, a5, a14
	xor	a14, a8, a15
	and	a14, a14, a3
	xor	a7, a7, a14
	xor	a14, a7, a15
	and	a14, a14, a8
	xor	a6, a6, a14
	xor	a8, a8, a2
	xor	a5, a5, a4
	xor	a4, a4, a8
	xor	a7, a7, a6
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	and	a2, a2, a10
	xor	a14, a10, a15
	and	a14, a14, a11
	xor	a9, a9, a14
	xor	a14, a11, a15
	and	a14, a14, a12
	xor	a10, a10, a14
	xor	a14, a13, a15
	and	a14, a14, a3
	xor	a12, a12, a14
	xor	a14, a12, a15
	and	a14, a14, a13
	xor	a11, a11, a14
	xor	a13, a13, a2
	xor	a10, a10, a9
	xor	a9, a9, a13
	xor	a12, a12, a11
	ssai	4
	src	a2, a9, a9
	ssai	5
	src	a3, a4, a4
	xor	a2, a2, a4
	xor	a3, a3, a9
	ssai	10
	src	a2, a2, a2
	ssai	9
	src	a3, a3, a3
	xor	a9, a9, a2
	xor	a4, a4, a3
	ssai	11
	src	a2, a5, a5
	src	a3, a10, a10
	xor	a2, a2, a5
	xor	a3, a3, a10
	ssai	20
	src	a2, a2, a2
	ssai	19
	src	a3, a3, a3
	xor	a10, a10, a2
	xor	a5, a5, a3
	ssai	2
	src	a2, a11, a11
	ssai	3
	src	a3, a6, a6
	xor	a2, a2, a6
	xor	a3, a3, a11
	ssai	1
	src	a2, a2, a2
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	3
	src	a2, a12, a12
	ssai	4
	src	a3, a7, a7
	xor	a2, a2, a7
	xor	a3, a3, a12
	ssai	5
	src	a2, a2, a2
	src	a3, a3, a3
	xor	a7, a7, a2
	xor	a12, a12, a3
	ssai	17
	src	a2, a8, a8
	src	a3, a13, a13
	xor	a2, a2, a8
	xor	a3, a3, a13
	ssai	4
	src	a2, a2, a2
	ssai	3
	src	a3, a3, a3
	xor	a13, a13, a2
	xor	a8, a8, a3
.L12:
	l32i.n	a2, sp, 0
	xor	a6, a6, a15
	xor	a11, a11, a15
	s32i.n	a4, a2, 0
	s32i.n	a9, a2, 4
	s32i.n	a5, a2, 8
	s32i.n	a10, a2, 12
	s32i.n	a6, a2, 16
	s32i.n	a11, a2, 20
	s32i.n	a7, a2, 24
	s32i.n	a12, a2, 28
	s32i.n	a8, a2, 32
	s32i.n	a13, a2, 36
#ifdef __XTENSA_WINDOWED_ABI__
	retw.n
#else
	l32i.n	a12, sp, 4
	l32i.n	a13, sp, 8
	l32i.n	a14, sp, 12
	l32i.n	a15, sp, 16
	addi	sp, sp, 32
	ret.n
#endif
	.size	ascon_permute, .-ascon_permute

#ifdef ESP8266
	.section .irom0.text,"ax",@progbits
#else
	.section .text.ascon_from_regular,"ax",@progbits
#endif
	.align	4
	.literal_position
	.global	ascon_from_regular
	.type	ascon_from_regular, @function
ascon_from_regular:
#ifdef __XTENSA_WINDOWED_ABI__
	entry	sp, 32
#endif
	.literal .LC1, -65536
	l32r	a8, .LC1
	movi.n	a9, 5
.L100:
	l32i.n	a3, a2, 0
	l32i.n	a4, a2, 4
#ifdef __XTENSA_EL__
	.literal .LC2, 572662306
	l32r	a7, .LC2
	srli	a5, a3, 1
	srli	a6, a4, 1
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 1
	slli	a6, a6, 1
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC3, 202116108
	l32r	a7, .LC3
	srli	a5, a3, 2
	srli	a6, a4, 2
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 2
	slli	a6, a6, 2
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC4, 983055
	l32r	a7, .LC4
	srli	a5, a3, 12
	srli	a6, a4, 12
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 12
	slli	a6, a6, 12
	xor	a3, a3, a5
	xor	a4, a4, a6
	movi	a7, 255
	srli	a5, a3, 24
	srli	a6, a4, 24
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 24
	slli	a6, a6, 24
	xor	a3, a3, a5
	xor	a4, a4, a6
#else /* __XTENSA_EB__ */
	.literal .LC5, 572662306
	l32r	a7, .LC5
	srli	a5, a3, 1
	srli	a6, a4, 1
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 1
	slli	a6, a6, 1
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC6, 202116108
	l32r	a7, .LC6
	srli	a5, a3, 2
	srli	a6, a4, 2
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 2
	slli	a6, a6, 2
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC7, 15728880
	l32r	a7, .LC7
	srli	a5, a3, 4
	srli	a6, a4, 4
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 4
	slli	a6, a6, 4
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC8, 65280
	l32r	a7, .LC8
	srli	a5, a3, 8
	srli	a6, a4, 8
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 8
	slli	a6, a6, 8
	xor	a3, a3, a5
	xor	a4, a4, a6
#endif /* __XTENSA_EB__ */
	extui	a5, a4, 0, 16
	slli	a6, a3, 16
	extui	a7, a4, 16, 16
	or	a5, a5, a6
	and	a3, a3, a8
	s32i.n	a5, a2, 0
	or	a3, a3, a7
	s32i.n	a3, a2, 4
	addi	a9, a9, -1
	addi	a2, a2, 8
	bnez	a9, .L100
#ifdef __XTENSA_WINDOWED_ABI__
	retw.n
#else
	ret.n
#endif
	.size	ascon_from_regular, .-ascon_from_regular

#ifdef ESP8266
	.section .irom0.text,"ax",@progbits
#else
	.section .text.ascon_to_regular,"ax",@progbits
#endif
	.align	4
	.literal_position
	.global	ascon_to_regular
	.type	ascon_to_regular, @function
ascon_to_regular:
#ifdef __XTENSA_WINDOWED_ABI__
	entry	sp, 32
#endif
	.literal .LC9, -65536
	l32r	a8, .LC9
	movi.n	a9, 5
.L101:
	l32i.n	a5, a2, 0
	l32i.n	a6, a2, 4
	extui	a3, a5, 16, 16
	and	a7, a6, a8
	extui	a4, a5, 0, 16
	or	a3, a3, a7
	slli	a6, a6, 16
	or	a4, a4, a6
#ifdef __XTENSA_EL__
	.literal .LC10, 43690
	l32r	a7, .LC10
	srli	a5, a3, 15
	srli	a6, a4, 15
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 15
	slli	a6, a6, 15
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC11, 52428
	l32r	a7, .LC11
	srli	a5, a3, 14
	srli	a6, a4, 14
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 14
	slli	a6, a6, 14
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC12, 61680
	l32r	a7, .LC12
	srli	a5, a3, 12
	srli	a6, a4, 12
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 12
	slli	a6, a6, 12
	xor	a3, a3, a5
	xor	a4, a4, a6
	movi	a7, 255
	srli	a5, a3, 24
	srli	a6, a4, 24
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 24
	slli	a6, a6, 24
	xor	a3, a3, a5
	xor	a4, a4, a6
#else /* __XTENSA_EB__ */
	.literal .LC13, 43690
	l32r	a7, .LC13
	srli	a5, a3, 15
	srli	a6, a4, 15
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 15
	slli	a6, a6, 15
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC14, 52428
	l32r	a7, .LC14
	srli	a5, a3, 14
	srli	a6, a4, 14
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 14
	slli	a6, a6, 14
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC15, 61680
	l32r	a7, .LC15
	srli	a5, a3, 12
	srli	a6, a4, 12
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 12
	slli	a6, a6, 12
	xor	a3, a3, a5
	xor	a4, a4, a6
	.literal .LC16, 65280
	l32r	a7, .LC16
	srli	a5, a3, 8
	srli	a6, a4, 8
	xor	a5, a5, a3
	xor	a6, a6, a4
	and	a5, a5, a7
	and	a6, a6, a7
	xor	a3, a3, a5
	xor	a4, a4, a6
	slli	a5, a5, 8
	slli	a6, a6, 8
	xor	a3, a3, a5
	xor	a4, a4, a6
#endif /* __XTENSA_EB__ */
	s32i.n	a3, a2, 0
	s32i.n	a4, a2, 4
	addi	a9, a9, -1
	addi	a2, a2, 8
	bnez	a9, .L101
#ifdef __XTENSA_WINDOWED_ABI__
	retw.n
#else
	ret.n
#endif
	.size	ascon_to_regular, .-ascon_to_regular

#endif
