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
	l32i.n	a9, a2, 0
	l32i.n	a4, a2, 4
	l32i.n	a10, a2, 8
	l32i.n	a5, a2, 12
	l32i.n	a11, a2, 16
	l32i.n	a6, a2, 20
	l32i.n	a12, a2, 24
	l32i.n	a7, a2, 28
	l32i.n	a13, a2, 32
	l32i.n	a8, a2, 36
	movi.n	a15, -1
	xor	a6, a6, a15
	xor	a11, a11, a15
	beqi	a3, 6, .L6
	beqz	a3, .L0
	beqi	a3, 4, .L4
	movi.n	a14, 11
	beq	a3, a14, .L11
	beqi	a3, 10, .L10
	movi.n	a14, 9
	beq	a3, a14, .L9
	beqi	a3, 8, .L8
	beqi	a3, 7, .L7
	beqi	a3, 5, .L5
	beqi	a3, 3, .L3
	beqi	a3, 2, .L2
	beqi	a3, 1, .L1
	j	.L12
.L0:
	movi	a2, -241
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L1:
	movi	a2, -226
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L2:
	movi	a2, -211
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L3:
	movi	a2, -196
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L4:
	movi	a2, -181
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L5:
	movi	a2, -166
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L6:
	movi	a2, -151
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L7:
	movi	a2, -136
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L8:
	movi	a2, -121
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L9:
	movi	a2, -106
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L10:
	movi	a2, -91
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L11:
	movi	a2, -76
	xor	a6, a6, a15
	xor	a11, a11, a2
	xor	a4, a4, a8
	xor	a8, a8, a7
	xor	a6, a6, a5
	mov	a3, a4
	xor	a2, a4, a15
	xor	a14, a5, a15
	and	a2, a2, a5
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
	xor	a7, a7, a6
	xor	a4, a4, a8
	xor	a9, a9, a13
	xor	a13, a13, a12
	xor	a11, a11, a10
	mov	a3, a9
	xor	a2, a9, a15
	xor	a14, a10, a15
	and	a2, a2, a10
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
	xor	a12, a12, a11
	xor	a9, a9, a13
	ssai	19
	src	a15, a9, a4
	src	a14, a4, a9
	ssai	28
	src	a3, a9, a4
	src	a2, a4, a9
	xor	a4, a4, a15
	xor	a9, a9, a14
	xor	a4, a4, a3
	xor	a9, a9, a2
	ssai	29
	src	a15, a5, a10
	src	a14, a10, a5
	ssai	7
	src	a3, a5, a10
	src	a2, a10, a5
	xor	a5, a5, a15
	xor	a10, a10, a14
	xor	a5, a5, a3
	xor	a10, a10, a2
	ssai	1
	src	a15, a11, a6
	src	a14, a6, a11
	ssai	6
	src	a3, a11, a6
	src	a2, a6, a11
	xor	a6, a6, a15
	xor	a11, a11, a14
	xor	a6, a6, a3
	xor	a11, a11, a2
	ssai	10
	src	a15, a12, a7
	src	a14, a7, a12
	ssai	17
	src	a3, a12, a7
	src	a2, a7, a12
	xor	a7, a7, a15
	xor	a12, a12, a14
	xor	a7, a7, a3
	xor	a12, a12, a2
	ssai	7
	src	a15, a13, a8
	src	a14, a8, a13
	ssai	9
	src	a3, a8, a13
	src	a2, a13, a8
	xor	a8, a8, a15
	xor	a13, a13, a14
	xor	a8, a8, a3
	xor	a13, a13, a2
	movi.n	a15, -1
.L12:
	l32i.n	a2, sp, 0
	xor	a6, a6, a15
	xor	a11, a11, a15
	s32i.n	a9, a2, 0
	s32i.n	a4, a2, 4
	s32i.n	a10, a2, 8
	s32i.n	a5, a2, 12
	s32i.n	a11, a2, 16
	s32i.n	a6, a2, 20
	s32i.n	a12, a2, 24
	s32i.n	a7, a2, 28
	s32i.n	a13, a2, 32
	s32i.n	a8, a2, 36
#ifdef __XTENSA_WINDOWED_ABI__
	movi.n	a3, 0
	movi.n	a4, 0
	movi.n	a5, 0
	movi.n	a6, 0
	movi.n	a7, 0
	movi.n	a8, 0
	movi.n	a9, 0
	movi.n	a10, 0
	movi.n	a11, 0
	movi.n	a12, 0
	movi.n	a13, 0
	movi.n	a14, 0
#endif
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

#ifndef __XTENSA_WINDOWED_ABI__
#ifdef ESP8266
	.section .irom0.text,"ax",@progbits
#else
	.section .text.ascon_backend_free,"ax",@progbits
#endif
	.align	4
	.literal_position
	.global	ascon_backend_free
	.type	ascon_backend_free, @function
ascon_backend_free:
	movi.n	a3, 0
	movi.n	a4, 0
	movi.n	a5, 0
	movi.n	a6, 0
	movi.n	a7, 0
	movi.n	a8, 0
	movi.n	a9, 0
	movi.n	a10, 0
	movi.n	a11, 0
#ifdef __XTENSA_WINDOWED_ABI__
	retw.n
#else
	ret.n
#endif
	.size	ascon_backend_free, .-ascon_backend_free
#endif

#endif
