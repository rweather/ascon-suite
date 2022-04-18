#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_RISCV64I)
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

#ifdef __riscv_cmodel_pic
	.option	pic
#else
	.option	nopic
#endif
	.text

	.align	1
	.globl	ascon_permute
	.type	ascon_permute, @function
ascon_permute:
	ld	a2, (a0)
	ld	a3, 8(a0)
	ld	a4, 16(a0)
	ld	a5, 24(a0)
	ld	a6, 32(a0)
	not	a4, a4
	li	t1, 6
	beq	a1, t1, .L6
	beq	a1, x0, .L0
	li	t1, 4
	beq	a1, t1, .L4
	li	t1, 11
	beq	a1, t1, .L11
	li	t1, 10
	beq	a1, t1, .L10
	li	t1, 9
	beq	a1, t1, .L9
	li	t1, 8
	beq	a1, t1, .L8
	li	t1, 7
	beq	a1, t1, .L7
	li	t1, 5
	beq	a1, t1, .L5
	li	t1, 3
	beq	a1, t1, .L3
	li	t1, 2
	beq	a1, t1, .L2
	li	t1, 1
	beq	a1, t1, .L1
	j	.L12
.L0:
	xori	a4, a4, -241
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L1:
	xori	a4, a4, -226
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L2:
	xori	a4, a4, -211
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L3:
	xori	a4, a4, -196
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L4:
	xori	a4, a4, -181
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L5:
	xori	a4, a4, -166
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L6:
	xori	a4, a4, -151
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L7:
	xori	a4, a4, -136
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L8:
	xori	a4, a4, -121
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L9:
	xori	a4, a4, -106
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L10:
	xori	a4, a4, -91
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L11:
	xori	a4, a4, -76
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	t4, a5
	not	t5, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	t4, t4, a6
	and	t5, t5, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, t4
	xor	a5, a5, t5
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	srli	t1, a2, 19
	slli	t2, a2, 45
	srli	t3, a2, 28
	slli	t4, a2, 36
	srli	t5, a3, 61
	slli	t6, a3, 3
	srli	a1, a3, 39
	slli	a7, a3, 25
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a2, a2, t1
	xor	a3, a3, t5
	xor	a2, a2, t3
	xor	a3, a3, a1
	srli	t1, a4, 1
	slli	t2, a4, 63
	srli	t3, a4, 6
	slli	t4, a4, 58
	srli	t5, a5, 10
	slli	t6, a5, 54
	srli	a1, a5, 17
	slli	a7, a5, 47
	or	t1, t1, t2
	or	t3, t3, t4
	or	t5, t5, t6
	or	a1, a1, a7
	xor	a4, a4, t1
	xor	a5, a5, t5
	xor	a4, a4, t3
	xor	a5, a5, a1
	srli	t1, a6, 7
	slli	t2, a6, 57
	srli	t3, a6, 41
	slli	t4, a6, 23
	or	t1, t1, t2
	or	t3, t3, t4
	xor	a6, a6, t1
	xor	a6, a6, t3
.L12:
	not	a4, a4
	sd	a2, (a0)
	sd	a3, 8(a0)
	sd	a4, 16(a0)
	sd	a5, 24(a0)
	sd	a6, 32(a0)
	ret
	.size	ascon_permute, .-ascon_permute

	.align	1
	.globl	ascon_backend_free
	.type	ascon_backend_free, @function
ascon_backend_free:
	li	a1, 0
	li	a2, 0
	li	a3, 0
	li	a4, 0
	li	a5, 0
	li	a6, 0
	li	a7, 0
	li	t1, 0
	li	t2, 0
	li	t3, 0
	li	t4, 0
	li	t5, 0
	li	t6, 0
	ret
	.size	ascon_backend_free, .-ascon_backend_free

#endif
