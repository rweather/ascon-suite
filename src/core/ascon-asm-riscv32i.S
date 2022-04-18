#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_RISCV32I)
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
	addi	sp, sp, -16
	sw	s1, (sp)
	lw	a2, (a0)
	lw	a7, 4(a0)
	lw	a3, 8(a0)
	lw	t0, 12(a0)
	lw	a4, 16(a0)
	lw	t4, 20(a0)
	lw	a5, 24(a0)
	lw	t5, 28(a0)
	lw	a6, 32(a0)
	lw	t6, 36(a0)
	not	a4, a4
	not	t4, t4
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
	xori	a4, a4, -13
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -13
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L1:
	xori	a4, a4, -10
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -13
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L2:
	xori	a4, a4, -13
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -10
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L3:
	xori	a4, a4, -10
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -10
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L4:
	xori	a4, a4, -7
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -13
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L5:
	xori	a4, a4, -4
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -13
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L6:
	xori	a4, a4, -7
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -10
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L7:
	xori	a4, a4, -4
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -10
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L8:
	xori	a4, a4, -13
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -7
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L9:
	xori	a4, a4, -10
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -7
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L10:
	xori	a4, a4, -13
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -4
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L11:
	xori	a4, a4, -10
	xor	a2, a2, a6
	xor	a4, a4, a3
	xor	a6, a6, a5
	not	t1, a2
	not	t2, a3
	not	t3, a4
	not	a1, a5
	not	s1, a6
	and	t1, t1, a3
	and	t2, t2, a4
	and	t3, t3, a5
	and	a1, a1, a6
	and	s1, s1, a2
	xor	a2, a2, t2
	xor	a3, a3, t3
	xor	a4, a4, a1
	xor	a5, a5, s1
	xor	a6, a6, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, a6
	xori	t4, t4, -4
	xor	a7, a7, t6
	xor	t4, t4, t0
	xor	t6, t6, t5
	not	t1, a7
	not	t2, t0
	not	t3, t4
	not	a1, t5
	not	s1, t6
	and	t1, t1, t0
	and	t2, t2, t4
	and	t3, t3, t5
	and	a1, a1, t6
	and	s1, s1, a7
	xor	a7, a7, t2
	xor	t0, t0, t3
	xor	t4, t4, a1
	xor	t5, t5, s1
	xor	t6, t6, t1
	xor	t0, t0, a7
	xor	t5, t5, t4
	xor	a7, a7, t6
	srli	t1, a7, 4
	srli	t2, a2, 5
	slli	t3, a7, 28
	slli	a1, a2, 27
	xor	t1, t1, a2
	xor	t2, t2, a7
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 10
	srli	a1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a7, a7, t3
	xor	a2, a2, a1
	xor	a7, a7, t1
	xor	a2, a2, t2
	srli	t2, t0, 11
	srli	t1, a3, 11
	slli	a1, t0, 21
	slli	t3, a3, 21
	xor	t1, t1, a3
	xor	t2, t2, t0
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 20
	srli	a1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	t0, t0, t3
	xor	a3, a3, a1
	xor	t0, t0, t1
	xor	a3, a3, t2
	srli	t1, t4, 2
	srli	t2, a4, 3
	slli	t3, t4, 30
	slli	a1, a4, 29
	xor	t1, t1, a4
	xor	t2, t2, t4
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 1
	slli	t1, t1, 31
	xor	t4, t4, t3
	xor	a4, a4, t2
	xor	t4, t4, t1
	srli	t1, t5, 3
	srli	t2, a5, 4
	slli	t3, t5, 29
	slli	a1, a5, 28
	xor	t1, t1, a5
	xor	t2, t2, t5
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 5
	srli	a1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	t5, t5, a1
	xor	a5, a5, t3
	xor	t5, t5, t2
	xor	a5, a5, t1
	srli	t2, t6, 17
	srli	t1, a6, 17
	slli	a1, t6, 15
	slli	t3, a6, 15
	xor	t1, t1, a6
	xor	t2, t2, t6
	xor	t1, t1, t3
	xor	t2, t2, a1
	srli	t3, t1, 4
	srli	a1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	t6, t6, t3
	xor	a6, a6, a1
	xor	t6, t6, t1
	xor	a6, a6, t2
.L12:
	not	a4, a4
	not	t4, t4
	sw	a2, (a0)
	sw	a7, 4(a0)
	sw	a3, 8(a0)
	sw	t0, 12(a0)
	sw	a4, 16(a0)
	sw	t4, 20(a0)
	sw	a5, 24(a0)
	sw	t5, 28(a0)
	sw	a6, 32(a0)
	sw	t6, 36(a0)
	lw	s1, (sp)
	addi	sp, sp, 16
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
	li	t0, 0
	li	t1, 0
	li	t2, 0
	li	t3, 0
	li	t4, 0
	li	t5, 0
	li	t6, 0
	ret
	.size	ascon_backend_free, .-ascon_backend_free

#endif
