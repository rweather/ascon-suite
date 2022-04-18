#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_RISCV32E)
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
	lw	a2, (a0)
	lw	a3, 8(a0)
	lw	a4, 16(a0)
	lw	t1, 20(a0)
	lw	a5, 24(a0)
	lw	t0, 32(a0)
	not	a4, a4
	not	t1, t1
	sw	s1, (sp)
	sw	fp, 4(sp)
	sw	t1, 20(a0)
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
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -13
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L1:
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -13
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L2:
	xori	a4, a4, -13
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L3:
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L4:
	xori	a4, a4, -7
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -13
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L5:
	xori	a4, a4, -4
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -13
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L6:
	xori	a4, a4, -7
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L7:
	xori	a4, a4, -4
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L8:
	xori	a4, a4, -13
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -7
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L9:
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -7
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L10:
	xori	a4, a4, -13
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -4
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L11:
	xori	a4, a4, -10
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	lw	a2, 4(a0)
	lw	a3, 12(a0)
	lw	a4, 20(a0)
	lw	a5, 28(a0)
	lw	t0, 36(a0)
	xori	a4, a4, -4
	xor	a2, a2, t0
	xor	a4, a4, a3
	xor	t0, t0, a5
	not	t1, a2
	not	t2, a3
	not	a1, a4
	not	s1, a5
	not	fp, t0
	and	t1, t1, a3
	and	t2, t2, a4
	and	a1, a1, a5
	and	s1, s1, t0
	and	fp, fp, a2
	xor	a2, a2, t2
	xor	a3, a3, a1
	xor	a4, a4, s1
	xor	a5, a5, fp
	xor	t0, t0, t1
	xor	a3, a3, a2
	xor	a5, a5, a4
	xor	a2, a2, t0
	lw	fp, (a0)
	srli	t1, a2, 4
	srli	t2, fp, 5
	slli	a1, a2, 28
	slli	s1, fp, 27
	xor	t1, t1, fp
	xor	t2, t2, a2
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 10
	srli	s1, t2, 9
	slli	t1, t1, 22
	slli	t2, t2, 23
	xor	a1, a1, a2
	xor	a2, fp, s1
	xor	a1, a1, t1
	xor	a2, a2, t2
	sw	a1, 4(a0)
	lw	fp, 8(a0)
	srli	t2, a3, 11
	srli	t1, fp, 11
	slli	s1, a3, 21
	slli	a1, fp, 21
	xor	t1, t1, fp
	xor	t2, t2, a3
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 20
	srli	s1, t2, 19
	slli	t1, t1, 12
	slli	t2, t2, 13
	xor	a1, a1, a3
	xor	a3, fp, s1
	xor	a1, a1, t1
	xor	a3, a3, t2
	sw	a1, 12(a0)
	lw	fp, 16(a0)
	srli	t1, a4, 2
	srli	t2, fp, 3
	slli	a1, a4, 30
	slli	s1, fp, 29
	xor	t1, t1, fp
	xor	t2, t2, a4
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 1
	slli	t1, t1, 31
	xor	a1, a1, a4
	xor	a4, fp, t2
	xor	a1, a1, t1
	sw	a1, 20(a0)
	lw	fp, 24(a0)
	srli	t1, a5, 3
	srli	t2, fp, 4
	slli	a1, a5, 29
	slli	s1, fp, 28
	xor	t1, t1, fp
	xor	t2, t2, a5
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 5
	srli	s1, t2, 5
	slli	t1, t1, 27
	slli	t2, t2, 27
	xor	s1, s1, a5
	xor	a5, fp, a1
	xor	s1, s1, t2
	xor	a5, a5, t1
	sw	s1, 28(a0)
	lw	fp, 32(a0)
	srli	t2, t0, 17
	srli	t1, fp, 17
	slli	s1, t0, 15
	slli	a1, fp, 15
	xor	t1, t1, fp
	xor	t2, t2, t0
	xor	t1, t1, a1
	xor	t2, t2, s1
	srli	a1, t1, 4
	srli	s1, t2, 3
	slli	t1, t1, 28
	slli	t2, t2, 29
	xor	a1, a1, t0
	xor	t0, fp, s1
	xor	a1, a1, t1
	xor	t0, t0, t2
	sw	a1, 36(a0)
.L12:
	not	a4, a4
	lw	t1, 20(a0)
	sw	a2, (a0)
	sw	a3, 8(a0)
	sw	a4, 16(a0)
	not	t1, t1
	sw	a5, 24(a0)
	sw	t0, 32(a0)
	sw	t1, 20(a0)
	lw	s1, (sp)
	lw	fp, 4(sp)
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
	li	t0, 0
	li	t1, 0
	li	t2, 0
	ret
	.size	ascon_backend_free, .-ascon_backend_free

#endif
