#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_M68K)
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

#NO_APP
	.text

	.align	2
	.globl	ascon_permute
	.type	ascon_permute, @function
ascon_permute:
	link.w	%fp, #-48
	move.l	%d2, -4(%fp)
	move.l	%d3, -8(%fp)
	move.l	%d4, -12(%fp)
	move.l	%d5, -16(%fp)
	move.l	%d6, -20(%fp)
	move.l	%d7, -24(%fp)
	move.l	%a2, -28(%fp)
	move.l	%a3, -32(%fp)
	move.l	%a4, -36(%fp)
	move.l	%a5, -40(%fp)
	movea.l	8(%fp), %a5
	move.l	(%a5), %d0
	move.l	8(%a5), %d1
	move.l	16(%a5), %d2
	move.l	24(%a5), %d3
	move.l	32(%a5), %d4
	not.l	%d2
	movea.l	4(%a5), %a0
	movea.l	12(%a5), %a1
	move.l	20(%a5), %d5
	movea.l	28(%a5), %a3
	not.l	%d5
	movea.l	36(%a5), %a4
	movea.l	%d5, %a2
	move.l	12(%fp), %d7
	cmpi.l	#6, %d7
	jbeq	.L6
	cmpi.l	#0, %d7
	jbeq	.L0
	cmpi.l	#4, %d7
	jbeq	.L4
	cmpi.l	#11, %d7
	jbeq	.L11
	cmpi.l	#10, %d7
	jbeq	.L10
	cmpi.l	#9, %d7
	jbeq	.L9
	cmpi.l	#8, %d7
	jbeq	.L8
	cmpi.l	#7, %d7
	jbeq	.L7
	cmpi.l	#5, %d7
	jbeq	.L5
	cmpi.l	#3, %d7
	jbeq	.L3
	cmpi.l	#2, %d7
	jbeq	.L2
	cmpi.l	#1, %d7
	jbeq	.L1
	jmp	.L12
.L0:
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L1:
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L2:
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L3:
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L4:
	eori.l	#-7, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L5:
	eori.l	#-4, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L6:
	eori.l	#-7, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L7:
	eori.l	#-4, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L8:
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-7, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L9:
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-7, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L10:
	eori.l	#-13, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-4, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L11:
	eori.l	#-10, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	movea.l	%d4, %a5
	move.l	%a4, %d4
	movea.l	%d3, %a4
	move.l	%a3, %d3
	movea.l	%d2, %a3
	move.l	%a2, %d2
	movea.l	%d1, %a2
	move.l	%a1, %d1
	movea.l	%d0, %a1
	move.l	%a0, %d0
	eori.l	#-4, %d2
	eor.l	%d4, %d0
	eor.l	%d3, %d4
	eor.l	%d1, %d2
	move.l	%d0, %d6
	move.l	%d0, %d5
	not.l	%d5
	and.l	%d1, %d5
	move.l	%d1, %d7
	not.l	%d7
	and.l	%d2, %d7
	eor.l	%d7, %d0
	move.l	%d2, %d7
	not.l	%d7
	and.l	%d3, %d7
	eor.l	%d7, %d1
	move.l	%d4, %d7
	not.l	%d7
	and.l	%d6, %d7
	eor.l	%d7, %d3
	move.l	%d3, %d7
	not.l	%d7
	and.l	%d4, %d7
	eor.l	%d7, %d2
	eor.l	%d5, %d4
	eor.l	%d0, %d1
	eor.l	%d4, %d0
	eor.l	%d2, %d3
	move.l	%d3, -44(%fp)
#ifdef __mcoldfire__
	move.l	%d4, -48(%fp)
#endif
	move.l	%a1, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#28, %d4
	lsl.l	%d4, %d3
	lsr.l	#4, %d5
	or.l	%d3, %d5
#else
	ror.l	#4, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#27, %d4
	lsl.l	%d4, %d3
	lsr.l	#5, %d6
	or.l	%d3, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d0, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#22, %d4
	lsl.l	%d4, %d3
	moveq.l	#10, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#10, %d3
	ror.l	%d3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#23, %d4
	lsl.l	%d4, %d3
	moveq.l	#9, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#9, %d3
	ror.l	%d3, %d6
#endif
	eor.l	%d0, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a0
	move.l	%d6, %d0
	move.l	%a2, %d7
	move.l	%d1, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#21, %d4
	lsl.l	%d4, %d3
	moveq.l	#11, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#11, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d1, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#13, %d4
	lsl.l	%d4, %d3
	moveq.l	#19, %d4
	lsr.l	%d4, %d6
	or.l	%d3, %d6
#else
	moveq.l	#19, %d3
	ror.l	%d3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#12, %d4
	lsl.l	%d4, %d3
	moveq.l	#20, %d4
	lsr.l	%d4, %d5
	or.l	%d3, %d5
#else
	moveq.l	#20, %d3
	ror.l	%d3, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d1, %d5
	movea.l	%d5, %a1
	move.l	%d6, %d1
	move.l	%a3, %d7
	move.l	%d0, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#30, %d4
	lsl.l	%d4, %d3
	lsr.l	#2, %d5
	or.l	%d3, %d5
#else
	ror.l	#2, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d3
	moveq.l	#29, %d4
	lsl.l	%d4, %d3
	lsr.l	#3, %d6
	or.l	%d3, %d6
#else
	ror.l	#3, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d2, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d3
	moveq.l	#31, %d4
	lsl.l	%d4, %d3
	lsr.l	#1, %d5
	or.l	%d3, %d5
#else
	ror.l	#1, %d5
#endif
	eor.l	%d2, %d5
	eor.l	%d7, %d6
	movea.l	%d5, %a2
	move.l	%d6, %d2
#ifdef __mcoldfire__
	move.l	-44(%fp), %d3
	move.l	-48(%fp), %d4
	move.l	%d0, -44(%fp)
	move.l	%d1, -48(%fp)
#else
	move.l	-44(%fp), %d3
	move.l	%d0, -44(%fp)
#endif
	move.l	%a4, %d7
	move.l	%d3, %d5
	move.l	%d7, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d5
	or.l	%d0, %d5
#else
	ror.l	#3, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d6
	or.l	%d0, %d6
#else
	ror.l	#4, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d5
	or.l	%d0, %d5
#else
	ror.l	#5, %d5
#endif
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#27, %d1
	lsl.l	%d1, %d0
	lsr.l	#5, %d6
	or.l	%d0, %d6
#else
	ror.l	#5, %d6
#endif
	eor.l	%d7, %d5
	eor.l	%d3, %d6
	move.l	%d5, %d3
	movea.l	%d6, %a3
	move.l	%a5, %d7
	move.l	%d4, %d6
	move.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d6
	or.l	%d0, %d6
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#15, %d1
	lsl.l	%d1, %d0
	moveq.l	#17, %d1
	lsr.l	%d1, %d5
	or.l	%d0, %d5
#else
	moveq.l	#17, %d0
	ror.l	%d0, %d5
#endif
	eor.l	%d4, %d6
	eor.l	%d7, %d5
#ifdef __mcoldfire__
	move.l	%d6, %d0
	moveq.l	#29, %d1
	lsl.l	%d1, %d0
	lsr.l	#3, %d6
	or.l	%d0, %d6
#else
	ror.l	#3, %d6
#endif
#ifdef __mcoldfire__
	move.l	%d5, %d0
	moveq.l	#28, %d1
	lsl.l	%d1, %d0
	lsr.l	#4, %d5
	or.l	%d0, %d5
#else
	ror.l	#4, %d5
#endif
	eor.l	%d7, %d6
	eor.l	%d4, %d5
	movea.l	%d5, %a4
	move.l	%d6, %d4
	move.l	-44(%fp), %d0
#ifdef __mcoldfire__
	move.l	-48(%fp), %d1
#endif
.L12:
	movea.l	8(%fp), %a5
	not.l	%d2
	move.l	%d0, (%a5)
	move.l	%d1, 8(%a5)
	move.l	%d2, 16(%a5)
	move.l	%d3, 24(%a5)
	move.l	%d4, 32(%a5)
	move.l	%a2, %d5
	move.l	%a0, 4(%a5)
	not.l	%d5
	move.l	%a1, 12(%a5)
	move.l	%d5, 20(%a5)
	move.l	%a3, 28(%a5)
	move.l	%a4, 36(%a5)
	move.l	%a5, -44(%fp)
#ifdef __mcoldfire__
	move.l	%a5, -48(%fp)
#endif
	move.l	-4(%fp), %d2
	move.l	-8(%fp), %d3
	move.l	-12(%fp), %d4
	move.l	-16(%fp), %d5
	move.l	-20(%fp), %d6
	move.l	-24(%fp), %d7
	movea.l	-28(%fp), %a2
	movea.l	-32(%fp), %a3
	movea.l	-36(%fp), %a4
	movea.l	-40(%fp), %a5
	unlk	%fp
	rts
	.size	ascon_permute, .-ascon_permute

	.align	2
	.globl	ascon_backend_free
	.type	ascon_backend_free, @function
ascon_backend_free:
	moveq.l	#0, %d0
	moveq.l	#0, %d1
	movea.l	%d0, %a0
	movea.l	%d1, %a1
	rts
	.size	ascon_backend_free, .-ascon_backend_free

#endif
