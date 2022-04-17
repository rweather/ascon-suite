#include "ascon-select-backend.h"
#if defined(ASCON_BACKEND_I386)
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

	.p2align 4,,15
#if defined(__CYGWIN32__) || defined(_WIN32)
	.globl	_ascon_permute
	.def	_ascon_permute;	.scl	2;	.type	32;	.endef
_ascon_permute:
#else
	.globl	ascon_permute
	.type	ascon_permute, @function
ascon_permute:
#endif
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	subl	$48, %esp
	movl	68(%esp), %eax
	movl	72(%esp), %ebp
	movl	4(%eax), %ebx
	movl	12(%eax), %ecx
	movl	20(%eax), %edx
	movl	28(%eax), %esi
	movl	36(%eax), %edi
	notl	%edx
	movl	%ebx, 4(%esp)
	movl	%ecx, 12(%esp)
	movl	%edx, 20(%esp)
	movl	%esi, 28(%esp)
	movl	%edi, 36(%esp)
	movl	(%eax), %ebx
	movl	8(%eax), %ecx
	movl	16(%eax), %edx
	movl	24(%eax), %esi
	movl	32(%eax), %edi
	notl	%edx
	cmpl	$6, %ebp
	je	.L6
	cmpl	$0, %ebp
	je	.L0
	cmpl	$4, %ebp
	je	.L4
	cmpl	$11, %ebp
	je	.L11
	cmpl	$10, %ebp
	je	.L10
	cmpl	$9, %ebp
	je	.L9
	cmpl	$8, %ebp
	je	.L8
	cmpl	$7, %ebp
	je	.L7
	cmpl	$5, %ebp
	je	.L5
	cmpl	$3, %ebp
	je	.L3
	cmpl	$2, %ebp
	je	.L2
	cmpl	$1, %ebp
	je	.L1
	jmp	.L12
.L0:
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L1:
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L2:
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L3:
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L4:
	xorl	$-7, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L5:
	xorl	$-4, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L6:
	xorl	$-7, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L7:
	xorl	$-4, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L8:
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-7, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L9:
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-7, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L10:
	xorl	$-13, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-4, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L11:
	xorl	$-10, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%ebx, (%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 16(%esp)
	movl	%esi, 24(%esp)
	movl	%edi, 32(%esp)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	xorl	$-4, %edx
	xorl	%edi, %ebx
	xorl	%esi, %edi
	xorl	%ecx, %edx
	movl	%ebx, 44(%esp)
	movl	%ebx, %eax
	notl	%eax
	andl	%ecx, %eax
	movl	%eax, 40(%esp)
	movl	%ecx, %ebp
	movl	%edx, %eax
	notl	%ebp
	notl	%eax
	andl	%edx, %ebp
	andl	%esi, %eax
	xorl	%ebp, %ebx
	xorl	%eax, %ecx
	movl	%edi, %eax
	movl	44(%esp), %ebp
	notl	%eax
	andl	%ebp, %eax
	xorl	%eax, %esi
	movl	%esi, %ebp
	notl	%ebp
	andl	%edi, %ebp
	xorl	%ebp, %edx
	movl	40(%esp), %eax
	xorl	%eax, %edi
	xorl	%ebx, %ecx
	xorl	%edi, %ebx
	xorl	%edx, %esi
	movl	%edi, 40(%esp)
	movl	(%esp), %edi
	movl	%ebx, %eax
	movl	%edi, %ebp
	rorl	$4, %eax
	rorl	$5, %ebp
	xorl	%edi, %eax
	xorl	%ebx, %ebp
	rorl	$10, %eax
	rorl	$9, %ebp
	xorl	%ebx, %eax
	xorl	%ebp, %edi
	movl	%eax, 4(%esp)
	movl	%edi, %ebx
	movl	8(%esp), %edi
	movl	%ecx, %ebp
	movl	%edi, %eax
	rorl	$11, %ebp
	rorl	$11, %eax
	xorl	%ecx, %ebp
	xorl	%edi, %eax
	rorl	$19, %ebp
	rorl	$20, %eax
	xorl	%ebp, %edi
	xorl	%ecx, %eax
	movl	%edi, %ecx
	movl	%eax, 12(%esp)
	movl	16(%esp), %edi
	movl	%edx, %eax
	movl	%edi, %ebp
	rorl	$2, %eax
	rorl	$3, %ebp
	xorl	%edi, %eax
	xorl	%edx, %ebp
	rorl	$1, %eax
	xorl	%ebp, %edi
	xorl	%edx, %eax
	movl	%edi, %edx
	movl	%eax, 20(%esp)
	movl	24(%esp), %edi
	movl	%esi, %eax
	movl	%edi, %ebp
	rorl	$3, %eax
	rorl	$4, %ebp
	xorl	%edi, %eax
	xorl	%esi, %ebp
	rorl	$5, %eax
	rorl	$5, %ebp
	xorl	%eax, %edi
	xorl	%esi, %ebp
	movl	%edi, %esi
	movl	%ebp, 28(%esp)
	movl	40(%esp), %edi
	movl	%ebx, 40(%esp)
	movl	32(%esp), %ebx
	movl	%edi, %ebp
	movl	%ebx, %eax
	rorl	$17, %ebp
	rorl	$17, %eax
	xorl	%edi, %ebp
	xorl	%ebx, %eax
	rorl	$3, %ebp
	rorl	$4, %eax
	xorl	%ebp, %ebx
	xorl	%edi, %eax
	movl	%ebx, %edi
	movl	%eax, 36(%esp)
	movl	40(%esp), %ebx
.L12:
	movl	68(%esp), %eax
	notl	%edx
	movl	%ebx, (%eax)
	movl	%ecx, 8(%eax)
	movl	%edx, 16(%eax)
	movl	%esi, 24(%eax)
	movl	%edi, 32(%eax)
	movl	4(%esp), %ebx
	movl	12(%esp), %ecx
	movl	20(%esp), %edx
	movl	28(%esp), %esi
	movl	36(%esp), %edi
	notl	%edx
	movl	%ebx, 4(%eax)
	movl	%ecx, 12(%eax)
	movl	%edx, 20(%eax)
	movl	%esi, 28(%eax)
	movl	%edi, 36(%eax)
	movl	$0, %eax
	movl	$0, %ecx
	movl	$0, %edx
	movl	%eax, (%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, 8(%esp)
	movl	%eax, 12(%esp)
	movl	%ecx, 16(%esp)
	movl	%edx, 20(%esp)
	movl	%eax, 24(%esp)
	movl	%ecx, 28(%esp)
	movl	%edx, 32(%esp)
	movl	%eax, 36(%esp)
	movl	%ecx, 40(%esp)
	movl	%edx, 44(%esp)
	addl	$48, %esp
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
#if !(defined(__CYGWIN32__) || defined(_WIN32))
	.size	ascon_permute, .-ascon_permute
#endif

#endif
