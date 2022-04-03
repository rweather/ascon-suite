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

#ifndef ASCON_PERMUTATION_SELECT_H
#define ASCON_PERMUTATION_SELECT_H

/* Select the default back end to use for the ASCON permutation,
 * and any properties we can use to optimize use of the permutation. */

#if defined(__AVR__)
#define ASCON_BACKEND_AVR 1
#define ASCON_BACKEND_DIRECT_XOR 1
#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define ASCON_BACKEND_ARMV7 1
#define ASCON_BACKEND_SLICED32 1
#elif 0 && (defined(__x86_64) || defined(__x86_64__) || \
      defined(__aarch64__) || defined(__ARM_ARCH_ISA_A64) || \
      defined(_M_AMD64) || defined(_M_X64) || defined(_M_IA64))
#define ASCON_BACKEND_C64 1
#else
#define ASCON_BACKEND_C32 1
#define ASCON_BACKEND_SLICED32 1
#endif

#endif
