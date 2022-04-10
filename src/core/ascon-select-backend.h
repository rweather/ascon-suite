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

#ifndef ASCON_SELECT_BACKEND_H
#define ASCON_SELECT_BACKEND_H

/* Select the default back end to use for the ASCON permutation,
 * and any properties we can use to optimize use of the permutation. */

#if defined(ASCON_FORCE_C32)

/* Force the use of the "c32" backend for testing purposes */
#define ASCON_BACKEND_C32 1
#define ASCON_BACKEND_SLICED32 1

#elif defined(ASCON_FORCE_C64)

/* Force the use of the "c64" backend for testing purposes */
#define ASCON_BACKEND_C64 1
#define ASCON_BACKEND_SLICED64 1

#elif defined(ASCON_FORCE_DIRECT_XOR) || defined(ASCON_FORCE_GENERIC)

/* Force the use of the "direct xor" backend for testing purposes */
#define ASCON_BACKEND_C64_DIRECT_XOR 1
#define ASCON_BACKEND_DIRECT_XOR 1

#elif defined(__AVR__) && __AVR_ARCH__ >= 5

/* AVR5 assembly code backend */
#define ASCON_BACKEND_AVR5 1
#define ASCON_BACKEND_DIRECT_XOR 1

#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7

/* The armv7m backend can also be used with armv7/thumb systems */
#define ASCON_BACKEND_ARMV7M 1
#define ASCON_BACKEND_SLICED32 1

#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 6 && defined(__ARM_ARCH_6M__)

/* The armv6m assembly code backend can also be used with armv6/thumb
 * systems but it is not as efficient as the armv6 backend below. */
#define ASCON_BACKEND_ARMV6M 1
#define ASCON_BACKEND_SLICED32 1

#elif defined(__ARM_ARCH) && __ARM_ARCH == 6

/* Assembly backend for armv6 systems, should work with thumb and non-thumb */
#define ASCON_BACKEND_ARMV6 1
#define ASCON_BACKEND_SLICED32 1

#elif defined(__ARM_ARCH_8A)

/* Assembly backend for armv8a systems (64-bit ARM) */
#define ASCON_BACKEND_ARMV8A 1
#define ASCON_BACKEND_SLICED64 1

#elif defined(__XTENSA__)

/* Assembly backend for Xtensa-based systems */
#define ASCON_BACKEND_XTENSA 1
#define ASCON_BACKEND_SLICED32 1

#elif defined(__x86_64) || defined(__x86_64__) || \
      defined(__aarch64__) || defined(__ARM_ARCH_ISA_A64) || \
      defined(_M_AMD64) || defined(_M_X64) || defined(_M_IA64)

/* C backend for 64-bit systems with words in host byte order */
#define ASCON_BACKEND_C64 1
#define ASCON_BACKEND_SLICED64 1

#else

/* C backend for 32-bit systems, using the bit-slicing method */
#define ASCON_BACKEND_C32 1
#define ASCON_BACKEND_SLICED32 1

#endif

#endif
