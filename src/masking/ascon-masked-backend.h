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

#ifndef ASCON_MASKED_BACKEND_H
#define ASCON_MASKED_BACKEND_H

#include "core/ascon-select-backend.h"
#include "ascon-masked-config.h"

/* Select the default back end to use for the masked ASCON permutation,
 * and any properties we can use to optimize use of the permutation. */

#if defined(ASCON_BACKEND_AVR5)

/* Masked backend for AVR5 based systems */
#define ASCON_MASKED_X2_BACKEND_AVR5 1
#define ASCON_MASKED_X3_BACKEND_AVR5 1
#define ASCON_MASKED_WORD_BACKEND_DIRECT_XOR 1

#elif defined(ASCON_BACKEND_X86_64)

/* Masked backend for x86-64 based systems */
#define ASCON_MASKED_X2_BACKEND_X86_64 1
#define ASCON_MASKED_X3_BACKEND_X86_64 1
#define ASCON_MASKED_X4_BACKEND_X86_64 1
#define ASCON_MASKED_WORD_BACKEND_X86_64 1
#define ASCON_MASKED_BACKEND_SLICED64 1

#elif defined(ASCON_BACKEND_SLICED32)

/* Use the 32-bit sliced backend for masking if we were using the
 * 32-bit sliced backend for the regular permutation as then it is
 * easier to convert between masked and unmasked representations. */
#define ASCON_MASKED_X2_BACKEND_C32 1
#define ASCON_MASKED_X3_BACKEND_C32 1
#define ASCON_MASKED_X4_BACKEND_C32 1
#define ASCON_MASKED_WORD_BACKEND_C32 1
#define ASCON_MASKED_BACKEND_SLICED32 1

#else

/* Fall back to the 64-bit version of the masked backend if nothing better */
#define ASCON_MASKED_X2_BACKEND_C64 1
#define ASCON_MASKED_X3_BACKEND_C64 1
#define ASCON_MASKED_X4_BACKEND_C64 1
#define ASCON_MASKED_WORD_BACKEND_C64 1
#define ASCON_MASKED_BACKEND_SLICED64 1

#endif

#endif
