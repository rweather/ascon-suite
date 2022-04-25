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

#ifndef ASCON_MASKING_H
#define ASCON_MASKING_H

#include <stdint.h>

/**
 * \file masking.h
 * \brief Definitions to support masked ASCON ciphers.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Masked 64-bit word with up to four shares.
 *
 * This structure should be treated as opaque.
 */
typedef union
{
    uint64_t S[4];      /**< 64-bit version of the masked shares */
    uint32_t W[8];      /**< 32-bit version of the masked shares */

} ascon_masked_word_t;

/**
 * \brief State of the ASCON permutation which has been masked
 * with up to 4 shares.
 *
 * This structure should be treated as opaque.
 */
typedef struct
{
    ascon_masked_word_t M[5]; /**< Masked words of the state */

} ascon_masked_state_t;

#ifdef __cplusplus
}
#endif

#endif
