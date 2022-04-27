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
 * \brief 128-bit key that has been masked to hide its value when the
 * code is operating on it.
 *
 * This structure should be treated as opaque.  The number of shares used,
 * the bit ordering, and the method of masking is determined by the library.
 *
 * The application can copy the entire contents of this structure
 * as-is to non-volatile memory to preserve the masked form of the key.
 * It is not possible to transport such keys between systems because
 * of different numbers of shares and bit ordering issues.
 */
typedef struct
{
    ascon_masked_word_t k[2]; /**< Masked words of the key */

} ascon_masked_key_128_t;

/**
 * \brief 160-bit key that has been masked to hide its value when the
 * code is operating on it.
 *
 * ASCON-80pq absorbs the key into state words at both offset 0 and 4.
 * This requires the key to be masked twice for the two offset values
 * to avoid additional word rotations when the key is used.
 *
 * This structure should be treated as opaque.  The number of shares used,
 * the bit ordering, and the method of masking is determined by the library.
 *
 * The application can copy the entire contents of this structure
 * as-is to non-volatile memory to preserve the masked form of the key.
 * It is not possible to transport such keys between systems because
 * of different numbers of shares and bit ordering issues.
 */
typedef struct
{
    ascon_masked_word_t k[6]; /**< Masked words of the key */

} ascon_masked_key_160_t;

/**
 * \brief Initializes a masked 128-bit key for ASCON.
 *
 * \param masked Masked version of the key on output.
 * \param key Points to the 16 bytes of the 128-bit key to be masked.
 *
 * Keys can be masked to protect them from casual snooping in memory.
 * Or they may be masked for later use by a masked cipher.
 */
void ascon_masked_key_128_init
    (ascon_masked_key_128_t *masked, const unsigned char *key);

/**
 * \brief Frees a masked 128-bit key and destroys all sensitive material.
 *
 * \param masked Points to the masked key to be freed.
 */
void ascon_masked_key_128_free(ascon_masked_key_128_t *masked);

/**
 * \brief Randomizes a masked 128-bit key by mixing in fresh random material.
 *
 * \param masked Points to the masked key to randomize.
 *
 * Long-lived keys should be randomized regularly to mix in fresh randomness.
 */
void ascon_masked_key_128_randomize(ascon_masked_key_128_t *masked);

/**
 * \brief Extracts the plain version of a 128-bit key from its masked version.
 *
 * \param masked Points to the masked key to be extracted.
 * \param key Points to a 16 byte buffer to receive the extracted key.
 */
void ascon_masked_key_128_extract
    (const ascon_masked_key_128_t *masked, unsigned char *key);

/**
 * \brief Initializes a masked 160-bit key for ASCON.
 *
 * \param masked Masked version of the key on output.
 * \param key Points to the 20 bytes of the 160-bit key to be masked.
 *
 * Keys can be masked to protect them from casual snooping in memory.
 * Or they may be masked for later use by a masked cipher.
 */
void ascon_masked_key_160_init
    (ascon_masked_key_160_t *masked, const unsigned char *key);

/**
 * \brief Frees a masked 160-bit key and destroys all sensitive material.
 *
 * \param masked Points to the masked key to be freed.
 */
void ascon_masked_key_160_free(ascon_masked_key_160_t *masked);

/**
 * \brief Randomizes a masked 160-bit key by mixing in fresh random material.
 *
 * \param masked Points to the masked key to randomize.
 *
 * Long-lived keys should be randomized regularly to mix in fresh randomness.
 */
void ascon_masked_key_160_randomize(ascon_masked_key_160_t *masked);

/**
 * \brief Extracts the plain version of a 160-bit key from its masked version.
 *
 * \param masked Points to the masked key to be extracted.
 * \param key Points to a 20 byte buffer to receive the extracted key.
 */
void ascon_masked_key_160_extract
    (const ascon_masked_key_160_t *masked, unsigned char *key);

#ifdef __cplusplus
}
#endif

#endif
