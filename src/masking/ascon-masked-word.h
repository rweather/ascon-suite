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

#ifndef ASCON_MASKED_WORD_H
#define ASCON_MASKED_WORD_H

#include <ascon/masking.h>
#include "ascon-masked-backend.h"
#include "random/ascon-trng.h"
#include "core/ascon-util.h"

/**
 * \file ascon-masked-word.h
 * \brief Utility functions for operating on masked words.
 *
 * Masked words may be stored in two different representations depending
 * upon the backend.
 *
 * The 64-bit masked word representation stores the 4 shares as regular
 * 64-bit words.  The shares are stored in a rotated form where shares
 * 1, 2, 3, and 4 are rotated right by 0, 11, 22, and 33 bits respectively.
 * The "real" value of a 64-bit masked word can be recovered as follows:
 *
 * \verbatim
 * value = share1 ^ (share2 <<< 11) ^ (share3 <<< 22) ^ (share <<< 33)
 * \endverbatim
 *
 * The 32-bit masked representation splits each of the 64-bit words into
 * two bit-sliced halves.  The even bits are in one half and the odd bits
 * are in the other half.  This can be more efficient on 32-bit platforms
 * that lack a funnel shift instruction.
 *
 * The shares of a 32-bit masked word are stored in a rotated form where
 * shares 1, 2, 3, and 4 are rotated right by 0, 5, 10, and 15 bits
 * respectively.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Masked 64-bit word with up to ASCON_MASKED_MAX_SHARES shares.
 *
 * This structure should be treated as opaque.
 */
typedef union
{
    /** 64-bit version of the masked shares */
    uint64_t S[ASCON_MASKED_MAX_SHARES];

    /** 32-bit version of the masked shares */
    uint32_t W[ASCON_MASKED_MAX_SHARES * 2];

    /** 8-bit version of the masked shares */
    uint8_t B[ASCON_MASKED_MAX_SHARES * 8];

} ascon_masked_word_t;

#if !defined(ASCON_MASKED_WORD_BACKEND_DIRECT_XOR)

/**
 * \brief Rotates 64-bit masked share 1 with respect to share 0.
 *
 * \param x Value of share 1 in the same bit positions as share 0.
 *
 * \return Value of share 1 after rotation with respect to share 0.
 */
#define ascon_mask64_rotate_share1_0(x) (rightRotate11_64((x)))

/**
 * \brief Rotates 64-bit masked share 2 with respect to share 0.
 *
 * \param x Value of share 2 in the same bit positions as share 0.
 *
 * \return Value of share 2 after rotation with respect to share 0.
 */
#define ascon_mask64_rotate_share2_0(x) (rightRotate22_64((x)))

/**
 * \brief Rotates 64-bit masked share 2 with respect to share 1.
 *
 * \param x Value of share 2 in the same bit positions as share 1.
 *
 * \return Value of share 2 after rotation with respect to share 1.
 */
#define ascon_mask64_rotate_share2_1(x) (rightRotate11_64((x)))

/**
 * \brief Rotates 64-bit masked share 3 with respect to share 0.
 *
 * \param x Value of share 3 in the same bit positions as share 0.
 *
 * \return Value of share 3 after rotation with respect to share 0.
 */
#define ascon_mask64_rotate_share3_0(x) (rightRotate33_64((x)))

/**
 * \brief Rotates 64-bit masked share 3 with respect to share 1.
 *
 * \param x Value of share 3 in the same bit positions as share 1.
 *
 * \return Value of share 3 after rotation with respect to share 1.
 */
#define ascon_mask64_rotate_share3_1(x) (rightRotate22_64((x)))

/**
 * \brief Rotates 64-bit masked share 3 with respect to share 2.
 *
 * \param x Value of share 3 in the same bit positions as share 2.
 *
 * \return Value of share 3 after rotation with respect to share 2.
 */
#define ascon_mask64_rotate_share3_2(x) (rightRotate11_64((x)))

/**
 * \brief Unrotates 64-bit masked share 1 with respect to share 0.
 *
 * \param x Value of share 1, rotated with respect to share 0.
 *
 * \return Value of share 1 in the same bit positions as share 0.
 */
#define ascon_mask64_unrotate_share1_0(x) (rightRotate53_64((x)))

/**
 * \brief Unrotates 64-bit masked share 2 with respect to share 0.
 *
 * \param x Value of share 2, rotated with respect to share 0.
 *
 * \return Value of share 2 in the same bit positions as share 0.
 */
#define ascon_mask64_unrotate_share2_0(x) (rightRotate42_64((x)))

/**
 * \brief Unrotates 64-bit masked share 2 with respect to share 1.
 *
 * \param x Value of share 2, rotated with respect to share 1.
 *
 * \return Value of share 2 in the same bit positions as share 1.
 */
#define ascon_mask64_unrotate_share2_1(x) (rightRotate53_64((x)))

/**
 * \brief Unrotates 64-bit masked share 3 with respect to share 0.
 *
 * \param x Value of share 3, rotated with respect to share 0.
 *
 * \return Value of share 3 in the same bit positions as share 0.
 */
#define ascon_mask64_unrotate_share3_0(x) (rightRotate31_64((x)))

/**
 * \brief Unrotates 64-bit masked share 3 with respect to share 1.
 *
 * \param x Value of share 3, rotated with respect to share 1.
 *
 * \return Value of share 3 in the same bit positions as share 1.
 */
#define ascon_mask64_unrotate_share3_1(x) (rightRotate42_64((x)))

/**
 * \brief Unrotates 64-bit masked share 3 with respect to share 2.
 *
 * \param x Value of share 3, rotated with respect to share 2.
 *
 * \return Value of share 3 in the same bit positions as share 2.
 */
#define ascon_mask64_unrotate_share3_2(x) (rightRotate53_64((x)))

/**
 * \brief Rotates 32-bit masked share 1 with respect to share 0.
 *
 * \param x Value of share 1 in the same bit positions as share 0.
 *
 * \return Value of share 1 after rotation with respect to share 0.
 */
#define ascon_mask32_rotate_share1_0(x) (rightRotate5((x)))

/**
 * \brief Rotates 32-bit masked share 2 with respect to share 0.
 *
 * \param x Value of share 2 in the same bit positions as share 0.
 *
 * \return Value of share 2 after rotation with respect to share 0.
 */
#define ascon_mask32_rotate_share2_0(x) (rightRotate10((x)))

/**
 * \brief Rotates 32-bit masked share 2 with respect to share 1.
 *
 * \param x Value of share 2 in the same bit positions as share 1.
 *
 * \return Value of share 2 after rotation with respect to share 1.
 */
#define ascon_mask32_rotate_share2_1(x) (rightRotate5((x)))

/**
 * \brief Rotates 32-bit masked share 3 with respect to share 0.
 *
 * \param x Value of share 3 in the same bit positions as share 0.
 *
 * \return Value of share 3 after rotation with respect to share 0.
 */
#define ascon_mask32_rotate_share3_0(x) (rightRotate15((x)))

/**
 * \brief Rotates 32-bit masked share 3 with respect to share 1.
 *
 * \param x Value of share 3 in the same bit positions as share 1.
 *
 * \return Value of share 3 after rotation with respect to share 1.
 */
#define ascon_mask32_rotate_share3_1(x) (rightRotate10((x)))

/**
 * \brief Rotates 32-bit masked share 3 with respect to share 2.
 *
 * \param x Value of share 3 in the same bit positions as share 2.
 *
 * \return Value of share 3 after rotation with respect to share 2.
 */
#define ascon_mask32_rotate_share3_2(x) (rightRotate5((x)))

/**
 * \brief Unrotates 32-bit masked share 1 with respect to share 0.
 *
 * \param x Value of share 1, rotated with respect to share 0.
 *
 * \return Value of share 1 in the same bit positions as share 0.
 */
#define ascon_mask32_unrotate_share1_0(x) (rightRotate27((x)))

/**
 * \brief Unrotates 32-bit masked share 2 with respect to share 0.
 *
 * \param x Value of share 2, rotated with respect to share 0.
 *
 * \return Value of share 2 in the same bit positions as share 0.
 */
#define ascon_mask32_unrotate_share2_0(x) (rightRotate22((x)))

/**
 * \brief Unrotates 32-bit masked share 2 with respect to share 1.
 *
 * \param x Value of share 2, rotated with respect to share 1.
 *
 * \return Value of share 2 in the same bit positions as share 1.
 */
#define ascon_mask32_unrotate_share2_1(x) (rightRotate27((x)))

/**
 * \brief Unrotates 32-bit masked share 3 with respect to share 0.
 *
 * \param x Value of share 3, rotated with respect to share 0.
 *
 * \return Value of share 3 in the same bit positions as share 0.
 */
#define ascon_mask32_unrotate_share3_0(x) (rightRotate17((x)))

/**
 * \brief Unrotates 32-bit masked share 3 with respect to share 1.
 *
 * \param x Value of share 3, rotated with respect to share 1.
 *
 * \return Value of share 3 in the same bit positions as share 1.
 */
#define ascon_mask32_unrotate_share3_1(x) (rightRotate22((x)))

/**
 * \brief Unrotates 32-bit masked share 3 with respect to share 2.
 *
 * \param x Value of share 3, rotated with respect to share 2.
 *
 * \return Value of share 3 in the same bit positions as share 2.
 */
#define ascon_mask32_unrotate_share3_2(x) (rightRotate27((x)))

#else /* ASCON_MASKED_WORD_BACKEND_DIRECT_XOR */

/* Direct XOR masking method does not rotate the shares */
#define ascon_mask64_rotate_share1_0(x)   (x)
#define ascon_mask64_rotate_share2_0(x)   (x)
#define ascon_mask64_rotate_share2_1(x)   (x)
#define ascon_mask64_rotate_share3_0(x)   (x)
#define ascon_mask64_rotate_share3_1(x)   (x)
#define ascon_mask64_rotate_share3_2(x)   (x)
#define ascon_mask64_unrotate_share1_0(x) (x)
#define ascon_mask64_unrotate_share2_0(x) (x)
#define ascon_mask64_unrotate_share2_1(x) (x)
#define ascon_mask64_unrotate_share3_0(x) (x)
#define ascon_mask64_unrotate_share3_1(x) (x)
#define ascon_mask64_unrotate_share3_2(x) (x)
#define ascon_mask32_rotate_share1_0(x)   (x)
#define ascon_mask32_rotate_share2_0(x)   (x)
#define ascon_mask32_rotate_share2_1(x)   (x)
#define ascon_mask32_rotate_share3_0(x)   (x)
#define ascon_mask32_rotate_share3_1(x)   (x)
#define ascon_mask32_rotate_share3_2(x)   (x)
#define ascon_mask32_unrotate_share1_0(x) (x)
#define ascon_mask32_unrotate_share2_0(x) (x)
#define ascon_mask32_unrotate_share2_1(x) (x)
#define ascon_mask32_unrotate_share3_0(x) (x)
#define ascon_mask32_unrotate_share3_1(x) (x)
#define ascon_mask32_unrotate_share3_2(x) (x)

#endif /* ASCON_MASKED_WORD_BACKEND_DIRECT_XOR */

/**
 * \brief Sets a x2 masked word to zero.
 *
 * \param word The x2 masked word to set to zero.
 * \param trng TRNG to use to generate masking material.
 */
void ascon_masked_word_x2_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng);

/**
 * \brief Loads a 64-bit big endian value from buffer, masks it,
 * and writes it to a x2 masked word structure.
 *
 * \param word The x2 masked word to write to.
 * \param data Points to the 64 bits of data to be loaded.
 * \param trng TRNG to use to generate masking material.
 *
 * \sa ascon_masked_word_x2_store()
 */
void ascon_masked_word_x2_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng);

/**
 * \brief Loads a 8-bit to 56-bit big endian value from buffer, masks it,
 * and writes it to a x2 masked word structure.
 *
 * \param word The x2 masked word to write to.
 * \param data Points to the data to be loaded.
 * \param size Number of bytes to load between 1 and 7.
 * \param trng TRNG to use to generate masking material.
 */
void ascon_masked_word_x2_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng);

/**
 * \brief Loads two 32-bit big endian values from buffers, masks them,
 * and writes the result to a x2 masked word structure.
 *
 * \param word The x2 masked word to write to.
 * \param data1 Points to the high 32 bits of data to be loaded.
 * \param data2 Points to the low 32 bits of data to be loaded.
 * \param trng TRNG to use to generate masking material.
 *
 * Normally ascon_masked_word_x2_load() should be used instead of this,
 * but ASCON-80pq mixes IV and key data in the same 64-bit word.
 */
void ascon_masked_word_x2_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng);

/**
 * \brief Unmasks and stores the contents of a x2 masked word structure.
 *
 * \param data Points to the buffer to receive the 64 bits of unmasked data.
 * \param word The x2 masked word to read from.
 *
 * \sa ascon_masked_word_x2_load()
 */
void ascon_masked_word_x2_store
    (uint8_t *data, const ascon_masked_word_t *word);

/**
 * \brief Unmasks and stores the contents of a x2 masked word structure to a
 * partial buffer.
 *
 * \param data Points to the buffer to receive the unmasked data.
 * \param size Number of bytes to unmask.
 * \param word The x2 masked word to read from.
 *
 * \sa ascon_masked_word_x2_load()
 */
void ascon_masked_word_x2_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word);

/**
 * \brief Randomizes a x2 masked word by incorporating fresh randomness.
 *
 * \param dest Points to the destination for the randomized version.
 * \param src Points to the source to randomize, can be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 *
 * The word will still have the same effective value, but this function
 * will mix in fresh randomness.
 */
void ascon_masked_word_x2_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief XOR's a source x2 masked word against a destination x2 masked word.
 *
 * \param dest The destination masked word.
 * \param src The source masked word.
 */
void ascon_masked_word_x2_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src);

/**
 * \brief Replace part of a destination x2 masked word with part of a source.
 *
 * \param dest Destination masked word.
 * \param src Source masked word.
 * \param size Number of bytes from the top of the masked word to copy.
 */
void ascon_masked_word_x2_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size);

/**
 * \brief Converts a x3 masked word into a x2 masked word.
 *
 * \param dest The destination x2 masked word.
 * \param src The source x3 masked word.  May be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 */
void ascon_masked_word_x2_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Converts a x4 masked word into a x2 masked word.
 *
 * \param dest The destination x2 masked word.
 * \param src The source x4 masked word.  May be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 */
void ascon_masked_word_x2_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Sets a x3 masked word to zero.
 *
 * \param word The x3 masked word to set to zero.
 * \param trng TRNG to use to generate masking material.
 */
void ascon_masked_word_x3_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng);

/**
 * \brief Loads a 64-bit big endian value from buffer, masks it,
 * and writes it to a x3 masked word structure.
 *
 * \param word The x3 masked word to write to.
 * \param data Points to the 64 bits of data to be loaded.
 * \param trng TRNG to use to generate masking material.
 *
 * \sa ascon_masked_word_x3_store()
 */
void ascon_masked_word_x3_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng);

/**
 * \brief Loads a 8-bit to 56-bit big endian value from buffer, masks it,
 * and writes it to a x3 masked word structure.
 *
 * \param word The x3 masked word to write to.
 * \param data Points to the data to be loaded.
 * \param size Number of bytes to load between 1 and 7.
 * \param trng TRNG to use to generate masking material.
 */
void ascon_masked_word_x3_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng);

/**
 * \brief Loads two 32-bit big endian values from buffers, masks them,
 * and writes the result to a x3 masked word structure.
 *
 * \param word The x3 masked word to write to.
 * \param data1 Points to the high 32 bits of data to be loaded.
 * \param data2 Points to the low 32 bits of data to be loaded.
 * \param trng TRNG to use to generate masking material.
 *
 * Normally ascon_masked_word_x3_load() should be used instead of this,
 * but ASCON-80pq mixes IV and key data in the same 64-bit word.
 */
void ascon_masked_word_x3_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng);

/**
 * \brief Unmasks and stores the contents of a x3 masked word structure.
 *
 * \param data Points to the buffer to receive the 64 bits of unmasked data.
 * \param word The x3 masked word to read from.
 *
 * \sa ascon_masked_word_x3_load()
 */
void ascon_masked_word_x3_store
    (uint8_t *data, const ascon_masked_word_t *word);

/**
 * \brief Unmasks and stores the contents of a x3 masked word structure to a
 * partial buffer.
 *
 * \param data Points to the buffer to receive the unmasked data.
 * \param size Number of bytes to unmask.
 * \param word The x3 masked word to read from.
 *
 * \sa ascon_masked_word_x3_load()
 */
void ascon_masked_word_x3_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word);

/**
 * \brief Randomizes a x3 masked word by incorporating fresh randomness.
 *
 * \param dest Points to the destination for the randomized version.
 * \param src Points to the source to randomize, can be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 *
 * The word will still have the same effective value, but this function
 * will mix in fresh randomness.
 */
void ascon_masked_word_x3_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief XOR's a source x3 masked word against a destination x3 masked word.
 *
 * \param dest The destination masked word.
 * \param src The source masked word.
 */
void ascon_masked_word_x3_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src);

/**
 * \brief Replace part of a destination x3 masked word with part of a source.
 *
 * \param dest Destination masked word.
 * \param src Source masked word.
 * \param size Number of bytes from the top of the masked word to copy.
 */
void ascon_masked_word_x3_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size);

/**
 * \brief Converts a x2 masked word into a x3 masked word.
 *
 * \param dest The destination x3 masked word.
 * \param src The source x2 masked word.  May be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 */
void ascon_masked_word_x3_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Converts a x4 masked word into a x3 masked word.
 *
 * \param dest The destination x3 masked word.
 * \param src The source x4 masked word.  May be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 */
void ascon_masked_word_x3_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Sets a x4 masked word to zero.
 *
 * \param word The x4 masked word to set to zero.
 * \param trng TRNG to use to generate masking material.
 */
void ascon_masked_word_x4_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng);

/**
 * \brief Loads a 64-bit big endian value from buffer, masks it,
 * and writes it to a x4 masked word structure.
 *
 * \param word The x4 masked word to write to.
 * \param data Points to the 64 bits of data to be loaded.
 * \param trng TRNG to use to generate masking material.
 *
 * \sa ascon_masked_word_x4_store()
 */
void ascon_masked_word_x4_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng);

/**
 * \brief Loads a 8-bit to 56-bit big endian value from buffer, masks it,
 * and writes it to a x4 masked word structure.
 *
 * \param word The x4 masked word to write to.
 * \param data Points to the data to be loaded.
 * \param size Number of bytes to load between 1 and 7.
 * \param trng TRNG to use to generate masking material.
 *
 * \sa ascon_masked_word_x4_store()
 */
void ascon_masked_word_x4_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng);

/**
 * \brief Loads two 32-bit big endian values from buffers, masks them,
 * and writes the result to a x4 masked word structure.
 *
 * \param word The x4 masked word to write to.
 * \param data1 Points to the high 32 bits of data to be loaded.
 * \param data2 Points to the low 32 bits of data to be loaded.
 * \param trng TRNG to use to generate masking material.
 *
 * Normally ascon_masked_word_x4_load() should be used instead of this,
 * but ASCON-80pq mixes IV and key data in the same 64-bit word.
 */
void ascon_masked_word_x4_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng);

/**
 * \brief Unmasks and stores the contents of a x4 masked word structure.
 *
 * \param data Points to the buffer to receive the 64 bits of unmasked data.
 * \param word The x4 masked word to read from.
 *
 * \sa ascon_masked_word_x4_load()
 */
void ascon_masked_word_x4_store
    (uint8_t *data, const ascon_masked_word_t *word);

/**
 * \brief Unmasks and stores the contents of a x4 masked word structure to a
 * partial buffer.
 *
 * \param data Points to the buffer to receive the unmasked data.
 * \param size Number of bytes to unmask.
 * \param word The x4 masked word to read from.
 *
 * \sa ascon_masked_word_x4_load()
 */
void ascon_masked_word_x4_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word);

/**
 * \brief Randomizes a x4 masked word by incorporating fresh randomness.
 *
 * \param dest Points to the destination for the randomized version.
 * \param src Points to the source to randomize, can be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 *
 * The word will still have the same effective value, but this function
 * will mix in fresh randomness.
 */
void ascon_masked_word_x4_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief XOR's a source x4 masked word against a destination x4 masked word.
 *
 * \param dest The destination masked word.
 * \param src The source masked word.
 */
void ascon_masked_word_x4_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src);

/**
 * \brief Replace part of a destination x4 masked word with part of a source.
 *
 * \param dest Destination masked word.
 * \param src Source masked word.
 * \param size Number of bytes from the top of the masked word to copy.
 */
void ascon_masked_word_x4_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size);

/**
 * \brief Converts a x2 masked word into a x4 masked word.
 *
 * \param dest The destination x4 masked word.
 * \param src The source x2 masked word.  May be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 */
void ascon_masked_word_x4_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Converts a x3 masked word into a x4 masked word.
 *
 * \param dest The destination x4 masked word.
 * \param src The source x3 masked word.  May be the same as \a dest.
 * \param trng TRNG to use to randomize the state.
 */
void ascon_masked_word_x4_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Adds a padding marker to a masked word.
 *
 * \param word The masked word to be padded.
 * \param offset Offset of the padding marker (0 to 7).
 */
void ascon_masked_word_pad(ascon_masked_word_t *word, unsigned offset);

/**
 * \brief Adds a separator marker to a masked word.
 *
 * \param word The masked word to add the separator marker to.
 */
void ascon_masked_word_separator(ascon_masked_word_t *word);

#ifdef __cplusplus
}
#endif

#endif
