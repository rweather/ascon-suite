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

#ifndef ASCON_AEAD_MASKED_COMMON_H
#define ASCON_AEAD_MASKED_COMMON_H

/* Common utilities for supporting the implementation of masked AEAD modes */

#include <ascon/aead-masked.h>
#include "masking/ascon-masked-config.h"
#include "masking/ascon-masked-state.h"
#include "aead/ascon-aead-common.h"
#include "core/ascon-util.h"
#include <string.h>

/**
 * \brief Absorbs data into a masked ASCON state with an 8-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 * \param word Points to temporary storage for a masked word.
 * \param preserve Preserved randomness from the previous step.
 * \param trng TRNG to use to generate randomness to mask the data.
 */
void ascon_masked_aead_absorb_8
    (ascon_masked_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, ascon_masked_word_t *word,
     uint64_t *preserve, ascon_trng_state_t *trng);

/**
 * \brief Absorbs data into a masked ASCON state with a 16-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 * \param word Points to temporary storage for a masked word.
 * \param preserve Preserved randomness from the previous step.
 * \param trng TRNG to use to generate randomness to mask the data.
 */
void ascon_masked_aead_absorb_16
    (ascon_masked_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, ascon_masked_word_t *word,
     uint64_t *preserve, ascon_trng_state_t *trng);

/**
 * \brief Encrypts a block of data with a masked ASCON state and an 8-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 * \param word Points to temporary storage for a masked word.
 * \param preserve Preserved randomness from the previous step.
 * \param trng TRNG to use to generate randomness to mask the data.
 */
void ascon_masked_aead_encrypt_8
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng);

/**
 * \brief Encrypts a block of data with a masked ASCON state and a 16-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 * \param word Points to temporary storage for a masked word.
 * \param preserve Preserved randomness from the previous step.
 * \param trng TRNG to use to generate randomness to mask the data.
 */
void ascon_masked_aead_encrypt_16
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng);

/**
 * \brief Decrypts a block of data with a masked ASCON state and an 8-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 * \param word Points to temporary storage for a masked word.
 * \param preserve Preserved randomness from the previous step.
 * \param trng TRNG to use to generate randomness to mask the data.
 */
void ascon_masked_aead_decrypt_8
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng);

/**
 * \brief Decrypts a block of data with an ASCON state and a 16-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 * \param word Points to temporary storage for a masked word.
 * \param preserve Preserved randomness from the previous step.
 * \param trng TRNG to use to generate randomness to mask the data.
 */
void ascon_masked_aead_decrypt_16
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng);

/** @cond masked_aead_utils */

#if ASCON_MASKED_KEY_SHARES == 2

#define ascon_masked_key_load(word, data, trng) \
    ascon_masked_word_x2_load((word), (data), (trng))
#define ascon_masked_key_store(data, word) \
    ascon_masked_word_x2_store((data), (word))
#define ascon_masked_key_xor(dest, src) \
    ascon_masked_word_x2_xor((dest), (const ascon_masked_word_t *)(src))
#define ascon_masked_key_permute(state, first_round, preserve) \
    ascon_x2_permute((state), (first_round), (preserve))
#define ascon_masked_key_randomize(state, trng) \
    ascon_x2_randomize((state), (trng))
#define ascon_copy_key_to_x1(state_x1, state) \
    ascon_x2_copy_to_x1((state_x1), (state))
#define ascon_copy_key_to_x2(state, trng) do { ; } while (0)
#define ascon_copy_key_from_x1(state, state_x1, trng) \
    ascon_x2_copy_from_x1((state), (state_x1), (trng))
#define ascon_copy_key_from_x2(state, trng) \
    ascon_x2_randomize((state), (trng))

#elif ASCON_MASKED_KEY_SHARES == 3

#define ascon_masked_key_load(word, data, trng) \
    ascon_masked_word_x3_load((word), (data), (trng))
#define ascon_masked_key_store(data, word) \
    ascon_masked_word_x3_store((data), (word))
#define ascon_masked_key_xor(dest, src) \
    ascon_masked_word_x3_xor((dest), (const ascon_masked_word_t *)(src))
#define ascon_masked_key_permute(state, first_round, preserve) \
    ascon_x3_permute((state), (first_round), (preserve))
#define ascon_masked_key_randomize(state, trng) \
    ascon_x3_randomize((state), (trng))
#define ascon_copy_key_to_x1(state_x1, state) \
    ascon_x3_copy_to_x1((state_x1), (state))
#define ascon_copy_key_to_x2(state, trng) \
    ascon_x2_copy_from_x3((state), (state), (trng))
#define ascon_copy_key_to_x3(state, trng) do { ; } while (0)
#define ascon_copy_key_from_x1(state, state_x1, trng) \
    ascon_x3_copy_from_x1((state), (state_x1), (trng))
#define ascon_copy_key_from_x2(state, trng) \
    ascon_x3_copy_from_x2((state), (state), (trng))
#define ascon_copy_key_from_x3(state, trng) \
    ascon_x3_randomize((state), (trng))

#else /* ASCON_MASKED_KEY_SHARES == 4 */

#define ascon_masked_key_load(word, data, trng) \
    ascon_masked_word_x4_load((word), (data), (trng))
#define ascon_masked_key_store(data, word) \
    ascon_masked_word_x4_store((data), (word))
#define ascon_masked_key_xor(dest, src) \
    ascon_masked_word_x4_xor((dest), (const ascon_masked_word_t *)(src))
#define ascon_masked_key_permute(state, first_round, preserve) \
    ascon_x4_permute((state), (first_round), (preserve))
#define ascon_masked_key_randomize(state, trng) \
    ascon_x4_randomize((state), (trng))
#define ascon_copy_key_to_x1(state_x1, state) \
    ascon_x4_copy_to_x1((state_x1), (state))
#define ascon_copy_key_to_x2(state, trng) \
    ascon_x2_copy_from_x4((state), (state), (trng))
#define ascon_copy_key_to_x3(state, trng) \
    ascon_x3_copy_from_x4((state), (state), (trng))
#define ascon_copy_key_to_x4(state, trng) do { ; } while (0)
#define ascon_copy_key_from_x1(state, state_x1, trng) \
    ascon_x4_copy_from_x1((state), (state_x1), (trng))
#define ascon_copy_key_from_x2(state, trng) \
    ascon_x4_copy_from_x2((state), (state), (trng))
#define ascon_copy_key_from_x3(state, trng) \
    ascon_x4_copy_from_x3((state), (state), (trng))
#define ascon_copy_key_from_x4(state, trng) \
    ascon_x4_randomize((state), (trng))

#endif /* ASCON_MASKED_KEY_SHARES == 4 */

#if ASCON_MASKED_DATA_SHARES == 1

/* Masking is not needed with 1 data share */

#elif ASCON_MASKED_DATA_SHARES == 2

#define ascon_masked_data_load(word, data, trng) \
    ascon_masked_word_x2_load((word), (data), (trng))
#define ascon_masked_data_load_partial(word, data, len, trng) \
    ascon_masked_word_x2_load_partial((word), (data), len, (trng))
#define ascon_masked_data_store(data, word) \
    ascon_masked_word_x2_store((data), (word))
#define ascon_masked_data_store_partial(data, len, word) \
    ascon_masked_word_x2_store_partial((data), (len), (word))
#define ascon_masked_data_xor(dest, src) \
    ascon_masked_word_x2_xor((dest), (src))
#define ascon_masked_data_permute(state, first_round, preserve) \
    ascon_x2_permute((state), (first_round), (preserve))
#define ascon_masked_data_replace(dest, src, size) \
    ascon_masked_word_x2_replace((dest), (src), (size))

#elif ASCON_MASKED_DATA_SHARES == 3

#define ascon_masked_data_load(word, data, trng) \
    ascon_masked_word_x3_load((word), (data), (trng))
#define ascon_masked_data_load_partial(word, data, len, trng) \
    ascon_masked_word_x3_load_partial((word), (data), len, (trng))
#define ascon_masked_data_store(data, word) \
    ascon_masked_word_x3_store((data), (word))
#define ascon_masked_data_store_partial(data, len, word) \
    ascon_masked_word_x3_store_partial((data), (len), (word))
#define ascon_masked_data_xor(dest, src) \
    ascon_masked_word_x3_xor((dest), (src))
#define ascon_masked_data_permute(state, first_round, preserve) \
    ascon_x3_permute((state), (first_round), (preserve))
#define ascon_masked_data_replace(dest, src, size) \
    ascon_masked_word_x3_replace((dest), (src), (size))

#else /* ASCON_MASKED_DATA_SHARES == 4 */

#define ascon_masked_data_load(word, data, trng) \
    ascon_masked_word_x4_load((word), (data), (trng))
#define ascon_masked_data_load_partial(word, data, len, trng) \
    ascon_masked_word_x4_load_partial((word), (data), len, (trng))
#define ascon_masked_data_store(data, word) \
    ascon_masked_word_x4_store((data), (word))
#define ascon_masked_data_store_partial(data, len, word) \
    ascon_masked_word_x4_store_partial((data), (len), (word))
#define ascon_masked_data_xor(dest, src) \
    ascon_masked_word_x4_xor((dest), (src))
#define ascon_masked_data_permute(state, first_round, preserve) \
    ascon_x4_permute((state), (first_round), (preserve))
#define ascon_masked_data_replace(dest, src, size) \
    ascon_masked_word_x4_replace((dest), (src), (size))

#endif /* ASCON_MASKED_DATA_SHARES == 4 */

/** @endcond */

#endif
