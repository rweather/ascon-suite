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

#include "ascon-masked-state.h"
#include "ascon-masked-backend.h"
#include "core/ascon-util-snp.h"
#include <ascon/utility.h>
#include <string.h>

#if defined(ASCON_MASKED_BACKEND_SLICED64)

void ascon_x2_init(ascon_masked_state_t *state)
{
    memset(state, 0, sizeof(ascon_masked_state_t));
}

void ascon_x2_free(ascon_masked_state_t *state)
{
    if (state)
        ascon_clean(state, sizeof(ascon_masked_state_t));
}

void ascon_x2_randomize(ascon_masked_state_t *state, ascon_trng_state_t *trng)
{
    int index;
    uint64_t random;
    for (index = 0; index < 5; ++index) {
        random = ascon_trng_generate_64(trng);
        state->M[index].S[0] ^= random;
        state->M[index].S[1] ^= ascon_mask64_rotate_share1_0(random);
    }
}

void ascon_x2_add_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset)
{
    state->M[offset / 8].S[0] ^= word->S[0];
    state->M[offset / 8].S[1] ^= word->S[1];
}

void ascon_x2_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset)
{
    state->M[offset / 8].S[0] = word->S[0];
    state->M[offset / 8].S[1] = word->S[1];
}

void ascon_x2_extract_word
    (const ascon_masked_state_t *state, ascon_masked_word_t *word,
     unsigned offset)
{
    word->S[0] = state->M[offset / 8].S[0];
    word->S[1] = state->M[offset / 8].S[1];
}

void ascon_x2_extract_and_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *input,
     ascon_masked_word_t *output, unsigned offset)
{
    uint64_t word0 = input->S[0];
    uint64_t word1 = input->S[1];
    output->S[0] = word0 ^ state->M[offset / 8].S[0];
    output->S[1] = word1 ^ state->M[offset / 8].S[1];
    state->M[offset / 8].S[0] = word0;
    state->M[offset / 8].S[1] = word1;
}

void ascon_x2_release(ascon_masked_state_t *state)
{
    /* Nothing to do here */
    (void)state;
}

void ascon_x2_acquire(ascon_masked_state_t *state)
{
    /* Nothing to do here */
    (void)state;
}

void ascon_x2_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng)
{
#if defined(ASCON_BACKEND_SLICED64)
    int index;
    uint64_t random;
    for (index = 0; index < 5; ++index) {
        random = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random ^ src->S[index];
        dest->M[index].S[1] = ascon_mask64_rotate_share1_0(random);
        dest->M[index].S[2] = 0;
        dest->M[index].S[3] = 0;
    }
#elif defined(ASCON_BACKEND_DIRECT_XOR)
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x2_load(&(dest->M[index]), src->B + index * 8, trng);
#else
    int index;
    unsigned char word[8];
    for (index = 0; index < 5; ++index) {
        ascon_squeeze_8(src, word, index * 8);
        ascon_masked_word_x2_load(&(dest->M[index]), word, trng);
    }
    ascon_clean(word, sizeof(word));
#endif
}

void ascon_x2_copy_to_x1(ascon_state_t *dest, const ascon_masked_state_t *src)
{
#if defined(ASCON_BACKEND_SLICED64)
    int index;
    for (index = 0; index < 5; ++index) {
        dest->S[index] = src->M[index].S[0] ^
                         ascon_mask64_unrotate_share1_0(src->M[index].S[1]);
    }
#elif defined(ASCON_BACKEND_SLICED32)
    int index;
    uint64_t word;
    for (index = 0; index < 5; ++index) {
        word = src->M[index].S[0] ^
               ascon_mask64_unrotate_share1_0(src->M[index].S[1]);
        ascon_set_word64(dest, word, index);
    }
#elif defined(ASCON_BACKEND_DIRECT_XOR)
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x2_store(dest->B + index * 8, &(src->M[index]));
#else
    int index;
    unsigned char word[8];
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x2_store(word, &(src->M[index]));
        ascon_overwrite_bytes(dest, word, index * 8, 8);
    }
    ascon_clean(word, sizeof(word));
#endif
}

void ascon_x2_copy_from_x2
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random;
    for (index = 0; index < 5; ++index) {
        random = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random ^ src->M[index].S[0];
        dest->M[index].S[1] =
            ascon_mask64_rotate_share1_0(random) ^ src->M[index].S[1];
        dest->M[index].S[2] = 0;
        dest->M[index].S[3] = 0;
    }
}

void ascon_x2_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random;
    for (index = 0; index < 5; ++index) {
        random = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random ^ src->M[index].S[0];
        dest->M[index].S[1] =
            (ascon_mask64_rotate_share1_0(random) ^ src->M[index].S[1]) ^
            ascon_mask64_unrotate_share2_1(src->M[index].S[2]);
        dest->M[index].S[2] = 0;
        dest->M[index].S[3] = 0;
    }
}

void ascon_x2_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random;
    for (index = 0; index < 5; ++index) {
        random = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = (random ^ src->M[index].S[0]) ^
            ascon_mask64_unrotate_share1_0(src->M[index].S[1]);
        dest->M[index].S[1] =
            (ascon_mask64_rotate_share1_0(random) ^
             ascon_mask64_unrotate_share2_1(src->M[index].S[2])) ^
            ascon_mask64_unrotate_share3_1(src->M[index].S[3]);
        dest->M[index].S[2] = 0;
        dest->M[index].S[3] = 0;
    }
}

void ascon_x3_init(ascon_masked_state_t *state)
{
    memset(state, 0, sizeof(ascon_masked_state_t));
}

void ascon_x3_free(ascon_masked_state_t *state)
{
    if (state)
        ascon_clean(state, sizeof(ascon_masked_state_t));
}

void ascon_x3_randomize(ascon_masked_state_t *state, ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        state->M[index].S[0] ^= random1 ^ random2;
        state->M[index].S[1] ^= ascon_mask64_rotate_share1_0(random1);
        state->M[index].S[2] ^= ascon_mask64_rotate_share2_0(random2);
    }
}

void ascon_x3_add_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset)
{
    state->M[offset / 8].S[0] ^= word->S[0];
    state->M[offset / 8].S[1] ^= word->S[1];
    state->M[offset / 8].S[2] ^= word->S[2];
}

void ascon_x3_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset)
{
    state->M[offset / 8].S[0] = word->S[0];
    state->M[offset / 8].S[1] = word->S[1];
    state->M[offset / 8].S[2] = word->S[2];
}

void ascon_x3_extract_word
    (const ascon_masked_state_t *state, ascon_masked_word_t *word,
     unsigned offset)
{
    word->S[0] = state->M[offset / 8].S[0];
    word->S[1] = state->M[offset / 8].S[1];
    word->S[2] = state->M[offset / 8].S[2];
}

void ascon_x3_extract_and_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *input,
     ascon_masked_word_t *output, unsigned offset)
{
    uint64_t word0 = input->S[0];
    uint64_t word1 = input->S[1];
    uint64_t word2 = input->S[2];
    output->S[0] = word0 ^ state->M[offset / 8].S[0];
    output->S[1] = word1 ^ state->M[offset / 8].S[1];
    output->S[2] = word2 ^ state->M[offset / 8].S[2];
    state->M[offset / 8].S[0] = word0;
    state->M[offset / 8].S[1] = word1;
    state->M[offset / 8].S[2] = word2;
}

void ascon_x3_release(ascon_masked_state_t *state)
{
    /* Nothing to do here */
    (void)state;
}

void ascon_x3_acquire(ascon_masked_state_t *state)
{
    /* Nothing to do here */
    (void)state;
}

void ascon_x3_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng)
{
#if defined(ASCON_BACKEND_SLICED64)
    int index;
    uint64_t random1;
    uint64_t random2;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ src->S[index];
        dest->M[index].S[1] = ascon_mask64_rotate_share1_0(random1);
        dest->M[index].S[2] = ascon_mask64_rotate_share2_0(random2);
        dest->M[index].S[3] = 0;
    }
#elif defined(ASCON_BACKEND_DIRECT_XOR)
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x3_load(&(dest->M[index]), src->B + index * 8, trng);
#else
    int index;
    unsigned char word[8];
    for (index = 0; index < 5; ++index) {
        ascon_squeeze_8(src, word, index * 8);
        ascon_masked_word_x3_load(&(dest->M[index]), word, trng);
    }
    ascon_clean(word, sizeof(word));
#endif
}

void ascon_x3_copy_to_x1(ascon_state_t *dest, const ascon_masked_state_t *src)
{
#if defined(ASCON_BACKEND_SLICED64)
    int index;
    for (index = 0; index < 5; ++index) {
        dest->S[index] = src->M[index].S[0] ^
                         ascon_mask64_unrotate_share1_0(src->M[index].S[1]) ^
                         ascon_mask64_unrotate_share2_0(src->M[index].S[2]);
    }
#elif defined(ASCON_BACKEND_SLICED32)
    int index;
    uint64_t word;
    for (index = 0; index < 5; ++index) {
        word = src->M[index].S[0] ^
               ascon_mask64_unrotate_share1_0(src->M[index].S[1]) ^
               ascon_mask64_unrotate_share2_0(src->M[index].S[2]);
        ascon_set_word64(dest, word, index);
    }
#elif defined(ASCON_BACKEND_DIRECT_XOR)
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x3_store(dest->B + index * 8, &(src->M[index]));
#else
    int index;
    unsigned char word[8];
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x3_store(word, &(src->M[index]));
        ascon_overwrite_bytes(dest, word, index * 8, 8);
    }
    ascon_clean(word, sizeof(word));
#endif
}

void ascon_x3_copy_from_x2
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ src->M[index].S[0];
        dest->M[index].S[1] =
            ascon_mask64_rotate_share1_0(random1) ^ src->M[index].S[1];
        dest->M[index].S[2] = ascon_mask64_rotate_share2_0(random2);
        dest->M[index].S[3] = 0;
    }
}

void ascon_x3_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ src->M[index].S[0];
        dest->M[index].S[1] =
            ascon_mask64_rotate_share1_0(random1) ^ src->M[index].S[1];
        dest->M[index].S[2] =
            ascon_mask64_rotate_share2_0(random2) ^ src->M[index].S[2];
        dest->M[index].S[3] = 0;
    }
}

void ascon_x3_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ src->M[index].S[0];
        dest->M[index].S[1] =
            (ascon_mask64_rotate_share1_0(random1) ^ src->M[index].S[1]) ^
            ascon_mask64_unrotate_share3_1(src->M[index].S[3]);
        dest->M[index].S[2] =
            ascon_mask64_rotate_share2_0(random2) ^ src->M[index].S[2];
        dest->M[index].S[3] = 0;
    }
}

void ascon_x4_init(ascon_masked_state_t *state)
{
    memset(state, 0, sizeof(ascon_masked_state_t));
}

void ascon_x4_free(ascon_masked_state_t *state)
{
    if (state)
        ascon_clean(state, sizeof(ascon_masked_state_t));
}

void ascon_x4_randomize(ascon_masked_state_t *state, ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    uint64_t random3;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        random3 = ascon_trng_generate_64(trng);
        state->M[index].S[0] ^= random1 ^ random2 ^ random3;
        state->M[index].S[1] ^= ascon_mask64_rotate_share1_0(random1);
        state->M[index].S[2] ^= ascon_mask64_rotate_share2_0(random2);
        state->M[index].S[3] ^= ascon_mask64_rotate_share3_0(random3);
    }
}

void ascon_x4_add_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset)
{
    state->M[offset / 8].S[0] ^= word->S[0];
    state->M[offset / 8].S[1] ^= word->S[1];
    state->M[offset / 8].S[2] ^= word->S[2];
    state->M[offset / 8].S[3] ^= word->S[3];
}

void ascon_x4_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset)
{
    state->M[offset / 8].S[0] = word->S[0];
    state->M[offset / 8].S[1] = word->S[1];
    state->M[offset / 8].S[2] = word->S[2];
    state->M[offset / 8].S[3] = word->S[3];
}

void ascon_x4_extract_word
    (const ascon_masked_state_t *state, ascon_masked_word_t *word,
     unsigned offset)
{
    word->S[0] = state->M[offset / 8].S[0];
    word->S[1] = state->M[offset / 8].S[1];
    word->S[2] = state->M[offset / 8].S[2];
    word->S[3] = state->M[offset / 8].S[3];
}

void ascon_x4_extract_and_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *input,
     ascon_masked_word_t *output, unsigned offset)
{
    uint64_t word0 = input->S[0];
    uint64_t word1 = input->S[1];
    uint64_t word2 = input->S[2];
    uint64_t word3 = input->S[3];
    output->S[0] = word0 ^ state->M[offset / 8].S[0];
    output->S[1] = word1 ^ state->M[offset / 8].S[1];
    output->S[2] = word2 ^ state->M[offset / 8].S[2];
    output->S[3] = word3 ^ state->M[offset / 8].S[3];
    state->M[offset / 8].S[0] = word0;
    state->M[offset / 8].S[1] = word1;
    state->M[offset / 8].S[2] = word2;
    state->M[offset / 8].S[3] = word3;
}

void ascon_x4_release(ascon_masked_state_t *state)
{
    /* Nothing to do here */
    (void)state;
}

void ascon_x4_acquire(ascon_masked_state_t *state)
{
    /* Nothing to do here */
    (void)state;
}

void ascon_x4_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng)
{
#if defined(ASCON_BACKEND_SLICED64)
    int index;
    uint64_t random1;
    uint64_t random2;
    uint64_t random3;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        random3 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ random3 ^ src->S[index];
        dest->M[index].S[1] = ascon_mask64_rotate_share1_0(random1);
        dest->M[index].S[2] = ascon_mask64_rotate_share2_0(random2);
        dest->M[index].S[3] = ascon_mask64_rotate_share3_0(random3);
    }
#elif defined(ASCON_BACKEND_DIRECT_XOR)
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x4_load(&(dest->M[index]), src->B + index * 8, trng);
#else
    int index;
    unsigned char word[8];
    for (index = 0; index < 5; ++index) {
        ascon_squeeze_8(src, word, index * 8);
        ascon_masked_word_x4_load(&(dest->M[index]), word, trng);
    }
    ascon_clean(word, sizeof(word));
#endif
}

void ascon_x4_copy_to_x1(ascon_state_t *dest, const ascon_masked_state_t *src)
{
#if defined(ASCON_BACKEND_SLICED64)
    int index;
    for (index = 0; index < 5; ++index) {
        dest->S[index] = src->M[index].S[0] ^
                         ascon_mask64_unrotate_share1_0(src->M[index].S[1]) ^
                         ascon_mask64_unrotate_share2_0(src->M[index].S[2]) ^
                         ascon_mask64_unrotate_share3_0(src->M[index].S[3]);
    }
#elif defined(ASCON_BACKEND_SLICED32)
    int index;
    uint64_t word;
    for (index = 0; index < 5; ++index) {
        word = src->M[index].S[0] ^
               ascon_mask64_unrotate_share1_0(src->M[index].S[1]) ^
               ascon_mask64_unrotate_share2_0(src->M[index].S[2]) ^
               ascon_mask64_unrotate_share3_0(src->M[index].S[3]);
        ascon_set_word64(dest, word, index);
    }
#elif defined(ASCON_BACKEND_DIRECT_XOR)
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x4_store(dest->B + index * 8, &(src->M[index]));
#else
    int index;
    unsigned char word[8];
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x4_store(word, &(src->M[index]));
        ascon_overwrite_bytes(dest, word, index * 8, 8);
    }
    ascon_clean(word, sizeof(word));
#endif
}

void ascon_x4_copy_from_x2
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    uint64_t random3;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        random3 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ src->M[index].S[0];
        dest->M[index].S[1] =
            ascon_mask64_rotate_share1_0(random1) ^ random3 ^
            src->M[index].S[1];
        dest->M[index].S[2] = ascon_mask64_rotate_share2_0(random2);
        dest->M[index].S[3] = ascon_mask64_rotate_share3_1(random3);
    }
}

void ascon_x4_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    uint64_t random3;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        random3 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ random3 ^ src->M[index].S[0];
        dest->M[index].S[1] =
            ascon_mask64_rotate_share1_0(random1) ^ src->M[index].S[1];
        dest->M[index].S[2] =
            ascon_mask64_rotate_share2_0(random2) ^ src->M[index].S[2];
        dest->M[index].S[3] = ascon_mask64_rotate_share3_0(random3);
    }
}

void ascon_x4_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    uint64_t random1;
    uint64_t random2;
    uint64_t random3;
    for (index = 0; index < 5; ++index) {
        random1 = ascon_trng_generate_64(trng);
        random2 = ascon_trng_generate_64(trng);
        random3 = ascon_trng_generate_64(trng);
        dest->M[index].S[0] = random1 ^ random2 ^ random3 ^ src->M[index].S[0];
        dest->M[index].S[1] =
            ascon_mask64_rotate_share1_0(random1) ^ src->M[index].S[1];
        dest->M[index].S[2] =
            ascon_mask64_rotate_share2_0(random2) ^ src->M[index].S[2];
        dest->M[index].S[3] =
            ascon_mask64_rotate_share3_0(random3) ^ src->M[index].S[3];
    }
}

#endif /* ASCON_MASKED_BACKEND_SLICED64 */
