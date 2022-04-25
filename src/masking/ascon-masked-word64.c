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

#include "ascon-masked-word.h"

#if defined(ASCON_MASKED_BACKEND_SLICED64)

void ascon_masked_word_x2_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    word->S[0] = random;
    word->S[1] = ascon_mask64_rotate_share1_0(random);
    word->S[2] = 0;
    word->S[3] = 0;
}

void ascon_masked_word_x2_randomize
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    word->S[0] ^= random;
    word->S[1] ^= ascon_mask64_rotate_share1_0(random);
}

void ascon_masked_word_x2_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    dest->S[0] = random ^ src->S[0];
    dest->S[1] = (ascon_mask64_rotate_share1_0(random) ^ src->S[1]) ^
                 ascon_mask64_unrotate_share2_1(src->S[2]);
    dest->S[2] = 0;
    dest->S[3] = 0;
}

void ascon_masked_word_x2_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    dest->S[0] = (random ^ src->S[0]) ^
                 ascon_mask64_unrotate_share2_0(src->S[2]);
    dest->S[1] = (ascon_mask64_rotate_share1_0(random) ^ src->S[1]) ^
                 ascon_mask64_unrotate_share3_1(src->S[3]);
    dest->S[2] = 0;
    dest->S[3] = 0;
}

void ascon_masked_word_x3_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ random2;
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = 0;
}

void ascon_masked_word_x3_randomize
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    word->S[0] ^= random1 ^ random2;
    word->S[1] ^= ascon_mask64_rotate_share1_0(random1);
    word->S[2] ^= ascon_mask64_rotate_share2_0(random2);
}

void ascon_masked_word_x3_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    dest->S[0] = random1 ^ random2 ^ src->S[0];
    dest->S[1] = ascon_mask64_rotate_share1_0(random1) ^ src->S[1];
    dest->S[2] = ascon_mask64_rotate_share2_0(random2);
    dest->S[3] = 0;
}

void ascon_masked_word_x3_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    dest->S[0] = (random1 ^ random2 ^ src->S[0]) ^ src->S[3];
    dest->S[1] = ascon_mask64_rotate_share1_0(random1) ^ src->S[1];
    dest->S[2] = ascon_mask64_rotate_share2_0(random2) ^ src->S[2];
    dest->S[3] = 0;
}

void ascon_masked_word_x4_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ random2 ^ random3;
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = ascon_mask64_rotate_share3_0(random3);
}

void ascon_masked_word_x4_randomize
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    word->S[0] ^= random1 ^ random2 ^ random3;
    word->S[1] ^= ascon_mask64_rotate_share1_0(random1);
    word->S[2] ^= ascon_mask64_rotate_share2_0(random2);
    word->S[3] ^= ascon_mask64_rotate_share3_0(random3);
}

void ascon_masked_word_x4_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    dest->S[0] = random1 ^ random2 ^ random3 ^ src->S[0];
    dest->S[1] = ascon_mask64_rotate_share1_0(random1) ^ src->S[1];
    dest->S[2] = ascon_mask64_rotate_share2_0(random2);
    dest->S[3] = ascon_mask64_rotate_share3_0(random3);
}

void ascon_masked_word_x4_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    dest->S[0] = random1 ^ random2 ^ random3 ^ src->S[0];
    dest->S[1] = ascon_mask64_rotate_share1_0(random1) ^ src->S[1];
    dest->S[2] = ascon_mask64_rotate_share2_0(random2) ^ src->S[2];
    dest->S[3] = ascon_mask64_rotate_share3_0(random3);
}

#endif /* ASCON_MASKED_BACKEND_SLICED64 */
