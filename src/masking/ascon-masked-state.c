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
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x2_randomize
            (&(state->M[index]), &(state->M[index]), trng);
    }
}

void ascon_x2_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng)
{
#if (defined(ASCON_BACKEND_SLICED64) && defined(ASCON_MASKED_BACKEND_SLICED64)) || \
        (defined(ASCON_BACKEND_SLICED32) && defined(ASCON_MASKED_BACKEND_SLICED32))
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x2_mask(&(dest->M[index]), src->S[index], trng);
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
#if (defined(ASCON_BACKEND_SLICED64) && defined(ASCON_MASKED_BACKEND_SLICED64)) || \
        (defined(ASCON_BACKEND_SLICED32) && defined(ASCON_MASKED_BACKEND_SLICED32))
    int index;
    for (index = 0; index < 5; ++index)
        dest->S[index] = ascon_masked_word_x2_unmask(&(src->M[index]));
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
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x2_randomize
            (&(dest->M[index]), &(src->M[index]), trng);
    }
}

void ascon_x2_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x2_from_x3(&(dest->M[index]), &(src->M[index]), trng);
}

void ascon_x2_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x2_from_x4(&(dest->M[index]), &(src->M[index]), trng);
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
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x3_randomize
            (&(state->M[index]), &(state->M[index]), trng);
    }
}

void ascon_x3_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng)
{
#if (defined(ASCON_BACKEND_SLICED64) && defined(ASCON_MASKED_BACKEND_SLICED64)) || \
        (defined(ASCON_BACKEND_SLICED32) && defined(ASCON_MASKED_BACKEND_SLICED32))
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x3_mask(&(dest->M[index]), src->S[index], trng);
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
#if (defined(ASCON_BACKEND_SLICED64) && defined(ASCON_MASKED_BACKEND_SLICED64)) || \
        (defined(ASCON_BACKEND_SLICED32) && defined(ASCON_MASKED_BACKEND_SLICED32))
    int index;
    for (index = 0; index < 5; ++index)
        dest->S[index] = ascon_masked_word_x3_unmask(&(src->M[index]));
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
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x3_from_x2(&(dest->M[index]), &(src->M[index]), trng);
}

void ascon_x3_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x3_randomize
            (&(dest->M[index]), &(src->M[index]), trng);
    }
}

void ascon_x3_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x3_from_x4(&(dest->M[index]), &(src->M[index]), trng);
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
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x4_randomize
            (&(state->M[index]), &(state->M[index]), trng);
    }
}

void ascon_x4_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng)
{
#if (defined(ASCON_BACKEND_SLICED64) && defined(ASCON_MASKED_BACKEND_SLICED64)) || \
        (defined(ASCON_BACKEND_SLICED32) && defined(ASCON_MASKED_BACKEND_SLICED32))
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x4_mask(&(dest->M[index]), src->S[index], trng);
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
#if (defined(ASCON_BACKEND_SLICED64) && defined(ASCON_MASKED_BACKEND_SLICED64)) || \
        (defined(ASCON_BACKEND_SLICED32) && defined(ASCON_MASKED_BACKEND_SLICED32))
    int index;
    for (index = 0; index < 5; ++index)
        dest->S[index] = ascon_masked_word_x4_unmask(&(src->M[index]));
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
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x4_from_x2(&(dest->M[index]), &(src->M[index]), trng);
}

void ascon_x4_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    for (index = 0; index < 5; ++index)
        ascon_masked_word_x4_from_x3(&(dest->M[index]), &(src->M[index]), trng);
}

void ascon_x4_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng)
{
    int index;
    for (index = 0; index < 5; ++index) {
        ascon_masked_word_x4_randomize
            (&(dest->M[index]), &(src->M[index]), trng);
    }
}
