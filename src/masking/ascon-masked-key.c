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

#include <ascon/masking.h>
#include <ascon/utility.h>
#include "ascon-masked-word.h"
#include <string.h>

void ascon_masked_key_128_init
    (ascon_masked_key_128_t *masked, const unsigned char *key)
{
    ascon_trng_state_t trng;
#if ASCON_MASKED_MAX_SHARES < 4
    memset(masked, 0, sizeof(ascon_masked_key_128_t));
#endif
    ascon_trng_init(&trng);
#if ASCON_MASKED_KEY_SHARES == 2
    ascon_masked_word_x2_load
        ((ascon_masked_word_t *)&(masked->k[0]), key, &trng);
    ascon_masked_word_x2_load
        ((ascon_masked_word_t *)&(masked->k[1]), key + 8, &trng);
#elif ASCON_MASKED_KEY_SHARES == 3
    ascon_masked_word_x3_load
        ((ascon_masked_word_t *)&(masked->k[0]), key, &trng);
    ascon_masked_word_x3_load
        ((ascon_masked_word_t *)&(masked->k[1]), key + 8, &trng);
#else
    ascon_masked_word_x4_load
        ((ascon_masked_word_t *)&(masked->k[0]), key, &trng);
    ascon_masked_word_x4_load
        ((ascon_masked_word_t *)&(masked->k[1]), key + 8, &trng);
#endif
    ascon_trng_free(&trng);
}

void ascon_masked_key_128_free(ascon_masked_key_128_t *masked)
{
    if (masked)
        ascon_clean(masked, sizeof(ascon_masked_key_128_t));
}

void ascon_masked_key_128_randomize_with_trng
    (ascon_masked_key_128_t *masked, ascon_trng_state_t *trng)
{
#if ASCON_MASKED_KEY_SHARES == 2
    ascon_masked_word_x2_randomize
        ((ascon_masked_word_t *)&(masked->k[0]),
         (ascon_masked_word_t *)&(masked->k[0]), trng);
    ascon_masked_word_x2_randomize
        ((ascon_masked_word_t *)&(masked->k[1]),
         (ascon_masked_word_t *)&(masked->k[1]), trng);
#elif ASCON_MASKED_KEY_SHARES == 3
    ascon_masked_word_x3_randomize
        ((ascon_masked_word_t *)&(masked->k[0]),
         (ascon_masked_word_t *)&(masked->k[0]), trng);
    ascon_masked_word_x3_randomize
        ((ascon_masked_word_t *)&(masked->k[1]),
         (ascon_masked_word_t *)&(masked->k[1]), trng);
#else
    ascon_masked_word_x4_randomize
        ((ascon_masked_word_t *)&(masked->k[0]),
         (ascon_masked_word_t *)&(masked->k[0]), trng);
    ascon_masked_word_x4_randomize
        ((ascon_masked_word_t *)&(masked->k[1]),
         (ascon_masked_word_t *)&(masked->k[1]), trng);
#endif
}

void ascon_masked_key_128_randomize(ascon_masked_key_128_t *masked)
{
    ascon_trng_state_t trng;
    ascon_trng_init(&trng);
    ascon_masked_key_128_randomize_with_trng(masked, &trng);
    ascon_trng_free(&trng);
}

void ascon_masked_key_128_extract
    (const ascon_masked_key_128_t *masked, unsigned char *key)
{
#if ASCON_MASKED_KEY_SHARES == 2
    ascon_masked_word_x2_store
        (key, (const ascon_masked_word_t *)&(masked->k[0]));
    ascon_masked_word_x2_store
        (key + 8, (const ascon_masked_word_t *)&(masked->k[1]));
#elif ASCON_MASKED_KEY_SHARES == 3
    ascon_masked_word_x3_store
        (key, (const ascon_masked_word_t *)&(masked->k[0]));
    ascon_masked_word_x3_store
        (key + 8, (const ascon_masked_word_t *)&(masked->k[1]));
#else
    ascon_masked_word_x4_store
        (key, (const ascon_masked_word_t *)&(masked->k[0]));
    ascon_masked_word_x4_store
        (key + 8, (const ascon_masked_word_t *)&(masked->k[1]));
#endif
}

void ascon_masked_key_160_init
    (ascon_masked_key_160_t *masked, const unsigned char *key)
{
    static unsigned char const zeroes[4] = {0, 0, 0, 0};
    ascon_trng_state_t trng;
#if ASCON_MASKED_MAX_SHARES < 4
    memset(masked, 0, sizeof(ascon_masked_key_160_t));
#endif
    ascon_trng_init(&trng);
#if ASCON_MASKED_KEY_SHARES == 2
    /* ASCON-80pq absorbs keys in two places so we need to mask it twice */
    ascon_masked_word_x2_load
        ((ascon_masked_word_t *)&(masked->k[0]), key, &trng);
    ascon_masked_word_x2_load
        ((ascon_masked_word_t *)&(masked->k[1]), key + 8, &trng);
    ascon_masked_word_x2_load_32
        ((ascon_masked_word_t *)&(masked->k[2]), key + 16, zeroes, &trng);
    ascon_masked_word_x2_load_32
        ((ascon_masked_word_t *)&(masked->k[3]), zeroes, key, &trng);
    ascon_masked_word_x2_load
        ((ascon_masked_word_t *)&(masked->k[4]), key + 4, &trng);
    ascon_masked_word_x2_load
        ((ascon_masked_word_t *)&(masked->k[5]), key + 12, &trng);
#elif ASCON_MASKED_KEY_SHARES == 3
    ascon_masked_word_x3_load
        ((ascon_masked_word_t *)&(masked->k[0]), key, &trng);
    ascon_masked_word_x3_load
        ((ascon_masked_word_t *)&(masked->k[1]), key + 8, &trng);
    ascon_masked_word_x3_load_32
        ((ascon_masked_word_t *)&(masked->k[2]), key + 16, zeroes, &trng);
    ascon_masked_word_x3_load_32
        ((ascon_masked_word_t *)&(masked->k[3]), zeroes, key, &trng);
    ascon_masked_word_x3_load
        ((ascon_masked_word_t *)&(masked->k[4]), key + 4, &trng);
    ascon_masked_word_x3_load
        ((ascon_masked_word_t *)&(masked->k[5]), key + 12, &trng);
#else
    ascon_masked_word_x4_load
        ((ascon_masked_word_t *)&(masked->k[0]), key, &trng);
    ascon_masked_word_x4_load
        ((ascon_masked_word_t *)&(masked->k[1]), key + 8, &trng);
    ascon_masked_word_x4_load_32
        ((ascon_masked_word_t *)&(masked->k[2]), key + 16, zeroes, &trng);
    ascon_masked_word_x4_load_32
        ((ascon_masked_word_t *)&(masked->k[3]), zeroes, key, &trng);
    ascon_masked_word_x4_load
        ((ascon_masked_word_t *)&(masked->k[4]), key + 4, &trng);
    ascon_masked_word_x4_load
        ((ascon_masked_word_t *)&(masked->k[5]), key + 12, &trng);
#endif
    ascon_trng_free(&trng);
}

void ascon_masked_key_160_free(ascon_masked_key_160_t *masked)
{
    if (masked)
        ascon_clean(masked, sizeof(ascon_masked_key_160_t));
}

void ascon_masked_key_160_randomize_with_trng
    (ascon_masked_key_160_t *masked, ascon_trng_state_t *trng)
{
    int index;
#if ASCON_MASKED_KEY_SHARES == 2
    for (index = 0; index < 6; ++index) {
        ascon_masked_word_x2_randomize
            ((ascon_masked_word_t *)&(masked->k[index]),
             (ascon_masked_word_t *)&(masked->k[index]), trng);
    }
#elif ASCON_MASKED_KEY_SHARES == 3
    for (index = 0; index < 6; ++index) {
        ascon_masked_word_x2_randomize
            ((ascon_masked_word_t *)&(masked->k[index]),
             (ascon_masked_word_t *)&(masked->k[index]), trng);
    }
#else
    for (index = 0; index < 6; ++index) {
        ascon_masked_word_x2_randomize
            ((ascon_masked_word_t *)&(masked->k[index]),
             (ascon_masked_word_t *)&(masked->k[index]), trng);
    }
#endif
}

void ascon_masked_key_160_randomize(ascon_masked_key_160_t *masked)
{
    ascon_trng_state_t trng;
    ascon_trng_init(&trng);
    ascon_masked_key_160_randomize_with_trng(masked, &trng);
    ascon_trng_free(&trng);
}

void ascon_masked_key_160_extract
    (const ascon_masked_key_160_t *masked, unsigned char *key)
{
#if ASCON_MASKED_KEY_SHARES == 2
    ascon_masked_word_x2_store
        (key, (const ascon_masked_word_t *)&(masked->k[0]));
    ascon_masked_word_x2_store
        (key + 8, (const ascon_masked_word_t *)&(masked->k[1]));
    ascon_masked_word_x2_store_partial
        (key + 16, 4, (const ascon_masked_word_t *)&(masked->k[2]));
#elif ASCON_MASKED_KEY_SHARES == 3
    ascon_masked_word_x3_store
        (key, (const ascon_masked_word_t *)&(masked->k[0]));
    ascon_masked_word_x3_store
        (key + 8, (const ascon_masked_word_t *)&(masked->k[1]));
    ascon_masked_word_x3_store_partial
        (key + 16, 4, (const ascon_masked_word_t *)&(masked->k[2]));
#else
    ascon_masked_word_x4_store
        (key, (const ascon_masked_word_t *)&(masked->k[0]));
    ascon_masked_word_x4_store
        (key + 8, (const ascon_masked_word_t *)&(masked->k[1]));
    ascon_masked_word_x4_store_partial
        (key + 16, 4, (const ascon_masked_word_t *)&(masked->k[2]));
#endif
}
