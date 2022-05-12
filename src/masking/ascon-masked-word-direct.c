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

#if defined(ASCON_MASKED_WORD_BACKEND_DIRECT_XOR)

/* Direct XOR of the key and plaintext data with the random data.
 * No rotation of the shares is performed.  This is used by AVR. */

typedef union { uint64_t w; uint8_t b[8]; } random_bytes_t;

void ascon_masked_word_x2_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[0] = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index)
        word->B[index + 8] = word->B[index];
#if ASCON_MASKED_MAX_SHARES >= 3
    word->S[2] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x2_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index)
        word->B[index] = data[index] ^ word->B[index + 8];
#if ASCON_MASKED_MAX_SHARES >= 3
    word->S[2] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x2_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    for (index = 0; index < size; ++index)
        word->B[index] = data[index] ^ word->B[index + 8];
    for (; index < 8; ++index)
        word->B[index] = word->B[index + 8];
#if ASCON_MASKED_MAX_SHARES >= 3
    word->S[2] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x2_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    for (index = 0; index < 4; ++index) {
        word->B[index]     = data1[index] ^ word->B[index + 8];
        word->B[index + 4] = data2[index] ^ word->B[index + 12];
    }
#if ASCON_MASKED_MAX_SHARES >= 3
    word->S[2] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x2_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    unsigned index;
    for (index = 0; index < 8; ++index)
        data[index] = word->B[index] ^ word->B[index + 8];
}

void ascon_masked_word_x2_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    unsigned index;
    for (index = 0; index < size; ++index)
        data[index] = word->B[index] ^ word->B[index + 8];
}

void ascon_masked_word_x2_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random;
    unsigned index;
    random.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index]     = src->B[index] ^ random.b[index];
        dest->B[index + 8] = src->B[index + 8] ^ random.b[index];
    }
}

void ascon_masked_word_x2_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src)
{
    unsigned index;
    for (index = 0; index < 8; ++index) {
        dest->B[index]     ^= src->B[index];
        dest->B[index + 8] ^= src->B[index + 8];
    }
}

void ascon_masked_word_x2_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size)
{
    unsigned index;
    for (index = 0; index < size; ++index) {
        dest->B[index]     = src->B[index];
        dest->B[index + 8] = src->B[index + 8];
    }
}

#if ASCON_MASKED_MAX_SHARES >= 3

void ascon_masked_word_x2_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random;
    unsigned index;
    random.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index] = random.b[index] ^ src->B[index];
        dest->B[index + 8] =
            (random.b[index] ^ src->B[index + 8]) ^ src->B[index + 16];
    }
    dest->S[2] = 0;
#if ASCON_MASKED_MAX_SHARES >= 4
    dest->S[3] = 0;
#endif
}

#endif /* ASCON_MASKED_MAX_SHARES >= 3 */

#if ASCON_MASKED_MAX_SHARES >= 4

void ascon_masked_word_x2_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random;
    unsigned index;
    random.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index] =
            (random.b[index] ^ src->B[index]) ^ src->B[index + 16];
        dest->B[index + 8] =
            (random.b[index] ^ src->B[index + 8]) ^ src->B[index + 24];
    }
    dest->S[2] = 0;
    dest->S[3] = 0;
}

#endif /* ASCON_MASKED_MAX_SHARES >= 4 */

#if ASCON_MASKED_MAX_SHARES >= 3

void ascon_masked_word_x3_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index)
        word->B[index] = word->B[index + 8] ^ word->B[index + 16];
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x3_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        word->B[index] =
            (word->B[index + 8] ^ data[index]) ^ word->B[index + 16];
    }
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x3_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    for (index = 0; index < size; ++index) {
        word->B[index] =
            (word->B[index + 8] ^ data[index]) ^ word->B[index + 16];
    }
    for (; index < 8; ++index)
        word->B[index] = word->B[index + 8] ^ word->B[index + 16];
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x3_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    for (index = 0; index < 4; ++index) {
        word->B[index] =
            (word->B[index + 8] ^ data1[index]) ^ word->B[index + 16];
        word->B[index + 4] =
            (word->B[index + 12] ^ data2[index]) ^ word->B[index + 20];
    }
#if ASCON_MASKED_MAX_SHARES >= 4
    word->S[3] = 0;
#endif
}

void ascon_masked_word_x3_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    unsigned index;
    for (index = 0; index < 8; ++index)
        data[index] = word->B[index] ^ word->B[index + 8] ^ word->B[index + 16];
}

void ascon_masked_word_x3_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    unsigned index;
    for (index = 0; index < size; ++index)
        data[index] = word->B[index] ^ word->B[index + 8] ^ word->B[index + 16];
}

void ascon_masked_word_x3_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random1;
    random_bytes_t random2;
    unsigned index;
    random1.w = ascon_trng_generate_64(trng);
    random2.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index]
            = (random1.b[index] ^ src->B[index]) ^ random2.b[index];
        dest->B[index + 8]  = src->B[index + 8] ^ random1.b[index];
        dest->B[index + 16] = src->B[index + 16] ^ random2.b[index];
    }
}

void ascon_masked_word_x3_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src)
{
    unsigned index;
    for (index = 0; index < 8; ++index) {
        dest->B[index]      ^= src->B[index];
        dest->B[index + 8]  ^= src->B[index + 8];
        dest->B[index + 16] ^= src->B[index + 16];
    }
}

void ascon_masked_word_x3_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size)
{
    unsigned index;
    for (index = 0; index < size; ++index) {
        dest->B[index]      = src->B[index];
        dest->B[index + 8]  = src->B[index + 8];
        dest->B[index + 16] = src->B[index + 16];
    }
}

void ascon_masked_word_x3_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random1;
    random_bytes_t random2;
    unsigned index;
    random1.w = ascon_trng_generate_64(trng);
    random2.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index] = (random1.b[index] ^ src->B[index]) ^ random2.b[index];
        dest->B[index + 8]  = (random1.b[index] ^ src->B[index + 8]);
        dest->B[index + 16] = random2.b[index];
    }
#if ASCON_MASKED_MAX_SHARES >= 4
    dest->S[3] = 0;
#endif
}

#if ASCON_MASKED_MAX_SHARES >= 4

void ascon_masked_word_x3_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random1;
    random_bytes_t random2;
    unsigned index;
    random1.w = ascon_trng_generate_64(trng);
    random2.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index] =
            ((random1.b[index] ^ src->B[index]) ^ random2.b[index]) ^
            src->B[index + 24];
        dest->B[index + 8]  = (random1.b[index] ^ src->B[index + 8]);
        dest->B[index + 16] = (random2.b[index] ^ src->B[index + 16]);
    }
    dest->S[3] = 0;
}

#endif /* ASCON_MASKED_MAX_SHARES >= 4 */

#endif /* ASCON_MASKED_MAX_SHARES >= 3 */

#if ASCON_MASKED_MAX_SHARES >= 4

void ascon_masked_word_x4_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    word->S[3] = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        word->B[index] =
            word->B[index + 8] ^ word->B[index + 16] ^ word->B[index + 24];
    }
}

void ascon_masked_word_x4_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    word->S[3] = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        word->B[index] =
            (word->B[index + 8] ^ data[index]) ^ word->B[index + 16] ^
            word->B[index + 24];
    }
}

void ascon_masked_word_x4_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    word->S[3] = ascon_trng_generate_64(trng);
    for (index = 0; index < size; ++index) {
        word->B[index] =
            (word->B[index + 8] ^ data[index]) ^ word->B[index + 16] ^
            word->B[index + 24];
    }
    for (; index < 8; ++index) {
        word->B[index] =
            word->B[index + 8] ^ word->B[index + 16] ^ word->B[index + 24];
    }
}

void ascon_masked_word_x4_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    unsigned index;
    word->S[1] = ascon_trng_generate_64(trng);
    word->S[2] = ascon_trng_generate_64(trng);
    word->S[3] = ascon_trng_generate_64(trng);
    for (index = 0; index < 4; ++index) {
        word->B[index] =
            (word->B[index + 8] ^ data1[index]) ^ word->B[index + 16] ^
            word->B[index + 24];
        word->B[index + 4] =
            (word->B[index + 12] ^ data2[index]) ^ word->B[index + 20] ^
            word->B[index + 28];
    }
}

void ascon_masked_word_x4_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    unsigned index;
    for (index = 0; index < 8; ++index) {
        data[index] =
            word->B[index] ^ word->B[index + 8] ^
            word->B[index + 16] ^ word->B[index + 24];
    }
}

void ascon_masked_word_x4_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    unsigned index;
    for (index = 0; index < size; ++index) {
        data[index] =
            word->B[index] ^ word->B[index + 8] ^
            word->B[index + 16] ^ word->B[index + 24];
    }
}

void ascon_masked_word_x4_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random1;
    random_bytes_t random2;
    random_bytes_t random3;
    unsigned index;
    random1.w = ascon_trng_generate_64(trng);
    random2.w = ascon_trng_generate_64(trng);
    random3.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index]
            = (random1.b[index] ^ src->B[index]) ^ random2.b[index] ^
              random3.b[index];
        dest->B[index + 8]  = src->B[index + 8] ^ random1.b[index];
        dest->B[index + 16] = src->B[index + 16] ^ random2.b[index];
        dest->B[index + 24] = src->B[index + 24] ^ random3.b[index];
    }
}

void ascon_masked_word_x4_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src)
{
    unsigned index;
    for (index = 0; index < 8; ++index) {
        dest->B[index]      ^= src->B[index];
        dest->B[index + 8]  ^= src->B[index + 8];
        dest->B[index + 16] ^= src->B[index + 16];
        dest->B[index + 24] ^= src->B[index + 24];
    }
}

void ascon_masked_word_x4_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size)
{
    unsigned index;
    for (index = 0; index < size; ++index) {
        dest->B[index]      = src->B[index];
        dest->B[index + 8]  = src->B[index + 8];
        dest->B[index + 16] = src->B[index + 16];
        dest->B[index + 24] = src->B[index + 24];
    }
}

void ascon_masked_word_x4_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random1;
    random_bytes_t random2;
    random_bytes_t random3;
    unsigned index;
    random1.w = ascon_trng_generate_64(trng);
    random2.w = ascon_trng_generate_64(trng);
    random3.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index] =
            (random1.b[index] ^ src->B[index]) ^
            random2.b[index] ^ random3.b[index];
        dest->B[index + 8]  = (random1.b[index] ^ src->B[index + 8]);
        dest->B[index + 16] = random2.b[index];
        dest->B[index + 24] = random3.b[index];
    }
}

void ascon_masked_word_x4_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    random_bytes_t random1;
    random_bytes_t random2;
    random_bytes_t random3;
    unsigned index;
    random1.w = ascon_trng_generate_64(trng);
    random2.w = ascon_trng_generate_64(trng);
    random3.w = ascon_trng_generate_64(trng);
    for (index = 0; index < 8; ++index) {
        dest->B[index] =
            (random1.b[index] ^ src->B[index]) ^
            random2.b[index] ^ random3.b[index];
        dest->B[index + 8]  = (random1.b[index] ^ src->B[index + 8]);
        dest->B[index + 16] = (random2.b[index] ^ src->B[index + 16]);
        dest->B[index + 24] = random3.b[index];
    }
}

#endif /* ASCON_MASKED_MAX_SHARES >= 4 */

void ascon_masked_word_pad(ascon_masked_word_t *word, unsigned offset)
{
    word->B[offset] ^= 0x80;
}

void ascon_masked_word_separator(ascon_masked_word_t *word)
{
    word->B[7] ^= 1;
}

#endif /* ASCON_MASKED_WORD_BACKEND_DIRECT_XOR */
