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

#if defined(ASCON_MASKED_WORD_BACKEND_C64)

/* Masked word load/store functions that should be written in assembly
 * code so as to carefully mask the values with minimal leakage. */

void ascon_masked_word_x2_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    word->S[0] = random;
    word->S[1] = ascon_mask64_rotate_share1_0(random);
    word->S[2] = 0;
    word->S[3] = 0;
}

void ascon_masked_word_x2_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    word->S[0] = random ^ be_load_word64(data);
    word->S[1] = ascon_mask64_rotate_share1_0(random);
    word->S[2] = 0;
    word->S[3] = 0;
}

void ascon_masked_word_x2_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    uint64_t masked = random;
    random = ascon_mask64_rotate_share1_0(random);
    if (size >= 4) {
        masked ^= be_load_word32(data + size - 4);
        masked = rightRotate32_64(masked);
        random = rightRotate32_64(random);
        size -= 4;
    }
    if (size >= 2) {
        masked ^= be_load_word16(data + size - 2);
        masked = rightRotate16_64(masked);
        random = rightRotate16_64(random);
        size -= 2;
    }
    if (size > 0) {
        masked ^= data[0];
        masked = rightRotate8_64(masked);
        random = rightRotate8_64(random);
    }
    word->S[0] = masked;
    word->S[1] = random;
    word->S[2] = 0;
    word->S[3] = 0;
}

void ascon_masked_word_x2_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    word->S[0] = random ^ ((uint64_t)be_load_word32(data1)) << 32;
    word->S[0] ^= be_load_word32(data2);
    word->S[1] = ascon_mask64_rotate_share1_0(random);
    word->S[2] = 0;
    word->S[3] = 0;
}

void ascon_masked_word_x2_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    be_store_word64
        (data, word->S[0] ^ ascon_mask64_unrotate_share1_0(word->S[1]));
}

void ascon_masked_word_x2_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    uint64_t masked1 = word->S[0];
    uint64_t masked2 = ascon_mask64_unrotate_share1_0(word->S[1]);
    if (size >= 4) {
        masked1 = leftRotate32_64(masked1);
        masked2 = leftRotate32_64(masked2);
        be_store_word32(data, (uint32_t)(masked1 ^ masked2));
        data += 4;
        size -= 4;
    }
    if (size >= 2) {
        masked1 = leftRotate16_64(masked1);
        masked2 = leftRotate16_64(masked2);
        be_store_word16(data, (uint16_t)(masked1 ^ masked2));
        data += 2;
        size -= 2;
    }
    if (size > 0) {
        masked1 = leftRotate8_64(masked1);
        masked2 = leftRotate8_64(masked2);
        data[0] = (uint8_t)(masked1 ^ masked2);
    }
}

void ascon_masked_word_x2_mask
    (ascon_masked_word_t *word, uint64_t data, ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    word->S[0] = random ^ data;
    word->S[1] = ascon_mask64_rotate_share1_0(random);
    word->S[2] = 0;
    word->S[3] = 0;
}

uint64_t ascon_masked_word_x2_unmask(const ascon_masked_word_t *word)
{
    return word->S[0] ^ ascon_mask64_unrotate_share1_0(word->S[1]);
}

void ascon_masked_word_x2_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random = ascon_trng_generate_64(trng);
    dest->S[0] = src->S[0] ^ random;
    dest->S[1] = src->S[1] ^ ascon_mask64_rotate_share1_0(random);
}

void ascon_masked_word_x2_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src)
{
    dest->S[0] ^= src->S[0];
    dest->S[1] ^= src->S[1];
}

void ascon_masked_word_x2_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size)
{
    uint64_t mask1 = (~((uint64_t)0)) >> (size * 8U);
    uint64_t mask2 = ~mask1;
    dest->S[0] = (dest->S[0] & mask1) | (src->S[0] & mask2);
    dest->S[1] = (dest->S[1] & ascon_mask64_rotate_share1_0(mask1)) |
                 ( src->S[1] & ascon_mask64_rotate_share1_0(mask2));
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

void ascon_masked_word_x3_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ random2 ^ be_load_word64(data);
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = 0;
}

void ascon_masked_word_x3_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t masked = random1;
    random1 = ascon_mask64_rotate_share1_0(random1);
    if (size >= 4) {
        masked ^= be_load_word32(data + size - 4);
        masked = rightRotate32_64(masked);
        random1 = rightRotate32_64(random1);
        size -= 4;
    }
    if (size >= 2) {
        masked ^= be_load_word16(data + size - 2);
        masked = rightRotate16_64(masked);
        random1 = rightRotate16_64(random1);
        size -= 2;
    }
    if (size > 0) {
        masked ^= data[0];
        masked = rightRotate8_64(masked);
        random1 = rightRotate8_64(random1);
    }
    word->S[0] = masked ^ random2;
    word->S[1] = random1;
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = 0;
}

void ascon_masked_word_x3_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ ((uint64_t)be_load_word32(data1)) << 32;
    word->S[0] ^= random2 ^ be_load_word32(data2);
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = 0;
}

void ascon_masked_word_x3_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    be_store_word64
        (data, word->S[0] ^ ascon_mask64_unrotate_share1_0(word->S[1])
                          ^ ascon_mask64_unrotate_share2_0(word->S[2]));
}

void ascon_masked_word_x3_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    uint64_t masked1 = word->S[0];
    uint64_t masked2 = ascon_mask64_unrotate_share1_0(word->S[1]);
    uint64_t masked3 = ascon_mask64_unrotate_share2_0(word->S[2]);
    if (size >= 4) {
        masked1 = leftRotate32_64(masked1);
        masked2 = leftRotate32_64(masked2);
        masked3 = leftRotate32_64(masked3);
        be_store_word32(data, (uint32_t)(masked1 ^ masked2 ^ masked3));
        data += 4;
        size -= 4;
    }
    if (size >= 2) {
        masked1 = leftRotate16_64(masked1);
        masked2 = leftRotate16_64(masked2);
        masked3 = leftRotate16_64(masked3);
        be_store_word16(data, (uint16_t)(masked1 ^ masked2 ^ masked3));
        data += 2;
        size -= 2;
    }
    if (size > 0) {
        masked1 = leftRotate8_64(masked1);
        masked2 = leftRotate8_64(masked2);
        masked3 = leftRotate8_64(masked3);
        data[0] = (uint8_t)(masked1 ^ masked2 ^ masked3);
    }
}

void ascon_masked_word_x3_mask
    (ascon_masked_word_t *word, uint64_t data, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ random2 ^ data;
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = 0;
}

uint64_t ascon_masked_word_x3_unmask(const ascon_masked_word_t *word)
{
    return word->S[0] ^ ascon_mask64_unrotate_share1_0(word->S[1]) ^
           ascon_mask64_unrotate_share2_0(word->S[2]);
}

void ascon_masked_word_x3_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    dest->S[0] = src->S[0] ^ random1 ^ random2;
    dest->S[1] = src->S[1] ^ ascon_mask64_rotate_share1_0(random1);
    dest->S[2] = src->S[2] ^ ascon_mask64_rotate_share2_0(random2);
}

void ascon_masked_word_x3_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src)
{
    dest->S[0] ^= src->S[0];
    dest->S[1] ^= src->S[1];
    dest->S[2] ^= src->S[2];
}

void ascon_masked_word_x3_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size)
{
    uint64_t mask1 = (~((uint64_t)0)) >> (size * 8U);
    uint64_t mask2 = ~mask1;
    dest->S[0] = (dest->S[0] & mask1) | (src->S[0] & mask2);
    dest->S[1] = (dest->S[1] & ascon_mask64_rotate_share1_0(mask1)) |
                 ( src->S[1] & ascon_mask64_rotate_share1_0(mask2));
    dest->S[2] = (dest->S[2] & ascon_mask64_rotate_share2_0(mask1)) |
                 ( src->S[2] & ascon_mask64_rotate_share2_0(mask2));
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
    dest->S[0] = (random1 ^ random2 ^ src->S[0]) ^
                 ascon_mask64_unrotate_share3_0(src->S[3]);
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

void ascon_masked_word_x4_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ random2 ^ random3 ^ be_load_word64(data);
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = ascon_mask64_rotate_share3_0(random3);
}

void ascon_masked_word_x4_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    uint64_t masked = random1;
    random1 = ascon_mask64_rotate_share1_0(random1);
    if (size >= 4) {
        masked ^= be_load_word32(data + size - 4);
        masked = rightRotate32_64(masked);
        random1 = rightRotate32_64(random1);
        size -= 4;
    }
    if (size >= 2) {
        masked ^= be_load_word16(data + size - 2);
        masked = rightRotate16_64(masked);
        random1 = rightRotate16_64(random1);
        size -= 2;
    }
    if (size > 0) {
        masked ^= data[0];
        masked = rightRotate8_64(masked);
        random1 = rightRotate8_64(random1);
    }
    word->S[0] = masked ^ random2 ^ random3;
    word->S[1] = random1;
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = ascon_mask64_rotate_share3_0(random3);
}

void ascon_masked_word_x4_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ random2 ^ ((uint64_t)be_load_word32(data1)) << 32;
    word->S[0] ^= random3 ^ be_load_word32(data2);
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = ascon_mask64_rotate_share3_0(random3);
}

void ascon_masked_word_x4_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    be_store_word64
        (data, word->S[0] ^ ascon_mask64_unrotate_share1_0(word->S[1])
                          ^ ascon_mask64_unrotate_share2_0(word->S[2])
                          ^ ascon_mask64_unrotate_share3_0(word->S[3]));
}

void ascon_masked_word_x4_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    uint64_t masked1 = word->S[0];
    uint64_t masked2 = ascon_mask64_unrotate_share1_0(word->S[1]);
    uint64_t masked3 = ascon_mask64_unrotate_share2_0(word->S[2]);
    uint64_t masked4 = ascon_mask64_unrotate_share3_0(word->S[3]);
    if (size >= 4) {
        masked1 = leftRotate32_64(masked1);
        masked2 = leftRotate32_64(masked2);
        masked3 = leftRotate32_64(masked3);
        masked4 = leftRotate32_64(masked4);
        be_store_word32(data, (uint32_t)(masked1 ^ masked2 ^ masked3 ^ masked4));
        data += 4;
        size -= 4;
    }
    if (size >= 2) {
        masked1 = leftRotate16_64(masked1);
        masked2 = leftRotate16_64(masked2);
        masked3 = leftRotate16_64(masked3);
        masked4 = leftRotate16_64(masked4);
        be_store_word16(data, (uint16_t)(masked1 ^ masked2 ^ masked3 ^ masked4));
        data += 2;
        size -= 2;
    }
    if (size > 0) {
        masked1 = leftRotate8_64(masked1);
        masked2 = leftRotate8_64(masked2);
        masked3 = leftRotate8_64(masked3);
        masked4 = leftRotate8_64(masked4);
        data[0] = (uint8_t)(masked1 ^ masked2 ^ masked3 ^ masked4);
    }
}

void ascon_masked_word_x4_mask
    (ascon_masked_word_t *word, uint64_t data, ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    word->S[0] = random1 ^ random2 ^ random3 ^ data;
    word->S[1] = ascon_mask64_rotate_share1_0(random1);
    word->S[2] = ascon_mask64_rotate_share2_0(random2);
    word->S[3] = ascon_mask64_rotate_share3_0(random3);
}

uint64_t ascon_masked_word_x4_unmask(const ascon_masked_word_t *word)
{
    return word->S[0] ^ ascon_mask64_unrotate_share1_0(word->S[1]) ^
           ascon_mask64_unrotate_share2_0(word->S[2]) ^
           ascon_mask64_unrotate_share3_0(word->S[3]);
}

void ascon_masked_word_x4_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint64_t random1 = ascon_trng_generate_64(trng);
    uint64_t random2 = ascon_trng_generate_64(trng);
    uint64_t random3 = ascon_trng_generate_64(trng);
    dest->S[0] = src->S[0] ^ random1 ^ random2 ^ random3;
    dest->S[1] = src->S[1] ^ ascon_mask64_rotate_share1_0(random1);
    dest->S[2] = src->S[2] ^ ascon_mask64_rotate_share2_0(random2);
    dest->S[3] = src->S[3] ^ ascon_mask64_rotate_share3_0(random3);
}

void ascon_masked_word_x4_xor
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src)
{
    dest->S[0] ^= src->S[0];
    dest->S[1] ^= src->S[1];
    dest->S[2] ^= src->S[2];
    dest->S[3] ^= src->S[3];
}

void ascon_masked_word_x4_replace
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src, unsigned size)
{
    uint64_t mask1 = (~((uint64_t)0)) >> (size * 8U);
    uint64_t mask2 = ~mask1;
    dest->S[0] = (dest->S[0] & mask1) | (src->S[0] & mask2);
    dest->S[1] = (dest->S[1] & ascon_mask64_rotate_share1_0(mask1)) |
                 ( src->S[1] & ascon_mask64_rotate_share1_0(mask2));
    dest->S[2] = (dest->S[2] & ascon_mask64_rotate_share2_0(mask1)) |
                 ( src->S[2] & ascon_mask64_rotate_share2_0(mask2));
    dest->S[3] = (dest->S[3] & ascon_mask64_rotate_share3_0(mask1)) |
                 ( src->S[3] & ascon_mask64_rotate_share3_0(mask2));
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

void ascon_masked_word_pad(ascon_masked_word_t *word, unsigned offset)
{
    word->S[0] ^= (0x8000000000000000ULL >> (offset * 8U));
}

void ascon_masked_word_separator(ascon_masked_word_t *word)
{
    word->S[0] ^= 1;
}

#endif /* ASCON_MASKED_WORD_BACKEND_C64 */
