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

#if defined(ASCON_MASKED_WORD_BACKEND_C32)

/* Masked word load/store functions that should be written in assembly
 * code so as to carefully mask the values with minimal leakage. */

/** @cond ascon_masked_bit_separation */

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define ascon_bit_permute_step(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/* Separates a 32-bit word into two 16-bit halves with all the even
 * bits in the bottom half and all the odd bits in the top half.
 *
 * Permutation generated with "http://programming.sirrida.de/calcperm.php"
 *
 * P = [0 16 1 17 2 18 3 19 4 20 5 21 6 22 7 23 8 24
 *      9 25 10 26 11 27 12 28 13 29 14 30 15 31]
 */
#define ascon_separate(x) \
    do { \
        ascon_bit_permute_step((x), 0x22222222, 1); \
        ascon_bit_permute_step((x), 0x0c0c0c0c, 2); \
        ascon_bit_permute_step((x), 0x00f000f0, 4); \
        ascon_bit_permute_step((x), 0x0000ff00, 8); \
    } while (0)
#define ascon_combine(x) \
    do { \
        ascon_bit_permute_step((x), 0x0000aaaa, 15); \
        ascon_bit_permute_step((x), 0x0000cccc, 14); \
        ascon_bit_permute_step((x), 0x0000f0f0, 12); \
        ascon_bit_permute_step((x), 0x0000ff00, 8); \
    } while (0)

/** @endcond */

void ascon_masked_word_x2_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    word->W[0] = random1a;
    word->W[1] = random1b;
    word->W[2] = ascon_mask32_rotate_share1_0(random1a);
    word->W[3] = ascon_mask32_rotate_share1_0(random1b);
#if ASCON_MASKED_MAX_SHARES >= 3
    word->W[4] = 0;
    word->W[5] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x2_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t high = random1a ^ be_load_word32(data);
    uint32_t low  = random1b ^ be_load_word32(data + 4);
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = (high << 16) | (low & 0x0000FFFFU);
    word->W[1] = (high & 0xFFFF0000U) | (low >> 16);
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
#if ASCON_MASKED_MAX_SHARES >= 3
    word->W[4] = 0;
    word->W[5] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x2_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    uint32_t high, low;
    uint32_t random1a, random1b;

    /* Load as a 64-bit word and mask with the first share */
    uint64_t random = ascon_trng_generate_64(trng);
    uint64_t masked = random;
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

    /* Slice the shares and store to the masked word */
    high = (uint32_t)(masked >> 32);
    low  = (uint32_t)masked;
    random1a = (uint32_t)(random >> 32);
    random1b = (uint32_t)random;
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = (high << 16) | (low & 0x0000FFFFU);
    word->W[1] = (high & 0xFFFF0000U) | (low >> 16);
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
#if ASCON_MASKED_MAX_SHARES >= 3
    word->W[4] = 0;
    word->W[5] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x2_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t high = random1a ^ be_load_word32(data1);
    uint32_t low  = random1b ^ be_load_word32(data2);
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = (high << 16) | (low & 0x0000FFFFU);
    word->W[1] = (high & 0xFFFF0000U) | (low >> 16);
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
#if ASCON_MASKED_MAX_SHARES >= 3
    word->W[4] = 0;
    word->W[5] = 0;
#endif
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x2_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    uint32_t high1 = (word->W[0] >> 16) | (word->W[1] & 0xFFFF0000U);
    uint32_t low1  = (word->W[0] & 0x0000FFFFU) | (word->W[1] << 16);
    uint32_t high2 = ascon_mask32_unrotate_share1_0(word->W[2]);
    uint32_t low2  = ascon_mask32_unrotate_share1_0(word->W[3]);
    uint32_t high3 = (high2 >> 16) | (low2 & 0xFFFF0000U);
    uint32_t low3  = (high2 & 0x0000FFFFU) | (low2 << 16);
    ascon_combine(high1);
    ascon_combine(low1);
    ascon_combine(high3);
    ascon_combine(low3);
    be_store_word32(data, high1 ^ high3);
    be_store_word32(data + 4, low1 ^ low3);
}

void ascon_masked_word_x2_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    uint64_t masked1, masked2;
    uint32_t high1, low1;
    uint32_t high2, low2;
    uint32_t high3, low3;

    /* Rearrange the bits while still in masked form */
    high1 = (word->W[0] >> 16) | (word->W[1] & 0xFFFF0000U);
    low1  = (word->W[0] & 0x0000FFFFU) | (word->W[1] << 16);
    high2 = ascon_mask32_unrotate_share1_0(word->W[2]);
    low2  = ascon_mask32_unrotate_share1_0(word->W[3]);
    high3 = (high2 >> 16) | (low2 & 0xFFFF0000U);
    low3  = (high2 & 0x0000FFFFU) | (low2 << 16);
    ascon_combine(high1);
    ascon_combine(low1);
    ascon_combine(high3);
    ascon_combine(low3);

    /* Convert to 64-bit, unmask, and store the bytes */
    masked1 = (((uint64_t)high1) << 32) | low1;
    masked2 = (((uint64_t)high3) << 32) | low3;
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

void ascon_masked_word_x2_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    dest->W[0] = src->W[0] ^ random1a;
    dest->W[1] = src->W[1] ^ random1b;
    dest->W[2] = src->W[2] ^ ascon_mask32_rotate_share1_0(random1a);
    dest->W[3] = src->W[3] ^ ascon_mask32_rotate_share1_0(random1b);
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
    uint32_t mask1 = (~((uint32_t)0)) >> (size * 4U);
    uint32_t mask2 = ~mask1;
    dest->W[0] = (dest->W[0] & mask1) | (src->W[0] & mask2);
    dest->W[1] = (dest->W[1] & mask1) | (src->W[1] & mask2);
    mask1 = ascon_mask32_rotate_share1_0(mask1);
    mask2 = ascon_mask32_rotate_share1_0(mask2);
    dest->W[2] = (dest->W[2] & mask1) | (src->W[2] & mask2);
    dest->W[3] = (dest->W[3] & mask1) | (src->W[3] & mask2);
}

#if ASCON_MASKED_MAX_SHARES >= 3

void ascon_masked_word_x2_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    dest->W[0] = random1a ^ src->W[0];
    dest->W[1] = random1b ^ src->W[1];
    dest->W[2] = (ascon_mask32_rotate_share1_0(random1a) ^ src->W[2]) ^
                 ascon_mask32_unrotate_share2_1(src->W[4]);
    dest->W[3] = (ascon_mask32_rotate_share1_0(random1b) ^ src->W[3]) ^
                 ascon_mask32_unrotate_share2_1(src->W[5]);
    dest->W[4] = 0;
    dest->W[5] = 0;
#if ASCON_MASKED_MAX_SHARES >= 4
    dest->W[6] = 0;
    dest->W[7] = 0;
#endif
}

#endif /* ASCON_MASKED_MAX_SHARES >= 3 */

#if ASCON_MASKED_MAX_SHARES >= 4

void ascon_masked_word_x2_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    dest->W[0] = random1a ^ src->W[0] ^
                 ascon_mask32_unrotate_share2_0(src->W[4]);
    dest->W[1] = random1b ^ src->W[1] ^
                 ascon_mask32_unrotate_share2_0(src->W[5]);
    dest->W[2] = (ascon_mask32_rotate_share1_0(random1a) ^ src->W[2]) ^
                 ascon_mask32_unrotate_share3_1(src->W[6]);
    dest->W[3] = (ascon_mask32_rotate_share1_0(random1b) ^ src->W[3]) ^
                 ascon_mask32_unrotate_share3_1(src->W[7]);
    dest->W[4] = 0;
    dest->W[5] = 0;
    dest->W[6] = 0;
    dest->W[7] = 0;
}

#endif /* ASCON_MASKED_MAX_SHARES >= 4 */

#if ASCON_MASKED_MAX_SHARES >= 3

void ascon_masked_word_x3_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    word->W[0] = random1a ^ random2a;
    word->W[1] = random1b ^ random2b;
    word->W[2] = ascon_mask32_rotate_share1_0(random1a);
    word->W[3] = ascon_mask32_rotate_share1_0(random1b);
    word->W[4] = ascon_mask32_rotate_share2_0(random2a);
    word->W[5] = ascon_mask32_rotate_share2_0(random2b);
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x3_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t high = random1a ^ be_load_word32(data);
    uint32_t low  = random1b ^ be_load_word32(data + 4);
    word->W[4] = ascon_trng_generate_32(trng); /* random2a */
    word->W[5] = ascon_trng_generate_32(trng); /* random2b */
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = ((high << 16) | (low & 0x0000FFFFU)) ^
                 ascon_mask32_unrotate_share2_0(word->W[4]);
    word->W[1] = ((high & 0xFFFF0000U) | (low >> 16)) ^
                 ascon_mask32_unrotate_share2_0(word->W[5]);
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x3_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    uint32_t high, low;
    uint32_t random1a, random1b;
    uint32_t random2a, random2b;

    /* Load as a 64-bit word and mask with the first share */
    uint64_t random = ascon_trng_generate_64(trng);
    uint64_t masked = random;
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

    /* Slice the shares and store to the masked word */
    random2a = ascon_trng_generate_32(trng);
    random2b = ascon_trng_generate_32(trng);
    high = (uint32_t)(masked >> 32);
    low  = (uint32_t)masked;
    random1a = (uint32_t)(random >> 32);
    random1b = (uint32_t)random;
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = ((high << 16) | (low & 0x0000FFFFU)) ^ random2a;
    word->W[1] = ((high & 0xFFFF0000U) | (low >> 16)) ^ random2b;
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
    word->W[4] = ascon_mask32_rotate_share2_0(random2a);
    word->W[5] = ascon_mask32_rotate_share2_0(random2b);
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x3_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t high = random1a ^ be_load_word32(data1);
    uint32_t low  = random1b ^ be_load_word32(data2);
    word->W[4] = ascon_trng_generate_32(trng); /* random2a */
    word->W[5] = ascon_trng_generate_32(trng); /* random2b */
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = ((high << 16) | (low & 0x0000FFFFU)) ^
                 ascon_mask32_unrotate_share2_0(word->W[4]);
    word->W[1] = ((high & 0xFFFF0000U) | (low >> 16)) ^
                 ascon_mask32_unrotate_share2_0(word->W[5]);
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
#if ASCON_MASKED_MAX_SHARES >= 4
    word->W[6] = 0;
    word->W[7] = 0;
#endif
}

void ascon_masked_word_x3_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    uint32_t high1 = (word->W[0] >> 16) | (word->W[1] & 0xFFFF0000U);
    uint32_t low1  = (word->W[0] & 0x0000FFFFU) | (word->W[1] << 16);
    uint32_t high2 = ascon_mask32_unrotate_share1_0(word->W[2]) ^
                     ascon_mask32_unrotate_share2_0(word->W[4]);
    uint32_t low2  = ascon_mask32_unrotate_share1_0(word->W[3]) ^
                     ascon_mask32_unrotate_share2_0(word->W[5]);
    uint32_t high3 = (high2 >> 16) | (low2 & 0xFFFF0000U);
    uint32_t low3  = (high2 & 0x0000FFFFU) | (low2 << 16);
    ascon_combine(high1);
    ascon_combine(low1);
    ascon_combine(high3);
    ascon_combine(low3);
    be_store_word32(data, high1 ^ high3);
    be_store_word32(data + 4, low1 ^ low3);
}

void ascon_masked_word_x3_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    uint64_t masked1, masked2;
    uint32_t high1, low1;
    uint32_t high2, low2;
    uint32_t high3, low3;

    /* Rearrange the bits while still in masked form */
    high1 = (word->W[0] >> 16) | (word->W[1] & 0xFFFF0000U);
    low1  = (word->W[0] & 0x0000FFFFU) | (word->W[1] << 16);
    high2 = ascon_mask32_unrotate_share1_0(word->W[2]) ^
            ascon_mask32_unrotate_share2_0(word->W[4]);
    low2  = ascon_mask32_unrotate_share1_0(word->W[3]) ^
            ascon_mask32_unrotate_share2_0(word->W[5]);
    high3 = (high2 >> 16) | (low2 & 0xFFFF0000U);
    low3  = (high2 & 0x0000FFFFU) | (low2 << 16);
    ascon_combine(high1);
    ascon_combine(low1);
    ascon_combine(high3);
    ascon_combine(low3);

    /* Convert to 64-bit, unmask, and store the bytes */
    masked1 = (((uint64_t)high1) << 32) | low1;
    masked2 = (((uint64_t)high3) << 32) | low3;
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

void ascon_masked_word_x3_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    dest->W[0] = src->W[0] ^ random1a ^ random2a;
    dest->W[1] = src->W[1] ^ random1b ^ random2b;
    dest->W[2] = src->W[2] ^ ascon_mask32_rotate_share1_0(random1a);
    dest->W[3] = src->W[3] ^ ascon_mask32_rotate_share1_0(random1b);
    dest->W[4] = src->W[4] ^ ascon_mask32_rotate_share2_0(random2a);
    dest->W[5] = src->W[5] ^ ascon_mask32_rotate_share2_0(random2b);
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
    uint32_t mask1 = (~((uint32_t)0)) >> (size * 4U);
    uint32_t mask2 = ~mask1;
    dest->W[0] = (dest->W[0] & mask1) | (src->W[0] & mask2);
    dest->W[1] = (dest->W[1] & mask1) | (src->W[1] & mask2);
    mask1 = ascon_mask32_rotate_share1_0(mask1);
    mask2 = ascon_mask32_rotate_share1_0(mask2);
    dest->W[2] = (dest->W[2] & mask1) | (src->W[2] & mask2);
    dest->W[3] = (dest->W[3] & mask1) | (src->W[3] & mask2);
    mask1 = ascon_mask32_rotate_share1_0(mask1);
    mask2 = ascon_mask32_rotate_share1_0(mask2);
    dest->W[4] = (dest->W[4] & mask1) | (src->W[4] & mask2);
    dest->W[5] = (dest->W[5] & mask1) | (src->W[5] & mask2);
}

void ascon_masked_word_x3_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    dest->W[0] = random1a ^ random2a ^ src->W[0];
    dest->W[1] = random1b ^ random2b ^ src->W[1];
    dest->W[2] = ascon_mask32_rotate_share1_0(random1a) ^ src->W[2];
    dest->W[3] = ascon_mask32_rotate_share1_0(random1b) ^ src->W[3];
    dest->W[4] = ascon_mask32_rotate_share2_0(random2a);
    dest->W[5] = ascon_mask32_rotate_share2_0(random2b);
#if ASCON_MASKED_MAX_SHARES >= 4
    dest->W[6] = 0;
    dest->W[7] = 0;
#endif
}

#if ASCON_MASKED_MAX_SHARES >= 4

void ascon_masked_word_x3_from_x4
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    dest->W[0] = random1a ^ random2a ^ src->W[0] ^
                 ascon_mask32_unrotate_share3_0(src->W[6]);
    dest->W[1] = random1b ^ random2b ^ src->W[1] ^
                 ascon_mask32_unrotate_share3_0(src->W[7]);
    dest->W[2] = ascon_mask32_rotate_share1_0(random1a) ^ src->W[2];
    dest->W[3] = ascon_mask32_rotate_share1_0(random1b) ^ src->W[3];
    dest->W[4] = ascon_mask32_rotate_share2_0(random2a) ^ src->W[4];
    dest->W[5] = ascon_mask32_rotate_share2_0(random2b) ^ src->W[5];
    dest->W[6] = 0;
    dest->W[7] = 0;
}

#endif /* ASCON_MASKED_MAX_SHARES >= 4 */

#endif /* ASCON_MASKED_MAX_SHARES >= 3 */

#if ASCON_MASKED_MAX_SHARES >= 4

void ascon_masked_word_x4_zero
    (ascon_masked_word_t *word, ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    uint32_t random3a = ascon_trng_generate_32(trng);
    uint32_t random3b = ascon_trng_generate_32(trng);
    word->W[0] = random1a ^ random2a ^ random3a;
    word->W[1] = random1b ^ random2b ^ random3b;
    word->W[2] = ascon_mask32_rotate_share1_0(random1a);
    word->W[3] = ascon_mask32_rotate_share1_0(random1b);
    word->W[4] = ascon_mask32_rotate_share2_0(random2a);
    word->W[5] = ascon_mask32_rotate_share2_0(random2b);
    word->W[6] = ascon_mask32_rotate_share3_0(random3a);
    word->W[7] = ascon_mask32_rotate_share3_0(random3b);
}

void ascon_masked_word_x4_load
    (ascon_masked_word_t *word, const uint8_t *data,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t high = random1a ^ be_load_word32(data);
    uint32_t low  = random1b ^ be_load_word32(data + 4);
    word->W[4] = ascon_trng_generate_32(trng); /* random2a */
    word->W[5] = ascon_trng_generate_32(trng); /* random2b */
    word->W[6] = ascon_trng_generate_32(trng); /* random3a */
    word->W[7] = ascon_trng_generate_32(trng); /* random3b */
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = ((high << 16) | (low & 0x0000FFFFU)) ^
                 ascon_mask32_unrotate_share2_0(word->W[4]) ^
                 ascon_mask32_unrotate_share3_0(word->W[6]);
    word->W[1] = ((high & 0xFFFF0000U) | (low >> 16)) ^
                 ascon_mask32_unrotate_share2_0(word->W[5]) ^
                 ascon_mask32_unrotate_share3_0(word->W[7]);
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
}

void ascon_masked_word_x4_load_partial
    (ascon_masked_word_t *word, const uint8_t *data, unsigned size,
     ascon_trng_state_t *trng)
{
    uint32_t high, low;
    uint32_t random1a, random1b;
    uint32_t random2a, random2b;
    uint32_t random3a, random3b;

    /* Load as a 64-bit word and mask with the first share */
    uint64_t random = ascon_trng_generate_64(trng);
    uint64_t masked = random;
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

    /* Slice the shares and store to the masked word */
    random2a = ascon_trng_generate_32(trng);
    random2b = ascon_trng_generate_32(trng);
    random3a = ascon_trng_generate_32(trng);
    random3b = ascon_trng_generate_32(trng);
    high = (uint32_t)(masked >> 32);
    low  = (uint32_t)masked;
    random1a = (uint32_t)(random >> 32);
    random1b = (uint32_t)random;
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = ((high << 16) | (low & 0x0000FFFFU)) ^ random2a ^ random3a;
    word->W[1] = ((high & 0xFFFF0000U) | (low >> 16)) ^ random2b ^ random3b;
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
    word->W[4] = ascon_mask32_rotate_share2_0(random2a);
    word->W[5] = ascon_mask32_rotate_share2_0(random2b);
    word->W[6] = ascon_mask32_rotate_share3_0(random3a);
    word->W[7] = ascon_mask32_rotate_share3_0(random3b);
}

void ascon_masked_word_x4_load_32
    (ascon_masked_word_t *word, const uint8_t *data1,
     const uint8_t *data2, ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t high = random1a ^ be_load_word32(data1);
    uint32_t low  = random1b ^ be_load_word32(data2);
    word->W[4] = ascon_trng_generate_32(trng); /* random2a */
    word->W[5] = ascon_trng_generate_32(trng); /* random2b */
    word->W[6] = ascon_trng_generate_32(trng); /* random3a */
    word->W[7] = ascon_trng_generate_32(trng); /* random3b */
    ascon_separate(random1a);
    ascon_separate(random1b);
    ascon_separate(high);
    ascon_separate(low);
    word->W[0] = ((high << 16) | (low & 0x0000FFFFU)) ^
                 ascon_mask32_unrotate_share2_0(word->W[4]) ^
                 ascon_mask32_unrotate_share3_0(word->W[6]);
    word->W[1] = ((high & 0xFFFF0000U) | (low >> 16)) ^
                 ascon_mask32_unrotate_share2_0(word->W[5]) ^
                 ascon_mask32_unrotate_share3_0(word->W[7]);
    high = (random1a << 16) | (random1b & 0x0000FFFFU);
    low  = (random1a & 0xFFFF0000U) | (random1b >> 16);
    word->W[2] = ascon_mask32_rotate_share1_0(high);
    word->W[3] = ascon_mask32_rotate_share1_0(low);
}

void ascon_masked_word_x4_store
    (uint8_t *data, const ascon_masked_word_t *word)
{
    uint32_t high1 = (word->W[0] >> 16) | (word->W[1] & 0xFFFF0000U);
    uint32_t low1  = (word->W[0] & 0x0000FFFFU) | (word->W[1] << 16);
    uint32_t high2 = ascon_mask32_unrotate_share1_0(word->W[2]) ^
                     ascon_mask32_unrotate_share2_0(word->W[4]) ^
                     ascon_mask32_unrotate_share3_0(word->W[6]);
    uint32_t low2  = ascon_mask32_unrotate_share1_0(word->W[3]) ^
                     ascon_mask32_unrotate_share2_0(word->W[5]) ^
                     ascon_mask32_unrotate_share3_0(word->W[7]);
    uint32_t high3 = (high2 >> 16) | (low2 & 0xFFFF0000U);
    uint32_t low3  = (high2 & 0x0000FFFFU) | (low2 << 16);
    ascon_combine(high1);
    ascon_combine(low1);
    ascon_combine(high3);
    ascon_combine(low3);
    be_store_word32(data, high1 ^ high3);
    be_store_word32(data + 4, low1 ^ low3);
}

void ascon_masked_word_x4_store_partial
    (uint8_t *data, unsigned size, const ascon_masked_word_t *word)
{
    uint64_t masked1, masked2;
    uint32_t high1, low1;
    uint32_t high2, low2;
    uint32_t high3, low3;

    /* Rearrange the bits while still in masked form */
    high1 = (word->W[0] >> 16) | (word->W[1] & 0xFFFF0000U);
    low1  = (word->W[0] & 0x0000FFFFU) | (word->W[1] << 16);
    high2 = ascon_mask32_unrotate_share1_0(word->W[2]) ^
            ascon_mask32_unrotate_share2_0(word->W[4]) ^
            ascon_mask32_unrotate_share3_0(word->W[6]);
    low2  = ascon_mask32_unrotate_share1_0(word->W[3]) ^
            ascon_mask32_unrotate_share2_0(word->W[5]) ^
            ascon_mask32_unrotate_share3_0(word->W[7]);
    high3 = (high2 >> 16) | (low2 & 0xFFFF0000U);
    low3  = (high2 & 0x0000FFFFU) | (low2 << 16);
    ascon_combine(high1);
    ascon_combine(low1);
    ascon_combine(high3);
    ascon_combine(low3);

    /* Convert to 64-bit, unmask, and store the bytes */
    masked1 = (((uint64_t)high1) << 32) | low1;
    masked2 = (((uint64_t)high3) << 32) | low3;
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

void ascon_masked_word_x4_randomize
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    uint32_t random3a = ascon_trng_generate_32(trng);
    uint32_t random3b = ascon_trng_generate_32(trng);
    dest->W[0] = src->W[0] ^ random1a ^ random2a ^ random3a;
    dest->W[1] = src->W[1] ^ random1b ^ random2b ^ random3b;
    dest->W[2] = src->W[2] ^ ascon_mask32_rotate_share1_0(random1a);
    dest->W[3] = src->W[3] ^ ascon_mask32_rotate_share1_0(random1b);
    dest->W[4] = src->W[4] ^ ascon_mask32_rotate_share2_0(random2a);
    dest->W[5] = src->W[5] ^ ascon_mask32_rotate_share2_0(random2b);
    dest->W[6] = src->W[6] ^ ascon_mask32_rotate_share3_0(random3a);
    dest->W[7] = src->W[7] ^ ascon_mask32_rotate_share3_0(random3b);
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
    uint32_t mask1 = (~((uint32_t)0)) >> (size * 4U);
    uint32_t mask2 = ~mask1;
    dest->W[0] = (dest->W[0] & mask1) | (src->W[0] & mask2);
    dest->W[1] = (dest->W[1] & mask1) | (src->W[1] & mask2);
    mask1 = ascon_mask32_rotate_share1_0(mask1);
    mask2 = ascon_mask32_rotate_share1_0(mask2);
    dest->W[2] = (dest->W[2] & mask1) | (src->W[2] & mask2);
    dest->W[3] = (dest->W[3] & mask1) | (src->W[3] & mask2);
    mask1 = ascon_mask32_rotate_share1_0(mask1);
    mask2 = ascon_mask32_rotate_share1_0(mask2);
    dest->W[4] = (dest->W[4] & mask1) | (src->W[4] & mask2);
    dest->W[5] = (dest->W[5] & mask1) | (src->W[5] & mask2);
    mask1 = ascon_mask32_rotate_share1_0(mask1);
    mask2 = ascon_mask32_rotate_share1_0(mask2);
    dest->W[6] = (dest->W[6] & mask1) | (src->W[6] & mask2);
    dest->W[7] = (dest->W[7] & mask1) | (src->W[7] & mask2);
}

void ascon_masked_word_x4_from_x2
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    uint32_t random3a = ascon_trng_generate_32(trng);
    uint32_t random3b = ascon_trng_generate_32(trng);
    dest->W[0] = random1a ^ random2a ^ random3a ^ src->W[0];
    dest->W[1] = random1b ^ random2b ^ random3b ^ src->W[1];
    dest->W[2] = ascon_mask32_rotate_share1_0(random1a) ^ src->W[2];
    dest->W[3] = ascon_mask32_rotate_share1_0(random1b) ^ src->W[3];
    dest->W[4] = ascon_mask32_rotate_share2_0(random2a);
    dest->W[5] = ascon_mask32_rotate_share2_0(random2b);
    dest->W[6] = ascon_mask32_rotate_share3_0(random3a);
    dest->W[7] = ascon_mask32_rotate_share3_0(random3b);
}

void ascon_masked_word_x4_from_x3
    (ascon_masked_word_t *dest, const ascon_masked_word_t *src,
     ascon_trng_state_t *trng)
{
    uint32_t random1a = ascon_trng_generate_32(trng);
    uint32_t random1b = ascon_trng_generate_32(trng);
    uint32_t random2a = ascon_trng_generate_32(trng);
    uint32_t random2b = ascon_trng_generate_32(trng);
    uint32_t random3a = ascon_trng_generate_32(trng);
    uint32_t random3b = ascon_trng_generate_32(trng);
    dest->W[0] = random1a ^ random2a ^ random3a ^ src->W[0];
    dest->W[1] = random1b ^ random2b ^ random3b ^ src->W[1];
    dest->W[2] = ascon_mask32_rotate_share1_0(random1a) ^ src->W[2];
    dest->W[3] = ascon_mask32_rotate_share1_0(random1b) ^ src->W[3];
    dest->W[4] = ascon_mask32_rotate_share2_0(random2a) ^ src->W[4];
    dest->W[5] = ascon_mask32_rotate_share2_0(random2b) ^ src->W[5];
    dest->W[6] = ascon_mask32_rotate_share3_0(random3a);
    dest->W[7] = ascon_mask32_rotate_share3_0(random3b);
}

#endif /* ASCON_MASKED_MAX_SHARES >= 4 */

void ascon_masked_word_pad(ascon_masked_word_t *word, unsigned offset)
{
    word->W[1] ^= (((uint32_t)0x80000000U) >> (offset * 4U));
}

void ascon_masked_word_separator(ascon_masked_word_t *word)
{
    word->W[0] ^= 1;
}

#endif /* ASCON_MASKED_WORD_BACKEND_C32 */
