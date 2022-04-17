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

/* Computes the initialization vectors for ASCON hash and XOF algorithms
 * in regular and sliced forms. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ascon-util.h"

#define ROUND_CONSTANT(round)   \
        (~(uint64_t)(((0x0F - (round)) << 4) | (round)))

static void ascon_permute(unsigned char state[40], uint8_t first_round)
{
    static const uint64_t RC[12] = {
        ROUND_CONSTANT(0),
        ROUND_CONSTANT(1),
        ROUND_CONSTANT(2),
        ROUND_CONSTANT(3),
        ROUND_CONSTANT(4),
        ROUND_CONSTANT(5),
        ROUND_CONSTANT(6),
        ROUND_CONSTANT(7),
        ROUND_CONSTANT(8),
        ROUND_CONSTANT(9),
        ROUND_CONSTANT(10),
        ROUND_CONSTANT(11)
    };
    uint64_t t0, t1, t2, t3, t4;
    uint64_t x0 = be_load_word64(state);
    uint64_t x1 = be_load_word64(state + 8);
    uint64_t x2 = be_load_word64(state + 16);
    uint64_t x3 = be_load_word64(state + 24);
    uint64_t x4 = be_load_word64(state + 32);
    x2 = ~x2;
    while (first_round < 12) {
        /* Add the round constant to the state */
        x2 ^= RC[first_round];

        /* Substitution layer - apply the s-box using bit-slicing
         * according to the algorithm recommended in the specification.
         *
         * The final "x2 = ~x2" term will be implicitly performed
         * by the inverted round constant for the next round.
         */
        x0 ^= x4;   x4 ^= x3;   x2 ^= x1;
        t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4;
        t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0;
        x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0;
        x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   /* x2 = ~x2; */

        /* Linear diffusion layer */
        x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0);
        x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1);
        x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2);
        x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3);
        x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4);

        /* Move onto the next round */
        ++first_round;
    }
    x2 = ~x2;
    be_store_word64(state,      x0);
    be_store_word64(state +  8, x1);
    be_store_word64(state + 16, x2);
    be_store_word64(state + 24, x3);
    be_store_word64(state + 32, x4);
}

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

int main(int argc, char *argv[])
{
    unsigned char state[40] = {0};
    int index, posn;

    if (argc < 2) {
        printf("Usage: %s IV\n", argv[0]);
        return 1;
    }

    /* Load the hex bytes of the initialisation vector from the arguments */
    for (index = 1, posn = 0; posn < 40 && index < argc; ++index) {
        state[posn++] = (uint8_t)strtol(argv[index], NULL, 16);
    }

    /* Run the permutation for 12 rounds */
    ascon_permute(state, 0);

    /* Dump the sliced-64 version of the state */
    printf("#if defined(ASCON_BACKEND_SLICED64)\n");
    printf("    static uint64_t const iv[5] = {\n");
    for (index = 0; index < 5; ++index) {
        unsigned long long word = be_load_word64(state + index * 8);
        if ((index % 2) == 0)
            printf("        ");
        printf("0x%016llxULL", word);
        if (index == 4)
            printf("\n");
        else if ((index % 2) == 0)
            printf(", ");
        else
            printf(",\n");
    }
    printf("    };\n");
    printf("    memcpy(state->state.S, iv, sizeof(iv));\n");

    /* Dump the sliced-32 version of the state */
    printf("#elif defined(ASCON_BACKEND_SLICED32)\n");
    printf("    static uint32_t const iv[10] = {\n");
    for (index = 0; index < 5; ++index) {
        uint32_t high = be_load_word32(state + index * 8);
        uint32_t low  = be_load_word32(state + index * 8 + 4);
        uint32_t new_high;
        uint32_t new_low;
        ascon_separate(high);
        ascon_separate(low);
        if ((index % 2) == 0)
            printf("        ");
        new_high = (high << 16) | (low  & 0x0000FFFFU);
        new_low  = (low  >> 16) | (high & 0xFFFF0000U);
        printf("0x%08lx, 0x%08lx",
               (unsigned long)new_high, (unsigned long)new_low);
        if (index == 4)
            printf("\n");
        else if ((index % 2) != 1)
            printf(", ");
        else
            printf(",\n");
    }
    printf("    };\n");
    printf("    memcpy(state->state.W, iv, sizeof(iv));\n");

    /* Fall back to the direct version of the state */
    printf("#else\n");
    printf("    static uint8_t const iv[40] = {\n");
    for (index = 0; index < 40; ++index) {
        if ((index % 8) == 0)
            printf("        ");
        else
            printf(", ");
        printf("0x%02x", state[index]);
        if (index == 39)
            printf("\n");
        else if ((index % 8) == 7)
            printf(",\n");
    }
    printf("    };\n");
    printf("#if defined(ASCON_BACKEND_DIRECT_XOR)\n");
    printf("    memcpy(state->state.B, iv, sizeof(iv));\n");
    printf("#else\n");
    printf("    ascon_init(&(state->state));\n");
    printf("    ascon_overwrite_bytes(&(state->state), iv, sizeof(iv));\n");
    printf("    ascon_release(&(state->state));\n");
    printf("#endif\n");
    printf("#endif\n");

    return 0;
}
