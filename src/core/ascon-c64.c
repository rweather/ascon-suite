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

/* Plain C implementation of the ASCON permutation for systems with a
 * 64-bit or better native word size. */

#include <ascon/permutation.h>
#include "ascon-select-backend.h"
#include "ascon-util.h"

#if defined(ASCON_BACKEND_C64) && !defined(ASCON_BACKEND_C64_DIRECT_XOR)

void ascon_to_regular(ascon_state_t *state)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    /* Convert from little-endian to big-endian */
    be_store_word64(state->B,      state->S[0]);
    be_store_word64(state->B +  8, state->S[1]);
    be_store_word64(state->B + 16, state->S[2]);
    be_store_word64(state->B + 24, state->S[3]);
    be_store_word64(state->B + 32, state->S[4]);
#else
    /* Already in big-endian byte order, so nothing to do */
    (void)state;
#endif
}

void ascon_from_regular(ascon_state_t *state)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    /* Convert from big-endian to little-endian */
    state->S[0] = be_load_word64(state->B);
    state->S[1] = be_load_word64(state->B + 8);
    state->S[2] = be_load_word64(state->B + 16);
    state->S[3] = be_load_word64(state->B + 24);
    state->S[4] = be_load_word64(state->B + 32);
#else
    /* Already in big-endian byte order, so nothing to do */
    (void)state;
#endif
}

#endif /* !ASCON_BACKEND_C64_DIRECT_XOR */

#if defined(ASCON_BACKEND_C64) || defined(ASCON_BACKEND_C64_DIRECT_XOR)

#define ROUND_CONSTANT(round)   \
        (~(uint64_t)(((0x0F - (round)) << 4) | (round)))

void ascon_permute(ascon_state_t *state, uint8_t first_round)
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
#if defined(ASCON_BACKEND_C64_DIRECT_XOR)
    uint64_t x0 = be_load_word64(state->B);
    uint64_t x1 = be_load_word64(state->B + 8);
    uint64_t x2 = be_load_word64(state->B + 16);
    uint64_t x3 = be_load_word64(state->B + 24);
    uint64_t x4 = be_load_word64(state->B + 32);
#else
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
    uint64_t x4 = state->S[4];
#endif
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
#if defined(ASCON_BACKEND_C64_DIRECT_XOR)
    be_store_word64(state->B,      x0);
    be_store_word64(state->B +  8, x1);
    be_store_word64(state->B + 16, x2);
    be_store_word64(state->B + 24, x3);
    be_store_word64(state->B + 32, x4);
#else
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
    state->S[4] = x4;
#endif
}

#endif /* ASCON_BACKEND_C64 */
