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
 * 32-bit native word size. */

#include <ascon/permutation.h>
#include "ascon-select-backend.h"
#include "ascon-sliced32.h"
#include "ascon-util.h"

#if defined(ASCON_BACKEND_C32)

#define ROUND_CONSTANT_PAIR(rc1, rc2) \
    (~((uint32_t)(rc1))), (~((uint32_t)(rc2)))

void ascon_permute(ascon_state_t *state, uint8_t first_round)
{
    static const uint32_t RC[12 * 2] = {
        ROUND_CONSTANT_PAIR(12, 12),
        ROUND_CONSTANT_PAIR( 9, 12),
        ROUND_CONSTANT_PAIR(12,  9),
        ROUND_CONSTANT_PAIR( 9,  9),
        ROUND_CONSTANT_PAIR( 6, 12),
        ROUND_CONSTANT_PAIR( 3, 12),
        ROUND_CONSTANT_PAIR( 6,  9),
        ROUND_CONSTANT_PAIR( 3,  9),
        ROUND_CONSTANT_PAIR(12,  6),
        ROUND_CONSTANT_PAIR( 9,  6),
        ROUND_CONSTANT_PAIR(12,  3),
        ROUND_CONSTANT_PAIR( 9,  3)
    };
    const uint32_t *rc = RC + first_round * 2;
    uint32_t t0, t1, t2, t3, t4;

    /* Load the state into local variables */
    uint32_t x0_e = state->W[0];
    uint32_t x0_o = state->W[1];
    uint32_t x1_e = state->W[2];
    uint32_t x1_o = state->W[3];
    uint32_t x2_e = state->W[4];
    uint32_t x2_o = state->W[5];
    uint32_t x3_e = state->W[6];
    uint32_t x3_o = state->W[7];
    uint32_t x4_e = state->W[8];
    uint32_t x4_o = state->W[9];

    /* We move the "x2 = ~x2" term of the substitution layer outside
     * the loop.  The round constants are modified to "NOT value" to
     * apply "x2 = ~x2" automatically each round.  Then we only
     * need to invert x2 for real before and after the loop. */
    x2_e = ~x2_e;
    x2_o = ~x2_o;

    /* Perform all permutation rounds */
    while (first_round < 12) {
        /* Add the round constants for this round to the state */
        x2_e ^= rc[0];
        x2_o ^= rc[1];
        rc += 2;

        /* Substitution layer */
        #define ascon_sbox(x0, x1, x2, x3, x4) \
            do { \
                x0 ^= x4;   x4 ^= x3;   x2 ^= x1; \
                t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4; \
                t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0; \
                x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0; \
                x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   /* x2 = ~x2; */ \
            } while (0)
        ascon_sbox(x0_e, x1_e, x2_e, x3_e, x4_e);
        ascon_sbox(x0_o, x1_o, x2_o, x3_o, x4_o);

        /* Linear diffusion layer */
        /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
        t0 = x0_e ^ rightRotate4(x0_o);
        t1 = x0_o ^ rightRotate5(x0_e);
        x0_e ^= rightRotate9(t1);
        x0_o ^= rightRotate10(t0);
        /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
        t0 = x1_e ^ rightRotate11(x1_e);
        t1 = x1_o ^ rightRotate11(x1_o);
        x1_e ^= rightRotate19(t1);
        x1_o ^= rightRotate20(t0);
        /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
        t0 = x2_e ^ rightRotate2(x2_o);
        t1 = x2_o ^ rightRotate3(x2_e);
        x2_e ^= t1;
        x2_o ^= rightRotate1(t0);
        /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
        t0 = x3_e ^ rightRotate3(x3_o);
        t1 = x3_o ^ rightRotate4(x3_e);
        x3_e ^= rightRotate5(t0);
        x3_o ^= rightRotate5(t1);
        /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
        t0 = x4_e ^ rightRotate17(x4_e);
        t1 = x4_o ^ rightRotate17(x4_o);
        x4_e ^= rightRotate3(t1);
        x4_o ^= rightRotate4(t0);

        /* Move onto the next round */
        ++first_round;
    }

    /* Apply the final NOT to x2 */
    x2_e = ~x2_e;
    x2_o = ~x2_o;

    /* Write the local variables back to the state */
    state->W[0] = x0_e;
    state->W[1] = x0_o;
    state->W[2] = x1_e;
    state->W[3] = x1_o;
    state->W[4] = x2_e;
    state->W[5] = x2_o;
    state->W[6] = x3_e;
    state->W[7] = x3_o;
    state->W[8] = x4_e;
    state->W[9] = x4_o;
}

#endif /* ASCON_BACKEND_C32 */
