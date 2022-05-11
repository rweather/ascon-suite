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
#include "core/ascon-util.h"

#if defined(ASCON_MASKED_X4_BACKEND_C64) && ASCON_MASKED_MAX_SHARES >= 4

/**
 * \brief Computes x ^= (~y & z) with a 4-share masked representation.
 *
 * \param x Output variable to XOR with.
 * \param y First input variable.
 * \param z Second input variable.
 */
#define and_not_xor(x, y, z) \
    do { \
        x##_a ^= (~(y##_a) & z##_a); \
        x##_a ^= (ascon_mask64_unrotate_share1_0(y##_b) & z##_a); \
        x##_a ^= (ascon_mask64_unrotate_share2_0(y##_c) & z##_a); \
        x##_a ^= (ascon_mask64_unrotate_share3_0(y##_d) & z##_a); \
        \
        x##_b ^= (ascon_mask64_rotate_share1_0(~(y##_a)) & z##_b); \
        x##_b ^= (y##_b & z##_b); \
        x##_b ^= (ascon_mask64_unrotate_share2_1(y##_c) & z##_b); \
        x##_b ^= (ascon_mask64_unrotate_share3_1(y##_d) & z##_b); \
        \
        x##_c ^= (ascon_mask64_rotate_share2_0(~(y##_a)) & z##_c); \
        x##_c ^= (ascon_mask64_rotate_share2_1(y##_b) & z##_c); \
        x##_c ^= (y##_c & z##_c); \
        x##_c ^= (ascon_mask64_unrotate_share3_2(y##_d) & z##_c); \
        \
        x##_d ^= (ascon_mask64_rotate_share3_0(~(y##_a)) & z##_d); \
        x##_d ^= (ascon_mask64_rotate_share3_1(y##_b) & z##_d); \
        x##_d ^= (ascon_mask64_rotate_share3_2(y##_c) & z##_d); \
        x##_d ^= (y##_d & z##_d); \
    } while (0)

/* Generate a pre-inverted round constant so that we can
 * avoid NOT'ing x2 in the S-box during the rounds */
#define ROUND_CONSTANT(round)   \
        (~(uint64_t)(((0x0F - (round)) << 4) | (round)))

void ascon_x4_permute
    (ascon_masked_state_t *state, uint8_t first_round, uint64_t preserve[3])
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
    uint64_t x0_a, x1_a, x2_a, x3_a, x4_a;
    uint64_t x0_b, x1_b, x2_b, x3_b, x4_b;
    uint64_t x0_c, x1_c, x2_c, x3_c, x4_c;
    uint64_t x0_d, x1_d, x2_d, x3_d, x4_d;
    uint64_t t0_a, t0_b, t0_c, t0_d;
    uint64_t t1_a, t1_b, t1_c, t1_d;

    /* Start with the randomness that the caller provided */
    t0_a = preserve[0];
    t0_b = preserve[1];
    t0_c = preserve[2];

    /* Load the state into local variables */
    x0_a = state->M[0].S[0];
    x0_b = state->M[0].S[1];
    x0_c = state->M[0].S[2];
    x0_d = state->M[0].S[3];
    x1_a = state->M[1].S[0];
    x1_b = state->M[1].S[1];
    x1_c = state->M[1].S[2];
    x1_d = state->M[1].S[3];
    x2_a = state->M[2].S[0];
    x2_b = state->M[2].S[1];
    x2_c = state->M[2].S[2];
    x2_d = state->M[2].S[3];
    x3_a = state->M[3].S[0];
    x3_b = state->M[3].S[1];
    x3_c = state->M[3].S[2];
    x3_d = state->M[3].S[3];
    x4_a = state->M[4].S[0];
    x4_b = state->M[4].S[1];
    x4_c = state->M[4].S[2];
    x4_d = state->M[4].S[3];

    /* The round constants invert x2 as part of the rounds so that we
     * don't need an explicit "x2 = ~x2" step in the S-box.  Pre-invert
     * x2 before the first round to compensate. */
    x2_a = ~x2_a;

    /* Perform all encryption rounds */
    while (first_round < 12) {
        /* Add the inverted round constant to x2 */
        x2_a ^= RC[first_round++];

        /* Start of the substitution layer, first share */
        x0_a ^= x4_a;
        x4_a ^= x3_a;
        x2_a ^= x1_a;
        t1_a  = x0_a;

        /* Start of the substitution layer, second share */
        x0_b ^= x4_b;
        x4_b ^= x3_b;
        x2_b ^= x1_b;
        t1_b  = x0_b;

        /* Start of the substitution layer, third share */
        x0_c ^= x4_c;
        x4_c ^= x3_c;
        x2_c ^= x1_c;
        t1_c  = x0_c;

        /* Start of the substitution layer, fourth share */
        x0_d ^= x4_d;
        x4_d ^= x3_d;
        x2_d ^= x1_d;
        t1_d  = x0_d;

        /* Middle part of the substitution layer, Chi5 */
        t0_d = ascon_mask64_rotate_share3_0(t0_a) ^ /* t0 = random shares */
               ascon_mask64_rotate_share3_1(t0_b) ^
               ascon_mask64_rotate_share3_2(t0_c);
        and_not_xor(t0, x0, x1);                    /* t0 ^= (~x0) & x1; */
        and_not_xor(x0, x1, x2);                    /* x0 ^= (~x1) & x2; */
        and_not_xor(x1, x2, x3);                    /* x1 ^= (~x2) & x3; */
        and_not_xor(x2, x3, x4);                    /* x2 ^= (~x3) & x4; */
        and_not_xor(x3, x4, t1);                    /* x3 ^= (~x4) & t1; */
        x4_a ^= t0_a;                               /* x4 ^= t0; */
        x4_b ^= t0_b;
        x4_c ^= t0_c;
        x4_d ^= t0_d;

        /* End of the substitution layer */
        x1_a ^= x0_a;
        x0_a ^= x4_a;
        x3_a ^= x2_a;
        x1_b ^= x0_b;
        x0_b ^= x4_b;
        x3_b ^= x2_b;
        x1_c ^= x0_c;
        x0_c ^= x4_c;
        x3_c ^= x2_c;
        x1_d ^= x0_d;
        x0_d ^= x4_d;
        x3_d ^= x2_d;

        /* NOT'ing x2 is done as part of the next round constant */
        /* x2_a = ~x2_a; */

        /* Linear diffusion layer, fourth share */
        x0_d ^= rightRotate19_64(x0_d) ^ rightRotate28_64(x0_d);
        x1_d ^= rightRotate61_64(x1_d) ^ rightRotate39_64(x1_d);
        x2_d ^= rightRotate1_64(x2_d)  ^ rightRotate6_64(x2_d);
        x3_d ^= rightRotate10_64(x3_d) ^ rightRotate17_64(x3_d);
        x4_d ^= rightRotate7_64(x4_d)  ^ rightRotate41_64(x4_d);

        /* Linear diffusion layer, third share */
        x0_c ^= rightRotate19_64(x0_c) ^ rightRotate28_64(x0_c);
        x1_c ^= rightRotate61_64(x1_c) ^ rightRotate39_64(x1_c);
        x2_c ^= rightRotate1_64(x2_c)  ^ rightRotate6_64(x2_c);
        x3_c ^= rightRotate10_64(x3_c) ^ rightRotate17_64(x3_c);
        x4_c ^= rightRotate7_64(x4_c)  ^ rightRotate41_64(x4_c);

        /* Linear diffusion layer, second share */
        x0_b ^= rightRotate19_64(x0_b) ^ rightRotate28_64(x0_b);
        x1_b ^= rightRotate61_64(x1_b) ^ rightRotate39_64(x1_b);
        x2_b ^= rightRotate1_64(x2_b)  ^ rightRotate6_64(x2_b);
        x3_b ^= rightRotate10_64(x3_b) ^ rightRotate17_64(x3_b);
        x4_b ^= rightRotate7_64(x4_b)  ^ rightRotate41_64(x4_b);

        /* Linear diffusion layer, first share */
        x0_a ^= rightRotate19_64(x0_a) ^ rightRotate28_64(x0_a);
        x1_a ^= rightRotate61_64(x1_a) ^ rightRotate39_64(x1_a);
        x2_a ^= rightRotate1_64(x2_a)  ^ rightRotate6_64(x2_a);
        x3_a ^= rightRotate10_64(x3_a) ^ rightRotate17_64(x3_a);
        x4_a ^= rightRotate7_64(x4_a)  ^ rightRotate41_64(x4_a);

        /* Rotate the randomness in t0 before the next round */
        t0_a = rightRotate13_64(t0_a);
        t0_b = rightRotate29_64(t0_b);
        t0_c = rightRotate59_64(t0_c);
    }

    /* Return the final randomness to the caller to preserve it */
    preserve[0] = t0_a;
    preserve[1] = t0_b;
    preserve[2] = t0_c;

    /* Store the local variables back to the state with a final invert of x2 */
    state->M[0].S[0] = x0_a;
    state->M[0].S[1] = x0_b;
    state->M[0].S[2] = x0_c;
    state->M[0].S[3] = x0_d;
    state->M[1].S[0] = x1_a;
    state->M[1].S[1] = x1_b;
    state->M[1].S[2] = x1_c;
    state->M[1].S[3] = x1_d;
    state->M[2].S[0] = ~x2_a;
    state->M[2].S[1] = x2_b;
    state->M[2].S[2] = x2_c;
    state->M[2].S[3] = x2_d;
    state->M[3].S[0] = x3_a;
    state->M[3].S[1] = x3_b;
    state->M[3].S[2] = x3_c;
    state->M[3].S[3] = x3_d;
    state->M[4].S[0] = x4_a;
    state->M[4].S[1] = x4_b;
    state->M[4].S[2] = x4_c;
    state->M[4].S[3] = x4_d;
}

#endif /* ASCON_MASKED_X4_BACKEND_C64 */
