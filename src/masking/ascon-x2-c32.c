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

#if defined(ASCON_MASKED_X2_BACKEND_C32)

/**
 * \brief Computes x ^= (~y & z) with a 2-share masked representation.
 *
 * \param x Output variable to XOR with.
 * \param y First input variable.
 * \param z Second input variable.
 * \param w e or o to indicate which word to operate on.
 */
#define and_not_xor(x, y, z, w) \
    do { \
        x##_a##w ^= ((~y##_a##w) & ascon_mask32_unrotate_share1_0(z##_b##w)); \
        x##_a##w ^= ((~y##_a##w) & z##_a##w); \
        x##_b##w ^= (y##_b##w & z##_b##w); \
        x##_b##w ^= (y##_b##w & ascon_mask32_rotate_share1_0(z##_a##w)); \
    } while (0)

/**
 * \brief Applies the 32-bit sliced linear layer to a share.
 *
 * \param w a or b to indicate which share to operate on.
 */
#define linear(w) \
    do { \
        t0 = x0_##w##e ^ rightRotate4(x0_##w##o); \
        t1 = x0_##w##o ^ rightRotate5(x0_##w##e); \
        t2 = x1_##w##e ^ rightRotate11(x1_##w##e); \
        t3 = x1_##w##o ^ rightRotate11(x1_##w##o); \
        t4 = x2_##w##e ^ rightRotate2(x2_##w##o); \
        t5 = x2_##w##o ^ rightRotate3(x2_##w##e); \
        t6 = x3_##w##e ^ rightRotate3(x3_##w##o); \
        t7 = x3_##w##o ^ rightRotate4(x3_##w##e); \
        t8 = x4_##w##e ^ rightRotate17(x4_##w##e); \
        t9 = x4_##w##o ^ rightRotate17(x4_##w##o); \
        x0_##w##e ^= rightRotate9(t1); \
        x0_##w##o ^= rightRotate10(t0); \
        x1_##w##e ^= rightRotate19(t3); \
        x1_##w##o ^= rightRotate20(t2); \
        x2_##w##e ^= t5; \
        x2_##w##o ^= rightRotate1(t4); \
        x3_##w##e ^= rightRotate5(t6); \
        x3_##w##o ^= rightRotate5(t7); \
        x4_##w##e ^= rightRotate3(t9); \
        x4_##w##o ^= rightRotate4(t8); \
    } while (0)

/* Generate a pair of pre-inverted round constants so that we can
 * avoid NOT'ing x2 in the S-box during the rounds */
#define ROUND_CONSTANT_PAIR(rc1, rc2) \
    (~((uint32_t)(rc1))), (~((uint32_t)(rc2)))

void ascon_x2_permute
    (ascon_masked_state_t *state, uint8_t first_round, uint64_t *preserve)
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
    uint32_t x0_ae, x1_ae, x2_ae, x3_ae, x4_ae;
    uint32_t x0_ao, x1_ao, x2_ao, x3_ao, x4_ao;
    uint32_t x0_be, x1_be, x2_be, x3_be, x4_be;
    uint32_t x0_bo, x1_bo, x2_bo, x3_bo, x4_bo;
    uint32_t t0_ao, t0_bo, t1_ao, t1_bo;
    uint32_t t0_ae, t0_be, t1_ae, t1_be;
    uint32_t t6, t7, t8, t9;

    /* Start with the randomness that the caller provided */
    t0_ae = ((uint32_t *)preserve)[0];
    t0_ao = ((uint32_t *)preserve)[1];

    /* Load the state into local variables */
    x0_ae = state->M[0].W[0];
    x0_ao = state->M[0].W[1];
    x0_be = state->M[0].W[2];
    x0_bo = state->M[0].W[3];
    x1_ae = state->M[1].W[0];
    x1_ao = state->M[1].W[1];
    x1_be = state->M[1].W[2];
    x1_bo = state->M[1].W[3];
    x2_ae = state->M[2].W[0];
    x2_ao = state->M[2].W[1];
    x2_be = state->M[2].W[2];
    x2_bo = state->M[2].W[3];
    x3_ae = state->M[3].W[0];
    x3_ao = state->M[3].W[1];
    x3_be = state->M[3].W[2];
    x3_bo = state->M[3].W[3];
    x4_ae = state->M[4].W[0];
    x4_ao = state->M[4].W[1];
    x4_be = state->M[4].W[2];
    x4_bo = state->M[4].W[3];

    /* The round constants invert x2 as part of the rounds so that we
     * don't need an explicit "x2 = ~x2" step in the S-box.  Pre-invert
     * x2 before the first round to compensate. */
    x2_ae = ~x2_ae;
    x2_ao = ~x2_ao;

    /* Perform all encryption rounds */
    while (first_round++ < 12) {
        /* Substitution layer, even words */

        /* Add the inverted round constant to x2 */
        x2_ae ^= *rc++;

        /* Start of the substitution layer, first share */
        x0_ae ^= x4_ae;
        x4_ae ^= x3_ae;
        x2_ae ^= x1_ae;
        t1_ae  = x0_ae;

        /* Start of the substitution layer, second share */
        x0_be ^= x4_be;
        x4_be ^= x3_be;
        x2_be ^= x1_be;
        t1_be  = x0_be;

        /* Middle part of the substitution layer, Chi5 */
        t0_be = ascon_mask32_rotate_share1_0(t0_ae); /* t0 = random shares */
        and_not_xor(t0, x0, x1, e);                  /* t0 ^= (~x0) & x1; */
        and_not_xor(x0, x1, x2, e);                  /* x0 ^= (~x1) & x2; */
        and_not_xor(x1, x2, x3, e);                  /* x1 ^= (~x2) & x3; */
        and_not_xor(x2, x3, x4, e);                  /* x2 ^= (~x3) & x4; */
        and_not_xor(x3, x4, t1, e);                  /* x3 ^= (~x4) & t1; */
        x4_ae ^= t0_ae;                              /* x4 ^= t0; */
        x4_be ^= t0_be;

        /* End of the substitution layer */
        x1_ae ^= x0_ae;
        x0_ae ^= x4_ae;
        x3_ae ^= x2_ae;
        x1_be ^= x0_be;
        x0_be ^= x4_be;
        x3_be ^= x2_be;

        /* NOT'ing x2 is done as part of the next round constant */
        /* x2_ae = ~x2_ae; */

        /* Substitution layer, odd words */

        /* Add the inverted round constant to x2 */
        x2_ao ^= *rc++;

        /* Start of the substitution layer, first share */
        x0_ao ^= x4_ao;
        x4_ao ^= x3_ao;
        x2_ao ^= x1_ao;
        t1_ao  = x0_ao;

        /* Start of the substitution layer, second share */
        x0_bo ^= x4_bo;
        x4_bo ^= x3_bo;
        x2_bo ^= x1_bo;
        t1_bo  = x0_bo;

        /* Middle part of the substitution layer, Chi5 */
        t0_bo = ascon_mask32_rotate_share1_0(t0_ao); /* t0 = random shares */
        and_not_xor(t0, x0, x1, o);                  /* t0 ^= (~x0) & x1; */
        and_not_xor(x0, x1, x2, o);                  /* x0 ^= (~x1) & x2; */
        and_not_xor(x1, x2, x3, o);                  /* x1 ^= (~x2) & x3; */
        and_not_xor(x2, x3, x4, o);                  /* x2 ^= (~x3) & x4; */
        and_not_xor(x3, x4, t1, o);                  /* x3 ^= (~x4) & t1; */
        x4_ao ^= t0_ao;                              /* x4 ^= t0; */
        x4_bo ^= t0_bo;

        /* End of the substitution layer */
        x1_ao ^= x0_ao;
        x0_ao ^= x4_ao;
        x3_ao ^= x2_ao;
        x1_bo ^= x0_bo;
        x0_bo ^= x4_bo;
        x3_bo ^= x2_bo;

        /* NOT'ing x2 is done as part of the next round constant */
        /* x2_ao = ~x2_ao; */

        /* Linear diffusion layer on each of the shares.  Reuse some of
         * the temporaries from substitution that we no longer require. */
        #define t0 t0_bo
        #define t1 t1_ao
        #define t2 t1_bo
        #define t3 t0_be
        #define t4 t1_ae
        #define t5 t1_be
        linear(b);
        linear(a);

        /* Rotate the randomness in t0 before the next round */
        t0_ae = rightRotate7(t0_ae);
        t0_ao = rightRotate7(t0_ao);
    }

    /* Return the final randomness to the caller to preserve it */
    ((uint32_t *)preserve)[0] = t0_ae;
    ((uint32_t *)preserve)[1] = t0_ao;

    /* Store the local variables back to the state with a final invert of x2 */
    state->M[0].W[0] = x0_ae;
    state->M[0].W[1] = x0_ao;
    state->M[0].W[2] = x0_be;
    state->M[0].W[3] = x0_bo;
    state->M[1].W[0] = x1_ae;
    state->M[1].W[1] = x1_ao;
    state->M[1].W[2] = x1_be;
    state->M[1].W[3] = x1_bo;
    state->M[2].W[0] = ~x2_ae;
    state->M[2].W[1] = ~x2_ao;
    state->M[2].W[2] = x2_be;
    state->M[2].W[3] = x2_bo;
    state->M[3].W[0] = x3_ae;
    state->M[3].W[1] = x3_ao;
    state->M[3].W[2] = x3_be;
    state->M[3].W[3] = x3_bo;
    state->M[4].W[0] = x4_ae;
    state->M[4].W[1] = x4_ao;
    state->M[4].W[2] = x4_be;
    state->M[4].W[3] = x4_bo;
}

#endif /* ASCON_MASKED_X2_BACKEND_C32 */
