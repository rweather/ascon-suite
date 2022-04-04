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
#include "ascon-permutation-select.h"
#include "ascon-internal-util.h"

#if defined(ASCON_BACKEND_C64)

/** @cond ascon_c64 */

/* Define to 1 to emulate a big-endian CPU on a little-endian host.
 * Intended for testing purposes only. */
#define ASCON_BACKEND_C64_EMUL_BIG 0

#if defined(LW_UTIL_LITTLE_ENDIAN) && !ASCON_BACKEND_C64_EMUL_BIG
#define ASCON_C64_BYTE_FOR_OFFSET(state, offset) \
    (state->B[((offset) & 0x38) + (7 - (offset & 0x07))])
#define ASCON_BACKEND_C64_LE 1
#else
#define ASCON_C64_BYTE_FOR_OFFSET(state, offset) (state->B[(offset)])
#endif

/** @endcond */

void ascon_init(ascon_state_t *state)
{
    state->S[0] = 0;
    state->S[1] = 0;
    state->S[2] = 0;
    state->S[3] = 0;
    state->S[4] = 0;
}

void ascon_to_regular(ascon_state_t *state)
{
#if defined(ASCON_BACKEND_C64_LE)
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
#if defined(ASCON_BACKEND_C64_LE)
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

void ascon_add_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        ASCON_C64_BYTE_FOR_OFFSET(state, offset) ^= *data++;
        ++offset;
        --size;
    }
}

void ascon_overwrite_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        ASCON_C64_BYTE_FOR_OFFSET(state, offset) = *data++;
        ++offset;
        --size;
    }
}

void ascon_overwrite_with_zeroes
    (ascon_state_t *state, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        ASCON_C64_BYTE_FOR_OFFSET(state, offset) = 0;
        ++offset;
        --size;
    }
}

void ascon_extract_bytes
    (const ascon_state_t *state, uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        *data++ = ASCON_C64_BYTE_FOR_OFFSET(state, offset);
        ++offset;
        --size;
    }
}

void ascon_extract_and_add_bytes
    (const ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        *output++ = *input++ ^ ASCON_C64_BYTE_FOR_OFFSET(state, offset);
        ++offset;
        --size;
    }
}

void ascon_permute(ascon_state_t *state, uint8_t first_round)
{
    uint64_t t0, t1, t2, t3, t4;
#if ASCON_BACKEND_C64_EMUL_BIG
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
    while (first_round < 12) {
        /* Add the round constant to the state */
        x2 ^= ((0x0F - first_round) << 4) | first_round;

        /* Substitution layer - apply the s-box using bit-slicing
         * according to the algorithm recommended in the specification */
        x0 ^= x4;   x4 ^= x3;   x2 ^= x1;
        t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4;
        t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0;
        x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0;
        x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2;

        /* Linear diffusion layer */
        x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0);
        x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1);
        x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2);
        x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3);
        x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4);

        /* Move onto the next round */
        ++first_round;
    }
#if ASCON_BACKEND_C64_EMUL_BIG
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
