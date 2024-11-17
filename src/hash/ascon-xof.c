/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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

#include <ascon/xof.h>
#include <ascon/hash.h>
#include "core/ascon-util.h"
#include "core/ascon-util-snp.h"
#include <string.h>

void ascon_xof128(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof128_state_t state;
    ascon_xof128_init(&state);
    ascon_xof128_absorb(&state, in, inlen);
    ascon_xof128_squeeze(&state, out, ASCON_HASH256_SIZE);
    ascon_xof128_free(&state);
}

void ascon_xof128_init(ascon_xof128_state_t *state)
{
    /* IV for Ascon-XOF128 after processing it with the permutation */
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0xda82ce768d9447ebULL, 0xcc7ce6c75f1ef969ULL,
        0xe7508fd780085631ULL, 0x0ee0ea53416b58ccULL,
        0xe0547524db6f0bdeULL
    };
    memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0xc0ae36b9, 0xb9b5a81f, 0xaeabf6d9, 0xa6d933e6,
        0xbc3f00e5, 0xd0b98214, 0x288d99ca, 0x3cf1072a,
        0x8ef2db1e, 0xc044b73b
    };
    memcpy(state->state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0xeb, 0x47, 0x94, 0x8d, 0x76, 0xce, 0x82, 0xda,
        0x69, 0xf9, 0x1e, 0x5f, 0xc7, 0xe6, 0x7c, 0xcc,
        0x31, 0x56, 0x08, 0x80, 0xd7, 0x8f, 0x50, 0xe7,
        0xcc, 0x58, 0x6b, 0x41, 0x53, 0xea, 0xe0, 0x0e,
        0xde, 0x0b, 0x6f, 0xdb, 0x24, 0x75, 0x54, 0xe0
    };
#if defined(ASCON_BACKEND_DIRECT_XOR)
    memcpy(state->state.B, iv, sizeof(iv));
#else
    ascon_init(&(state->state));
    ascon_overwrite_bytes(&(state->state), iv, sizeof(iv));
    ascon_release(&(state->state));
#endif
#endif
    state->count = 0;
    state->mode = 0;
}

static void ascon_cxof128_absorb_custom_size
    (ascon_xof128_state_t *state, size_t customlen)
{
    unsigned char size[8];
    le_store_word64(size, customlen * 8U);
    ascon_xof128_absorb(state, size, sizeof(size));
}

void ascon_cxof128_init
    (ascon_xof128_state_t *state, const unsigned char *custom, size_t customlen)
{
    /* IV for Ascon-CXOF128 after processing it with the permutation */
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0x675527c2a0e8de03ULL, 0x43d12d7dc0377bbcULL,
        0xe9901dec426e81b5ULL, 0x2ab14907720780b6ULL,
        0x8f3f1d02d432bc46ULL
    };
    memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0xbf3808e1, 0x5059ceb1, 0x9d3f87d6, 0x1866857e,
        0x947a8a17, 0xe82e178c, 0x0593c306, 0x7c21518d,
        0x3770e46a, 0xb72185e1
    };
    memcpy(state->state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0x03, 0xde, 0xe8, 0xa0, 0xc2, 0x27, 0x55, 0x67,
        0xbc, 0x7b, 0x37, 0xc0, 0x7d, 0x2d, 0xd1, 0x43,
        0xb5, 0x81, 0x6e, 0x42, 0xec, 0x1d, 0x90, 0xe9,
        0xb6, 0x80, 0x07, 0x72, 0x07, 0x49, 0xb1, 0x2a,
        0x46, 0xbc, 0x32, 0xd4, 0x02, 0x1d, 0x3f, 0x8f
    };
#if defined(ASCON_BACKEND_DIRECT_XOR)
    memcpy(state->state.B, iv, sizeof(iv));
#else
    ascon_init(&(state->state));
    ascon_overwrite_bytes(&(state->state), iv, sizeof(iv));
    ascon_release(&(state->state));
#endif
#endif
    state->count = 0;
    state->mode = 0;

    /* Absorb the customization string */
    ascon_cxof128_absorb_custom_size(state, customlen);
    ascon_xof128_absorb(state, custom, customlen);
    ascon_xof128_pad(state);
}

void ascon_cxof128_init_named
    (ascon_xof128_state_t *state, const char *name,
     const unsigned char *custom, size_t customlen)
{
    if (name && name[0] != '\0') {
        ascon_cxof128_init(state, (const unsigned char *)name, strlen(name));
        if (customlen > 0) {
            ascon_xof128_absorb(state, custom, customlen);
            ascon_xof128_pad(state);
        }
    } else {
        ascon_cxof128_init(state, custom, customlen);
    }
}

void ascon_xof128_reinit(ascon_xof128_state_t *state)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_xof128_init(state);
#else
    ascon_xof128_free(state);
    ascon_xof128_init(state);
#endif
}

void ascon_cxof128_reinit
    (ascon_xof128_state_t *state, const unsigned char *custom, size_t customlen)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_cxof128_init(state, custom, customlen);
#else
    ascon_xof128_free(state);
    ascon_cxof128_init(state, custom, customlen);
#endif
}

void ascon_cxof128_reinit_named
    (ascon_xof128_state_t *state, const char *name,
     const unsigned char *custom, size_t customlen)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_cxof128_init_named(state, name, custom, customlen);
#else
    ascon_xof128_free(state);
    ascon_cxof128_init_named(state, name, custom, customlen);
#endif
}

void ascon_xof128_free(ascon_xof128_state_t *state)
{
    if (state) {
        ascon_acquire(&(state->state));
        ascon_free(&(state->state));
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_xof128_absorb
    (ascon_xof128_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    ascon_acquire(&(state->state));

    /* If we were squeezing output, then go back to the absorb phase */
    if (state->mode) {
        state->mode = 0;
        state->count = 0;
        ascon_permute(&(state->state), 0);
    }

    /* Handle the partial left-over block from last time */
    if (state->count) {
        temp = ASCON_XOF128_RATE - state->count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            ascon_absorb_partial(&(state->state), in, state->count, temp);
            state->count += temp;
            ascon_release(&(state->state));
            return;
        }
        ascon_absorb_partial(&(state->state), in, state->count, temp);
        state->count = 0;
        in += temp;
        inlen -= temp;
        ascon_permute(&(state->state), 0);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ASCON_XOF128_RATE) {
        ascon_absorb_8(&(state->state), in, 0);
        in += ASCON_XOF128_RATE;
        inlen -= ASCON_XOF128_RATE;
        ascon_permute(&(state->state), 0);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    if (temp > 0)
        ascon_absorb_partial(&(state->state), in, 0, temp);
    state->count = temp;

    /* Release access to the shared hardware */
    ascon_release(&(state->state));
}

void ascon_xof128_squeeze
    (ascon_xof128_state_t *state, unsigned char *out, size_t outlen)
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    ascon_acquire(&(state->state));

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->mode) {
        ascon_pad(&(state->state), state->count);
        state->count = 0;
        state->mode = 1;
    }

    /* Handle left-over partial blocks from last time */
    if (state->count) {
        temp = ASCON_XOF128_RATE - state->count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            ascon_squeeze_partial(&(state->state), out, state->count, temp);
            state->count += temp;
            ascon_release(&(state->state));
            return;
        }
        ascon_squeeze_partial(&(state->state), out, state->count, temp);
        out += temp;
        outlen -= temp;
        state->count = 0;
    }

    /* Handle full blocks */
    while (outlen >= ASCON_XOF128_RATE) {
        ascon_permute(&(state->state), 0);
        ascon_squeeze_8(&(state->state), out, 0);
        out += ASCON_XOF128_RATE;
        outlen -= ASCON_XOF128_RATE;
    }

    /* Handle the left-over block */
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_permute(&(state->state), 0);
        ascon_squeeze_partial(&(state->state), out, 0, temp);
        state->count = temp;
    }

    /* Release access to the shared hardware */
    ascon_release(&(state->state));
}

void ascon_xof128_pad(ascon_xof128_state_t *state)
{
    if (state->mode) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary.
         * The input data was already padded prior to squeezing. */
        ascon_xof128_absorb(state, 0, 0);
    } else {
        /* Pad and invoke the permutation */
        ascon_acquire(&(state->state));
        ascon_pad(&(state->state), state->count);
        ascon_permute(&(state->state), 0);
        ascon_release(&(state->state));
        state->count = 0;
    }
}

void ascon_xof128_zero_pad(ascon_xof128_state_t *state)
{
    if (state->mode) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        ascon_xof128_absorb(state, 0, 0);
    } else if (state->count != 0) {
        /* Not currently aligned, so invoke the permutation */
        ascon_acquire(&(state->state));
        ascon_permute(&(state->state), 0);
        ascon_release(&(state->state));
        state->count = 0;
    }
}

void ascon_xof128_copy
    (ascon_xof128_state_t *dest, const ascon_xof128_state_t *src)
{
    if (dest != src) {
        ascon_init(&(dest->state));
        ascon_copy(&(dest->state), &(src->state));
        ascon_release(&(dest->state));
        dest->count = src->count;
        dest->mode = src->mode;
    }
}
