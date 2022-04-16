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
#include "core/ascon-util-snp.h"

int ascon_xofa(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_xofa_init(&state);
    ascon_xofa_absorb(&state, in, inlen);
    ascon_xofa_squeeze(&state, out, ASCON_HASH_SIZE);
    ascon_free(&(state.state));
    return 0;
}

void ascon_xofa_init(ascon_xof_state_t *state)
{
    /* IV for ASCON-XOFA after processing it with the permutation */
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0x44906568b77b9832ULL, 0xcd8d6cae53455532ULL,
        0xf7b5212756422129ULL, 0x246885e1de0d225bULL,
        0xa8cb5ce33449973fULL
    };
    memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0xa4b87d44, 0x0846d7a5, 0xb3a2dbf4, 0xaa6f1005,
        0xf713e811, 0xdc451146, 0x2839e30d, 0x468cb253,
        0x09e96977, 0xeb2d4297
    };
    memcpy(state->state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0x44, 0x90, 0x65, 0x68, 0xb7, 0x7b, 0x98, 0x32,
        0xcd, 0x8d, 0x6c, 0xae, 0x53, 0x45, 0x55, 0x32,
        0xf7, 0xb5, 0x21, 0x27, 0x56, 0x42, 0x21, 0x29,
        0x24, 0x68, 0x85, 0xe1, 0xde, 0x0d, 0x22, 0x5b,
        0xa8, 0xcb, 0x5c, 0xe3, 0x34, 0x49, 0x97, 0x3f
    };
    memcpy(state->state.B, iv, sizeof(iv));
#if !defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_from_regular(&(state->state));
#endif
#endif
    state->count = 0;
    state->mode = 0;
}

void ascon_xofa_init_fixed(ascon_xof_state_t *state, size_t outlen)
{
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    if (outlen >= (((size_t)1) << 29))
        outlen = 0; /* Too large, so switch to arbitrary-length output */
#endif
    if (outlen == 0U) {
        /* Output length of zero is equivalent to regular XOF */
        ascon_xofa_init(state);
    } else if (outlen == 32U) {
        /* Output length of 32 is equivalent to ASCON-HASHA */
#if defined(ASCON_BACKEND_SLICED64)
        static uint64_t const iv[5] = {
            0x01470194fc6528a6ULL, 0x738ec38ac0adffa7ULL,
            0x2ec8e3296c76384cULL, 0xd6f6a54d7f52377dULL,
            0xa13c42a223be8d87ULL
        };
        memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
        static uint32_t const iv[10] = {
            0x1b16eb02, 0x0108e46d, 0xd29083f3, 0x5b9b8efd,
            0x2891ae4a, 0x7ad66562, 0xee3bfc7f, 0x9dc27156,
            0x16801633, 0xc61d5fa9
        };
        memcpy(state->state.W, iv, sizeof(iv));
#else
        static uint8_t const iv[40] = {
            0x01, 0x47, 0x01, 0x94, 0xfc, 0x65, 0x28, 0xa6,
            0x73, 0x8e, 0xc3, 0x8a, 0xc0, 0xad, 0xff, 0xa7,
            0x2e, 0xc8, 0xe3, 0x29, 0x6c, 0x76, 0x38, 0x4c,
            0xd6, 0xf6, 0xa5, 0x4d, 0x7f, 0x52, 0x37, 0x7d,
            0xa1, 0x3c, 0x42, 0xa2, 0x23, 0xbe, 0x8d, 0x87
        };
        memcpy(state->state.B, iv, sizeof(iv));
#if !defined(ASCON_BACKEND_DIRECT_XOR)
        ascon_from_regular(&(state->state));
#endif
#endif
        state->count = 0;
        state->mode = 0;
    } else {
        /* For all other lengths, we need to run the permutation
         * to get the initial block for the XOF process */
        be_store_word64(state->state.B, 0x00400c0400000000ULL | (outlen * 8UL));
        memset(state->state.B + 8, 0, sizeof(state->state.B) - 8);
        ascon_from_regular(&(state->state));
        ascon_permute(&(state->state), 0);
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_xofa_free(ascon_xof_state_t *state)
{
    if (state) {
        ascon_free(&(state->state));
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_xofa_absorb
    (ascon_xof_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned temp;

    /* If we were squeezing output, then go back to the absorb phase */
    if (state->mode) {
        state->mode = 0;
        state->count = 0;
        ascon_permute(&(state->state), 0);
    }

    /* Handle the partial left-over block from last time */
    if (state->count) {
        temp = ASCON_XOF_RATE - state->count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            ascon_absorb_partial(&(state->state), in, state->count, temp);
            state->count += temp;
            return;
        }
        ascon_absorb_partial(&(state->state), in, state->count, temp);
        state->count = 0;
        in += temp;
        inlen -= temp;
        ascon_permute(&(state->state), 4);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ASCON_XOF_RATE) {
        ascon_absorb_8(&(state->state), in, 0);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_permute(&(state->state), 4);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    if (temp > 0)
        ascon_absorb_partial(&(state->state), in, 0, temp);
    state->count = temp;
}

void ascon_xofa_squeeze
    (ascon_xof_state_t *state, unsigned char *out, size_t outlen)
{
    unsigned temp;

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->mode) {
        ascon_pad(&(state->state), state->count);
        state->count = 0;
        state->mode = 1;
        ascon_permute(&(state->state), 0);
    }

    /* Handle left-over partial blocks from last time */
    if (state->count) {
        temp = ASCON_XOF_RATE - state->count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            ascon_squeeze_partial(&(state->state), out, state->count, temp);
            state->count += temp;
            return;
        }
        ascon_squeeze_partial(&(state->state), out, state->count, temp);
        out += temp;
        outlen -= temp;
        state->count = 0;
        ascon_permute(&(state->state), 4);
    }

    /* Handle full blocks */
    while (outlen >= ASCON_XOF_RATE) {
        ascon_squeeze_8(&(state->state), out, 0);
        ascon_permute(&(state->state), 4);
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }

    /* Handle the left-over block */
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_squeeze_partial(&(state->state), out, 0, temp);
        state->count = temp;
    }
}

void ascon_xofa_pad(ascon_xof_state_t *state)
{
    if (state->mode) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        ascon_xofa_absorb(state, 0, 0);
    } else if (state->count != 0) {
        /* Not currently aligned, so invoke the permutation */
        ascon_permute(&(state->state), 4);
        state->count = 0;
    }
}
