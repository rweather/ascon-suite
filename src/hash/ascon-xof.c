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
#include "ascon-util-snp.h"

int ascon_xof(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_xof_init(&state);
    ascon_xof_absorb(&state, in, inlen);
    ascon_xof_squeeze(&state, out, ASCON_HASH_SIZE);
    return 0;
}

void ascon_xof_init(ascon_xof_state_t *state)
{
    /* IV for ASCON-XOF after processing it with the permutation */
    static unsigned char const xof_iv[40] = {
        0xb5, 0x7e, 0x27, 0x3b, 0x81, 0x4c, 0xd4, 0x16,
        0x2b, 0x51, 0x04, 0x25, 0x62, 0xae, 0x24, 0x20,
        0x66, 0xa3, 0xa7, 0x76, 0x8d, 0xdf, 0x22, 0x18,
        0x5a, 0xad, 0x0a, 0x7a, 0x81, 0x53, 0x65, 0x0c,
        0x4f, 0x3e, 0x0e, 0x32, 0x53, 0x94, 0x93, 0xb6
    };
    memcpy(state->state.B, xof_iv, sizeof(xof_iv));
    ascon_from_regular(&(state->state));
    state->count = 0;
    state->mode = 0;
}

void ascon_xof_init_fixed(ascon_xof_state_t *state, size_t outlen)
{
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    if (outlen >= (((size_t)1) << 29))
        outlen = 0; /* Too large, so switch to arbitrary-length output */
#endif
    if (outlen == 0U) {
        /* Output length of zero is equivalent to regular XOF */
        ascon_xof_init(state);
    } else if (outlen == 32U) {
        /* Output length of 32 is equivalent to ASCON-HASH */
        static unsigned char const hash_iv[40] = {
            /* IV for ASCON-HASH after processing it with the permutation */
            0xee, 0x93, 0x98, 0xaa, 0xdb, 0x67, 0xf0, 0x3d,
            0x8b, 0xb2, 0x18, 0x31, 0xc6, 0x0f, 0x10, 0x02,
            0xb4, 0x8a, 0x92, 0xdb, 0x98, 0xd5, 0xda, 0x62,
            0x43, 0x18, 0x99, 0x21, 0xb8, 0xf8, 0xe3, 0xe8,
            0x34, 0x8f, 0xa5, 0xc9, 0xd5, 0x25, 0xe1, 0x40
        };
        memcpy(state->state.B, hash_iv, sizeof(hash_iv));
        ascon_from_regular(&(state->state));
        state->count = 0;
        state->mode = 0;
    } else {
        /* For all other lengths, we need to run the permutation
         * to get the initial block for the XOF process */
        be_store_word64(state->state.B, 0x00400c0000000000ULL | (outlen * 8UL));
        memset(state->state.B + 8, 0, sizeof(state->state.B) - 8);
        ascon_from_regular(&(state->state));
        ascon_permute(&(state->state), 0);
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_xof_absorb
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
        ascon_permute(&(state->state), 0);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ASCON_XOF_RATE) {
        ascon_absorb_8(&(state->state), in);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_permute(&(state->state), 0);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    if (temp > 0)
        ascon_absorb_partial(&(state->state), in, 0, temp);
    state->count = temp;
}

void ascon_xof_squeeze
    (ascon_xof_state_t *state, unsigned char *out, size_t outlen)
{
    unsigned temp;

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->mode) {
        ascon_pad(&(state->state), state->count);
        state->count = 0;
        state->mode = 1;
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
    }

    /* Handle full blocks */
    while (outlen >= ASCON_XOF_RATE) {
        ascon_permute(&(state->state), 0);
        ascon_squeeze_8(&(state->state), out);
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }

    /* Handle the left-over block */
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_permute(&(state->state), 0);
        ascon_squeeze_partial(&(state->state), out, 0, temp);
        state->count = temp;
    }
}

void ascon_xof_pad(ascon_xof_state_t *state)
{
    if (state->mode) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        ascon_xof_absorb(state, 0, 0);
    } else if (state->count != 0) {
        /* Not currently aligned, so invoke the permutation */
        ascon_permute(&(state->state), 0);
        state->count = 0;
    }
}
