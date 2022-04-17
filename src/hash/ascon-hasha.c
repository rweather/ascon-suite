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

#include <ascon/hash.h>
#include "core/ascon-util-snp.h"
#include <string.h>

int ascon_hasha(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_hasha_init(&state);
    ascon_xofa_absorb(&state, in, inlen);
    ascon_xofa_squeeze(&state, out, ASCON_HASH_SIZE);
    ascon_xofa_free(&state);
    return 0;
}

void ascon_hasha_init(ascon_hash_state_t *state)
{
    /* IV for ASCON-HASHA after processing it with the permutation */
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

void ascon_hasha_reinit(ascon_hash_state_t *state)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_hasha_init(state);
#else
    ascon_hasha_free(state);
    ascon_hasha_init(state);
#endif
}

void ascon_hasha_free(ascon_hash_state_t *state)
{
    if (state) {
        ascon_acquire(&(state->state));
        ascon_free(&(state->state));
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_hasha_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xofa_absorb(state, in, inlen);
}

void ascon_hasha_finalize(ascon_hash_state_t *state, unsigned char *out)
{
    ascon_xofa_squeeze(state, out, ASCON_HASH_SIZE);
}
