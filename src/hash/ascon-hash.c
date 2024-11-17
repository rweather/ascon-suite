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

void ascon_hash256(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_hash256_state_t state;
    ascon_hash256_init(&state);
    ascon_xof128_absorb(&(state.xof), in, inlen);
    ascon_xof128_squeeze(&(state.xof), out, ASCON_HASH256_SIZE);
    ascon_xof128_free(&(state.xof));
}

void ascon_hash256_init(ascon_hash256_state_t *state)
{
    /* IV for Ascon-Hash256 after processing it with the permutation */
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0x9b1e5494e934d681ULL, 0x4bc3a01e333751d2ULL,
        0xae65396c6b34b81aULL, 0x3c7fd4a4d56a4db3ULL,
        0x1a5c464906c5976dULL
    };
    memcpy(state->xof.state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0x56e696e1, 0xb308e498, 0x990657dc, 0x39c35509,
        0x2b5a9644, 0xf46674e3, 0x6fe2f8b5, 0x678c872d,
        0x4ea92b7b, 0x32121896
    };
    memcpy(state->xof.state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0x81, 0xd6, 0x34, 0xe9, 0x94, 0x54, 0x1e, 0x9b,
        0xd2, 0x51, 0x37, 0x33, 0x1e, 0xa0, 0xc3, 0x4b,
        0x1a, 0xb8, 0x34, 0x6b, 0x6c, 0x39, 0x65, 0xae,
        0xb3, 0x4d, 0x6a, 0xd5, 0xa4, 0xd4, 0x7f, 0x3c,
        0x6d, 0x97, 0xc5, 0x06, 0x49, 0x46, 0x5c, 0x1a
    };
#if defined(ASCON_BACKEND_DIRECT_XOR)
    memcpy(state->xof.state.B, iv, sizeof(iv));
#else
    ascon_init(&(state->xof.state));
    ascon_overwrite_bytes(&(state->xof.state), iv, sizeof(iv));
    ascon_release(&(state->xof.state));
#endif
#endif
    state->xof.count = 0;
    state->xof.mode = 0;
}

void ascon_hash256_reinit(ascon_hash256_state_t *state)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_hash256_init(state);
#else
    ascon_hash256_free(state);
    ascon_hash256_init(state);
#endif
}

void ascon_hash256_free(ascon_hash256_state_t *state)
{
    ascon_xof128_free(&(state->xof));
}

void ascon_hash256_update
    (ascon_hash256_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xof128_absorb(&(state->xof), in, inlen);
}

void ascon_hash256_finalize(ascon_hash256_state_t *state, unsigned char *out)
{
    ascon_xof128_squeeze(&(state->xof), out, ASCON_HASH256_SIZE);
}

void ascon_hash256_copy
    (ascon_hash256_state_t *dest, const ascon_hash256_state_t *src)
{
    ascon_xof128_copy(&(dest->xof), &(src->xof));
}
