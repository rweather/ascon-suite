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

void ascon_hash(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_hash_state_t state;
    ascon_hash_init(&state);
    ascon_xof_absorb(&(state.xof), in, inlen);
    ascon_xof_squeeze(&(state.xof), out, ASCON_HASH_SIZE);
    ascon_xof_free(&(state.xof));
}

void ascon_hash_init(ascon_hash_state_t *state)
{
    /* IV for ASCON-HASH after processing it with the permutation */
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0xee9398aadb67f03dULL, 0x8bb21831c60f1002ULL,
        0xb48a92db98d5da62ULL, 0x43189921b8f8e3e8ULL,
        0x348fa5c9d525e140ULL
    };
    memcpy(state->xof.state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0xa540dbc7, 0xf9afb5c6, 0x1445a340, 0xbd249301,
        0x604d4fc8, 0xcb9ba8b5, 0x94514c98, 0x12a4eede,
        0x6339f398, 0x4bca84c0
    };
    memcpy(state->xof.state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0xee, 0x93, 0x98, 0xaa, 0xdb, 0x67, 0xf0, 0x3d,
        0x8b, 0xb2, 0x18, 0x31, 0xc6, 0x0f, 0x10, 0x02,
        0xb4, 0x8a, 0x92, 0xdb, 0x98, 0xd5, 0xda, 0x62,
        0x43, 0x18, 0x99, 0x21, 0xb8, 0xf8, 0xe3, 0xe8,
        0x34, 0x8f, 0xa5, 0xc9, 0xd5, 0x25, 0xe1, 0x40
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

void ascon_hash_reinit(ascon_hash_state_t *state)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_hash_init(state);
#else
    ascon_hash_free(state);
    ascon_hash_init(state);
#endif
}

void ascon_hash_free(ascon_hash_state_t *state)
{
    ascon_xof_free(&(state->xof));
}

void ascon_hash_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xof_absorb(&(state->xof), in, inlen);
}

void ascon_hash_finalize(ascon_hash_state_t *state, unsigned char *out)
{
    ascon_xof_squeeze(&(state->xof), out, ASCON_HASH_SIZE);
}

void ascon_hash_copy(ascon_hash_state_t *dest, const ascon_hash_state_t *src)
{
    ascon_xof_copy(&(dest->xof), &(src->xof));
}
