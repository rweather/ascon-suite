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
#include <string.h>

int ascon_hash(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_hash_init(&state);
    ascon_xof_absorb(&state, in, inlen);
    ascon_xof_squeeze(&state, out, ASCON_HASH_SIZE);
    return 0;
}

void ascon_hash_init(ascon_hash_state_t *state)
{
    /* IV for ASCON-HASH after processing it with the permutation */
    static unsigned char const hash_iv[40] = {
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
}

void ascon_hash_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xof_absorb(state, in, inlen);
}

void ascon_hash_finalize(ascon_hash_state_t *state, unsigned char *out)
{
    ascon_xof_squeeze(state, out, ASCON_HASH_SIZE);
}
