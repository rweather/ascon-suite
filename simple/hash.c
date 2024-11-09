/*
 * Copyright (C) 2024 Southern Storm Software, Pty Ltd.
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

#include "hash.h"
#include "permutation.h"
#include <string.h>

/**
 * \brief Rate of absorbing and squeezing.
 */
#define ASCON_HASH_RATE 8

static void ascon_simple_xof_internal
    (unsigned char *out, size_t outlen,
     const void *custom, size_t customlen,
     const void *data, size_t len, uint64_t iv)
{
    ascon_simple_state_t state;
    const unsigned char *d = (const unsigned char *)data;
    unsigned char *o = (unsigned char *)out;

    /* Initialise the hash state */
    ascon_simple_init_iv(&state, iv);
    ascon_simple_permute_12(&state);

    /* Absorb the customisation string if we have one.  This assumes
     * that the maximum customisation string length is <= 256 bytes. */
    if (custom) {
        const unsigned char *c = (const unsigned char *)custom;
        state.B[0] ^= (uint8_t)(customlen * 8); /* Need a bit length */
        state.B[1] ^= (uint8_t)(customlen >> 5);
        ascon_simple_permute_12(&state);
        while (customlen >= ASCON_HASH_RATE) {
            ascon_simple_xor(state.B, state.B, c, ASCON_HASH_RATE);
            ascon_simple_permute_12(&state);
            c += ASCON_HASH_RATE;
            customlen -= ASCON_HASH_RATE;
        }
        ascon_simple_xor(state.B, state.B, c, customlen);
        state.B[customlen] ^= 0x01;
        ascon_simple_permute_12(&state);
    }

    /* Absorb the input data */
    while (len >= ASCON_HASH_RATE) {
        ascon_simple_xor(state.B, state.B, d, ASCON_HASH_RATE);
        ascon_simple_permute_12(&state);
        d += ASCON_HASH_RATE;
        len -= ASCON_HASH_RATE;
    }

    /* Pad and absorb the final block */
    ascon_simple_xor(state.B, state.B, d, len);
    state.B[len] ^= 0x01;
    ascon_simple_permute_12(&state);

    /* Squeeze out data */
    while (outlen >= ASCON_HASH_RATE) {
        memcpy(o, state.B, ASCON_HASH_RATE);
        ascon_simple_permute_12(&state);
        o += ASCON_HASH_RATE;
        outlen -= ASCON_HASH_RATE;
    }
    if (outlen > 0) {
        memcpy(o, state.B, outlen);
    }
}

void ascon_simple_hash
    (unsigned char hash[ASCON_HASH_SIZE], const void *data, size_t len)
{
    ascon_simple_xof_internal
        (hash, ASCON_HASH_SIZE, 0, 0, data, len, 0x0000080100cc0002);
}

void ascon_simple_xof
    (unsigned char *out, size_t outlen, const void *data, size_t len)
{
    ascon_simple_xof_internal
        (out, outlen, 0, 0, data, len, 0x0000080000cc0003);
}

void ascon_simple_cxof
    (unsigned char *out, size_t outlen,
     const void *custom, size_t customlen,
     const void *data, size_t len)
{
    ascon_simple_xof_internal
        (out, outlen, custom, customlen, data, len, 0x0000080000cc0004);
}

void ascon_simple_cxof_prefix
    (unsigned char prefix[40], const void *custom, size_t customlen)
{
    ascon_simple_state_t state;
    const unsigned char *c = (const unsigned char *)custom;

    /* Initialise the hash state */
    ascon_simple_init_iv(&state, 0x0000080000cc0004);
    ascon_simple_permute_12(&state);

    /* Absorb the customisation string.  This assumes that the maximum
     * customisation string length is <= 256 bytes. */
    state.B[0] ^= (uint8_t)(customlen * 8); /* Need a bit length */
    state.B[1] ^= (uint8_t)(customlen >> 5);
    ascon_simple_permute_12(&state);
    while (customlen >= ASCON_HASH_RATE) {
        ascon_simple_xor(state.B, state.B, c, ASCON_HASH_RATE);
        ascon_simple_permute_12(&state);
        c += ASCON_HASH_RATE;
        customlen -= ASCON_HASH_RATE;
    }
    ascon_simple_xor(state.B, state.B, c, customlen);
    state.B[customlen] ^= 0x01;
    ascon_simple_permute_12(&state);

    /* Return the prefix */
    memcpy(prefix, state.B, 40);
}
