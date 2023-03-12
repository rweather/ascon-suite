/*
 * Copyright (C) 2023 Southern Storm Software, Pty Ltd.
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

#include <ascon/kmac.h>
#include <ascon/utility.h>
#include "hash/ascon-xof-internal.h"
#include "core/ascon-util-snp.h"
#include <string.h>

/**
 * \brief Intializes a ASCON-KMAC context with the first block pre-computed.
 *
 * \param state Points to the internal ASCON-XOF state to initialize.
 */
static void ascon_kmac_init_precomputed(ascon_xof_state_t *state)
{
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0x7a09132495dfa176ULL, 0x1b19e04f31cc4caeULL,
        0x64ba72afaa61d2b1ULL, 0xd2964e09a5169084ULL,
        0x05bc6c865abe514bULL
    };
    memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0xc1527f1e, 0x72148bc5, 0x558b5aa2, 0x32c34a2f,
        0xa4c309c5, 0x4f5ff49c, 0xc6a13642, 0x9932c188,
        0x36a2c6d9, 0x0e693f03
    };
    memcpy(state->state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0x7a, 0x09, 0x13, 0x24, 0x95, 0xdf, 0xa1, 0x76,
        0x1b, 0x19, 0xe0, 0x4f, 0x31, 0xcc, 0x4c, 0xae,
        0x64, 0xba, 0x72, 0xaf, 0xaa, 0x61, 0xd2, 0xb1,
        0xd2, 0x96, 0x4e, 0x09, 0xa5, 0x16, 0x90, 0x84,
        0x05, 0xbc, 0x6c, 0x86, 0x5a, 0xbe, 0x51, 0x4b
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

void ascon_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen)
{
    ascon_kmac_state_t state;
    ascon_kmac_init(&state, key, keylen, custom, customlen, outlen);
    ascon_xof_absorb(&(state.xof), in, inlen);
    ascon_xof_squeeze(&(state.xof), out, outlen);
    ascon_kmac_free(&state);
}

void ascon_kmac_init
    (ascon_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
    if (outlen == ASCON_KMAC_SIZE) {
        ascon_kmac_init_precomputed(&(state->xof));
        ascon_xof_absorb_custom(&(state->xof), custom, customlen);
    } else {
        ascon_xof_init_custom(&(state->xof), "KMAC", custom, customlen, outlen);
    }
    ascon_xof_absorb(&(state->xof), key, keylen);
}

void ascon_kmac_reinit
    (ascon_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
    ascon_kmac_free(state);
    ascon_kmac_init(state, key, keylen, custom, customlen, outlen);
}

void ascon_kmac_free(ascon_kmac_state_t *state)
{
    if (state)
        ascon_xof_free(&(state->xof));
}

void ascon_kmac_absorb
    (ascon_kmac_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xof_absorb(&(state->xof), in, inlen);
}

void ascon_kmac_squeeze
    (ascon_kmac_state_t *state, unsigned char *out, size_t outlen)
{
    ascon_xof_squeeze(&(state->xof), out, outlen);
}
