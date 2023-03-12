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
 * \brief Intializes a ASCON-KMACA context with the first block pre-computed.
 *
 * \param state Points to the internal ASCON-XOFA state to initialize.
 */
static void ascon_kmaca_init_precomputed(ascon_xofa_state_t *state)
{
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0x47d45e034222e472ULL, 0xed0da2bb5580c30aULL,
        0xedceed89ce04c765ULL, 0xffe052a5533eaa30ULL,
        0xc8be4956f967f91aULL
    };
    memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0xbee180ac, 0x183115c5, 0xb305f090, 0xe2df0893,
        0xbab1a2bb, 0xebeab094, 0xf8c3d604, 0xfc1c17f4,
        0x869edbd4, 0xaf21e5e3
    };
    memcpy(state->state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0x47, 0xd4, 0x5e, 0x03, 0x42, 0x22, 0xe4, 0x72,
        0xed, 0x0d, 0xa2, 0xbb, 0x55, 0x80, 0xc3, 0x0a,
        0xed, 0xce, 0xed, 0x89, 0xce, 0x04, 0xc7, 0x65,
        0xff, 0xe0, 0x52, 0xa5, 0x53, 0x3e, 0xaa, 0x30,
        0xc8, 0xbe, 0x49, 0x56, 0xf9, 0x67, 0xf9, 0x1a
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

void ascon_kmaca
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen)
{
    ascon_kmaca_state_t state;
    ascon_kmaca_init(&state, key, keylen, custom, customlen, outlen);
    ascon_xofa_absorb(&(state.xof), in, inlen);
    ascon_xofa_squeeze(&(state.xof), out, outlen);
    ascon_kmaca_free(&state);
}

void ascon_kmaca_init
    (ascon_kmaca_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
    if (outlen == ASCON_KMACA_SIZE) {
        ascon_kmaca_init_precomputed(&(state->xof));
        ascon_xofa_absorb_custom(&(state->xof), custom, customlen);
    } else {
        ascon_xofa_init_custom(&(state->xof), "KMAC", custom, customlen, outlen);
    }
    ascon_xofa_absorb(&(state->xof), key, keylen);
}

void ascon_kmaca_reinit
    (ascon_kmaca_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
    ascon_kmaca_free(state);
    ascon_kmaca_init(state, key, keylen, custom, customlen, outlen);
}

void ascon_kmaca_free(ascon_kmaca_state_t *state)
{
    if (state)
        ascon_xofa_free(&(state->xof));
}

void ascon_kmaca_absorb
    (ascon_kmaca_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xofa_absorb(&(state->xof), in, inlen);
}

void ascon_kmaca_squeeze
    (ascon_kmaca_state_t *state, unsigned char *out, size_t outlen)
{
    ascon_xofa_squeeze(&(state->xof), out, outlen);
}
