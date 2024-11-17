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
#include "core/ascon-util-snp.h"
#include <string.h>

void ascon_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen)
{
    ascon_kmac_state_t state;
    ascon_kmac_init(&state, key, keylen, custom, customlen);
    ascon_xof128_absorb(&(state.xof), in, inlen);
    ascon_xof128_squeeze(&(state.xof), out, outlen);
    ascon_kmac_free(&state);
}

void ascon_kmac_init
    (ascon_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen)
{
    ascon_cxof128_init_named(&(state->xof), "KMAC256", custom, customlen);
    ascon_xof128_absorb(&(state->xof), key, keylen);
}

void ascon_kmac_reinit
    (ascon_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen)
{
    ascon_kmac_free(state);
    ascon_kmac_init(state, key, keylen, custom, customlen);
}

void ascon_kmac_free(ascon_kmac_state_t *state)
{
    if (state)
        ascon_xof128_free(&(state->xof));
}

void ascon_kmac_absorb
    (ascon_kmac_state_t *state, const unsigned char *in, size_t inlen)
{
    ascon_xof128_absorb(&(state->xof), in, inlen);
}

void ascon_kmac_squeeze
    (ascon_kmac_state_t *state, unsigned char *out, size_t outlen)
{
    ascon_xof128_squeeze(&(state->xof), out, outlen);
}
