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

#include <ascon/kdf.h>
#include <ascon/utility.h>
#include "core/ascon-util.h"
#include "core/ascon-util-snp.h"
#include "hash/ascon-xof-internal.h"
#include <string.h>

void ascon_kdfa
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen)
{
    ascon_kdfa_state_t state;
    ascon_kdfa_init(&state, key, keylen, custom, customlen, outlen);
    ascon_xofa_squeeze(&(state.state), out, outlen);
    ascon_xofa_free(&(state.state));
}

void ascon_kdfa_init
    (ascon_kdfa_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
    ascon_xofa_init_custom(&(state->state), "KDF", custom, customlen, outlen);
    ascon_xofa_absorb(&(state->state), key, keylen);
}

void ascon_kdfa_reinit
    (ascon_kdfa_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_kdfa_init(state, key, keylen, custom, customlen, outlen);
#else
    ascon_kdfa_free(state);
    ascon_kdfa_init(state, key, keylen, custom, customlen, outlen);
#endif
}

void ascon_kdfa_free(ascon_kdfa_state_t *state)
{
    if (state)
        ascon_xofa_free(&(state->state));
}

void ascon_kdfa_squeeze
    (ascon_kdfa_state_t *state, unsigned char *out, size_t outlen)
{
    ascon_xofa_squeeze(&(state->state), out, outlen);
}
