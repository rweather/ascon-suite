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

/* SnP helper functions for backends that use the Direct-XOR method */

#include <ascon/permutation.h>
#include <ascon/utility.h>
#include "ascon-select-backend.h"
#include "ascon-util.h"
#include "ascon-util-snp.h"
#include <string.h>

#if defined(ASCON_BACKEND_DIRECT_XOR)

#if defined(ASCON_CHECK_ACQUIRE_RELEASE)
#include <stdlib.h>
#include <stdio.h>

static int acquired = 0;
#endif

void ascon_init(ascon_state_t *state)
{
#if defined(ASCON_CHECK_ACQUIRE_RELEASE)
    if (acquired) {
        fprintf(stderr, "acquire and release operations are not balanced\n");
        abort();
    }
    acquired = 1;
#endif
    state->S[0] = 0;
    state->S[1] = 0;
    state->S[2] = 0;
    state->S[3] = 0;
    state->S[4] = 0;
    ascon_backend_init(state);
}

void ascon_free(ascon_state_t *state)
{
#if defined(ASCON_CHECK_ACQUIRE_RELEASE)
    if (!acquired) {
        fprintf(stderr, "acquire and release operations are not balanced\n");
        abort();
    }
    acquired = 0;
#endif
    if (state) {
        ascon_backend_free(state);
        ascon_clean(state, sizeof(ascon_state_t));
    }
}

void ascon_add_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        state->B[offset] ^= *data++;
        ++offset;
        --size;
    }
}

void ascon_overwrite_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        state->B[offset] = *data++;
        ++offset;
        --size;
    }
}

void ascon_overwrite_with_zeroes
    (ascon_state_t *state, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        state->B[offset] = 0;
        ++offset;
        --size;
    }
}

void ascon_extract_bytes
    (const ascon_state_t *state, uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        *data++ = state->B[offset];
        ++offset;
        --size;
    }
}

void ascon_extract_and_add_bytes
    (const ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        *output++ = *input++ ^ state->B[offset];
        ++offset;
        --size;
    }
}

void ascon_extract_and_overwrite_bytes
    (ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        unsigned char in = *input++;
        *output++ = in ^ state->B[offset];
        state->B[offset] = in;
        ++offset;
        --size;
    }
}

void ascon_release(ascon_state_t *state)
{
    /* Not needed in this implementation */
    (void)state;
#if defined(ASCON_CHECK_ACQUIRE_RELEASE)
    if (!acquired) {
        fprintf(stderr, "acquire and release operations are not balanced\n");
        abort();
    }
    acquired = 0;
#endif
}

void ascon_acquire(ascon_state_t *state)
{
    /* Not needed in this implementation */
    (void)state;
#if defined(ASCON_CHECK_ACQUIRE_RELEASE)
    if (acquired) {
        fprintf(stderr, "acquire and release operations are not balanced\n");
        abort();
    }
    acquired = 1;
#endif
}

void ascon_copy(ascon_state_t *dest, const ascon_state_t *src)
{
    memcpy(dest->B, src->B, sizeof(dest->B));
}

#endif /* ASCON_BACKEND_DIRECT_XOR */
