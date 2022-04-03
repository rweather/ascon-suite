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

/* Non-assembly part of the AVR implementation of the ASCON permutation */

#include <ascon/permutation.h>
#include "ascon-permutation-select.h"
#include "ascon-internal-util.h"

#if defined(ASCON_BACKEND_AVR)

void ascon_init(ascon_state_t *state)
{
    state->S[0] = 0;
    state->S[1] = 0;
    state->S[2] = 0;
    state->S[3] = 0;
    state->S[4] = 0;
}

void ascon_to_regular(ascon_state_t *state)
{
    /* Already in big-endian byte order, so nothing to do */
    (void)state;
}

void ascon_from_regular(ascon_state_t *state)
{
    /* Already in big-endian byte order, so nothing to do */
    (void)state;
}

void ascon_set_iv_64(ascon_state_t *state, uint64_t iv)
{
    be_store_word64(state->B, iv);
}

void ascon_set_iv_32(ascon_state_t *state, uint32_t iv)
{
    be_store_word32(state->B, iv);
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

void ascon_add_and_extract_bytes
    (const ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        *output++ = (state->B[offset] ^= *input++);
        ++offset;
        --size;
    }
}

#endif /* ASCON_BACKEND_AVR */
