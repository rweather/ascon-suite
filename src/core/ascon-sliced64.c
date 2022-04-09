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

/* SnP helper functions for backends that use the "sliced64" method */

#include <ascon/permutation.h>
#include "ascon-select-backend.h"
#include "ascon-util.h"

#if defined(ASCON_BACKEND_SLICED64)

/** @cond ascon_c64 */

#if defined(LW_UTIL_LITTLE_ENDIAN)
#define ASCON_C64_BYTE_FOR_OFFSET(state, offset) \
    (state->B[((offset) & 0x38) + (7 - (offset & 0x07))])
#else
#define ASCON_C64_BYTE_FOR_OFFSET(state, offset) (state->B[(offset)])
#endif

/** @endcond */

void ascon_init(ascon_state_t *state)
{
    state->S[0] = 0;
    state->S[1] = 0;
    state->S[2] = 0;
    state->S[3] = 0;
    state->S[4] = 0;
}

void ascon_add_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        ASCON_C64_BYTE_FOR_OFFSET(state, offset) ^= *data++;
        ++offset;
        --size;
    }
}

void ascon_overwrite_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        ASCON_C64_BYTE_FOR_OFFSET(state, offset) = *data++;
        ++offset;
        --size;
    }
}

void ascon_overwrite_with_zeroes
    (ascon_state_t *state, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        ASCON_C64_BYTE_FOR_OFFSET(state, offset) = 0;
        ++offset;
        --size;
    }
}

void ascon_extract_bytes
    (const ascon_state_t *state, uint8_t *data, unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        *data++ = ASCON_C64_BYTE_FOR_OFFSET(state, offset);
        ++offset;
        --size;
    }
}

void ascon_extract_and_add_bytes
    (const ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size)
{
    while (offset < 40 && size > 0) {
        *output++ = *input++ ^ ASCON_C64_BYTE_FOR_OFFSET(state, offset);
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
        *output++ = in ^ ASCON_C64_BYTE_FOR_OFFSET(state, offset);
        ASCON_C64_BYTE_FOR_OFFSET(state, offset) = in;
        ++offset;
        --size;
    }
}

#endif /* ASCON_BACKEND_SLICED64 */
