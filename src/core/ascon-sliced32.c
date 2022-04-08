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

/* SnP helper functions for backends that use the "sliced32" method */

#include "ascon-sliced32.h"
#include "ascon-util.h"

#if defined(ASCON_BACKEND_SLICED32)

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
    uint64_t value;
    unsigned posn, shift, ofs, len;
    ofs = offset & 7U;
    if (ofs != 0U) {
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        value = 0;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_absorb_word64(state, value, offset / 8U);
        data += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_absorb_sliced(state, data, offset / 8U);
        data += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        shift = 56U;
        value = 0;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_absorb_word64(state, value, offset / 8U);
    }
}

void ascon_overwrite_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        ofs = offset & 7U;
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
        data += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_set_sliced(state, data, offset / 8U);
        data += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = 56U;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
    }
}

void ascon_overwrite_with_zeroes
    (ascon_state_t *state, unsigned offset, unsigned size)
{
    uint64_t value;
    unsigned posn, ofs;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        posn = 8U - ofs;
        if (posn > size)
            posn = size;
        value = (value & (~((uint64_t)0)) << ((8U - ofs) * 8)) |
                (value & ((((uint64_t)1) << ((8U - ofs - posn) * 8)) - 1U));
        ascon_set_word64(state, value, offset / 8U);
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        state->S[offset / 8U] = 0;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        value &= (~((uint64_t)0)) >> (size * 8);
        ascon_set_word64(state, value, offset / 8U);
    }
}

void ascon_extract_bytes
    (const ascon_state_t *state, uint8_t *data, unsigned offset, unsigned size)
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            data[posn] = (uint8_t)(value >> shift);
        }
        data += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_squeeze_sliced(state, data, offset / 8U);
        data += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = 56U;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            data[posn] = (uint8_t)(value >> shift);
        }
    }
}

void ascon_extract_and_add_bytes
    (const ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size)
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            output[posn] = input[posn] ^ (uint8_t)(value >> shift);
        }
        output += posn;
        input += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_decrypt_sliced_no_insert(state, output, input, offset / 8U);
        output += 8;
        input += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = 56U;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            output[posn] = input[posn] ^ (uint8_t)(value >> shift);
        }
    }
}

void ascon_extract_and_overwrite_bytes
    (ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size)
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    uint8_t in;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            in = input[posn];
            output[posn] = in ^ (uint8_t)(value >> shift);
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)in) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
        output += posn;
        input += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_decrypt_sliced(state, output, input, offset / 8U);
        output += 8;
        input += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = 56U;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            in = input[posn];
            output[posn] = in ^ (uint8_t)(value >> shift);
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)in) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
    }
}

#endif /* ASCON_BACKEND_SLICED32 */
