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

#ifndef ASCON_UTIL_SNP_H
#define ASCON_UTIL_SNP_H

/*
 * Utilities to help with absorbing and squeezing data without the
 * function call overhead of the SnP API in <ascon/permutation.h>.
 *
 * These utilties are highly tied to the specific backend that is
 * selected so they are not suitable for the public-facing API.
 */

#include <ascon/permutation.h>
#include "ascon-select-backend.h"
#include "ascon-util.h"
#include <string.h>

#if defined(xxxxASCON_BACKEND_SLICED32)

#include "ascon-sliced32.h"

// TODO

#define ascon_separator(state) ((state)->W[8] ^= 0x01)

#elif defined(xxxxASCON_BACKEND_SLICED64)

// TODO

#define ascon_separator(state) ((state)->S[4] ^= 0x01)
#define ascon_pad(state, offset) \
    ((state)->S[(offset) / 8] ^= \
            (0x8000000000000000ULL >> (((offset) & 7) * 8)))

#elif defined(xxxxASCON_BACKEND_DIRECT_XOR)

#define ascon_separator(state) ((state)->B[39] ^= 0x01)
#define ascon_pad(state, offset) ((state)->B[(offset)] ^= 0x80)

#define ascon_absorb_8(state, data) \
    lw_xor_block((state)->B, (data), 8)
#define ascon_absorb_16(state, data) \
    lw_xor_block((state)->B, (data), 16)
#define ascon_absorb_partial(state, data, offset, count) \
    lw_xor_block((state)->B + (offset), (data), (count))

#define ascon_squeeze_8(state, data) \
    memcpy((data), (state)->B, 8)
#define ascon_squeeze_16(state, data) \
    memcpy((data), (state)->B, 16)
#define ascon_squeeze_partial(state, data, offset, count) \
    memcpy((data), (state)->B + (offset), (count))

#else /* ASCON_BACKEND_GENERIC */

#define ascon_separator(state) \
    do { \
        uint8_t sep = 0x01; \
        ascon_add_bytes((state), &sep, 39, 1); \
    } while (0)
#define ascon_pad(state, offset) \
    do { \
        uint8_t padding = 0x80; \
        ascon_add_bytes((state), &padding, (offset), 1); \
    } while (0)

#define ascon_absorb_8(state, data) \
    ascon_add_bytes((state), (data), 0, 8)
#define ascon_absorb_16(state, data) \
    ascon_add_bytes((state), (data), 0, 16)
#define ascon_absorb_partial(state, data, offset, count) \
    ascon_add_bytes((state), (data), (offset), (count))

#define ascon_squeeze_8(state, data) \
    ascon_extract_bytes((state), (data), 0, 8)
#define ascon_squeeze_16(state, data) \
    ascon_extract_bytes((state), (data), 0, 16)
#define ascon_squeeze_partial(state, data, offset, count) \
    ascon_extract_bytes((state), (data), (offset), (count))

#endif /* ASCON_BACKEND_GENERIC */

#endif
