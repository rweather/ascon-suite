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

#if defined(ASCON_BACKEND_SLICED32)

#include "ascon-sliced32.h"

#define ascon_separator(state) ((state)->W[8] ^= 0x01)
#define ascon_pad(state, offset) \
    ((state)->W[((offset) / 8) * 2 + 1] ^= \
            (0x80000000U >> (((offset) & 7) * 4)))

#define ascon_absorb_8(state, data, offset) \
    ascon_absorb_sliced((state), (data), (offset) / 8)
#define ascon_absorb_16(state, data, offset) \
    do { \
        ascon_absorb_sliced((state), (data), (offset) / 8); \
        ascon_absorb_sliced((state), (data) + 8, (offset) / 8 + 1); \
    } while (0)
#define ascon_absorb_partial(state, data, offset, count) \
    ascon_add_bytes((state), (data), (offset), (count))

#define ascon_squeeze_8(state, data, offset) \
    ascon_squeeze_sliced((state), (data), (offset) / 8)
#define ascon_squeeze_16(state, data, offset) \
    do { \
        ascon_squeeze_sliced((state), (data), (offset) / 8); \
        ascon_squeeze_sliced((state), (data) + 8, (offset) / 8 + 1); \
    } while (0)
#define ascon_squeeze_partial(state, data, offset, count) \
    ascon_extract_bytes((state), (data), (offset), (count))

#define ascon_encrypt_8(state, dest, src, offset) \
    ascon_encrypt_sliced((state), (dest), (src), (offset) / 8)
#define ascon_encrypt_16(state, dest, src, offset) \
    do { \
        ascon_encrypt_sliced((state), (dest), (src), (offset) / 8); \
        ascon_encrypt_sliced((state), (dest) + 8, (src) + 8, (offset) / 8 + 1); \
    } while (0)
#define ascon_encrypt_partial(state, dest, src, offset, count) \
    do { \
        ascon_add_bytes((state), (src), (offset), (count)); \
        ascon_extract_bytes((state), (dest), (offset), (count)); \
    } while (0)

#define ascon_decrypt_8(state, dest, src, offset) \
    ascon_decrypt_sliced((state), (dest), (src), (offset) / 8)
#define ascon_decrypt_16(state, dest, src, offset) \
    do { \
        ascon_decrypt_sliced((state), (dest), (src), (offset) / 8); \
        ascon_decrypt_sliced((state), (dest) + 8, (src) + 8, (offset) / 8 + 1); \
    } while (0)
#define ascon_decrypt_partial(state, dest, src, offset, count) \
    ascon_extract_and_overwrite_bytes((state), (src), (dest), (offset), (count))

#elif defined(ASCON_BACKEND_SLICED64)

#define ascon_separator(state) ((state)->S[4] ^= 0x01)
#define ascon_pad(state, offset) \
    ((state)->S[(offset) / 8] ^= \
            (0x8000000000000000ULL >> (((offset) & 7) * 8)))

#define ascon_absorb_8(state, data, offset) \
    ((state)->S[(offset) / 8] ^= be_load_word64((data)))
#define ascon_absorb_16(state, data, offset) \
    do { \
        ((state)->S[(offset) / 8] ^= be_load_word64((data))); \
        ((state)->S[(offset) / 8 + 1] ^= be_load_word64((data) + 8)); \
    } while (0)
#define ascon_absorb_partial(state, data, offset, count) \
    ascon_add_bytes((state), (data), (offset), (count))

#define ascon_squeeze_8(state, data, offset) \
    be_store_word64((data), (state)->S[(offset) / 8])
#define ascon_squeeze_16(state, data, offset) \
    do { \
        be_store_word64((data), (state)->S[(offset) / 8]); \
        be_store_word64((data) + 8, (state)->S[(offset) / 8 + 1]); \
    } while (0)
#define ascon_squeeze_partial(state, data, offset, count) \
    ascon_extract_bytes((state), (data), (offset), (count))

#define ascon_encrypt_8(state, dest, src, offset) \
    do { \
        (state)->S[(offset) / 8] ^= be_load_word64((src)); \
        be_store_word64((dest), (state)->S[(offset) / 8]); \
    } while (0)
#define ascon_encrypt_16(state, dest, src, offset) \
    do { \
        (state)->S[(offset) / 8] ^= be_load_word64((src)); \
        (state)->S[(offset) / 8 + 1] ^= be_load_word64((src) + 8); \
        be_store_word64((dest), (state)->S[(offset) / 8]); \
        be_store_word64((dest) + 8, (state)->S[(offset) / 8 + 1]); \
    } while (0)
#define ascon_encrypt_partial(state, dest, src, offset, count) \
    do { \
        ascon_add_bytes((state), (src), (offset), (count)); \
        ascon_extract_bytes((state), (dest), (offset), (count)); \
    } while (0)

#define ascon_decrypt_8(state, dest, src, offset) \
    do { \
        uint64_t word = be_load_word64((src)); \
        be_store_word64((dest), word ^ (state)->S[(offset) / 8]); \
        (state)->S[(offset) / 8] = word; \
    } while (0)
#define ascon_decrypt_16(state, dest, src, offset) \
    do { \
        uint64_t word = be_load_word64((src)); \
        be_store_word64((dest), word ^ (state)->S[(offset) / 8]); \
        (state)->S[(offset) / 8] = word; \
        word = be_load_word64((src) + 8); \
        be_store_word64((dest) + 8, word ^ (state)->S[(offset) / 8 + 1]); \
        (state)->S[(offset) / 8 + 1] = word; \
    } while (0)
#define ascon_decrypt_partial(state, dest, src, offset, count) \
    ascon_extract_and_overwrite_bytes((state), (src), (dest), (offset), (count))

#elif defined(ASCON_BACKEND_DIRECT_XOR) && !defined(ASCON_FORCE_GENERIC)

#define ascon_separator(state) ((state)->B[39] ^= 0x01)
#define ascon_pad(state, offset) ((state)->B[(offset)] ^= 0x80)

#define ascon_absorb_8(state, data, offset) \
    lw_xor_block((state)->B + (offset), (data), 8)
#define ascon_absorb_16(state, data, offset) \
    lw_xor_block((state)->B + (offset), (data), 16)
#define ascon_absorb_partial(state, data, offset, count) \
    lw_xor_block((state)->B + (offset), (data), (count))

#define ascon_squeeze_8(state, data, offset) \
    memcpy((data), (state)->B + (offset), 8)
#define ascon_squeeze_16(state, data, offset) \
    memcpy((data), (state)->B + (offset), 16)
#define ascon_squeeze_partial(state, data, offset, count) \
    memcpy((data), (state)->B + (offset), (count))

#define ascon_encrypt_8(state, dest, src, offset) \
    lw_xor_block_2_dest((dest), (state)->B + (offset), (src), 8)
#define ascon_encrypt_16(state, dest, src, offset) \
    lw_xor_block_2_dest((dest), (state)->B + (offset), (src), 16)
#define ascon_encrypt_partial(state, dest, src, offset, count) \
    lw_xor_block_2_dest((dest), (state)->B + (offset), (src), (count))

#define ascon_decrypt_8(state, dest, src, offset) \
    lw_xor_block_swap((dest), (state)->B + (offset), (src), 8)
#define ascon_decrypt_16(state, dest, src, offset) \
    lw_xor_block_swap((dest), (state)->B + (offset), (src), 16)
#define ascon_decrypt_partial(state, dest, src, offset, count) \
    lw_xor_block_swap((dest), (state)->B + (offset), (src), (count))

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

#define ascon_absorb_8(state, data, offset) \
    ascon_add_bytes((state), (data), (offset), 8)
#define ascon_absorb_16(state, data, offset) \
    ascon_add_bytes((state), (data), (offset), 16)
#define ascon_absorb_partial(state, data, offset, count) \
    ascon_add_bytes((state), (data), (offset), (count))

#define ascon_squeeze_8(state, data, offset) \
    ascon_extract_bytes((state), (data), (offset), 8)
#define ascon_squeeze_16(state, data, offset) \
    ascon_extract_bytes((state), (data), (offset), 16)
#define ascon_squeeze_partial(state, data, offset, count) \
    ascon_extract_bytes((state), (data), (offset), (count))

#define ascon_encrypt_8(state, dest, src, offset) \
    do { \
        ascon_add_bytes((state), (src), (offset), 8); \
        ascon_extract_bytes((state), (dest), (offset), 8); \
    } while (0)
#define ascon_encrypt_16(state, dest, src, offset) \
    do { \
        ascon_add_bytes((state), (src), (offset), 16); \
        ascon_extract_bytes((state), (dest), (offset), 16); \
    } while (0)
#define ascon_encrypt_partial(state, dest, src, offset, count) \
    do { \
        ascon_add_bytes((state), (src), (offset), (count)); \
        ascon_extract_bytes((state), (dest), (offset), (count)); \
    } while (0)

#define ascon_decrypt_8(state, dest, src, offset) \
    ascon_extract_and_overwrite_bytes((state), (src), (dest), (offset), 8)
#define ascon_decrypt_16(state, dest, src, offset) \
    ascon_extract_and_overwrite_bytes((state), (src), (dest), (offset), 16)
#define ascon_decrypt_partial(state, dest, src, offset, count) \
    ascon_extract_and_overwrite_bytes((state), (src), (dest), (offset), (count))

#endif /* ASCON_BACKEND_GENERIC */

#endif
