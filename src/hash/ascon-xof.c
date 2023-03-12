/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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

#include <ascon/xof.h>
#include "core/ascon-util-snp.h"
#include "hash/ascon-xof-internal.h"
#include <string.h>

void ascon_xof(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_xof_state_t state;
    ascon_xof_init(&state);
    ascon_xof_absorb(&state, in, inlen);
    ascon_xof_squeeze(&state, out, ASCON_HASH_SIZE);
    ascon_xof_free(&state);
}

void ascon_xof_init(ascon_xof_state_t *state)
{
    /* IV for ASCON-XOF after processing it with the permutation */
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0xb57e273b814cd416ULL, 0x2b51042562ae2420ULL,
        0x66a3a7768ddf2218ULL, 0x5aad0a7a8153650cULL,
        0x4f3e0e32539493b6ULL
    };
    memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0x7e351ae6, 0xc7578281, 0x1d238220, 0x70045f44,
        0xa13e3f04, 0x5dd5ab52, 0xc30c1db2, 0x3e378142,
        0xb624d656, 0x3735189d
    };
    memcpy(state->state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0xb5, 0x7e, 0x27, 0x3b, 0x81, 0x4c, 0xd4, 0x16,
        0x2b, 0x51, 0x04, 0x25, 0x62, 0xae, 0x24, 0x20,
        0x66, 0xa3, 0xa7, 0x76, 0x8d, 0xdf, 0x22, 0x18,
        0x5a, 0xad, 0x0a, 0x7a, 0x81, 0x53, 0x65, 0x0c,
        0x4f, 0x3e, 0x0e, 0x32, 0x53, 0x94, 0x93, 0xb6
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

void ascon_xof_init_fixed(ascon_xof_state_t *state, size_t outlen)
{
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    if (outlen >= (((size_t)1) << 29))
        outlen = 0; /* Too large, so switch to arbitrary-length output */
#endif
    if (outlen == 0U) {
        /* Output length of zero is equivalent to regular XOF */
        ascon_xof_init(state);
    } else if (outlen == 32U) {
        /* Output length of 32 is equivalent to ASCON-HASH */
#if defined(ASCON_BACKEND_SLICED64)
        static uint64_t const iv[5] = {
            0xee9398aadb67f03dULL, 0x8bb21831c60f1002ULL,
            0xb48a92db98d5da62ULL, 0x43189921b8f8e3e8ULL,
            0x348fa5c9d525e140ULL
        };
        memcpy(state->state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
        static uint32_t const iv[10] = {
            0xa540dbc7, 0xf9afb5c6, 0x1445a340, 0xbd249301,
            0x604d4fc8, 0xcb9ba8b5, 0x94514c98, 0x12a4eede,
            0x6339f398, 0x4bca84c0
        };
        memcpy(state->state.W, iv, sizeof(iv));
#else
        static uint8_t const iv[40] = {
            0xee, 0x93, 0x98, 0xaa, 0xdb, 0x67, 0xf0, 0x3d,
            0x8b, 0xb2, 0x18, 0x31, 0xc6, 0x0f, 0x10, 0x02,
            0xb4, 0x8a, 0x92, 0xdb, 0x98, 0xd5, 0xda, 0x62,
            0x43, 0x18, 0x99, 0x21, 0xb8, 0xf8, 0xe3, 0xe8,
            0x34, 0x8f, 0xa5, 0xc9, 0xd5, 0x25, 0xe1, 0x40
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
    } else {
        /* For all other lengths, we need to run the permutation
         * to get the initial block for the XOF process */
        uint8_t iv[8];
        ascon_init(&(state->state));
        be_store_word64(iv, 0x00400c0000000000ULL | (outlen * 8UL));
        ascon_overwrite_bytes(&(state->state), iv, 0, 8);
        ascon_permute(&(state->state), 0);
        ascon_release(&(state->state));
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_xof_absorb_custom
    (ascon_xof_state_t *state, const unsigned char *custom, size_t customlen)
{
    if (customlen > 0) {
        ascon_xof_absorb(state, custom, customlen);
        ascon_acquire(&(state->state));
        ascon_pad(&(state->state), state->count);
        ascon_permute(&(state->state), 0);
        ascon_separator(&(state->state));
        ascon_release(&(state->state));
        state->count = 0;
    }
}

void ascon_xof_init_custom
    (ascon_xof_state_t *state, const char *function_name,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
    /* Format the initial block with the function name and output length */
    uint8_t temp[ASCON_HASH_SIZE];
    size_t len = function_name ? strlen(function_name) : 0;
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    if (outlen >= (((size_t)1) << 29))
        outlen = 0; /* Too large, so switch to arbitrary-length output */
#endif
    if (len == 0) {
        /* No function name specified */
        memset(temp, 0, ASCON_HASH_SIZE);
    } else if (len <= 32) {
        /* Pad the function name with zeroes */
        memcpy(temp, function_name, len);
        memset(temp + len, 0, ASCON_HASH_SIZE - len);
    } else {
        /* Compute ASCON-HASH(function_name) */
        ascon_xof_init_fixed(state, ASCON_HASH_SIZE);
        ascon_xof_absorb(state, (const unsigned char *)function_name, len);
        ascon_xof_squeeze(state, temp, ASCON_HASH_SIZE);
        ascon_xof_free(state);
    }
    ascon_init(&(state->state));
    ascon_overwrite_bytes(&(state->state), temp, 8, ASCON_HASH_SIZE);
    be_store_word64(temp, 0x00400c0000000000ULL | (outlen * 8UL));
    ascon_overwrite_bytes(&(state->state), temp, 0, 8);
    ascon_permute(&(state->state), 0);
    ascon_release(&(state->state));
    state->count = 0;
    state->mode = 0;

    /* Absorb the customization string */
    ascon_xof_absorb_custom(state, custom, customlen);
}

void ascon_xof_reinit(ascon_xof_state_t *state)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_xof_init(state);
#else
    ascon_xof_free(state);
    ascon_xof_init(state);
#endif
}

void ascon_xof_reinit_fixed(ascon_xof_state_t *state, size_t outlen)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_xof_init_fixed(state, outlen);
#else
    ascon_xof_free(state);
    ascon_xof_init_fixed(state, outlen);
#endif
}

void ascon_xof_reinit_custom
    (ascon_xof_state_t *state, const char *function_name,
     const unsigned char *custom, size_t customlen, size_t outlen)
{
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    ascon_xof_init_custom(state, function_name, custom, customlen, outlen);
#else
    ascon_xof_free(state);
    ascon_xof_init_custom(state, function_name, custom, customlen, outlen);
#endif
}

void ascon_xof_free(ascon_xof_state_t *state)
{
    if (state) {
        ascon_acquire(&(state->state));
        ascon_free(&(state->state));
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_xof_absorb
    (ascon_xof_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    ascon_acquire(&(state->state));

    /* If we were squeezing output, then go back to the absorb phase */
    if (state->mode) {
        state->mode = 0;
        state->count = 0;
        ascon_permute(&(state->state), 0);
    }

    /* Handle the partial left-over block from last time */
    if (state->count) {
        temp = ASCON_XOF_RATE - state->count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            ascon_absorb_partial(&(state->state), in, state->count, temp);
            state->count += temp;
            ascon_release(&(state->state));
            return;
        }
        ascon_absorb_partial(&(state->state), in, state->count, temp);
        state->count = 0;
        in += temp;
        inlen -= temp;
        ascon_permute(&(state->state), 0);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ASCON_XOF_RATE) {
        ascon_absorb_8(&(state->state), in, 0);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_permute(&(state->state), 0);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    if (temp > 0)
        ascon_absorb_partial(&(state->state), in, 0, temp);
    state->count = temp;

    /* Release access to the shared hardware */
    ascon_release(&(state->state));
}

void ascon_xof_squeeze
    (ascon_xof_state_t *state, unsigned char *out, size_t outlen)
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    ascon_acquire(&(state->state));

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->mode) {
        ascon_pad(&(state->state), state->count);
        state->count = 0;
        state->mode = 1;
    }

    /* Handle left-over partial blocks from last time */
    if (state->count) {
        temp = ASCON_XOF_RATE - state->count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            ascon_squeeze_partial(&(state->state), out, state->count, temp);
            state->count += temp;
            ascon_release(&(state->state));
            return;
        }
        ascon_squeeze_partial(&(state->state), out, state->count, temp);
        out += temp;
        outlen -= temp;
        state->count = 0;
    }

    /* Handle full blocks */
    while (outlen >= ASCON_XOF_RATE) {
        ascon_permute(&(state->state), 0);
        ascon_squeeze_8(&(state->state), out, 0);
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }

    /* Handle the left-over block */
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_permute(&(state->state), 0);
        ascon_squeeze_partial(&(state->state), out, 0, temp);
        state->count = temp;
    }

    /* Release access to the shared hardware */
    ascon_release(&(state->state));
}

void ascon_xof_pad(ascon_xof_state_t *state)
{
    if (state->mode) {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        ascon_xof_absorb(state, 0, 0);
    } else if (state->count != 0) {
        /* Not currently aligned, so invoke the permutation */
        ascon_acquire(&(state->state));
        ascon_permute(&(state->state), 0);
        ascon_release(&(state->state));
        state->count = 0;
    }
}

void ascon_xof_copy(ascon_xof_state_t *dest, const ascon_xof_state_t *src)
{
    if (dest != src) {
        ascon_init(&(dest->state));
        ascon_copy(&(dest->state), &(src->state));
        ascon_release(&(dest->state));
        dest->count = src->count;
        dest->mode = src->mode;
    }
}
