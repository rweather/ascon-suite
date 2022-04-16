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

#include "sha256.h"
#include <ascon/utility.h>
#include "core/ascon-util.h"
#include <string.h>

static void sha256_transform(sha256_state_t *state)
{
    uint8_t index;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t temp1, temp2;

    /* Round constants for SHA-256 */
    static uint32_t const k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

#if defined(LW_UTIL_LITTLE_ENDIAN)
    /* Convert the first 16 words from big endian to host byte order */
    for (index = 0; index < 16; ++index)
        state->w[index] = be_load_word32((const uint8_t *)&(state->w[index]));
#endif

    /* Initialise working variables to the current hash value */
    a = state->h[0];
    b = state->h[1];
    c = state->h[2];
    d = state->h[3];
    e = state->h[4];
    f = state->h[5];
    g = state->h[6];
    h = state->h[7];

    /* Perform the first 16 rounds of the compression function main loop */
    for (index = 0; index < 16; ++index) {
        temp1 = h + k[index] + state->w[index] +
                (rightRotate6(e) ^ rightRotate11(e) ^ rightRotate25(e)) +
                ((e & f) ^ ((~e) & g));
        temp2 = (rightRotate2(a) ^ rightRotate13(a) ^ rightRotate22(a)) +
                ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    /* Perform the 48 remaining rounds.  We expand the first 16 words to
     * 64 in-place in the "w" array.  This saves 192 bytes of memory
     * that would have otherwise need to be allocated to the "w" array. */
    for (; index < 64; ++index) {
        /* Expand the next word */
        temp1 = state->w[(index - 15) & 0x0F];
        temp2 = state->w[(index - 2) & 0x0F];
        temp1 = state->w[index & 0x0F] =
            state->w[(index - 16) & 0x0F] + state->w[(index - 7) & 0x0F] +
                (rightRotate7(temp1) ^ rightRotate18(temp1) ^ (temp1 >> 3)) +
                (rightRotate17(temp2) ^ rightRotate19(temp2) ^ (temp2 >> 10));

        /* Perform the round */
        temp1 = h + k[index] + temp1 +
                (rightRotate6(e) ^ rightRotate11(e) ^ rightRotate25(e)) +
                ((e & f) ^ ((~e) & g));
        temp2 = (rightRotate2(a) ^ rightRotate13(a) ^ rightRotate22(a)) +
                ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    /* Add the compressed chunk to the current hash value */
    state->h[0] += a;
    state->h[1] += b;
    state->h[2] += c;
    state->h[3] += d;
    state->h[4] += e;
    state->h[5] += f;
    state->h[6] += g;
    state->h[7] += h;
}

int sha256_hash(unsigned char *out, const unsigned char *in, size_t inlen)
{
    sha256_state_t state;
    unsigned temp;
    uint64_t len_bytes = inlen * 8; /* Length in bits, not bytes */

    /* Initialize the SHA256 state */
    state.h[0] = 0x6a09e667U;
    state.h[1] = 0xbb67ae85U;
    state.h[2] = 0x3c6ef372U;
    state.h[3] = 0xa54ff53aU,
    state.h[4] = 0x510e527fU;
    state.h[5] = 0x9b05688cU;
    state.h[6] = 0x1f83d9abU;
    state.h[7] = 0x5be0cd19U;

    /* Break the input up into 512-bit chunks and process each in turn */
    while (inlen >= 64) {
        memcpy(state.w, in, 64);
        inlen -= 64;
        in += 64;
        sha256_transform(&state);
    }
    temp = (unsigned)inlen;
    memcpy(state.w, in, temp);

    /* Pad the final chunk and process it */
    ((uint8_t *)(state.w))[temp] = 0x80;
    if (temp <= (64U - 9U)) {
        memset(((uint8_t *)(state.w)) + temp + 1, 0, 64 - 9 - temp);
    } else {
        memset(((uint8_t *)(state.w)) + temp + 1, 0, 64 - 1 - temp);
        sha256_transform(&state);
        memset(state.w, 0, 64 - 8);
    }
    be_store_word64(((uint8_t *)(state.w)) + 64 - 8, len_bytes);
    sha256_transform(&state);

    /* Convert the hash into big-endian and return it */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    be_store_word32(out,      state.h[0]);
    be_store_word32(out + 4,  state.h[1]);
    be_store_word32(out + 8,  state.h[2]);
    be_store_word32(out + 12, state.h[3]);
    be_store_word32(out + 16, state.h[4]);
    be_store_word32(out + 20, state.h[5]);
    be_store_word32(out + 24, state.h[6]);
    be_store_word32(out + 28, state.h[7]);
#else
    memcpy(out, state.h, SHA256_HASH_SIZE);
#endif
    return 0;
}

void sha256_hash_init(sha256_state_t *state)
{
    state->h[0] = 0x6a09e667U;
    state->h[1] = 0xbb67ae85U;
    state->h[2] = 0x3c6ef372U;
    state->h[3] = 0xa54ff53aU,
    state->h[4] = 0x510e527fU;
    state->h[5] = 0x9b05688cU;
    state->h[6] = 0x1f83d9abU;
    state->h[7] = 0x5be0cd19U;
    state->length = 0;
    state->posn = 0;
}

void sha256_hash_free(sha256_state_t *state)
{
    memset(state, 0, sizeof(sha256_state_t));
}

void sha256_hash_update
    (sha256_state_t *state, const unsigned char *in, size_t inlen)
{
    /* Update the total length (in bits, not bytes) */
    state->length += ((uint64_t)inlen) << 3;

    /* Break the input up into 512-bit chunks and process each in turn */
    while (inlen > 0) {
        uint8_t size = 64 - state->posn;
        if (size > inlen)
            size = inlen;
        memcpy(((uint8_t *)state->w) + state->posn, in, size);
        state->posn += size;
        inlen -= size;
        in += size;
        if (state->posn == 64) {
            sha256_transform(state);
            state->posn = 0;
        }
    }
}

void sha256_hash_finalize(sha256_state_t *state, unsigned char *out)
{
    unsigned temp = state->posn;

    /* Pad the final chunk and process it */
    ((uint8_t *)(state->w))[temp] = 0x80;
    if (temp <= (64U - 9U)) {
        memset(((uint8_t *)(state->w)) + temp + 1, 0, 64 - 9 - temp);
    } else {
        memset(((uint8_t *)(state->w)) + temp + 1, 0, 64 - 1 - temp);
        sha256_transform(state);
        memset(state->w, 0, 64 - 8);
    }
    be_store_word64(((uint8_t *)(state->w)) + 64 - 8, state->length);
    sha256_transform(state);

    /* Convert the hash into big-endian and return it */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    be_store_word32(out,      state->h[0]);
    be_store_word32(out + 4,  state->h[1]);
    be_store_word32(out + 8,  state->h[2]);
    be_store_word32(out + 12, state->h[3]);
    be_store_word32(out + 16, state->h[4]);
    be_store_word32(out + 20, state->h[5]);
    be_store_word32(out + 24, state->h[6]);
    be_store_word32(out + 28, state->h[7]);
#else
    memcpy(out, state->h, SHA256_HASH_SIZE);
#endif
}

/* The actual HMAC implementation is in the "ascon-hmac-common.h" file */
#define HMAC_ALG_NAME sha256_hmac
#define HMAC_HASH_SIZE SHA256_HASH_SIZE
#define HMAC_BLOCK_SIZE 64
#define HMAC_STATE sha256_state_t
#define HMAC_HASH_INIT sha256_hash_init
#define HMAC_HASH_FREE sha256_hash_free
#define HMAC_HASH_UPDATE sha256_hash_update
#define HMAC_HASH_FINALIZE sha256_hash_finalize
#include "mac/ascon-hmac-common.h"
