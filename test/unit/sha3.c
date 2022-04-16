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

#include "sha3.h"
#include "test-cipher.h"
#include "core/ascon-util.h"
#include <string.h>
#include <stdio.h>

void sha3_init(sha3_state_t *state, unsigned capacity, unsigned padding)
{
    memset(state->A, 0, sizeof(state->A));
    state->inputSize = 0;
    state->outputSize = 0;
    state->rate = (1600 - capacity) / 8;
    state->absorbing = 1;
    state->padding = padding;
}

void sha3_free(sha3_state_t *state)
{
    memset(state, 0, sizeof(sha3_state_t));
}

void sha3_256_init(sha3_state_t *state)
{
    sha3_init(state, 512, 0x06);
}

void sha3_512_init(sha3_state_t *state)
{
    sha3_init(state, 1024, 0x06);
}

void shake128_init(sha3_state_t *state)
{
    sha3_init(state, 256, 0x1F);
}

void shake256_init(sha3_state_t *state)
{
    sha3_init(state, 512, 0x1F);
}

void cshake128_init(sha3_state_t *state)
{
    sha3_init(state, 256, 0x04);
}

void cshake256_init(sha3_state_t *state)
{
    sha3_init(state, 512, 0x04);
}

/**
 * \brief Runs the Keccak-p[1600] permutation on a SHA3 hashing state.
 *
 * \param state Points to the SHA3 state.
 */
static void sha3_keccakp(sha3_state_t *state)
{
    static uint64_t const RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
        0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
        0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
    };
    #define addMod5(x, y) (((x) + (y)) % 5)
    uint64_t B[5][5];
    uint64_t D;
    uint8_t index, index2, round;
#if !defined(LW_UTIL_LITTLE_ENDIAN)
    for (index = 0; index < 5; ++index) {
        for (index2 = 0; index2 < 5; ++index2) {
            state->A[index][index2] =
                le_load_word64((const uint8_t *)(&(state->a[index, index2])));
        }
    }
#endif
    for (round = 0; round < 24; ++round) {
        /* Step mapping theta.  The specification mentions two temporary
         * arrays of size 5 called C and D.  To save a bit of memory,
         * we use the first row of B to store C and compute D on the fly. */
        for (index = 0; index < 5; ++index) {
            B[0][index] = state->A[0][index] ^ state->A[1][index] ^
                          state->A[2][index] ^ state->A[3][index] ^
                          state->A[4][index];
        }
        for (index = 0; index < 5; ++index) {
            D = B[0][addMod5(index, 4)] ^
                leftRotate1_64(B[0][addMod5(index, 1)]);
            for (index2 = 0; index2 < 5; ++index2)
                state->A[index2][index] ^= D;
        }

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange. */
        B[0][0] = state->A[0][0];
        B[1][0] = leftRotate28_64(state->A[0][3]);
        B[2][0] = leftRotate1_64 (state->A[0][1]);
        B[3][0] = leftRotate27_64(state->A[0][4]);
        B[4][0] = leftRotate62_64(state->A[0][2]);
        B[0][1] = leftRotate44_64(state->A[1][1]);
        B[1][1] = leftRotate20_64(state->A[1][4]);
        B[2][1] = leftRotate6_64 (state->A[1][2]);
        B[3][1] = leftRotate36_64(state->A[1][0]);
        B[4][1] = leftRotate55_64(state->A[1][3]);
        B[0][2] = leftRotate43_64(state->A[2][2]);
        B[1][2] = leftRotate3_64 (state->A[2][0]);
        B[2][2] = leftRotate25_64(state->A[2][3]);
        B[3][2] = leftRotate10_64(state->A[2][1]);
        B[4][2] = leftRotate39_64(state->A[2][4]);
        B[0][3] = leftRotate21_64(state->A[3][3]);
        B[1][3] = leftRotate45_64(state->A[3][1]);
        B[2][3] = leftRotate8_64 (state->A[3][4]);
        B[3][3] = leftRotate15_64(state->A[3][2]);
        B[4][3] = leftRotate41_64(state->A[3][0]);
        B[0][4] = leftRotate14_64(state->A[4][4]);
        B[1][4] = leftRotate61_64(state->A[4][2]);
        B[2][4] = leftRotate18_64(state->A[4][0]);
        B[3][4] = leftRotate56_64(state->A[4][3]);
        B[4][4] = leftRotate2_64 (state->A[4][1]);

        /* Step mapping chi.  Combine each lane with two other lanes. */
        for (index = 0; index < 5; ++index) {
            for (index2 = 0; index2 < 5; ++index2) {
                state->A[index2][index] =
                    B[index2][index] ^
                    ((~B[index2][addMod5(index, 1)]) &
                     B[index2][addMod5(index, 2)]);
            }
        }

        // Step mapping iota.  XOR A[0][0] with the round constant.
        state->A[0][0] ^= RC[round];
    }
#if !defined(LW_UTIL_LITTLE_ENDIAN)
    for (index = 0; index < 5; ++index) {
        for (index2 = 0; index2 < 5; ++index2) {
            le_store_word64((uint8_t *)(&(state->a[index, index2])),
                            state->A[index][index2]);
        }
    }
#endif
}

void sha3_absorb
    (sha3_state_t *state, const unsigned char *data, size_t size)
{
    const uint8_t *d = (const uint8_t *)data;
    uint8_t *Abytes;
    unsigned posn, len;

    /* Stop generating output while we incorporate the new data */
    state->absorbing = 1;
    state->outputSize = 0;

    /* Break the input up into chunks and process each in turn */
    while (size > 0) {
        len = state->rate - state->inputSize;
        if (len > size)
            len = size;
        Abytes = ((uint8_t *)state->A) + state->inputSize;
        for (posn = 0; posn < len; ++posn)
            Abytes[posn] ^= d[posn];
        state->inputSize += len;
        size -= len;
        d += len;
        if (state->inputSize >= state->rate) {
            sha3_keccakp(state);
            state->inputSize = 0;
        }
    }
}

void sha3_squeeze
    (sha3_state_t *state, unsigned char *data, size_t size)
{
    uint8_t *d = (uint8_t *)data;
    unsigned tempSize;

    /* Stop accepting input while we are generating output */
    if (state->absorbing) {
        /* Pad the final input block */
        unsigned size = state->inputSize;
        uint64_t *Awords = &(state->A[0][0]);
        Awords[size / 8] ^= (((uint64_t)(state->padding)) << ((size % 8) * 8));
        Awords[(state->rate - 1) / 8] ^= 0x8000000000000000ULL;
        sha3_keccakp(state);
        state->inputSize = 0;
        state->outputSize = 0;
        state->absorbing = 0;
    }

    /* Copy the output data into the caller's return buffer */
    while (size > 0) {
        /* Generate another output block if the current one is exhausted */
        if (state->outputSize >= state->rate) {
            sha3_keccakp(state);
            state->outputSize = 0;
        }

        /* How many bytes can we copy this time around? */
        tempSize = state->rate - state->outputSize;
        if (tempSize > size)
            tempSize = size;

        /* Copy the partial output data into the caller's return buffer */
        memcpy(d, ((uint8_t *)(state->A)) + state->outputSize, tempSize);
        state->outputSize += tempSize;
        size -= tempSize;
        d += tempSize;
    }
}

void sha3_pad(sha3_state_t *state)
{
    state->absorbing = 1;
    state->outputSize = 0;
    if (state->inputSize != 0) {
        sha3_keccakp(state);
        state->inputSize = 0;
    }
}

int sha3_256_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    sha3_state_t state;
    sha3_256_init(&state);
    sha3_absorb(&state, in, inlen);
    sha3_squeeze(&state, out, 32);
    return 0;
}

int sha3_512_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    sha3_state_t state;
    sha3_512_init(&state);
    sha3_absorb(&state, in, inlen);
    sha3_squeeze(&state, out, 64);
    return 0;
}

int shake128_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    sha3_state_t state;
    shake128_init(&state);
    sha3_absorb(&state, in, inlen);
    sha3_squeeze(&state, out, 64);
    return 0;
}

int shake256_hash
    (unsigned char *out, const unsigned char *in, size_t inlen)
{
    sha3_state_t state;
    shake256_init(&state);
    sha3_absorb(&state, in, inlen);
    sha3_squeeze(&state, out, 64);
    return 0;
}
