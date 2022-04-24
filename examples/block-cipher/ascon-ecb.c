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

#include "ascon-ecb.h"
#include <ascon/permutation.h>
#include <ascon/utility.h>
#include <string.h>

/* Check that the number of rounds is between 4 and 64 */
#if ASCON_ECB_ROUNDS < 4 || ASCON_ECB_ROUNDS > 64
#error "Incorrect number of rounds for ASCON-ECB"
#endif

/*
 * \brief Number of rounds to run on the ASCON permutation each
 * ECB round (1 to 12).
 */
#define ASCON_ECB_PERMUTE_ROUNDS 6

/**
 * \brief Round constants from SHA-256, which we also use for ASCON-ECB.
 *
 * Restrict the size of the table.  We probably won't need all 64.
 */
static unsigned char const RC[][4] = {
    {0x42, 0x8a, 0x2f, 0x98}, {0x71, 0x37, 0x44, 0x91},
    {0xb5, 0xc0, 0xfb, 0xcf}, {0xe9, 0xb5, 0xdb, 0xa5},
#if ASCON_ECB_ROUNDS > 4
    {0x39, 0x56, 0xc2, 0x5b}, {0x59, 0xf1, 0x11, 0xf1},
#endif
#if ASCON_ECB_ROUNDS > 6
    {0x92, 0x3f, 0x82, 0xa4}, {0xab, 0x1c, 0x5e, 0xd5},
#endif
#if ASCON_ECB_ROUNDS > 8
    {0xd8, 0x07, 0xaa, 0x98}, {0x12, 0x83, 0x5b, 0x01},
#endif
#if ASCON_ECB_ROUNDS > 10
    {0x24, 0x31, 0x85, 0xbe}, {0x55, 0x0c, 0x7d, 0xc3},
#endif
#if ASCON_ECB_ROUNDS > 12
    {0x72, 0xbe, 0x5d, 0x74}, {0x80, 0xde, 0xb1, 0xfe},
#endif
#if ASCON_ECB_ROUNDS > 14
    {0x9b, 0xdc, 0x06, 0xa7}, {0xc1, 0x9b, 0xf1, 0x74},
#endif
#if ASCON_ECB_ROUNDS > 16
    {0xe4, 0x9b, 0x69, 0xc1}, {0xef, 0xbe, 0x47, 0x86},
#endif
#if ASCON_ECB_ROUNDS > 18
    {0x0f, 0xc1, 0x9d, 0xc6}, {0x24, 0x0c, 0xa1, 0xcc},
#endif
#if ASCON_ECB_ROUNDS > 20
    {0x2d, 0xe9, 0x2c, 0x6f}, {0x4a, 0x74, 0x84, 0xaa},
#endif
#if ASCON_ECB_ROUNDS > 22
    {0x5c, 0xb0, 0xa9, 0xdc}, {0x76, 0xf9, 0x88, 0xda},
#endif
#if ASCON_ECB_ROUNDS > 24
    {0x98, 0x3e, 0x51, 0x52}, {0xa8, 0x31, 0xc6, 0x6d},
#endif
#if ASCON_ECB_ROUNDS > 26
    {0xb0, 0x03, 0x27, 0xc8}, {0xbf, 0x59, 0x7f, 0xc7},
#endif
#if ASCON_ECB_ROUNDS > 28
    {0xc6, 0xe0, 0x0b, 0xf3}, {0xd5, 0xa7, 0x91, 0x47},
#endif
#if ASCON_ECB_ROUNDS > 30
    {0x06, 0xca, 0x63, 0x51}, {0x14, 0x29, 0x29, 0x67},
#endif
#if ASCON_ECB_ROUNDS > 32
    {0x27, 0xb7, 0x0a, 0x85}, {0x2e, 0x1b, 0x21, 0x38},
#endif
#if ASCON_ECB_ROUNDS > 34
    {0x4d, 0x2c, 0x6d, 0xfc}, {0x53, 0x38, 0x0d, 0x13},
#endif
#if ASCON_ECB_ROUNDS > 36
    {0x65, 0x0a, 0x73, 0x54}, {0x76, 0x6a, 0x0a, 0xbb},
#endif
#if ASCON_ECB_ROUNDS > 38
    {0x81, 0xc2, 0xc9, 0x2e}, {0x92, 0x72, 0x2c, 0x85},
#endif
#if ASCON_ECB_ROUNDS > 40
    {0xa2, 0xbf, 0xe8, 0xa1}, {0xa8, 0x1a, 0x66, 0x4b},
#endif
#if ASCON_ECB_ROUNDS > 42
    {0xc2, 0x4b, 0x8b, 0x70}, {0xc7, 0x6c, 0x51, 0xa3},
#endif
#if ASCON_ECB_ROUNDS > 44
    {0xd1, 0x92, 0xe8, 0x19}, {0xd6, 0x99, 0x06, 0x24},
#endif
#if ASCON_ECB_ROUNDS > 46
    {0xf4, 0x0e, 0x35, 0x85}, {0x10, 0x6a, 0xa0, 0x70},
#endif
#if ASCON_ECB_ROUNDS > 48
    {0x19, 0xa4, 0xc1, 0x16}, {0x1e, 0x37, 0x6c, 0x08},
#endif
#if ASCON_ECB_ROUNDS > 50
    {0x27, 0x48, 0x77, 0x4c}, {0x34, 0xb0, 0xbc, 0xb5},
#endif
#if ASCON_ECB_ROUNDS > 52
    {0x39, 0x1c, 0x0c, 0xb3}, {0x4e, 0xd8, 0xaa, 0x4a},
#endif
#if ASCON_ECB_ROUNDS > 54
    {0x5b, 0x9c, 0xca, 0x4f}, {0x68, 0x2e, 0x6f, 0xf3},
#endif
#if ASCON_ECB_ROUNDS > 56
    {0x74, 0x8f, 0x82, 0xee}, {0x78, 0xa5, 0x63, 0x6f},
#endif
#if ASCON_ECB_ROUNDS > 58
    {0x84, 0xc8, 0x78, 0x14}, {0x8c, 0xc7, 0x02, 0x08},
#endif
#if ASCON_ECB_ROUNDS > 60
    {0x90, 0xbe, 0xff, 0xfa}, {0xa4, 0x50, 0x6c, 0xeb},
#endif
#if ASCON_ECB_ROUNDS > 62
    {0xbe, 0xf9, 0xa3, 0xf7}, {0xc6, 0x71, 0x78, 0xf2},
#endif
};

/**
 * \brief Doubles a 16-byte value in the GF(128) field.
 *
 * \param out The output block.
 * \param in The input block.
 */
static void ascon_ecb_double(unsigned char out[16], const unsigned char in[16])
{
    unsigned index;
    unsigned char mask;
    mask = (unsigned char)(((signed char)(in[0])) >> 7);
    for (index = 0; index < 15; ++index)
        out[index] = (in[index] << 1) | (in[index + 1] >> 7);
    out[15] = (in[15] << 1) ^ (mask & 0x87);
}

void ascon_ecb_init(ascon_ecb_key_schedule_t *ks, const unsigned char *k)
{
    unsigned round;

    /* Populate the key and round constant for the first round */
    memcpy(ks->k[0], k, ASCON_ECB_KEY_SIZE);

    /* Populate the keys for the remaining rounds by applying a doubling
     * operation in GF(128) for each successive key.  This makes all the
     * round keys different from each other under the same tweak. */
    for (round = 1; round < ASCON_ECB_ROUNDS; ++round)
        ascon_ecb_double(ks->k[round], ks->k[round - 1]);
}

void ascon_ecb_free(ascon_ecb_key_schedule_t *ks)
{
    if (ks)
        ascon_clean(ks, sizeof(ascon_ecb_key_schedule_t));
}

void ascon_ecb_encrypt
    (ascon_ecb_key_schedule_t *ks, const unsigned char *tweak,
     unsigned char *c, const unsigned char *m)
{
    ascon_state_t state;
    unsigned char l[8];
    unsigned char r[8];
    unsigned char block[8];
    unsigned char *L = l;
    unsigned char *R = r;
    unsigned char *temp;
    unsigned round;

    /* Split the plaintext input into two halves */
    memcpy(L, m, 8);
    memcpy(R, m + 8, 8);

    /* Run all of the rounds */
    ascon_init(&state);
    for (round = 0; round < ASCON_ECB_ROUNDS; ++round) {
        /* Concatenate R, the round key, the tweak, and the round constant */
        ascon_overwrite_bytes(&state, R, 0, 8);
        ascon_overwrite_bytes(&state, ks->k[round], 8, 16);
        if (tweak)
            ascon_overwrite_bytes(&state, tweak, 24, 12);
        else
            ascon_overwrite_with_zeroes(&state, 24, 12);
        ascon_overwrite_bytes(&state, RC[round], 36, 4);

        /* Run the permutation and XOR the first 8 bytes of the result with L */
        ascon_permute(&state, 12 - ASCON_ECB_PERMUTE_ROUNDS);
        ascon_extract_bytes(&state, block, 0, 8);
        L[0] ^= block[0];
        L[1] ^= block[1];
        L[2] ^= block[2];
        L[3] ^= block[3];
        L[4] ^= block[4];
        L[5] ^= block[5];
        L[6] ^= block[6];
        L[7] ^= block[7];

        /* Swap the two halves for the next round */
        temp = L;
        L = R;
        R = temp;
    }
    ascon_free(&state);

    /* Unswap the last round and copy to the ciphertext buffer */
    memcpy(c, R, 8);
    memcpy(c + 8, L, 8);
}

void ascon_ecb_decrypt
    (ascon_ecb_key_schedule_t *ks, const unsigned char *tweak,
     unsigned char *m, const unsigned char *c)
{
    ascon_state_t state;
    unsigned char l[8];
    unsigned char r[8];
    unsigned char block[8];
    unsigned char *L = l;
    unsigned char *R = r;
    unsigned char *temp;
    unsigned round;

    /* Split the ciphertext input into two halves */
    memcpy(L, c, 8);
    memcpy(R, c + 8, 8);

    /* Run all of the rounds in reverse */
    ascon_init(&state);
    for (round = ASCON_ECB_ROUNDS; round > 0; --round) {
        /* Concatenate R, the round key, the tweak, and the round constant */
        ascon_overwrite_bytes(&state, R, 0, 8);
        ascon_overwrite_bytes(&state, ks->k[round - 1], 8, 16);
        if (tweak)
            ascon_overwrite_bytes(&state, tweak, 24, 12);
        else
            ascon_overwrite_with_zeroes(&state, 24, 12);
        ascon_overwrite_bytes(&state, RC[round - 1], 36, 4);

        /* Run the permutation and XOR the first 8 bytes of the result with L */
        ascon_permute(&state, 12 - ASCON_ECB_PERMUTE_ROUNDS);
        ascon_extract_bytes(&state, block, 0, 8);
        L[0] ^= block[0];
        L[1] ^= block[1];
        L[2] ^= block[2];
        L[3] ^= block[3];
        L[4] ^= block[4];
        L[5] ^= block[5];
        L[6] ^= block[6];
        L[7] ^= block[7];

        /* Swap the two halves for the next round */
        temp = L;
        L = R;
        R = temp;
    }
    ascon_free(&state);

    /* Unswap the last round and copy to the plaintext buffer */
    memcpy(m, R, 8);
    memcpy(m + 8, L, 8);
}
