/*
 * Copyright (C) 2024 Southern Storm Software, Pty Ltd.
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

#include "aead.h"
#include "permutation.h"
#include <string.h>

/**
 * \brief Rate of absorbing and encrypting.
 */
#define ASCON_AEAD_RATE 16

static void ascon_simple_absorb_ad
    (ascon_simple_state_t *state,
     const unsigned char *ad, size_t adlen)
{
    while (adlen >= ASCON_AEAD_RATE) {
        ascon_simple_xor(state->B, state->B, ad, ASCON_AEAD_RATE);
        ascon_simple_permute_8(state);
        ad += ASCON_AEAD_RATE;
        adlen -= ASCON_AEAD_RATE;
    }
    ascon_simple_xor(state->B, state->B, ad, adlen);
    state->B[adlen] ^= 0x01;
    ascon_simple_permute_8(state);
}

void ascon_simple_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_simple_state_t state;

    /* Initialize the ASCON state */
    ascon_simple_init_iv(&state, 0x00001000808c0001);
    memcpy(state.B + 8, k, ASCON_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON_NONCE_SIZE);
    ascon_simple_permute_12(&state);
    ascon_simple_xor(state.B + 24, state.B + 24, k, ASCON_KEY_SIZE);

    /* Absorb the associated data */
    if (adlen) {
        ascon_simple_absorb_ad(&state, ad, adlen);
    }

    /* Domain separation */
    state.B[39] ^= 0x80;

    /* Encrypt the plaintext */
    *clen = mlen + ASCON_TAG_SIZE;
    while (mlen >= ASCON_AEAD_RATE) {
        ascon_simple_xor(state.B, state.B, m, ASCON_AEAD_RATE);
        memcpy(c, state.B, ASCON_AEAD_RATE);
        ascon_simple_permute_8(&state);
        c += ASCON_AEAD_RATE;
        m += ASCON_AEAD_RATE;
        mlen -= ASCON_AEAD_RATE;
    }
    ascon_simple_xor(state.B, state.B, m, mlen);
    memcpy(c, state.B, mlen);
    state.B[mlen] ^= 0x01;
    c += mlen;

    /* Generate the tag */
    ascon_simple_xor(state.B + 16, state.B + 16, k, ASCON_KEY_SIZE);
    ascon_simple_permute_12(&state);
    ascon_simple_xor(state.B + 24, state.B + 24, k, ASCON_KEY_SIZE);
    memcpy(c, state.B + 24, ASCON_TAG_SIZE);
}

static void ascon_decrypt_xor
    (unsigned char *dest, unsigned char *src1,
     const unsigned char *src2, size_t len)
{
    while (len > 0) {
        unsigned char ch = *src2++;
        *dest++ = *src1 ^ ch;
        *src1++ = ch;
        --len;
    }
}

int ascon_simple_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_simple_state_t state;

    /* Bail out if the ciphertext length is invalid */
    if (clen < ASCON_TAG_SIZE) {
        return -1;
    }
    *mlen = clen - ASCON_TAG_SIZE;
    clen -= ASCON_TAG_SIZE;

    /* Initialize the ASCON state */
    ascon_simple_init_iv(&state, 0x00001000808c0001);
    memcpy(state.B + 8, k, ASCON_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON_NONCE_SIZE);
    ascon_simple_permute_12(&state);
    ascon_simple_xor(state.B + 24, state.B + 24, k, ASCON_KEY_SIZE);

    /* Absorb the associated data */
    if (adlen) {
        ascon_simple_absorb_ad(&state, ad, adlen);
    }

    /* Domain separation */
    state.B[39] ^= 0x80;

    /* Decrypt the ciphertext */
    while (clen >= ASCON_AEAD_RATE) {
        ascon_decrypt_xor(m, state.B, c, ASCON_AEAD_RATE);
        ascon_simple_permute_8(&state);
        c += ASCON_AEAD_RATE;
        m += ASCON_AEAD_RATE;
        clen -= ASCON_AEAD_RATE;
    }
    ascon_decrypt_xor(m, state.B, c, clen);
    state.B[clen] ^= 0x01;
    c += clen;

    /* Generate and check the tag */
    ascon_simple_xor(state.B + 16, state.B + 16, k, ASCON_KEY_SIZE);
    ascon_simple_permute_12(&state);
    ascon_simple_xor(state.B + 24, state.B + 24, k, ASCON_KEY_SIZE);

    /* Warning: This check is not constant time! */
    return (!memcmp(c, state.B + 24, ASCON_TAG_SIZE)) ? 0 : -1;
}

void ascon_simple_nm_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char nonce[ASCON_NONCE_SIZE];
    ascon_simple_xor(nonce, npub, k + 16, ASCON_NONCE_SIZE);
    ascon_simple_encrypt(c, clen, m, mlen, ad, adlen, nonce, k);
}

int ascon_simple_nm_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char nonce[ASCON_NONCE_SIZE];
    ascon_simple_xor(nonce, npub, k + 16, ASCON_NONCE_SIZE);
    return ascon_simple_decrypt(m, mlen, c, clen, ad, adlen, nonce, k);
}
