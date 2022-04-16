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

#include "aead/ascon-aead-common.h"
#include "core/ascon-util-snp.h"
#include <string.h>

/**
 * \brief Initialization vector for ASCON-128.
 */
#define ASCON128_IV     0x80400c0600000000ULL

int ascon128_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
#if defined(ASCON_BACKEND_INIT)
    ascon_init(&state);
#endif
    be_store_word64(state.B, ASCON128_IV);
    memcpy(state.B + 8, k, ASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON128_NONCE_SIZE);
    ascon_from_regular(&state);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_8(&state, ad, adlen, 6, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_aead_encrypt_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
    ascon_absorb_16(&state, k, 8);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_squeeze_partial(&state, c + mlen, 24, ASCON128_TAG_SIZE);
    ascon_free(&state);
    return 0;
}

int ascon128_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    int result;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
#if defined(ASCON_BACKEND_INIT)
    ascon_init(&state);
#endif
    be_store_word64(state.B, ASCON128_IV);
    memcpy(state.B + 8, k, ASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON128_NONCE_SIZE);
    ascon_from_regular(&state);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_8(&state, ad, adlen, 6, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_aead_decrypt_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag */
    ascon_absorb_16(&state, k, 8);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_to_regular(&state);
    result = ascon_aead_check_tag
        (m, *mlen, state.B + 24, c + *mlen, ASCON128_TAG_SIZE);
    ascon_free(&state);
    return result;
}
