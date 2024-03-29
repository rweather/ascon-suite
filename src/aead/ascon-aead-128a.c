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
 * \brief Initialization vector for ASCON-128a.
 */
static uint8_t const ASCON128a_IV[8] =
    {0x80, 0x80, 0x0c, 0x08, 0x00, 0x00, 0x00, 0x00};

void ascon128a_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    unsigned char partial;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
    ascon_init(&state);
    ascon_overwrite_bytes(&state, ASCON128a_IV, 0, 8);
    ascon_overwrite_bytes(&state, k, 8, ASCON128_KEY_SIZE);
    ascon_overwrite_bytes(&state, npub, 24, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_16(&state, ad, adlen, 4, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Encrypt the plaintext to create the ciphertext */
    partial = ascon_aead_encrypt_16(&state, c, m, mlen, 4, 0);
    ascon_pad(&state, partial);

    /* Finalize and compute the authentication tag */
    ascon_absorb_16(&state, k, 16);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_squeeze_partial(&state, c + mlen, 24, ASCON128_TAG_SIZE);
    ascon_free(&state);
}

int ascon128a_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    unsigned char tag[ASCON128_TAG_SIZE];
    unsigned char partial;
    int result;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
    ascon_init(&state);
    ascon_overwrite_bytes(&state, ASCON128a_IV, 0, 8);
    ascon_overwrite_bytes(&state, k, 8, ASCON128_KEY_SIZE);
    ascon_overwrite_bytes(&state, npub, 24, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_16(&state, ad, adlen, 4, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Decrypt the ciphertext to create the plaintext */
    partial = ascon_aead_decrypt_16(&state, m, c, *mlen, 4, 0);
    ascon_pad(&state, partial);

    /* Finalize and check the authentication tag */
    ascon_absorb_16(&state, k, 16);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_squeeze_16(&state, tag, 24);
    result = ascon_aead_check_tag(m, *mlen, tag, c + *mlen, ASCON128_TAG_SIZE);
    ascon_clean(tag, sizeof(tag));
    ascon_free(&state);
    return result;
}
