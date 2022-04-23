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

#include <ascon/siv.h>
#include "aead/ascon-aead-common.h"
#include "core/ascon-util-snp.h"
#include <string.h>

/**
 * \brief Initialization vector for ASCON-128-SIV, authentication phase.
 */
static uint8_t const ASCON128_IV1[8] =
    {0x81, 0x40, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00};

/**
 * \brief Initialization vector for ASCON-128-SIV, encryption phase.
 */
static uint8_t const ASCON128_IV2[8] =
    {0x82, 0x40, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00};

/**
 * \brief Initializes the ASCON state for ASCON-128-SIV.
 *
 * \param state ASCON state to be initialized.
 * \param npub Points to the nonce.
 * \param k Points to the key.
 * \param iv Initialization vector value for the ASCON state.
 */
static void ascon128_siv_init
    (ascon_state_t *state, const unsigned char *npub,
     const unsigned char *k, const uint8_t iv[8])
{
    ascon_init(state);
    ascon_overwrite_bytes(state, iv, 0, 8);
    ascon_overwrite_bytes(state, k, 8, ASCON128_KEY_SIZE);
    ascon_overwrite_bytes(state, npub, 24, ASCON128_NONCE_SIZE);
    ascon_permute(state, 0);
    ascon_absorb_16(state, k, 24);
}

/**
 * \brief Encrypts a block of data with an ASCON state and an 8-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 *
 * This operates the ASCON permutation in OFB mode, which can be used to
 * perform both encryption and decryption.
 */
static void ascon_siv_encrypt_8
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    unsigned char block[8];
    while (len >= 8) {
        ascon_permute(state, first_round);
        ascon_squeeze_8(state, block, 0);
        lw_xor_block_2_src(dest, block, src, 8);
        dest += 8;
        src += 8;
        len -= 8;
    }
    if (len > 0) {
        ascon_permute(state, first_round);
        ascon_squeeze_8(state, block, 0);
        lw_xor_block_2_src(dest, block, src, len);
    }
}

void ascon128_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_TAG_SIZE;

    /* Initialize the ASCON state for the authentication phase */
    ascon128_siv_init(&state, npub, k, ASCON128_IV1);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_8(&state, ad, adlen, 6, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Absorb the plaintext data into the state */
    ascon_aead_absorb_8(&state, m, mlen, 6, 0);

    /* Compute the authentication tag */
    ascon_absorb_16(&state, k, 8);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_squeeze_16(&state, c + mlen, 24);
    ascon_free(&state);

    /* Re-initalize the ASCON state for the encryption phase */
    ascon128_siv_init(&state, c + mlen, k, ASCON128_IV2);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_siv_encrypt_8(&state, c, m, mlen, 6);
    ascon_free(&state);
}

int ascon128_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    unsigned char tag[ASCON128_TAG_SIZE];
    int result;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_TAG_SIZE)
        return -1;
    clen -= ASCON128_TAG_SIZE;
    *mlen = clen;

    /* Initalize the ASCON state for the encryption phase */
    ascon128_siv_init(&state, c + clen, k, ASCON128_IV2);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_siv_encrypt_8(&state, m, c, clen, 6);
    ascon_free(&state);

    /* Re-initialize the ASCON state for the authentication phase */
    ascon128_siv_init(&state, npub, k, ASCON128_IV1);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_8(&state, ad, adlen, 6, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Absorb the plaintext data into the state */
    ascon_aead_absorb_8(&state, m, clen, 6, 0);

    /* Compute and check authentication tag */
    ascon_absorb_16(&state, k, 8);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_squeeze_16(&state, tag, 24);
    result = ascon_aead_check_tag(m, clen, tag, c + clen, ASCON128_TAG_SIZE);
    ascon_clean(tag, sizeof(tag));
    ascon_free(&state);
    return result;
}
