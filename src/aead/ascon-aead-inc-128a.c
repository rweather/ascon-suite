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

#include "aead/ascon-aead-common.h"
#include "core/ascon-util-snp.h"
#include <string.h>

/* Initialization vector for ASCON-128a */
static uint8_t const ASCON128a_IV[8] =
    {0x80, 0x80, 0x0c, 0x08, 0x00, 0x00, 0x00, 0x00};

void ascon128a_aead_init
    (ascon128a_state_t *state, const unsigned char *npub,
     const unsigned char *k)
{
    ascon_init(&(state->state));
    ascon_release(&(state->state));
    ascon128a_aead_reinit(state, npub, k);
}

void ascon128a_aead_reinit
    (ascon128a_state_t *state, const unsigned char *npub,
     const unsigned char *k)
{
    if (k)
        memcpy(state->key, k, ASCON128_KEY_SIZE);
    else
        memset(state->key, 0, ASCON128_KEY_SIZE);
    if (npub)
        memcpy(state->nonce, npub, ASCON128_NONCE_SIZE);
    else if (npub != state->nonce)
        memset(state->nonce, 0, ASCON128_NONCE_SIZE);
    state->posn = 0;
}

void ascon128a_aead_start
    (ascon128a_state_t *state, const unsigned char *ad, size_t adlen)
{
    /* Initialize the ASCON state */
    ascon_acquire(&(state->state));
    ascon_overwrite_bytes(&(state->state), ASCON128a_IV, 0, 8);
    ascon_overwrite_bytes(&(state->state), state->key, 8, ASCON128_KEY_SIZE);
    ascon_overwrite_bytes
        (&(state->state), state->nonce, 24, ASCON128_NONCE_SIZE);
    ascon_permute(&(state->state), 0);
    ascon_absorb_16(&(state->state), state->key, 24);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_16(&(state->state), ad, adlen, 4, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&(state->state));

    /* Prepare for encryption or decryption */
    ascon_release(&(state->state));
    state->posn = 0;

    /* Increment the nonce for the next packet */
    ascon_aead_increment_nonce(state->nonce);
}

void ascon128a_aead_free(ascon128a_state_t *state)
{
    if (state) {
        ascon_acquire(&(state->state));
        ascon_free(&(state->state));
        ascon_clean(state, sizeof(ascon128a_state_t));
    }
}

void ascon128a_aead_encrypt_block
    (ascon128a_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len)
{
    ascon_acquire(&(state->state));
    state->posn = ascon_aead_encrypt_16
        (&(state->state), out, in, len, 4, state->posn);
    ascon_release(&(state->state));
}

void ascon128a_aead_encrypt_finalize
    (ascon128a_state_t *state, unsigned char *tag)
{
    /* Pad the final plaintext block */
    ascon_acquire(&(state->state));
    ascon_pad(&(state->state), state->posn);

    /* Finalize and compute the authentication tag */
    ascon_absorb_16(&(state->state), state->key, 16);
    ascon_permute(&(state->state), 0);
    ascon_absorb_16(&(state->state), state->key, 24);
    ascon_squeeze_partial(&(state->state), tag, 24, ASCON128_TAG_SIZE);
    ascon_release(&(state->state));
}

void ascon128a_aead_decrypt_block
    (ascon128a_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len)
{
    ascon_acquire(&(state->state));
    state->posn = ascon_aead_decrypt_16
        (&(state->state), out, in, len, 4, state->posn);
    ascon_release(&(state->state));
}

int ascon128a_aead_decrypt_finalize
    (ascon128a_state_t *state, const unsigned char *tag)
{
    unsigned char tag2[ASCON128_TAG_SIZE];
    int result;

    /* Pad the final ciphertext block */
    ascon_acquire(&(state->state));
    ascon_pad(&(state->state), state->posn);

    /* Finalize and check the authentication tag */
    ascon_absorb_16(&(state->state), state->key, 16);
    ascon_permute(&(state->state), 0);
    ascon_absorb_16(&(state->state), state->key, 24);
    ascon_squeeze_16(&(state->state), tag2, 24);
    ascon_release(&(state->state));
    result = ascon_aead_check_tag(0, 0, tag2, tag, ASCON128_TAG_SIZE);

    /* Clean up */
    ascon_clean(tag2, sizeof(tag2));
    return result;
}
