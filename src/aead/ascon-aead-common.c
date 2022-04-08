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

#include "ascon-aead-common.h"
#include "ascon-util-snp.h"

int ascon_aead_check_tag
    (unsigned char *plaintext, size_t plaintext_len,
     const unsigned char *tag1, const unsigned char *tag2, size_t size)
{
    /* Set "accum" to -1 if the tags match, or 0 if they don't match */
    int accum = 0;
    while (size > 0) {
        accum |= (*tag1++ ^ *tag2++);
        --size;
    }
    accum = (accum - 1) >> 8;

    /* Destroy the plaintext if the tag match failed */
    while (plaintext_len > 0) {
        *plaintext++ &= accum;
        --plaintext_len;
    }

    /* If "accum" is 0, return -1, otherwise return 0 */
    return ~accum;
}

void ascon_aead_absorb_8
    (ascon_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, int last_permute)
{
    while (len >= 8) {
        ascon_absorb_8(state, data, 0);
        ascon_permute(state, first_round);
        data += 8;
        len -= 8;
    }
    if (len > 0)
        ascon_absorb_partial(state, data, 0, len);
    ascon_pad(state, len);
    if (last_permute)
        ascon_permute(state, first_round);
}

void ascon_aead_absorb_16
    (ascon_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, int last_permute)
{
    while (len >= 16) {
        ascon_absorb_16(state, data, 0);
        ascon_permute(state, first_round);
        data += 16;
        len -= 16;
    }
    if (len > 0)
        ascon_absorb_partial(state, data, 0, len);
    ascon_pad(state, len);
    if (last_permute)
        ascon_permute(state, first_round);
}

void ascon_aead_encrypt_8
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    while (len >= 8) {
        ascon_encrypt_8(state, dest, src, 0);
        ascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    if (len > 0)
        ascon_encrypt_partial(state, dest, src, 0, len);
    ascon_pad(state, len);
}

void ascon_aead_encrypt_16
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    while (len >= 16) {
        ascon_encrypt_16(state, dest, src, 0);
        ascon_permute(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    if (len > 0)
        ascon_encrypt_partial(state, dest, src, 0, len);
    ascon_pad(state, len);
}

void ascon_aead_decrypt_8
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    while (len >= 8) {
        ascon_decrypt_8(state, dest, src, 0);
        ascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    if (len > 0)
        ascon_decrypt_partial(state, dest, src, 0, len);
    ascon_pad(state, len);
}

void ascon_aead_decrypt_16
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round)
{
    while (len >= 16) {
        ascon_decrypt_16(state, dest, src, 0);
        ascon_permute(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    if (len > 0)
        ascon_decrypt_partial(state, dest, src, 0, len);
    ascon_pad(state, len);
}
