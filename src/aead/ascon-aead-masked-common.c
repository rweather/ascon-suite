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

#include "aead/ascon-aead-masked-common.h"

/* Not needed if we won't be masking associated data and plaintext */
#if ASCON_MASKED_DATA_SHARES != 1

void ascon_masked_aead_absorb_8
    (ascon_masked_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, ascon_masked_word_t *word,
     uint64_t *preserve, ascon_trng_state_t *trng)
{
    while (len >= 8) {
        ascon_masked_data_load(word, data, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_permute(state, first_round, preserve);
        data += 8;
        len -= 8;
    }
    if (len > 0) {
        ascon_masked_data_load_partial(word, data, len, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
    }
    ascon_masked_word_pad(&(state->M[0]), len);
    ascon_masked_data_permute(state, first_round, preserve);
}

void ascon_masked_aead_absorb_16
    (ascon_masked_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, ascon_masked_word_t *word,
     uint64_t *preserve, ascon_trng_state_t *trng)
{
    while (len >= 16) {
        ascon_masked_data_load(word, data, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_load(word, data + 8, trng);
        ascon_masked_data_xor(&(state->M[1]), word);
        ascon_masked_data_permute(state, first_round, preserve);
        data += 16;
        len -= 16;
    }
    if (len >= 8) {
        ascon_masked_data_load(word, data, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        data += 8;
        len -= 8;
        if (len > 0) {
            ascon_masked_data_load_partial(word, data, len, trng);
            ascon_masked_data_xor(&(state->M[1]), word);
        }
        ascon_masked_word_pad(&(state->M[1]), len);
    } else {
        if (len > 0) {
            ascon_masked_data_load_partial(word, data, len, trng);
            ascon_masked_data_xor(&(state->M[0]), word);
        }
        ascon_masked_word_pad(&(state->M[0]), len);
    }
    ascon_masked_data_permute(state, first_round, preserve);
}

void ascon_masked_aead_encrypt_8
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng)
{
    while (len >= 8) {
        ascon_masked_data_load(word, src, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_store(dest, &(state->M[0]));
        ascon_masked_data_permute(state, first_round, preserve);
        dest += 8;
        src += 8;
        len -= 8;
    }
    if (len > 0) {
        ascon_masked_data_load_partial(word, src, len, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_store_partial(dest, len, &(state->M[0]));
    }
    ascon_masked_word_pad(&(state->M[0]), len);
}

void ascon_masked_aead_encrypt_16
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng)
{
    while (len >= 16) {
        ascon_masked_data_load(word, src, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_load(word, src + 8, trng);
        ascon_masked_data_xor(&(state->M[1]), word);
        ascon_masked_data_store(dest, &(state->M[0]));
        ascon_masked_data_store(dest + 8, &(state->M[1]));
        ascon_masked_data_permute(state, first_round, preserve);
        dest += 16;
        src += 16;
        len -= 16;
    }
    if (len >= 8) {
        ascon_masked_data_load(word, src, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_store(dest, &(state->M[0]));
        dest += 8;
        src += 8;
        len -= 8;
        if (len > 0) {
            ascon_masked_data_load_partial(word, src, len, trng);
            ascon_masked_data_xor(&(state->M[1]), word);
            ascon_masked_data_store_partial(dest, len, &(state->M[1]));
        }
        ascon_masked_word_pad(&(state->M[1]), len);
    } else {
        if (len > 0) {
            ascon_masked_data_load_partial(word, src, len, trng);
            ascon_masked_data_xor(&(state->M[0]), word);
            ascon_masked_data_store_partial(dest, len, &(state->M[0]));
        }
        ascon_masked_word_pad(&(state->M[0]), len);
    }
}

void ascon_masked_aead_decrypt_8
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng)
{
    while (len >= 8) {
        ascon_masked_data_load(word, src, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_store(dest, &(state->M[0]));
        state->M[0] = *word;
        ascon_masked_data_permute(state, first_round, preserve);
        dest += 8;
        src += 8;
        len -= 8;
    }
    if (len > 0) {
        ascon_masked_data_load_partial(word, src, len, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_store_partial(dest, len, &(state->M[0]));
        ascon_masked_data_replace(&(state->M[0]), word, len);
    }
    ascon_masked_word_pad(&(state->M[0]), len);
}

void ascon_masked_aead_decrypt_16
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round,
     ascon_masked_word_t *word, uint64_t *preserve, ascon_trng_state_t *trng)
{
    while (len >= 16) {
        ascon_masked_data_load(word, src, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_store(dest, &(state->M[0]));
        state->M[0] = *word;
        ascon_masked_data_load(word, src + 8, trng);
        ascon_masked_data_xor(&(state->M[1]), word);
        ascon_masked_data_store(dest + 8, &(state->M[1]));
        state->M[1] = *word;
        ascon_masked_data_permute(state, first_round, preserve);
        dest += 16;
        src += 16;
        len -= 16;
    }
    if (len >= 8) {
        ascon_masked_data_load(word, src, trng);
        ascon_masked_data_xor(&(state->M[0]), word);
        ascon_masked_data_store(dest, &(state->M[0]));
        state->M[0] = *word;
        dest += 8;
        src += 8;
        len -= 8;
        if (len > 0) {
            ascon_masked_data_load_partial(word, src, len, trng);
            ascon_masked_data_xor(&(state->M[1]), word);
            ascon_masked_data_store_partial(dest, len, &(state->M[1]));
            ascon_masked_data_replace(&(state->M[1]), word, len);
        }
        ascon_masked_word_pad(&(state->M[1]), len);
    } else {
        if (len > 0) {
            ascon_masked_data_load_partial(word, src, len, trng);
            ascon_masked_data_xor(&(state->M[0]), word);
            ascon_masked_data_store_partial(dest, len, &(state->M[0]));
            ascon_masked_data_replace(&(state->M[0]), word, len);
        }
        ascon_masked_word_pad(&(state->M[0]), len);
    }
}

#endif /* ASCON_MASKED_DATA_SHARES != 1 */
