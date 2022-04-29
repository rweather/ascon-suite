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

#include "aead/ascon-aead-masked-common.h"
#include "core/ascon-util-snp.h"

/* Initialization vector for ASCON-80pq, expanded to 8 bytes */
static uint8_t const ASCON80PQ_IV[8] =
    {0xa0, 0x40, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00};

/* Absorb the key and nonce, and then convert the state from the
 * number of key shares into the number of data shares */
static void ascon80pq_masked_aead_init
    (ascon_masked_state_t *state,
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_state_t *state_x1,
#endif
    ascon_trng_state_t *trng, ascon_masked_word_t *word,
    uint64_t *preserve, const unsigned char *npub,
    const ascon_masked_key_160_t *k)
{
    /* Generate random words for use in permutation calls */
#if ASCON_MASKED_KEY_SHARES == 2
    preserve[0] = ascon_trng_generate_64(trng);
#elif ASCON_MASKED_KEY_SHARES == 3
    preserve[0] = ascon_trng_generate_64(trng);
    preserve[1] = ascon_trng_generate_64(trng);
#else
    preserve[0] = ascon_trng_generate_64(trng);
    preserve[1] = ascon_trng_generate_64(trng);
    preserve[2] = ascon_trng_generate_64(trng);
#endif

    /* Format the key and nonce into the initial state */
    ascon_masked_state_init(state);
    ascon_masked_key_randomize(state, trng);
    ascon_masked_key_load(word, ASCON80PQ_IV, trng);
    ascon_masked_key_xor(&(state->M[0]), word);
    ascon_masked_key_xor(&(state->M[0]), &(k->k[3]));
    ascon_masked_key_xor(&(state->M[1]), &(k->k[4]));
    ascon_masked_key_xor(&(state->M[2]), &(k->k[5]));
    ascon_masked_key_load(word, npub, trng);
    ascon_masked_key_xor(&(state->M[3]), word);
    ascon_masked_key_load(word, npub + 8, trng);
    ascon_masked_key_xor(&(state->M[4]), word);
    ascon_masked_key_permute(state, 0, preserve);
    ascon_masked_key_xor(&(state->M[2]), &(k->k[3]));
    ascon_masked_key_xor(&(state->M[3]), &(k->k[4]));
    ascon_masked_key_xor(&(state->M[4]), &(k->k[5]));

    /* Convert the key shares form into the data shares form */
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_copy_key_to_x1(state_x1, state);
#elif ASCON_MASKED_DATA_SHARES == 2
    ascon_copy_key_to_x2(state, trng);
#elif ASCON_MASKED_DATA_SHARES == 3
    ascon_copy_key_to_x3(state, trng);
#else
    ascon_copy_key_to_x4(state, trng);
#endif
}

/* Finalize and generate the authentication tag in the state */
static void ascon80pq_masked_aead_finalize
    (ascon_masked_state_t *state,
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_state_t *state_x1,
#endif
    ascon_trng_state_t *trng, uint64_t *preserve,
    const ascon_masked_key_160_t *k, unsigned char *tag)
{
    /* Refresh the randomness for the final permutation call */
#if ASCON_MASKED_KEY_SHARES == 2
    preserve[0] = ascon_trng_generate_64(trng);
#elif ASCON_MASKED_KEY_SHARES == 3
    preserve[0] = ascon_trng_generate_64(trng);
    preserve[1] = ascon_trng_generate_64(trng);
#else
    preserve[0] = ascon_trng_generate_64(trng);
    preserve[1] = ascon_trng_generate_64(trng);
    preserve[2] = ascon_trng_generate_64(trng);
#endif

    /* Convert the data shares form back into the key shares form */
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_copy_key_from_x1(state, state_x1, trng);
#elif ASCON_MASKED_DATA_SHARES == 2
    ascon_copy_key_from_x2(state, trng);
#elif ASCON_MASKED_DATA_SHARES == 3
    ascon_copy_key_from_x3(state, trng);
#else
    ascon_copy_key_from_x4(state, trng);
#endif

    /* Finalize the state and generate the tag */
    ascon_masked_key_xor(&(state->M[1]), &(k->k[0]));
    ascon_masked_key_xor(&(state->M[2]), &(k->k[1]));
    ascon_masked_key_xor(&(state->M[3]), &(k->k[2]));
    ascon_masked_key_permute(state, 0, preserve);
    ascon_masked_key_xor(&(state->M[3]), &(k->k[4]));
    ascon_masked_key_xor(&(state->M[4]), &(k->k[5]));
    ascon_masked_key_store(tag, &(state->M[3]));
    ascon_masked_key_store(tag + 8, &(state->M[4]));
}

void ascon80pq_masked_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon_masked_key_160_t *k)
{
    ascon_masked_state_t state;
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_state_t state_x1;
    unsigned char partial;
#endif
    ascon_trng_state_t trng;
    ascon_masked_word_t word;
    uint64_t preserve[ASCON_MASKED_KEY_SHARES - 1];

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON80PQ_TAG_SIZE;

    /* Initialize the random number generator */
    ascon_trng_init(&trng);

#if ASCON_MASKED_DATA_SHARES == 1
    /* Initialize the ASCON state */
    ascon80pq_masked_aead_init
        (&state, &state_x1, &trng, &word, preserve, npub, k);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_8(&state_x1, ad, adlen, 6, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state_x1);

    /* Encrypt the plaintext to create the ciphertext */
    partial = ascon_aead_encrypt_8(&state_x1, c, m, mlen, 6, 0);
    ascon_pad(&state_x1, partial);

    /* Convert the state back into key masked form and finalize */
    ascon80pq_masked_aead_finalize
        (&state, &state_x1, &trng, preserve, k, c + mlen);
#else
    /* Initialize the ASCON state */
    ascon80pq_masked_aead_init(&state, &trng, &word, preserve, npub, k);

    /* Absorb the associated data into the state */
    if (adlen > 0) {
        ascon_masked_aead_absorb_8
            (&state, ad, adlen, 6, &word, preserve, &trng);
    }

    /* Separator between the associated data and the payload */
    ascon_masked_word_separator(&(state.M[4]));

    /* Encrypt the plaintext to create the ciphertext */
    ascon_masked_aead_encrypt_8
        (&state, c, m, mlen, 6, &word, preserve, &trng);

    /* Convert the state back into key masked form and finalize */
    ascon80pq_masked_aead_finalize(&state, &trng, preserve, k, c + mlen);
#endif

    /* Clean up */
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_free(&state_x1);
#endif
    ascon_masked_state_free(&state);
    ascon_clean(&word, sizeof(word));
    ascon_clean(preserve, sizeof(preserve));
    ascon_trng_free(&trng);
}

int ascon80pq_masked_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon_masked_key_160_t *k)
{
    ascon_masked_state_t state;
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_state_t state_x1;
    unsigned char partial;
#endif
    ascon_trng_state_t trng;
    ascon_masked_word_t word;
    uint64_t preserve[ASCON_MASKED_KEY_SHARES - 1];
    unsigned char tag[ASCON80PQ_TAG_SIZE];
    int result;

    /* Set the length of the returned plaintext */
    if (clen < ASCON80PQ_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON80PQ_TAG_SIZE;

    /* Initialize the random number generator */
    ascon_trng_init(&trng);

#if ASCON_MASKED_DATA_SHARES == 1
    /* Initialize the ASCON state */
    ascon80pq_masked_aead_init
        (&state, &state_x1, &trng, &word, preserve, npub, k);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_aead_absorb_8(&state_x1, ad, adlen, 6, 1);

    /* Separator between the associated data and the payload */
    ascon_separator(&state_x1);

    /* Decrypt the ciphertext to create the plaintext */
    partial = ascon_aead_decrypt_8(&state_x1, m, c, *mlen, 6, 0);
    ascon_pad(&state_x1, partial);

    /* Convert the state back into key masked form and finalize */
    ascon80pq_masked_aead_finalize(&state, &state_x1, &trng, preserve, k, tag);
#else
    /* Initialize the ASCON state */
    ascon80pq_masked_aead_init(&state, &trng, &word, preserve, npub, k);

    /* Absorb the associated data into the state */
    if (adlen > 0) {
        ascon_masked_aead_absorb_8
            (&state, ad, adlen, 6, &word, preserve, &trng);
    }

    /* Separator between the associated data and the payload */
    ascon_masked_word_separator(&(state.M[4]));

    /* Decrypt the ciphertext to create the plaintext */
    ascon_masked_aead_decrypt_8
        (&state, m, c, *mlen, 6, &word, preserve, &trng);

    /* Convert the state back into key masked form and finalize */
    ascon80pq_masked_aead_finalize(&state, &trng, preserve, k, tag);
#endif

    /* Check the authentication tag */
    result = ascon_aead_check_tag(m, *mlen, tag, c + *mlen, ASCON80PQ_TAG_SIZE);

    /* Clean up */
#if ASCON_MASKED_DATA_SHARES == 1
    ascon_free(&state_x1);
#endif
    ascon_masked_state_free(&state);
    ascon_clean(&word, sizeof(word));
    ascon_clean(preserve, sizeof(preserve));
    ascon_clean(tag, sizeof(tag));
    ascon_trng_free(&trng);
    return result;
}
