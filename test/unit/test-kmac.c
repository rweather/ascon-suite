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

#include <ascon/kmac.h>
#include <ascon/utility.h>
#include "test-cipher.h"
#include "core/ascon-util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define AEAD_MAX_KEY_LEN 32
#define AEAD_MAX_DATA_LEN 256
#define AEAD_MAX_HASH_LEN 64

/* Information about a test vector for a keyed MAC algorithm */
typedef struct
{
    const char *name;
    unsigned char key[AEAD_MAX_KEY_LEN];
    unsigned key_len;
    unsigned char input[AEAD_MAX_DATA_LEN];
    unsigned input_len;
    const char *salt;
    unsigned output_len;

} aead_mac_test_vector_t;

/* Test vectors from: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf */
static aead_mac_test_vector_t const testVectorNIST_1 = {
    "Test Vector 1",
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
     0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
     0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
     0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F},
    32,
    {0x00, 0x01, 0x02, 0x03},
    4,
    "",
    32
};
static aead_mac_test_vector_t const testVectorNIST_2 = {
    "Test Vector 2",
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
     0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
     0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
     0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F},
    32,
    {0x00, 0x01, 0x02, 0x03},
    4,
    "My Tagged Application",
    32
};

typedef void (*aead_hash_init_custom_t)
    (void *state, const char *function_name,
     const unsigned char *custom, size_t customlen, size_t outlen);
typedef void (*aead_hash_free_t)(void *state);
typedef void (*aead_xof_absorb_t)
    (void *state, const unsigned char *in, size_t inlen);
typedef void (*aead_xof_squeeze_t)
    (void *state, unsigned char *out, size_t outlen);

typedef struct
{
    size_t state_size;
    size_t hash_len;
    aead_hash_init_custom_t init;
    aead_hash_free_t free;
    aead_xof_absorb_t absorb;
    aead_xof_squeeze_t squeeze;

} aead_hash_algorithm_t;

static aead_hash_algorithm_t const ascon_xof_algorithm = {
    .state_size = sizeof(ascon_xof_state_t),
    .hash_len = ASCON_HASH_SIZE,
    .init = (aead_hash_init_custom_t)ascon_xof_init_custom,
    .free = (aead_hash_free_t)ascon_xof_free,
    .absorb = (aead_xof_absorb_t)ascon_xof_absorb,
    .squeeze = (aead_xof_squeeze_t)ascon_xof_squeeze
};

static aead_hash_algorithm_t const ascon_xofa_algorithm = {
    .state_size = sizeof(ascon_xofa_state_t),
    .hash_len = ASCON_HASHA_SIZE,
    .init = (aead_hash_init_custom_t)ascon_xofa_init_custom,
    .free = (aead_hash_free_t)ascon_xofa_free,
    .absorb = (aead_xof_absorb_t)ascon_xofa_absorb,
    .squeeze = (aead_xof_squeeze_t)ascon_xofa_squeeze
};

/* Simple implementation of KMAC based on a configurable XOF algorithm
 * for cross-checking the implementation in the library */
static void simple_kmac
    (const aead_hash_algorithm_t *alg,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen)
{
    void *state;

    /* Allocate space for the XOF state */
    state = malloc(alg->state_size);
    if (!state)
        exit(1);

    /* Initialize the XOF context for the KMAC function */
    (*(alg->init))(state, "KMAC", custom, customlen, outlen);

    /* Absorb the key */
    (*(alg->absorb))(state, key, keylen);

    /* Absorb the input data */
    (*(alg->absorb))(state, in, inlen);

    /* Squeeze out the result */
    (*(alg->squeeze))(state, out, outlen);

    /* Clean up */
    (*(alg->free))(state);
    free(state);
}

typedef void (*kmac_allinone_t)
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);
typedef void (*kmac_init_t)
    (void *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen);
typedef void (*kmac_free_t)(void *state);
typedef void (*kmac_absorb_t)
    (void *state, const unsigned char *in, size_t inlen);
typedef void (*kmac_squeeze_t)
    (void *state, unsigned char *out, size_t outlen);

static void test_kmac_alg
    (const char *name, const aead_hash_algorithm_t *alg, unsigned state_size,
     kmac_allinone_t allinone, kmac_init_t init, kmac_free_t free,
     kmac_absorb_t absorb, kmac_squeeze_t squeeze,
     const aead_mac_test_vector_t *test)
{
    unsigned char expected[AEAD_MAX_HASH_LEN];
    unsigned char out[AEAD_MAX_HASH_LEN];
    void *state;
    int ok;

    printf("%s %s ... ", name, test->name);
    fflush(stdout);

    /* Use the simple implementation to get the output we're looking for */
    memset(expected, 0xAA, sizeof(expected));
    simple_kmac(alg, test->key, test->key_len,
                test->input, test->input_len,
                (const unsigned char *)(test->salt),
                strlen(test->salt), expected, test->output_len);

    /* Check the all-in-one instantiation */
    memset(out, 0x66, sizeof(out));
    (*allinone)(test->key, test->key_len,
                test->input, test->input_len,
                (const unsigned char *)(test->salt),
                strlen(test->salt), out, test->output_len);
    ok = (test_memcmp(out, expected, test->output_len) == 0);

    /* Check the incremental instantiation */
    memset(out, 0xBB, sizeof(out));
    state = malloc(state_size);
    if (!state)
        exit(1);
    (*init)(state, test->key, test->key_len,
            (const unsigned char *)(test->salt), strlen(test->salt),
            test->output_len);
    (*absorb)(state, test->input, test->input_len);
    (*squeeze)(state, out, test->output_len);
    (*free)(state);
    if (test_memcmp(out, expected, test->output_len) != 0)
        ok = 0;
    free(state);

    /* Report the results */
    if (ok) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    if (!hash_sanity_check())
        return 1;

    test_kmac_alg("ASCON KMAC", &ascon_xof_algorithm,
                  sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmac,
                  (kmac_init_t)ascon_kmac_init,
                  (kmac_free_t)ascon_kmac_free,
                  (kmac_absorb_t)ascon_kmac_absorb,
                  (kmac_squeeze_t)ascon_kmac_squeeze,
                  &testVectorNIST_1);
    test_kmac_alg("ASCON KMAC", &ascon_xof_algorithm,
                  sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmac,
                  (kmac_init_t)ascon_kmac_init,
                  (kmac_free_t)ascon_kmac_free,
                  (kmac_absorb_t)ascon_kmac_absorb,
                  (kmac_squeeze_t)ascon_kmac_squeeze,
                  &testVectorNIST_2);

    test_kmac_alg("ASCON-A KMAC", &ascon_xofa_algorithm,
                  sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmaca,
                  (kmac_init_t)ascon_kmaca_init,
                  (kmac_free_t)ascon_kmaca_free,
                  (kmac_absorb_t)ascon_kmaca_absorb,
                  (kmac_squeeze_t)ascon_kmaca_squeeze,
                  &testVectorNIST_1);
    test_kmac_alg("ASCON-A KMAC", &ascon_xofa_algorithm,
                  sizeof(ascon_kmac_state_t),
                  (kmac_allinone_t)ascon_kmaca,
                  (kmac_init_t)ascon_kmaca_init,
                  (kmac_free_t)ascon_kmaca_free,
                  (kmac_absorb_t)ascon_kmaca_absorb,
                  (kmac_squeeze_t)ascon_kmaca_squeeze,
                  &testVectorNIST_2);

    return test_exit_result;
}
