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

#include "sha256.h"
#include "core/ascon-util.h"
#include "test-cipher.h"
#include <ascon/hkdf.h>
#include <ascon/utility.h>
#include <ascon/hmac.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Test the HKDF implementation using SHA-256 to verify the code structure */
typedef struct {
    unsigned char prk[32];
    unsigned char out[32];
    unsigned char counter;
    unsigned char posn;
} sha256_hkdf_state_t;
int sha256_hkdf
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen);
void sha256_hkdf_extract
    (sha256_hkdf_state_t *state,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen);
int sha256_hkdf_expand
    (sha256_hkdf_state_t *state,
     const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen);
void sha256_hkdf_free(sha256_hkdf_state_t *state);
#define HKDF_ALG_NAME sha256_hkdf
#define HKDF_STATE sha256_hkdf_state_t
#define HKDF_HMAC_SIZE SHA256_HASH_SIZE
#define HKDF_HMAC_STATE sha256_hmac_state_t
#define HKDF_HMAC_INIT sha256_hmac_init
#define HKDF_HMAC_UPDATE sha256_hmac_update
#define HKDF_HMAC_FINALIZE sha256_hmac_finalize
#include "kdf/ascon-hkdf-common.h"

#define MAX_KEY_LEN 80
#define MAX_SALT_LEN 80
#define MAX_INFO_LEN 80
#define MAX_OUT_LEN 82

typedef struct
{
    const char *name;
    unsigned char key[MAX_KEY_LEN];
    size_t key_len;
    unsigned char salt[MAX_SALT_LEN];
    size_t salt_len;
    unsigned char info[MAX_INFO_LEN];
    size_t info_len;
    unsigned char out[MAX_OUT_LEN];
    size_t out_len;

} TestHKDFVector;

/* Test cases from RFC-5869 */
static TestHKDFVector const testVectorHKDF_1 = {
    "Test Vector 1",
    {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
    22,
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c},
    13,
    {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
     0xf8, 0xf9},
    10,
    {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
     0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
     0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
     0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
     0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
     0x58, 0x65},
    42
};
static TestHKDFVector const testVectorHKDF_2 = {
    "Test Vector 2",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
     0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
     0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
     0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f},
    80,
    {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
     0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
     0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
     0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
     0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
     0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
     0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
     0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
     0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf},
    80,
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
     0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
     0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
     0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
     0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
     0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
     0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
     0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
     0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff},
    80,
    {0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
     0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
     0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
     0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
     0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
     0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
     0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
     0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
     0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
     0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
     0x1d, 0x87},
    82
};
static TestHKDFVector const testVectorHKDF_3 = {
    "Test Vector 3",
    {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
    22,
    {0},
    0,
    {0},
    0,
    {0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
     0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
     0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
     0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
     0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
     0x96, 0xc8},
    42
};

static void test_sha256_hkdf_vector(const TestHKDFVector *test_vector)
{
    sha256_hkdf_state_t state;
    unsigned char actual[MAX_OUT_LEN];
    int result;
    size_t offset;
    int ok = 1;

    printf("    SHA256-HKDF %s ... ", test_vector->name);
    fflush(stdout);

    /* Test the all-in-one HKDF function */
    memset(actual, 0xAA, sizeof(actual));
    result = sha256_hkdf
        (actual, test_vector->out_len,
         test_vector->key, test_vector->key_len,
         test_vector->salt, test_vector->salt_len,
         test_vector->info, test_vector->info_len);
    if (result != 0 ||
            test_memcmp(actual, test_vector->out, test_vector->out_len) != 0) {
        ok = 0;
    }

    /* Test incremental expansion, byte by byte */
    memset(actual, 0xAA, sizeof(actual));
    sha256_hkdf_extract
        (&state, test_vector->key, test_vector->key_len,
         test_vector->salt, test_vector->salt_len);
    result = 0;
    for (offset = 0; offset < test_vector->out_len; ++offset) {
        result = sha256_hkdf_expand
            (&state, test_vector->info, test_vector->info_len,
             actual + offset, 1);
        if (result != 0)
            break;
    }
    if (result != 0 ||
            test_memcmp(actual, test_vector->out, test_vector->out_len) != 0) {
        ok = 0;
    }

    if (ok) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

/* Simple implementation of HKDF from RFC 5869 that is used to
 * cross-check the more efficient version in the library */
typedef void (*hmac_func_t)
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);
static void HKDF
    (hmac_func_t hmac, unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen)
{
    unsigned char PRK[ASCON_HMAC_SIZE];
    unsigned char T[ASCON_HMAC_SIZE];
    unsigned char block[ASCON_HMAC_SIZE + infolen + 1];
    size_t blocklen, tlen;
    size_t posn;

    /* HKDF-Extract */
    (*hmac)(PRK, salt, saltlen, key, keylen);

    /* HKDF-Expand */
    memset(T, 0, sizeof(T));
    tlen = 0;
    for (posn = 0; posn < outlen; posn += sizeof(T)) {
        memcpy(block, T, tlen);
        memcpy(block + tlen, info, infolen);
        block[tlen + infolen] = (unsigned char)((posn / ASCON_HMAC_SIZE) + 1);
        blocklen = tlen + infolen + 1;
        (*hmac)(T, PRK, sizeof(PRK), block, blocklen);
        tlen = sizeof(T);
        if ((outlen - posn) >= sizeof(T))
            memcpy(out + posn, T, sizeof(T));
        else
            memcpy(out + posn, T, outlen - posn);
    }
}

typedef int (*hkdf_all_in_one_t)
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen);
typedef void (*hkdf_extract_t)
    (void *state, const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen);
typedef int (*hkdf_expand_t)
    (void *state, const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen);

/* Perform tests on the HKDF implementation in the library */
static void test_hkdf_vector
    (const char *name, const TestHKDFVector *test_vector,
     hkdf_all_in_one_t all_in_one, hkdf_extract_t extract,
     hkdf_expand_t expand, hmac_func_t hmac, size_t state_size)
{
    unsigned char state[state_size];
    unsigned char actual[MAX_OUT_LEN];
    unsigned char expected[MAX_OUT_LEN];
    int result;
    size_t offset;
    int ok = 1;

    printf("    %s %s ... ", name, test_vector->name);
    fflush(stdout);

    /* Test the all-in-one HKDF function */
    memset(actual, 0xAA, sizeof(actual));
    result = (*all_in_one)
        (actual, test_vector->out_len,
         test_vector->key, test_vector->key_len,
         test_vector->salt, test_vector->salt_len,
         test_vector->info, test_vector->info_len);
    HKDF(hmac, expected, test_vector->out_len,
         test_vector->key, test_vector->key_len,
         test_vector->salt, test_vector->salt_len,
         test_vector->info, test_vector->info_len);
    if (result != 0 || test_memcmp(actual, expected, test_vector->out_len) != 0) {
        ok = 0;
    }

    /* Test incremental expansion, byte by byte */
    memset(actual, 0xAA, sizeof(actual));
    (*extract)(state, test_vector->key, test_vector->key_len,
               test_vector->salt, test_vector->salt_len);
    result = 0;
    for (offset = 0; offset < test_vector->out_len; ++offset) {
        result = (*expand)
            (state, test_vector->info, test_vector->info_len,
             actual + offset, 1);
        if (result != 0)
            break;
    }
    if (result != 0 || test_memcmp(actual, expected, test_vector->out_len) != 0) {
        ok = 0;
    }

    if (ok) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

void test_hkdf(void)
{
    printf("HKDF:\n");

    test_sha256_hkdf_vector(&testVectorHKDF_1);
    test_sha256_hkdf_vector(&testVectorHKDF_2);
    test_sha256_hkdf_vector(&testVectorHKDF_3);

    test_hkdf_vector
        ("ASCON-HKDF", &testVectorHKDF_1,
         (hkdf_all_in_one_t)ascon_hkdf,
         (hkdf_extract_t)ascon_hkdf_extract,
         (hkdf_expand_t)ascon_hkdf_expand,
         ascon_hmac, sizeof(ascon_hkdf_state_t));
    test_hkdf_vector
        ("ASCON-HKDF", &testVectorHKDF_2,
         (hkdf_all_in_one_t)ascon_hkdf,
         (hkdf_extract_t)ascon_hkdf_extract,
         (hkdf_expand_t)ascon_hkdf_expand,
         ascon_hmac, sizeof(ascon_hkdf_state_t));
    test_hkdf_vector
        ("ASCON-HKDF", &testVectorHKDF_3,
         (hkdf_all_in_one_t)ascon_hkdf,
         (hkdf_extract_t)ascon_hkdf_extract,
         (hkdf_expand_t)ascon_hkdf_expand,
         ascon_hmac, sizeof(ascon_hkdf_state_t));

    test_hkdf_vector
        ("ASCON-HKDFA", &testVectorHKDF_1,
         (hkdf_all_in_one_t)ascon_hkdfa,
         (hkdf_extract_t)ascon_hkdfa_extract,
         (hkdf_expand_t)ascon_hkdfa_expand,
         ascon_hmaca, sizeof(ascon_hkdfa_state_t));
    test_hkdf_vector
        ("ASCON-HKDFA", &testVectorHKDF_2,
         (hkdf_all_in_one_t)ascon_hkdfa,
         (hkdf_extract_t)ascon_hkdfa_extract,
         (hkdf_expand_t)ascon_hkdfa_expand,
         ascon_hmaca, sizeof(ascon_hkdfa_state_t));
    test_hkdf_vector
        ("ASCON-HKDFA", &testVectorHKDF_3,
         (hkdf_all_in_one_t)ascon_hkdfa,
         (hkdf_extract_t)ascon_hkdfa_extract,
         (hkdf_expand_t)ascon_hkdfa_expand,
         ascon_hmaca, sizeof(ascon_hkdfa_state_t));

    printf("\n");
}
