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

#include "test-cipher.h"
#include <ascon/hmac.h>
#include <ascon/pbkdf2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_OUT_LEN 40

typedef struct
{
    const char *name;
    const char *password;
    const char *salt;
    unsigned count;
    unsigned char out[MAX_OUT_LEN];
    size_t out_len;

} TestPBKDF2Vector;

/* We use the SHA256 test vectors but ignore the output.  Instead we use a
 * very simple implementation of PBKDF2 to cross-check the one in the library */
/* https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors */
static TestPBKDF2Vector const testVectorPBKDF2_1 = {
    "Test Vector 1",
    "password",
    "salt",
    1,
    {0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
     0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
     0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
     0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b},
    32
};
static TestPBKDF2Vector const testVectorPBKDF2_2 = {
    "Test Vector 2",
    "password",
    "salt",
    2,
    {0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
     0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
     0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
     0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43},
    32
};
static TestPBKDF2Vector const testVectorPBKDF2_3 = {
    "Test Vector 3",
    "password",
    "salt",
    4096,
    {0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
     0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
     0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
     0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a},
    32
};
static TestPBKDF2Vector const testVectorPBKDF2_4 = {
    "Test Vector 4",
    "passwordPASSWORDpassword",
    "saltSALTsaltSALTsaltSALTsaltSALTsalt",
    4096,
    {0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
     0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
     0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
     0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
     0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9},
    40
};

typedef void (*pbkdf2_func_t)
    (unsigned char *out, size_t outlen,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen, unsigned long count);
typedef void (*hmac_func_t)
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/* Simple implementation of PBKDF2 based on RFC 8018 for
 * cross-checking the more efficient one in the library. */
static void PRF(hmac_func_t hmac, size_t hmac_size,
                const char *password, const char *salt,
                uint32_t i, const unsigned char *in, unsigned char *out)
{
    if (salt) {
        size_t salt_len = strlen(salt);
        unsigned char temp[salt_len + 4];
        memcpy(temp, salt, salt_len);
        temp[salt_len]     = (unsigned char)(i >> 24);
        temp[salt_len + 1] = (unsigned char)(i >> 16);
        temp[salt_len + 2] = (unsigned char)(i >> 8);
        temp[salt_len + 3] = (unsigned char)i;
        (*hmac)(out, (const unsigned char *)password, strlen(password),
                temp, salt_len + 4);
    } else {
        (*hmac)(out, (const unsigned char *)password, strlen(password),
                in, hmac_size);
    }
}
static void F(hmac_func_t hmac, size_t hmac_size,
              const char *password, const char *salt,
              uint32_t c, uint32_t i, unsigned char *out)
{
    unsigned char U[hmac_size];
    size_t posn;
    PRF(hmac, hmac_size, password, salt, i, 0, out);
    memcpy(U, out, hmac_size);
    while (c > 1) {
        PRF(hmac, hmac_size, password, 0, i, U, U);
        for (posn = 0; posn < hmac_size; ++posn)
            out[posn] ^= U[posn];
        --c;
    }
}
static void PBKDF2(hmac_func_t hmac, size_t hmac_size,
                   const char *password, const char *salt,
                   uint32_t c, unsigned char *out, size_t outlen)
{
    unsigned char T[hmac_size];
    uint32_t i = 1;
    while (outlen > 0) {
        size_t len = outlen;
        if (len > hmac_size)
            len = hmac_size;
        F(hmac, hmac_size, password, salt, c, i, T);
        memcpy(out, T, len);
        out += len;
        outlen -= len;
        ++i;
    }
}

static void test_pbkdf2_vector
    (const char *hash_name, pbkdf2_func_t pbkdf2, hmac_func_t hmac,
     size_t hmac_size, const TestPBKDF2Vector *test_vector)
{
    unsigned char expected[MAX_OUT_LEN];
    unsigned char actual[MAX_OUT_LEN];
    int ok = 1;

    printf("%s %s ... ", hash_name, test_vector->name);
    fflush(stdout);

    /* Create the expected vector using the underlying HMAC function */
    PBKDF2(hmac, hmac_size, test_vector->password,
           test_vector->salt, test_vector->count,
           expected, test_vector->out_len);

    /* Test generating the full output in one go */
    memset(actual, 0xAA, sizeof(actual));
    (*pbkdf2)
        (actual, test_vector->out_len,
         (const unsigned char *)(test_vector->password),
         strlen(test_vector->password),
         (const unsigned char *)(test_vector->salt),
         strlen(test_vector->salt),
         test_vector->count);
    if (test_memcmp(actual, expected, test_vector->out_len) != 0) {
        ok = 0;
    }

    /* Test generating 1/3rd the output to check output truncation */
    memset(actual, 0xAA, sizeof(actual));
    (*pbkdf2)
        (actual, test_vector->out_len / 3,
         (const unsigned char *)(test_vector->password),
         strlen(test_vector->password),
         (const unsigned char *)(test_vector->salt),
         strlen(test_vector->salt),
         test_vector->count);
    if (test_memcmp(actual, expected, test_vector->out_len / 3) != 0) {
        ok = 0;
    }

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

    test_pbkdf2_vector
        ("ASCON", ascon_pbkdf2, ascon_hmac,
         ASCON_HMAC_SIZE, &testVectorPBKDF2_1);
    test_pbkdf2_vector
        ("ASCON", ascon_pbkdf2, ascon_hmac,
         ASCON_HMAC_SIZE, &testVectorPBKDF2_2);
    test_pbkdf2_vector
        ("ASCON", ascon_pbkdf2, ascon_hmac,
         ASCON_HMAC_SIZE, &testVectorPBKDF2_3);
    test_pbkdf2_vector
        ("ASCON", ascon_pbkdf2, ascon_hmac,
         ASCON_HMAC_SIZE, &testVectorPBKDF2_4);

    return test_exit_result;
}
