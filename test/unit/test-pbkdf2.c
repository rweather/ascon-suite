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
#include <ascon/xof.h>
#include <ascon/pbkdf2.h>
#include <ascon/hmac.h>
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
    32
};
static TestPBKDF2Vector const testVectorPBKDF2_2 = {
    "Test Vector 2",
    "password",
    "salt",
    2,
    32
};
static TestPBKDF2Vector const testVectorPBKDF2_3 = {
    "Test Vector 3",
    "password",
    "salt",
    4096,
    32
};
static TestPBKDF2Vector const testVectorPBKDF2_4 = {
    "Test Vector 4",
    "passwordPASSWORDpassword",
    "saltSALTsaltSALTsaltSALTsaltSALTsalt",
    4096,
    40
};

typedef void (*pbkdf2_func_t)
    (unsigned char *out, size_t outlen,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen, unsigned long count);

/* Simple implementation of PBKDF2 based on RFC 8018 for
 * cross-checking the more efficient one in the library. */
static void PRF(size_t block_size, const char *password, const char *salt,
                uint32_t i, const unsigned char *in, unsigned char *out)
{
    ascon_xof_state_t state;
    ascon_xof_init_custom
        (&state, "PBKDF2", (const unsigned char *)password, strlen(password),
         block_size);
    if (salt) {
        size_t salt_len = strlen(salt);
        unsigned char temp[salt_len + 4];
        memcpy(temp, salt, salt_len);
        temp[salt_len]     = (unsigned char)(i >> 24);
        temp[salt_len + 1] = (unsigned char)(i >> 16);
        temp[salt_len + 2] = (unsigned char)(i >> 8);
        temp[salt_len + 3] = (unsigned char)i;
        ascon_xof_absorb(&state, temp, salt_len + 4);
    } else {
        ascon_xof_absorb(&state, in, block_size);
    }
    ascon_xof_squeeze(&state, out, block_size);
    ascon_xof_free(&state);
}
static void F(size_t block_size, const char *password, const char *salt,
              uint32_t c, uint32_t i, unsigned char *out)
{
    unsigned char U[block_size];
    size_t posn;
    PRF(block_size, password, salt, i, 0, out);
    memcpy(U, out, block_size);
    while (c > 1) {
        PRF(block_size, password, 0, i, U, U);
        for (posn = 0; posn < block_size; ++posn)
            out[posn] ^= U[posn];
        --c;
    }
}
static void PBKDF2(size_t block_size, const char *password, const char *salt,
                   uint32_t c, unsigned char *out, size_t outlen)
{
    unsigned char T[block_size];
    uint32_t i = 1;
    while (outlen > 0) {
        size_t len = outlen;
        if (len > block_size)
            len = block_size;
        F(block_size, password, salt, c, i, T);
        memcpy(out, T, len);
        out += len;
        outlen -= len;
        ++i;
    }
}

/* Simple implementation of PBKDF2 based on RFC 8018 using ASCON-HMAC. */
static void PRF_HMAC(size_t hmac_size, const char *password, const char *salt,
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
        ascon_hmac(out, (const unsigned char *)password, strlen(password),
                   temp, salt_len + 4);
    } else {
        ascon_hmac(out, (const unsigned char *)password, strlen(password),
                   in, hmac_size);
    }
}
static void F_HMAC(size_t hmac_size, const char *password, const char *salt,
                   uint32_t c, uint32_t i, unsigned char *out)
{
    unsigned char U[hmac_size];
    size_t posn;
    PRF_HMAC(hmac_size, password, salt, i, 0, out);
    memcpy(U, out, hmac_size);
    while (c > 1) {
        PRF_HMAC(hmac_size, password, 0, i, U, U);
        for (posn = 0; posn < hmac_size; ++posn)
            out[posn] ^= U[posn];
        --c;
    }
}
static void PBKDF2_HMAC(size_t hmac_size, const char *password,
                        const char *salt, uint32_t c,
                        unsigned char *out, size_t outlen)
{
    unsigned char T[hmac_size];
    uint32_t i = 1;
    while (outlen > 0) {
        size_t len = outlen;
        if (len > hmac_size)
            len = hmac_size;
        F_HMAC(hmac_size, password, salt, c, i, T);
        memcpy(out, T, len);
        out += len;
        outlen -= len;
        ++i;
    }
}

static void test_pbkdf2_vector
    (const char *hash_name, pbkdf2_func_t pbkdf2,
     size_t block_size, const TestPBKDF2Vector *test_vector, int is_hmac)
{
    unsigned char expected[MAX_OUT_LEN];
    unsigned char actual[MAX_OUT_LEN];
    int ok = 1;

    printf("%s %s ... ", hash_name, test_vector->name);
    fflush(stdout);

    /* Create the expected vector using the underlying PRF function */
    if (is_hmac) {
        PBKDF2_HMAC(block_size, test_vector->password,
                    test_vector->salt, test_vector->count,
                    expected, test_vector->out_len);
    } else {
        PBKDF2(block_size, test_vector->password,
               test_vector->salt, test_vector->count,
               expected, test_vector->out_len);
    }

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

    if (!hash_sanity_check())
        return 1;

    test_pbkdf2_vector
        ("ASCON-PBKDF2", ascon_pbkdf2,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_1, 0);
    test_pbkdf2_vector
        ("ASCON-PBKDF2", ascon_pbkdf2,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_2, 0);
    test_pbkdf2_vector
        ("ASCON-PBKDF2", ascon_pbkdf2,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_3, 0);
    test_pbkdf2_vector
        ("ASCON-PBKDF2", ascon_pbkdf2,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_4, 0);

    test_pbkdf2_vector
        ("ASCON-PBKDF2-HMAC", ascon_pbkdf2_hmac,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_1, 1);
    test_pbkdf2_vector
        ("ASCON-PBKDF2-HMAC", ascon_pbkdf2_hmac,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_2, 1);
    test_pbkdf2_vector
        ("ASCON-PBKDF2-HMAC", ascon_pbkdf2_hmac,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_3, 1);
    test_pbkdf2_vector
        ("ASCON-PBKDF2-HMAC", ascon_pbkdf2_hmac,
         ASCON_PBKDF2_SIZE, &testVectorPBKDF2_4, 1);

    return test_exit_result;
}
