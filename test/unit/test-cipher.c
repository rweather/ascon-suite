/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
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
#include <ascon/hash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_exit_result = 0;

static void test_print_hex
    (const char *tag, const unsigned char *data, unsigned long long len)
{
    printf("%s =", tag);
    while (len > 0) {
        printf(" %02x", data[0]);
        ++data;
        --len;
    }
    printf("\n");
}

int test_memcmp
    (const unsigned char *actual, const unsigned char *expected,
     unsigned long long len)
{
    int cmp = memcmp(actual, expected, (size_t)len);
    if (cmp == 0)
        return 0;
    printf("\n");
    test_print_hex("actual  ", actual, len);
    test_print_hex("expected", expected, len);
    return cmp;
}

/*
 * HMAC, HKDF, KMAC, and PBKDF2 unit tests use Ascon-Hash256 and
 * Ascon-XOF128 to cross-check the actual code against simplified versions.
 *
 * The problem is that if the hash is broken the tests will appear to
 * succeed because it is checking the broken hash against itself.
 *
 * This sanity check is used to make sure the core hash functions
 * are basically working before falsely reporting that the modes work.
 */
int hash_sanity_check(void)
{
    static unsigned char const hash_expected[ASCON_HASH256_SIZE] = {
        0x45, 0xAA, 0x03, 0x43, 0x1C, 0x3C, 0x82, 0x9B,
        0x3B, 0x06, 0x6F, 0x33, 0xE8, 0x44, 0xB0, 0xCC,
        0x4D, 0x20, 0xA4, 0x5A, 0xF9, 0x2D, 0x3D, 0xCF,
        0xDF, 0x34, 0xF4, 0x0F, 0xC2, 0x09, 0x35, 0xCF
    };
    unsigned char hash[ASCON_HASH256_SIZE];
    int ok = 1;
    printf("Hash Sanity Check ...");
    fflush(stdout);
    ascon_hash256(hash, (const unsigned char *)"abc", 3);
    if (test_memcmp(hash, hash_expected, sizeof(hash)) != 0)
        ok = 0;
    if (!ok)
        printf("failed\n");
    else
        printf("ok\n");
    return ok;
}
