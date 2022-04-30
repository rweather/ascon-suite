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
 * HMAC, HKDF, KMAC, and PBKDF2 use ASCON-HASH and ASCON-HASHA to
 * cross-check the actual code against simplified versions.
 *
 * The problem is that if the hash is broken the tests will appear to
 * succeed because it is checking the broken hash against itself.
 *
 * This sanity check is used to make sure ASCON-HASH and ASCON-HASHA
 * are basically working before falsely reporting that the modes work.
 */
int hash_sanity_check(void)
{
    static unsigned char const hash_expected[ASCON_HASH_SIZE] = {
        0xd3, 0x7f, 0xe9, 0xf1, 0xd1, 0x0d, 0xbc, 0xfa,
        0xd8, 0x40, 0x8a, 0x68, 0x04, 0xdb, 0xe9, 0x11,
        0x24, 0xa8, 0x91, 0x26, 0x93, 0x32, 0x2b, 0xb2,
        0x3e, 0xc1, 0x70, 0x1e, 0x19, 0xe3, 0xfd, 0x51
    };
    static unsigned char const hasha_expected[ASCON_HASHA_SIZE] = {
        0xb2, 0x09, 0x99, 0x00, 0x45, 0x71, 0xad, 0x14,
        0x61, 0xb2, 0xa9, 0xb4, 0x7a, 0x8e, 0xab, 0xa6,
        0x23, 0x87, 0xa8, 0x27, 0xf0, 0xc3, 0xba, 0xd3,
        0x99, 0xe6, 0xf2, 0x51, 0xc3, 0x5e, 0x16, 0x34
    };
    unsigned char hash[ASCON_HASH_SIZE];
    unsigned char hasha[ASCON_HASHA_SIZE];
    int ok = 1;
    printf("Hash Sanity Check ...");
    fflush(stdout);
    ascon_hash(hash, (const unsigned char *)"abc", 3);
    ascon_hasha(hasha, (const unsigned char *)"xyzzy", 5);
    if (test_memcmp(hash, hash_expected, sizeof(hash)) != 0)
        ok = 0;
    if (test_memcmp(hasha, hasha_expected, sizeof(hasha)) != 0)
        ok = 0;
    if (!ok)
        printf("failed\n");
    else
        printf("ok\n");
    return ok;
}
