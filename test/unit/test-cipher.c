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
//#include <ascon/hash.h>
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

#if 0
void HMAC_common(unsigned char out[32],
                 const unsigned char key[32], size_t key_len,
                 const unsigned char *data1, size_t data1_len,
                 const unsigned char *data2, size_t data2_len,
                 const unsigned char *data3, size_t data3_len)
{
    ascon_hash_context_t ctx;
    unsigned char block[64];
    unsigned char temp[32];
    size_t len;
    int index;

    /* Format the inner key block */
    if (key_len <= 64) {
        memcpy(block, key, key_len);
        len = key_len;
    } else {
        ascon_hash(block, key, key_len);
        len = ASCON_HASH_SIZE;
    }
    memset(block + len, 0, 64 - len);
    for (index = 0; index < 64; ++index)
        block[index] ^= 0x36;

    /* Inner hashing process */
    ascon_hash_init(&ctx);
    ascon_hash_update(&ctx, block, 64);
    ascon_hash_update(&ctx, data1, data1_len);
    ascon_hash_update(&ctx, data2, data2_len);
    ascon_hash_update(&ctx, data3, data3_len);
    ascon_hash_finalize(&ctx, temp);

    /* Format the outer key block */
    if (key_len <= 64) {
        memcpy(block, key, key_len);
        len = key_len;
    } else {
        ascon_hash(block, key, key_len);
        len = ASCON_HASH_SIZE;
    }
    memset(block + len, 0, 64 - len);
    for (index = 0; index < 64; ++index)
        block[index] ^= 0x5C;

    /* Outer hashing process */
    ascon_hash_init(&ctx);
    ascon_hash_update(&ctx, block, 64);
    ascon_hash_update(&ctx, temp, 32);
    ascon_hash_finalize(&ctx, out);
}
#endif
