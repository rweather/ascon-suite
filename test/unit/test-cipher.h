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

#ifndef TEST_CIPHER_H
#define TEST_CIPHER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Value to return from the main() function for the test result */
extern int test_exit_result;

/* Version of memcmp() that dumps its arguments on failure */
int test_memcmp
    (const unsigned char *actual, const unsigned char *expected,
     unsigned long long len);

/* Simple implementation of ASCON-based HMAC */
void HMAC_common(unsigned char out[32],
                 const unsigned char *key, size_t key_len,
                 const unsigned char *data1, size_t data1_len,
                 const unsigned char *data2, size_t data2_len,
                 const unsigned char *data3, size_t data3_len);
#define HMAC(out, key, data, len) \
    HMAC_common((out), (key), 32, (data), (len), 0, 0, 0, 0)
#define HMAC_2(out, key, data1, len1, data2, len2) \
    HMAC_common((out), (key), 32, (data1), (len1), (data2), (len2), 0, 0)
#define HMAC_3(out, key, data1, len1, data2, len2, data3, len3) \
    HMAC_common((out), (key), 32, (data1), (len1), \
                (data2), (len2), (data3), (len3))

#ifdef __cplusplus
}
#endif

#endif
