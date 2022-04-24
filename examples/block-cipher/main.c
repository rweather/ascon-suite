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

#include "ascon-ecb.h"
#include <stdio.h>
#include <string.h>

typedef struct
{
    unsigned char key[16];
    unsigned char tweak[12];
    unsigned char pt[16];

} TestVector;

static TestVector const vec1 = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};

static TestVector const vec2 = {
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
    {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
     0x19, 0x1a, 0x1b, 0x1c},
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
     0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
};

/* Slight change to the tweak */
static TestVector const vec3 = {
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
    {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
     0x19, 0x1a, 0x1b, 0x1d},
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
     0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
};

/* Slight change to the key */
static TestVector const vec4 = {
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff},
    {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
     0x19, 0x1a, 0x1b, 0x1c},
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
     0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
};

/* Slight change to the plaintext */
static TestVector const vec5 = {
    {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
    {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
     0x19, 0x1a, 0x1b, 0x1c},
    {0xaf, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
     0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
};

/* Randomly generated */
static TestVector const vec6 = {
    {0x73, 0x18, 0xac, 0x18, 0x8b, 0x8d, 0x46, 0x45,
     0x8e, 0x3a, 0xef, 0x22, 0x5f, 0xa0, 0xc8, 0x62},
    {0x59, 0x19, 0x06, 0x5b, 0xf2, 0x01, 0x42, 0x4c,
     0xa2, 0xef, 0xcd, 0xa1},
    {0xe0, 0x06, 0xc3, 0x0f, 0x8e, 0x0b, 0x4b, 0x05,
     0x85, 0x2d, 0xca, 0x86, 0x5c, 0x9d, 0x4c, 0x32}
};

static void print_hex
    (const char *name, const unsigned char *data, unsigned len)
{
    printf("%-7s = ", name);
    while (len > 0) {
        printf("%02X", *data);
        ++data;
        --len;
    }
    printf("\n");
}

static int exit_val = 0;

static void run_test(const TestVector *vec)
{
    ascon_ecb_key_schedule_t ks;
    unsigned char c[16];
    unsigned char p[16];

    print_hex("Key", vec->key, sizeof(vec->key));
    print_hex("Tweak", vec->tweak, sizeof(vec->tweak));
    print_hex("PT", vec->pt, sizeof(vec->pt));

    ascon_ecb_init(&ks, vec->key);
    ascon_ecb_encrypt(&ks, vec->tweak, c, vec->pt);
    ascon_ecb_decrypt(&ks, vec->tweak, p, c);
    ascon_ecb_free(&ks);

    print_hex("CT", c, sizeof(c));
    print_hex("Inverse", p, sizeof(p));

    if (memcmp(p, vec->pt, sizeof(p)) != 0) {
        printf("FAILED!\n");
        exit_val = 1;
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    run_test(&vec1);
    run_test(&vec2);
    run_test(&vec3);
    run_test(&vec4);
    run_test(&vec5);
    run_test(&vec6);

    return exit_val;
}
