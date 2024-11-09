/*
 * Copyright (C) 2024 Southern Storm Software, Pty Ltd.
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

#include "permutation.h"
#include "hash.h"
#include "aead.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void print_header(const char *name)
{
    printf("\n%s:\n", name);
}

static void print_c_hex(const char *name, const uint8_t *data, size_t len)
{
    if (name) {
        printf("%s:\n", name);
    }
    unsigned offset = 0;
    while (len > 0) {
        if ((offset % 8) == 0)
            printf("   ");
        printf(" 0x%02x", data[0]);
        if (len > 1)
            printf(",");
        if ((offset % 8) == 7)
            printf("\n");
        ++data;
        --len;
        ++offset;
    }
    if ((offset % 8) != 0) {
        printf("\n");
    }
}

static void print_hex(const char *name, const uint8_t *data, size_t len)
{
    if (name) {
        printf("%s = ", name);
    }
    while (len > 0) {
        printf("%02X", data[0]);
        ++data;
        --len;
    }
    printf("\n");
}

static void test_permutation(void)
{
    static uint8_t const input[40] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };
    ascon_simple_state_t state;

    print_header("Permutation 8 Rounds");
    print_c_hex("Input", input, 40);
    memcpy(state.B, input, sizeof(state.B));
    ascon_simple_permute(&state, 8);
    print_c_hex("Output", state.B, 40);

    print_header("Permutation 12 Rounds");
    print_c_hex("Input", input, 40);
    memcpy(state.B, input, sizeof(state.B));
    ascon_simple_permute(&state, 4);
    print_c_hex("Output", state.B, 40);

    print_header("Permutation 16 Rounds");
    print_c_hex("Input", input, 40);
    memcpy(state.B, input, sizeof(state.B));
    ascon_simple_permute(&state, 0);
    print_c_hex("Output", state.B, 40);
}

static void test_hash(const char *test)
{
    unsigned char hash[ASCON_HASH_SIZE] = {0};
    if (!test)
        test = "";
    ascon_simple_hash(hash, test, strlen(test));
    print_hex(NULL, hash, ASCON_HASH_SIZE);
}

static void test_xof(const char *test)
{
    unsigned char hash[ASCON_HASH_SIZE * 2] = {0};
    if (!test)
        test = "";
    ascon_simple_xof(hash, sizeof(hash), test, strlen(test));
    print_hex(NULL, hash, sizeof(hash));
}

static void test_cxof(const char *custom, const char *test)
{
    unsigned char hash[ASCON_HASH_SIZE * 2] = {0};
    if (!custom)
        custom = "";
    if (!test)
        test = "";
    ascon_simple_cxof
        (hash, sizeof(hash), custom, strlen(custom), test, strlen(test));
    print_hex(NULL, hash, sizeof(hash));
}

static void kat_hash(void)
{
    unsigned char hash[ASCON_HASH_SIZE] = {0};
    unsigned char input[1024];
    unsigned index;
    for (index = 0; index < sizeof(input); ++index) {
        input[index] = (unsigned char)index;
    }
    for (index = 0; index <= sizeof(input); ++index) {
        printf("Count = %u\n", index + 1);
        print_hex("Msg", input, index);
        ascon_simple_hash(hash, input, index);
        print_hex("MD", hash, sizeof(hash));
        printf("\n");
    }
}

static void kat_xof(void)
{
    unsigned char hash[ASCON_HASH_SIZE] = {0};
    unsigned char input[1024];
    unsigned index;
    for (index = 0; index < sizeof(input); ++index) {
        input[index] = (unsigned char)index;
    }
    for (index = 0; index <= sizeof(input); ++index) {
        printf("Count = %u\n", index + 1);
        print_hex("Msg", input, index);
        ascon_simple_xof(hash, sizeof(hash), input, index);
        print_hex("MD", hash, sizeof(hash));
        printf("\n");
    }
}

static void kat_cxof(void)
{
    unsigned char hash[ASCON_HASH_SIZE] = {0};
    unsigned char input[128];
    unsigned char custom[32];
    unsigned index, index2;
    unsigned count = 1;
    for (index = 0; index < sizeof(input); ++index) {
        input[index] = (unsigned char)index;
    }
    for (index2 = 0; index2 < sizeof(custom); ++index2) {
        custom[index2] = (unsigned char)index2;
    }
    for (index = 0; index <= sizeof(input); ++index) {
        for (index2 = 0; index2 <= sizeof(custom); ++index2) {
            printf("Count = %u\n", count++);
            print_hex("Msg", input, index);
            print_hex("Custom", custom, index2);
            ascon_simple_cxof(hash, sizeof(hash), custom, index2, input, index);
            print_hex("MD", hash, sizeof(hash));
            printf("\n");
        }
    }
}

static void kat_aead(int with_nonce_masking)
{
    unsigned char plaintext[32];
    unsigned char ciphertext[48];
    unsigned char ad[32];
    unsigned char nonce[16];
    unsigned char key[32];
    unsigned index, index2;
    unsigned count = 1;
    size_t clen;
    for (index = 0; index < 32; ++index) {
        plaintext[index] = (unsigned char)index;
        ad[index] = (unsigned char)index;
        key[index] = (unsigned char)index;
        if (index < 16) {
            nonce[index] = (unsigned char)index;
        }
    }
    for (index = 0; index <= 32; ++index) {
        for (index2 = 0; index2 <= 32; ++index2) {
            printf("Count = %u\n", count++);
            if (with_nonce_masking) {
                print_hex("Key", key, 32);
            } else {
                print_hex("Key", key, 16);
            }
            print_hex("Nonce", nonce, 16);
            print_hex("PT", plaintext, index);
            print_hex("AD", ad, index2);
            if (with_nonce_masking) {
                ascon_simple_encrypt
                    (ciphertext, &clen, plaintext, index, ad, index2,
                     nonce, key);
            } else {
                ascon_simple_nm_encrypt
                    (ciphertext, &clen, plaintext, index, ad, index2,
                     nonce, key);
            }
            print_hex("CT", ciphertext, clen);
            printf("\n");
        }
    }
}

/* Create the starting ASCON state to use for a fixed customization string */
static void create_custom_prefix(const char *custom)
{
    unsigned char prefix[40] = {0};
    if (!custom)
        custom = "";
    ascon_simple_cxof_prefix(prefix, custom, strlen(custom));
    print_c_hex(NULL, prefix, sizeof(prefix));
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        test_permutation();
    } else if (!strcmp(argv[1], "permutation")) {
        test_permutation();
    } else if (!strcmp(argv[1], "hash")) {
        if (argc < 3) {
            kat_hash();
        } else {
            test_hash(argv[2]);
        }
    } else if (!strcmp(argv[1], "xof")) {
        if (argc < 3) {
            kat_xof();
        } else {
            test_xof(argv[2]);
        }
    } else if (!strcmp(argv[1], "cxof")) {
        if (argc < 3) {
            kat_cxof();
        } else if (argc < 4) {
            test_cxof("", argv[2]);
        } else {
            test_cxof(argv[2], argv[3]);
        }
    } else if (!strcmp(argv[1], "aead")) {
        kat_aead(0);
    } else if (!strcmp(argv[1], "aead-nm")) {
        kat_aead(1);
    } else if (!strcmp(argv[1], "prefix")) {
        if (argc < 3) {
            create_custom_prefix("");
        } else {
            create_custom_prefix(argv[2]);
        }
    } else {
        fprintf(stderr, "Unknown mode '%s'\n", argv[1]);
        return 1;
    }
    return 0;
}
