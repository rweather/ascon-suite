/*
 * Copyright (C) 2023 Southern Storm Software, Pty Ltd.
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

/*
This example runs tests on the ASCON-128 implementation to verify
correct behaviour.

We use the test vectors from the original CAESAR version of ASCON-128
to verify that the algorithm hasn't changed between then and the final
version during the NIST Lightweight Cryptography Competition.
*/

#include <ASCON.h>
#include <string.h>
#if defined(__AVR__)
#include <avr/pgmspace.h>
#else
#undef PROGMEM
#undef memcpy_P
#define PROGMEM
#define memcpy_P(d,s,l) memcpy((d), (s), (l))
#endif

#define MAX_PLAINTEXT_LEN 43
#define MAX_AUTHDATA_LEN 17

struct TestVector
{
    const char *name;
    uint8_t key[16];
    uint8_t plaintext[MAX_PLAINTEXT_LEN];
    uint8_t ciphertext[MAX_PLAINTEXT_LEN];
    uint8_t authdata[MAX_AUTHDATA_LEN];
    uint8_t iv[16];
    uint8_t tag[16];
    size_t authsize;
    size_t datasize;
};

// Test vectors for Ascon128, generated with the reference Python version:
// https://github.com/meichlseder/pyascon
static TestVector const testVectorAscon128_1 PROGMEM = {
    .name        = "Ascon128 #1",
    .key         = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .plaintext   = {0x61, 0x73, 0x63, 0x6f, 0x6e},
    .ciphertext  = {0x86, 0x88, 0x62, 0x14, 0x0e},
    .authdata    = {0x41, 0x53, 0x43, 0x4f, 0x4e},
    .iv          = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .tag         = {0xad, 0x65, 0xf5, 0x94, 0x22, 0x58, 0xda, 0xd5,
                    0x3c, 0xaa, 0x7a, 0x56, 0xf3, 0xa2, 0x92, 0xd8},
    .authsize    = 5,
    .datasize    = 5
};
static TestVector const testVectorAscon128_2 PROGMEM = {
    .name        = "Ascon128 #2",
    .key         = {0x0d, 0x49, 0x29, 0x92, 0x65, 0x8b, 0xd8, 0xa3,
                    0xe4, 0x7b, 0xf9, 0x10, 0xd4, 0xc5, 0x87, 0xad},
    .plaintext   = {0x61},
    .ciphertext  = {0xc5},
    .authdata    = {0},
    .iv          = {0x5a, 0xcb, 0x17, 0x2a, 0x1a, 0x93, 0x3d, 0xb1,
                    0x8a, 0x6a, 0x40, 0xac, 0x6e, 0x4c, 0x68, 0xd0},
    .tag         = {0x2e, 0x0b, 0xf2, 0xb1, 0xfc, 0xd8, 0x64, 0x69,
                    0x01, 0x1c, 0x4f, 0x8b, 0x78, 0x4a, 0x65, 0x0d},
    .authsize    = 0,
    .datasize    = 1
};
static TestVector const testVectorAscon128_3 PROGMEM = {
    .name        = "Ascon128 #3",
    .key         = {0x91, 0xb3, 0x9d, 0x22, 0xf3, 0xb7, 0x7f, 0x51,
                    0x33, 0x0a, 0xa3, 0xa4, 0xea, 0x38, 0xea, 0xa2},
    .plaintext   = {0},
    .ciphertext  = {0},
    .authdata    = {0x64},
    .iv          = {0x2e, 0xec, 0x64, 0x25, 0xb3, 0xec, 0xf0, 0x63,
                    0xb4, 0x3e, 0x29, 0xc7, 0x68, 0x29, 0x3c, 0x49},
    .tag         = {0xfd, 0x24, 0x0e, 0x3c, 0x3d, 0xc4, 0x11, 0x0d,
                    0xe1, 0x54, 0x4c, 0xd5, 0x24, 0x18, 0xd9, 0x4c},
    .authsize    = 1,
    .datasize    = 0
};
static TestVector const testVectorAscon128_4 PROGMEM = {
    .name        = "Ascon128 #4",
    .key         = {0x72, 0xfd, 0x18, 0xde, 0xbd, 0xee, 0x86, 0x13,
                    0x4f, 0x7c, 0x44, 0x29, 0x84, 0x37, 0x56, 0x06},
    .plaintext   = {0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x78, 0x74},
    .ciphertext  = {0x91, 0xd0, 0xc3, 0x88, 0xea, 0xc0, 0xe6, 0xd9},
    .authdata    = {0x61, 0x73, 0x73, 0x64, 0x61, 0x74, 0x31, 0x32},
    .iv          = {0x91, 0x5f, 0xf8, 0xff, 0xca, 0xd8, 0xae, 0x1d,
                    0xf4, 0x45, 0xeb, 0x03, 0xe2, 0x18, 0xfd, 0x25},
    .tag         = {0x16, 0x69, 0x74, 0xbf, 0xbd, 0x43, 0xd7, 0xa8,
                    0xfe, 0x43, 0xf0, 0xce, 0xe2, 0xdd, 0xb9, 0xf8},
    .authsize    = 8,
    .datasize    = 8
};
static TestVector const testVectorAscon128_5 PROGMEM = {
    .name        = "Ascon128 #5",
    .key         = {0x8a, 0xa5, 0xed, 0xc5, 0x88, 0x49, 0x75, 0xc8,
                    0xd1, 0xa1, 0xb8, 0x44, 0xd0, 0x15, 0x50, 0x5a},
    .plaintext   = {0x54, 0x68, 0x65, 0x20, 0x72, 0x61, 0x69, 0x6e,
                    0x20, 0x69, 0x6e, 0x20, 0x73, 0x70, 0x61, 0x69,
                    0x6e, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x73, 0x20,
                    0x6d, 0x61, 0x69, 0x6e, 0x6c, 0x79, 0x20, 0x6f,
                    0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x6c,
                    0x61, 0x69, 0x6e},
    .ciphertext  = {0x4a, 0xb4, 0xe2, 0x87, 0x90, 0x07, 0x4b, 0x78,
                    0x88, 0x70, 0x71, 0xc0, 0x62, 0xd6, 0xab, 0x6b,
                    0x32, 0xd4, 0xb1, 0xec, 0xc7, 0xd8, 0x44, 0x93,
                    0x36, 0x9a, 0x38, 0x81, 0xd6, 0x65, 0x2f, 0x85,
                    0xaa, 0xf9, 0x70, 0x90, 0x61, 0x97, 0x3e, 0x1f,
                    0x60, 0x12, 0x66},
    .authdata    = {0x48, 0x6f, 0x77, 0x20, 0x6e, 0x6f, 0x77, 0x20,
                    0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x63, 0x6f,
                    0x77},
    .iv          = {0xbc, 0x52, 0x27, 0xa5, 0x72, 0x58, 0xfe, 0x00,
                    0xcb, 0x7b, 0x0f, 0x31, 0xa4, 0xb6, 0xff, 0xda},
    .tag         = {0x92, 0xfe, 0x72, 0xf8, 0x69, 0xc9, 0x95, 0x41,
                    0x1f, 0xc4, 0x57, 0xde, 0xa6, 0xf2, 0xf9, 0x2d},
    .authsize    = 17,
    .datasize    = 43
};

TestVector testVector;
ascon128_state_t testState;

byte buffer[128];
byte buffer2[128];

bool testCipher_N(const struct TestVector *test, size_t inc)
{
    size_t posn;
    size_t clen = 0;
    size_t mlen = 0;
    int result;

    memset(buffer, 0xBA, sizeof(buffer));
    if (inc == test->datasize) {
        // All-in-one encryption.
        ascon128_aead_encrypt
            (buffer, &clen, test->plaintext, test->datasize,
             test->authdata, test->authsize, test->iv, test->key);
    } else {
        // Use the incremental version of the encryption algorithm.
        memset(&testState, 0x77, sizeof(&testState));
        ascon128_aead_init(&testState, test->iv, test->key);
        ascon128_aead_start(&testState, test->authdata, test->authsize);
        for (posn = 0; posn < test->datasize; posn += inc) {
            size_t len = test->datasize - posn;
            if (len > inc)
                len = inc;
            ascon128_aead_encrypt_block
                (&testState, test->plaintext + posn, buffer + posn, len);
        }
        ascon128_aead_encrypt_finalize(&testState, buffer + test->datasize);
        ascon128_aead_free(&testState);
    }

    if (clen != (test->datasize + 16) ||
            memcmp(buffer, test->ciphertext, test->datasize) != 0 ||
            memcmp(buffer + test->datasize, test->tag, 16) != 0) {
        Serial.print(buffer[0], HEX);
        Serial.print("->");
        Serial.print(test->ciphertext[0], HEX);
        return false;
    }

    memset(buffer, 0xAB, sizeof(buffer));
    memcpy(buffer2, test->ciphertext, test->datasize);
    memcpy(buffer2 + test->datasize, test->tag, 16);
    if (inc == test->datasize) {
        // All-in-one decryption.
        result = ascon128_aead_decrypt
            (buffer, &mlen, buffer2, test->datasize + 16,
             test->authdata, test->authsize, test->iv, test->key);
    } else {
        // Use the incremental version of the decryption algorithm.
        memset(&testState, 0x55, sizeof(&testState));
        ascon128_aead_init(&testState, test->iv, test->key);
        ascon128_aead_start(&testState, test->authdata, test->authsize);
        for (posn = 0; posn < test->datasize; posn += inc) {
            size_t len = test->datasize - posn;
            if (len > inc)
                len = inc;
            ascon128_aead_decrypt_block
                (&testState, test->ciphertext + posn, buffer + posn, len);
        }
        result = ascon128_aead_decrypt_finalize
            (&testState, buffer + test->datasize);
        ascon128_aead_free(&testState);
    }

    if (result < 0 || mlen != test->datasize ||
            memcmp(buffer, test->plaintext, test->datasize) != 0) {
        return false;
    }

    return true;
}

void testCipher(const struct TestVector *test)
{
    bool ok;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" ... ");

    ok  = testCipher_N(test, test->datasize);
    //ok &= testCipher_N(test, 1);
    //ok &= testCipher_N(test, 2);
    //ok &= testCipher_N(test, 5);
    //ok &= testCipher_N(test, 8);
    //ok &= testCipher_N(test, 13);
    //ok &= testCipher_N(test, 16);

    if (ok)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

void setup()
{
    Serial.begin(9600);

    Serial.println();

    Serial.print("Incremental State Size ... ");
    Serial.println(sizeof(ascon128_state_t));
    Serial.println();

    Serial.println("Test Vectors:");
    testCipher(&testVectorAscon128_1);
    testCipher(&testVectorAscon128_2);
    testCipher(&testVectorAscon128_3);
    testCipher(&testVectorAscon128_4);
    testCipher(&testVectorAscon128_5);

    Serial.println();
}

void loop()
{
}
