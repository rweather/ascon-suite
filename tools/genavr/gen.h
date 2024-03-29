/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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

#ifndef GENAVR_GEN_H
#define GENAVR_GEN_H

#include "code.h"

// Information about a test vector for a block cipher.
typedef struct
{
    const char *name;
    unsigned char key[48];
    unsigned key_len;
    unsigned char plaintext[16];
    unsigned char ciphertext[16];

} block_cipher_test_vector_t;

// ASCON permutation.
void gen_ascon_permutation(Code &code);
void gen_ascon_cleanup(Code &code);
bool test_ascon_permutation(Code &code);

// 2-share version of the ASCON permutation.
void gen_ascon_x2_permutation(Code &code, int max_shares);
bool test_ascon_x2_permutation(Code &code, int max_shares);

// 3-share version of the ASCON permutation.
void gen_ascon_x3_permutation(Code &code);
bool test_ascon_x3_permutation(Code &code);

#endif
