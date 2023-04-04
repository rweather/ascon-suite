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

#include <ascon/aead.h>
#include "core/ascon-util.h"

void ascon_aead_set_counter
    (unsigned char npub[ASCON128_NONCE_SIZE], uint64_t n)
{
    be_store_word64(npub, 0);
    be_store_word64(npub + 8, n);
}

void ascon_aead_increment_nonce(unsigned char npub[ASCON128_NONCE_SIZE])
{
    unsigned index;
    uint16_t carry = 1;
    for (index = ASCON128_NONCE_SIZE; index > 0; ) {
        --index;
        carry += npub[index];
        npub[index] = (unsigned char)carry;
        carry >>= 8;
    }
}
