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

#include <ascon/pbkdf2.h>
#include <ascon/hmac.h>
#include <ascon/utility.h>
#include "core/ascon-util.h"
#include <string.h>

/* Implementation of the "F" function from RFC 8018, section 5.2 */
static void ascon_pbkdf2_f
    (ascon_hmac_state_t *state, unsigned char *T, unsigned char *U,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen,
     unsigned long count, unsigned long blocknum)
{
    unsigned char b[4];
    be_store_word32(b, blocknum);
    ascon_hmac_init(state, password, passwordlen);
    ascon_hmac_update(state, salt, saltlen);
    ascon_hmac_update(state, b, sizeof(b));
    ascon_hmac_finalize(state, password, passwordlen, T);
    if (count > 1) {
        ascon_hmac_init(state, password, passwordlen);
        ascon_hmac_update(state, T, ASCON_HMAC_SIZE);
        ascon_hmac_finalize(state, password, passwordlen, U);
        lw_xor_block(T, U, ASCON_HMAC_SIZE);
        while (count > 2) {
            ascon_hmac_init(state, password, passwordlen);
            ascon_hmac_update(state, U, ASCON_HMAC_SIZE);
            ascon_hmac_finalize(state, password, passwordlen, U);
            lw_xor_block(T, U, ASCON_HMAC_SIZE);
            --count;
        }
    }
}

void ascon_pbkdf2
    (unsigned char *out, size_t outlen,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen, unsigned long count)
{
    ascon_hmac_state_t state;
    unsigned char U[ASCON_HMAC_SIZE];
    unsigned long blocknum = 1;
    while (outlen > 0) {
        if (outlen >= ASCON_HMAC_SIZE) {
            ascon_pbkdf2_f(&state, out, U, password, passwordlen,
                           salt, saltlen, count, blocknum);
            out += ASCON_HMAC_SIZE;
            outlen -= ASCON_HMAC_SIZE;
        } else {
            unsigned char T[ASCON_HMAC_SIZE];
            ascon_pbkdf2_f(&state, T, U, password, passwordlen,
                           salt, saltlen, count, blocknum);
            memcpy(out, T, outlen);
            ascon_clean(T, sizeof(T));
            break;
        }
        ++blocknum;
    }
    ascon_clean(&state, sizeof(state));
    ascon_clean(U, sizeof(U));
}
