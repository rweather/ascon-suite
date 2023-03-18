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
#include <ascon/xof.h>
#include <ascon/utility.h>
#include "core/ascon-util.h"
#include "core/ascon-util-snp.h"
#include <string.h>

/* Determine if we need to explicitly free the XOF state between iterations */
#if defined(ASCON_BACKEND_SLICED64) || defined(ASCON_BACKEND_SLICED32) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
#define ASCON_PBKDF2_FREE_STATE 0
#else
#define ASCON_PBKDF2_FREE_STATE 1
#endif

/*
 * Implementation of the "F" function from RFC 8018, section 5.2
 *
 * Note: Instead of HMAC like in RFC 8018, we use the following PRF:
 *
 * PRF(P, X) = ASCON-cXOF(X, 256, "PBKDF2", P)
 */
static void ascon_pbkdf2_f
    (ascon_xof_state_t *state, unsigned char *T, unsigned char *U,
     const unsigned char *salt, size_t saltlen,
     unsigned long count, unsigned long blocknum)
{
    ascon_xof_state_t state2;
    unsigned char b[4];
    be_store_word32(b, blocknum);
    ascon_xof_copy(&state2, state);
    ascon_xof_absorb(&state2, salt, saltlen);
    ascon_xof_absorb(&state2, b, sizeof(b));
    ascon_xof_squeeze(&state2, T, ASCON_PBKDF2_SIZE);
#if ASCON_PBKDF2_FREE_STATE
    ascon_xof_free(&state2);
#endif
    if (count > 1) {
        ascon_xof_copy(&state2, state);
        ascon_xof_absorb(&state2, T, ASCON_PBKDF2_SIZE);
        ascon_xof_squeeze(&state2, U, ASCON_PBKDF2_SIZE);
#if ASCON_PBKDF2_FREE_STATE
        ascon_xof_free(&state2);
#endif
        lw_xor_block(T, U, ASCON_PBKDF2_SIZE);
        while (count > 2) {
            ascon_xof_copy(&state2, state);
            ascon_xof_absorb(&state2, U, ASCON_PBKDF2_SIZE);
            ascon_xof_squeeze(&state2, U, ASCON_PBKDF2_SIZE);
            ascon_xof_free(&state2);
            lw_xor_block(T, U, ASCON_PBKDF2_SIZE);
            --count;
        }
    }
#if !ASCON_PBKDF2_FREE_STATE
    ascon_xof_free(&state2);
#endif
}

void ascon_pbkdf2
    (unsigned char *out, size_t outlen,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen, unsigned long count)
{
    ascon_xof_state_t state;
    unsigned char U[ASCON_PBKDF2_SIZE];
    unsigned long blocknum = 1;
    ascon_xof_init_custom
        (&state, "PBKDF2", password, passwordlen, ASCON_PBKDF2_SIZE);
    while (outlen > 0) {
        if (outlen >= ASCON_PBKDF2_SIZE) {
            ascon_pbkdf2_f(&state, out, U, salt, saltlen, count, blocknum);
            out += ASCON_PBKDF2_SIZE;
            outlen -= ASCON_PBKDF2_SIZE;
        } else {
            unsigned char T[ASCON_PBKDF2_SIZE];
            ascon_pbkdf2_f(&state, T, U, salt, saltlen, count, blocknum);
            memcpy(out, T, outlen);
            ascon_clean(T, sizeof(T));
            break;
        }
        ++blocknum;
    }
    ascon_xof_free(&state);
    ascon_clean(U, sizeof(U));
}
