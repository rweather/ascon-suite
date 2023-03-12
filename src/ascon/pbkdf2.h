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

#ifndef ASCON_PBKDF2_H
#define ASCON_PBKDF2_H

#include <stddef.h>

/**
 * \file pbkdf2.h
 * \brief Password-based key derivation function based on ASCON-HMAC.
 *
 * Reference: https://tools.ietf.org/html/rfc8018
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default output block size for ASCON-PBKDF2.  Key material is
 * generated in blocks of this size.
 */
#define ASCON_PBKDF2_SIZE 32

/**
 * \brief Derives key material using ASCON-PBKDF2.
 *
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate.
 * \param password Points to the bytes of the password.
 * \param passwordlen Number of bytes in the password.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 * \param count Number of iterations to perform.  If this is set to zero,
 * then the value will be changed to 1.
 *
 * This function can generate a maximum of (2^32 - 1) *
 * ASCON_PBKDF2_SIZE bytes, but this limit is not checked.
 * The \a count value should be large enough to provide resistance
 * against dictionary attacks on the password.
 *
 * \note This function uses ASCON-XOF to implement the pseudorandom
 * function PRF from RFC 8018 rather than HMAC.  This is more efficient
 * in terms of time and code size.
 */
void ascon_pbkdf2
    (unsigned char *out, size_t outlen,
     const unsigned char *password, size_t passwordlen,
     const unsigned char *salt, size_t saltlen, unsigned long count);

#ifdef __cplusplus
}
#endif

#endif
