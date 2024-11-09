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

#ifndef SIMPLE_HASH_H
#define SIMPLE_HASH_H

#include <stddef.h>

/**
 * \brief Size of the default ASCON hash output.
 */
#define ASCON_HASH_SIZE 32

/**
 * \brief Hashes a buffer with ASCON-HASH256.
 *
 * \param hash Returns the hash.
 * \param data Points to the data to be hashed.
 * \param len Length of the data to be hashed in bytes.
 */
void ascon_simple_hash
    (unsigned char hash[ASCON_HASH_SIZE], const void *data, size_t len);

/**
 * \brief Hashes a buffer with ASCON-XOF128.
 *
 * \param out Returns the buffer to receive the output data.
 * \param outlen Length of the output data in bytes.
 * \param data Points to the data to be hashed.
 * \param len Length of the data to be hashed in bytes.
 */
void ascon_simple_xof
    (unsigned char *out, size_t outlen, const void *data, size_t len);

/**
 * \brief Hashes a buffer with ASCON-CXOF128.
 *
 * \param out Returns the buffer to receive the output data.
 * \param outlen Length of the output data in bytes.
 * \param custom Points to the customization string.  Must not be NULL.
 * \param customlen Length of the customization string hashed in bytes.
 * \param data Points to the data to be hashed.
 * \param len Length of the data to be hashed in bytes.
 */
void ascon_simple_cxof
    (unsigned char *out, size_t outlen,
     const void *custom, size_t customlen,
     const void *data, size_t len);

/**
 * \brief Hashes a customization string to produce the state prefix.
 *
 * \param prefix Returns the state prefix.
 * \param custom Points to the customization string.  Must not be NULL.
 * \param customlen Length of the customization string hashed in bytes.
 */
void ascon_simple_cxof_prefix
    (unsigned char prefix[40], const void *custom, size_t customlen);

#endif
