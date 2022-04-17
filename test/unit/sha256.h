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

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

/**
 * \file sha256.h
 * \brief SHA256 hash algorithm.
 *
 * This SHA256 implementation is based on the one from the
 * <a href="http://rweather.github.com/arduinolibs/crypto.html">Arduino
 * Cryptography Library</a>.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash for SHA256.
 */
#define SHA256_HASH_SIZE 32

/**
 * \brief State for SHA256 incremental mode.
 */
typedef struct
{
    uint32_t h[8];      /**< Current hash state */
    uint32_t w[16];     /**< Current block that is being filled */
    uint64_t length;    /**< Total length of the input in bits */
    unsigned posn;      /**< Position in the current block */

} sha256_state_t;

/**
 * \brief Hashes a block of input data with SHA256 to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * SHA256_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int sha256_hash(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for a SHA256 hashing operation.
 *
 * \param state Hash state to be initialized.
 */
void sha256_hash_init(sha256_state_t *state);

/**
 * \brief Frees the state for a SHA256 hashing operation.
 *
 * \param state Hash state to be freed.
 */
void sha256_hash_free(sha256_state_t *state);

/**
 * \brief Updates a SHA256 state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 */
void sha256_hash_update
    (sha256_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from a SHA256 hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 */
void sha256_hash_finalize(sha256_state_t *state, unsigned char *out);

/**
 * \brief State information for the SHA256 incremental HMAC mode.
 */
typedef struct
{
    sha256_state_t hash;    /**< Internal SHA256 state */

} sha256_hmac_state_t;

/**
 * \brief Computes a HMAC value using SHA256.
 *
 * \param out Buffer to receive the output HMAC value; must be at least
 * SHA256_HASH_SIZE bytes in length.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 */
void sha256_hmac
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/**
 * \brief Initializes an incremental HMAC state using SHA256.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 */
void sha256_hmac_init
    (sha256_hmac_state_t *state, const unsigned char *key, size_t keylen);

/**
 * \brief Frees the SHA256-HMAC state and destroys any sensitive material.
 *
 * \param state HMAC state to be freed.
 */
void sha256_hmac_free(sha256_hmac_state_t *state);

/**
 * \brief Updates an incremental SHA256-HMAC state with more input data.
 *
 * \param state HMAC state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 */
void sha256_hmac_update
    (sha256_hmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Finalizes an incremental SHA256-HMAC state.
 *
 * \param state HMAC state to squeeze the output data from.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param out Points to the output buffer to receive the HMAC value;
 * must be at least SHA256_HASH_SIZE bytes in length.
 */
void sha256_hmac_finalize
    (sha256_hmac_state_t *state, const unsigned char *key, size_t keylen,
     unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
