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

#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State information for hashing with SHA3.
 */
typedef struct
{
    uint64_t A[5][5];
    unsigned inputSize;
    unsigned outputSize;
    unsigned rate;
    unsigned absorbing;
    unsigned padding;

} sha3_state_t;

/**
 * \brief Initializes a SHA3 hashing state.
 *
 * \param state Points to the SHA3 state.
 * \param capacity Capacity for the SHA3 variant in bits.
 * \param padding Value to use to pad the input when switching to squeezing.
 */
void sha3_init(sha3_state_t *state, unsigned capacity, unsigned padding);

/**
 * \brief Frees a SHA3 hashing state.
 *
 * \param state Points to the SHA3 state.
 */
void sha3_free(sha3_state_t *state);

/**
 * \brief Initializes a SHA3 hashing state for SHA3-256.
 *
 * \param state Points to the SHA3 state.
 */
void sha3_256_init(sha3_state_t *state);

/**
 * \brief Initializes a SHA3 hashing state for SHA3-512.
 *
 * \param state Points to the SHA3 state.
 */
void sha3_512_init(sha3_state_t *state);

/**
 * \brief Initializes a SHA3 hashing state for SHAKE128 XOF mode.
 *
 * \param state Points to the SHA3 state.
 */
void shake128_init(sha3_state_t *state);

/**
 * \brief Initializes a SHA3 hashing state for SHAKE256 XOF mode.
 *
 * \param state Points to the SHA3 state.
 */
void shake256_init(sha3_state_t *state);

/**
 * \brief Initializes a SHA3 hashing state for cSHAKE128 XOF mode.
 *
 * \param state Points to the SHA3 state.
 */
void cshake128_init(sha3_state_t *state);

/**
 * \brief Initializes a SHA3 hashing state for cSHAKE256 XOF mode.
 *
 * \param state Points to the SHA3 state.
 */
void cshake256_init(sha3_state_t *state);

/**
 * \brief Absorbs data into the SHA3 hashing state.
 *
 * \param state Points to the SHA3 state.
 * \param data Points to the input data to absorb.
 * \param size Length of the input data in bytes.
 */
void sha3_absorb
    (sha3_state_t *state, const unsigned char *data, size_t size);

/**
 * \brief Squeezes data from the SHA3 hashing state.
 *
 * \param state Points to the SHA3 state.
 * \param data Points to the buffer to receive the squeezed data.
 * \param size Length of the output data in bytes.
 */
void sha3_squeeze
    (sha3_state_t *state, unsigned char *data, size_t size);

/**
 * \brief Pads the input with zeroes to the next multiple of the rate.
 *
 * \param state Points to the SHA3 state.
 */
void sha3_pad(sha3_state_t *state);

/**
 * \brief Hashes a block of input data with SHA3-256.
 *
 * \param out Buffer to receive the hash output.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int sha3_256_hash
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Hashes a block of input data with SHA3-512.
 *
 * \param out Buffer to receive the hash output.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int sha3_512_hash
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Hashes a block of input data with SHAKE128.
 *
 * \param out Buffer to receive the hash output.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int shake128_hash
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Hashes a block of input data with SHAKE256.
 *
 * \param out Buffer to receive the hash output.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int shake256_hash
    (unsigned char *out, const unsigned char *in, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif
