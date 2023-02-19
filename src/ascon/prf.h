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

#ifndef ASCON_PRF_H
#define ASCON_PRF_H

/**
 * \file prf.h
 * \brief ASCON-Prf, ASCON-PrfShort, and ASCON-Mac algorithms.
 *
 * ASCON-Prf is a pseudorandom function (PRF) built around the ASCON
 * permutation.  It provides a method to combine a 128-bit key and an
 * arbitary amount of input to produce an arbitrary amount of output.
 *
 * ASCON-Prf can be used as a lightweight key derivation function (KDF)
 * in place of other options like ASCON-HKDF or ASCON-KMAC when the
 * key is 128 bits in size.
 *
 * ASCON-Mac wraps ASCON-Prf to turn it into a message authentication
 * code (MAC) with an arbitrary amount of input and a fixed 128 bits
 * of output.  ASCON-Mac is identical to ASCON-Prf with an output length
 * of 128 bits and also provides an API to verify authentication tags.
 *
 * ASCON-PrfShort is a cut-down version of ASCON-Prf that is limited to a
 * single block of input of 128 bits or less in size, and a single block of
 * output of 128 bits or less in size.
 *
 * ASCON-PrfShort is suitable for authenticating very small amounts of data
 * in a single ASCON permutation call.  It can also be used as a key
 * derivation function (KDF) in protocols that derive 128-bit symmetric
 * keys from a 128-bit master key, with the input being used for domain
 * separation between the different derived keys.
 *
 * References: https://eprint.iacr.org/2021/1574
 */

#include <ascon/permutation.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for ASCON-Prf in bytes.
 */
#define ASCON_PRF_KEY_SIZE 16

/**
 * \brief Default size of the ASCON-Prf output in bytes.
 */
#define ASCON_PRF_TAG_SIZE 16

/**
 * \brief Size of the key for ASCON-PrfShort in bytes.
 */
#define ASCON_PRF_SHORT_KEY_SIZE ASCON_PRF_KEY_SIZE

/**
 * \brief Maximum number of bytes that can be input to ASCON-PrfShort.
 */
#define ASCON_PRF_SHORT_MAX_INPUT_SIZE 16

/**
 * \brief Maximum number of bytes that can be output from ASCON-PrfShort.
 */
#define ASCON_PRF_SHORT_MAX_OUTPUT_SIZE 16

/**
 * \brief Default size of the ASCON-PrfShort output in bytes.
 */
#define ASCON_PRF_SHORT_TAG_SIZE ASCON_PRF_SHORT_MAX_OUTPUT_SIZE

/**
 * \brief Size of the key for ASCON-Mac in bytes.
 */
#define ASCON_MAC_KEY_SIZE ASCON_PRF_KEY_SIZE

/**
 * \brief Size of the ASCON-Mac output in bytes.
 */
#define ASCON_MAC_TAG_SIZE ASCON_PRF_TAG_SIZE

/**
 * \brief State information for the ASCON-Prf incremental mode.
 *
 * This structure should be treated as opaque.
 */
typedef struct
{
    ascon_state_t state;    /**< Current hash state */
    unsigned char count;    /**< Number of bytes in the current block */
    unsigned char mode;     /**< Hash mode: 0 for absorb, 1 for squeeze */

} ascon_prf_state_t;

/**
 * \brief Processes a key and input data with ASCON-Prf to produce a tag.
 *
 * \param out Buffer to receive the PRF tag which must be at least
 * \a outlen bytes in length.
 * \param outlen Length of the output buffer in bytes.  Recommended to be
 * ASCON_PRF_TAG_SIZE.
 * \param in Points to the input data to be processed.
 * \param inlen Length of the input data in bytes.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 *
 * This function operates ASCON-Prf in unlimited output mode, with the
 * output truncated at \a outlen bytes.
 *
 * \sa ascon_prf_fixed(), ascon_prf_short(), ascon_mac()
 */
void ascon_prf
    (unsigned char *out, size_t outlen,
     const unsigned char *in, size_t inlen,
     const unsigned char *key);

/**
 * \brief Processes a key and input data with ASCON-Prf to produce a
 * fixed-length output tag.
 *
 * \param out Buffer to receive the PRF tag which must be at least
 * \a outlen bytes in length.
 * \param outlen Length of the output buffer in bytes.  Recommended to be
 * ASCON_PRF_TAG_SIZE.
 * \param in Points to the input data to be processed.
 * \param inlen Length of the input data in bytes.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 *
 * This function operates ASCON-Prf in fixed-length output mode, with the
 * output length set at exactly \a outlen bytes.
 *
 * \sa ascon_prf(), ascon_prf_short(), ascon_mac()
 */
void ascon_prf_fixed
    (unsigned char *out, size_t outlen,
     const unsigned char *in, size_t inlen,
     const unsigned char *key);

/**
 * \brief Processes a key and input data with ASCON-PrfShort to produce a tag.
 *
 * \param out Buffer to receive the PRF tag which must be at least
 * \a outlen bytes in length.
 * \param outlen Length of the output buffer in bytes between 0 and
 * ASCON_PRF_SHORT_MAX_OUTPUT_SIZE.
 * \param in Points to the input data to be processed.
 * \param inlen Length of the input data in bytes between 0 and
 * ASCON_PRF_SHORT_MAX_INPUT_SIZE.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 *
 * \return 0 if the output was generated, or -1 if either \a outlen or
 * \a inlen are out of range.
 *
 * \sa ascon_prf(), ascon_prf_fixed(), ascon_mac()
 */
int ascon_prf_short
    (unsigned char *out, size_t outlen,
     const unsigned char *in, size_t inlen,
     const unsigned char *key);

/**
 * \brief Processes a key and input data with ASCON-Mac to produce a tag.
 *
 * \param tag Buffer to receive the ASCON_PRF_TAG_SIZE bytes of the tag.
 * \param in Points to the input data to be processed.
 * \param inlen Length of the input data in bytes.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 *
 * This function operates ASCON-Prf in fixed-length output mode
 * with the output length set to ASCON_PRF_TAG_SIZE.
 *
 * \sa ascon_mac_verify(), ascon_prf()
 */
void ascon_mac
    (unsigned char *tag,
     const unsigned char *in, size_t inlen,
     const unsigned char *key);

/**
 * \brief Verifies an ASCON-Mac tag value.
 *
 * \param tag Buffer that contains the ASCON_PRF_TAG_SIZE bytes of the tag.
 * \param in Points to the input data to be processed.
 * \param inlen Length of the input data in bytes.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 *
 * \return 0 if the \a tag is correct or -1 if incorrect.
 *
 * \sa ascon_mac(), ascon_prf()
 */
int ascon_mac_verify
    (const unsigned char *tag,
     const unsigned char *in, size_t inlen,
     const unsigned char *key);

/**
 * \brief Initializes the state for an incremental ASCON-Prf operation.
 *
 * \param state PRF state to be initialized.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 *
 * This function will set ASCON-Prf into unlimited output mode.
 *
 * \sa ascon_prf_fixed_init(), ascon_prf_absorb(), ascon_prf_squeeze()
 */
void ascon_prf_init(ascon_prf_state_t *state, const unsigned char *key);

/**
 * \brief Initializes the state for an incremental ASCON-Prf operation
 * with fixed-length output.
 *
 * \param state PRF state to be initialized.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 * \param outlen Number of bytes of output that is desired, or 0 for unlimited.
 *
 * This function will set ASCON-Prf into unlimited output mode.
 *
 * \sa ascon_prf_init(), ascon_prf_absorb(), ascon_prf_squeeze()
 */
void ascon_prf_fixed_init
    (ascon_prf_state_t *state, const unsigned char *key, size_t outlen);

/**
 * \brief Re-initializes the state for an incremental ASCON-Prf operation.
 *
 * \param state PRF state to be re-initialized.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 *
 * This function is equivalent to calling ascon_prf_free() and then
 * ascon_prf_init() to restart the hashing process.
 *
 * \sa ascon_prf_fixed_reinit(), ascon_prf_init()
 */
void ascon_prf_reinit(ascon_prf_state_t *state, const unsigned char *key);

/**
 * \brief Re-initializes the state for an incremental ASCON-Prf operation
 * with fixed-length output.
 *
 * \param state PRF state to be re-initialized.
 * \param key Points to the ASCON_PRF_KEY_SIZE bytes of the key.
 * \param outlen Number of bytes of output that is desired, or 0 for unlimited.
 *
 * This function is equivalent to calling ascon_prf_free() and then
 * ascon_prf_init() to restart the hashing process.
 *
 * \sa ascon_prf_reinit(), ascon_prf_fixed_init()
 */
void ascon_prf_fixed_reinit
    (ascon_prf_state_t *state, const unsigned char *key, size_t outlen);

/**
 * \brief Frees the ASCON-Prf state and destroys any sensitive material.
 *
 * \param state PRF state to be freed.
 */
void ascon_prf_free(ascon_prf_state_t *state);

/**
 * \brief Absorbs input data into an incremental ASCON-Prf state.
 *
 * \param state PRF state to be absorb.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_prf_init(), ascon_prf_squeeze()
 */
void ascon_prf_absorb
    (ascon_prf_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Squeezes output from an incremental ASCON-Prf operation.
 *
 * \param state PRF state to squeeze output from.
 * \param out Points to the output buffer to receive the output.
 * \param outlen Number of bytes of output that are required for this call.
 *
 * This function can be called any number of times until all desired
 * output has been retrieved.
 *
 * \sa ascon_prf_init(), ascon_prf_absorb()
 */
void ascon_prf_squeeze
    (ascon_prf_state_t *state, unsigned char *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif
