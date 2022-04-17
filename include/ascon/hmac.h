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

#ifndef ASCON_HMAC_H
#define ASCON_HMAC_H

#include <ascon/hash.h>

/**
 * \file hmac.h
 * \brief Hashed Message Authentication Code (HMAC) based on ASCON-HASH.
 *
 * The HMAC mode provides a method to authenticate a sequence of bytes
 * using ASCON-HASH or ASCON-HASHA as the underlying digest algorithm.
 *
 * HMAC uses an underlying block size to pad the key data.
 * The ASCON-HASH block absorption rate of 8 bytes is too short
 * so we use the HMAC-SHA-256 block size of 64 instead.
 *
 * \note The KMAC construction is preferable for sponge-based hash
 * algorithms as it is simpler and more efficient.  HMAC mode is
 * provided for drop-in compatibility with existing designs.
 *
 * Reference: https://tools.ietf.org/html/rfc2104
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default size of the output for ASCON-HMAC and ASCON-HMACA.
 */
#define ASCON_HMAC_SIZE ASCON_HASH_SIZE

/**
 * \brief State information for the ASCON-HMAC incremental mode.
 */
typedef struct
{
    ascon_hash_state_t hash;    /**< Internal ASCON-HASH state */

} ascon_hmac_state_t;

/**
 * \brief State information for the ASCON-HMACA incremental mode.
 */
typedef struct
{
    ascon_hasha_state_t hash;   /**< Internal ASCON-HASHA state */

} ascon_hmaca_state_t;

/**
 * \brief Computes a HMAC value using ASCON-HASH.
 *
 * \param out Buffer to receive the output HMAC value; must be at least
 * ASCON_HMAC_SIZE bytes in length.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 */
void ascon_hmac
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/**
 * \brief Initializes an incremental HMAC state using ASCON-HASH.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 *
 * The \a key needs to be preserved until the ascon_hmac_finalize() call
 * to provide the outer HMAC hashing key.
 *
 * \sa ascon_hmac_update(), ascon_hmac_finalize()
 */
void ascon_hmac_init
    (ascon_hmac_state_t *state, const unsigned char *key, size_t keylen);

/**
 * \brief Re-initializes an incremental HMAC state using ASCON-HASH.
 *
 * \param state Points to the state to be re-initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 *
 * The \a key needs to be preserved until the ascon_hmac_finalize() call
 * to provide the outer HMAC hashing key.
 *
 * This function is equivalent to calling ascon_hmac_free() followed by
 * ascon_hmac_init().
 *
 * \sa ascon_hmac_init()
 */
void ascon_hmac_reinit
    (ascon_hmac_state_t *state, const unsigned char *key, size_t keylen);

/**
 * \brief Frees the ASCON-HMAC state and destroys any sensitive material.
 *
 * \param state HMAC state to be freed.
 */
void ascon_hmac_free(ascon_hmac_state_t *state);

/**
 * \brief Updates an incremental ASCON-HMAC state with more input data.
 *
 * \param state HMAC state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hmac_init(), ascon_hmac_finalize()
 */
void ascon_hmac_update
    (ascon_hmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Finalizes an incremental ASCON-HMAC state.
 *
 * \param state HMAC state to squeeze the output data from.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param out Points to the output buffer to receive the HMAC value;
 * must be at least ASCON_HMAC_SIZE bytes in length.
 *
 * \sa ascon_hmac_init(), ascon_hmac_update()
 */
void ascon_hmac_finalize
    (ascon_hmac_state_t *state, const unsigned char *key, size_t keylen,
     unsigned char *out);

/**
 * \brief Computes a HMAC value using ASCON-HASHA.
 *
 * \param out Buffer to receive the output HMAC value; must be at least
 * ASCON_HMAC_SIZE bytes in length.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 */
void ascon_hmaca
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/**
 * \brief Initializes an incremental HMAC state using ASCON-HASHA.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 *
 * The \a key needs to be preserved until the ascon_hmaca_finalize() call
 * to provide the outer HMAC hashing key.
 *
 * \sa ascon_hmaca_update(), ascon_hmaca_finalize()
 */
void ascon_hmaca_init
    (ascon_hmaca_state_t *state, const unsigned char *key, size_t keylen);

/**
 * \brief Re-initializes an incremental HMAC state using ASCON-HASHA.
 *
 * \param state Points to the state to be re-initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 *
 * The \a key needs to be preserved until the ascon_hmaca_finalize() call
 * to provide the outer HMAC hashing key.
 *
 * This function is equivalent to calling ascon_hmaca_free() followed by
 * ascon_hmaca_init().
 *
 * \sa ascon_hmac_init()
 */
void ascon_hmaca_reinit
    (ascon_hmaca_state_t *state, const unsigned char *key, size_t keylen);

/**
 * \brief Frees the ASCON-HMACA state and destroys any sensitive material.
 *
 * \param state HMAC state to be freed.
 */
void ascon_hmaca_free(ascon_hmaca_state_t *state);

/**
 * \brief Updates an incremental ASCON-HMACA state with more input data.
 *
 * \param state HMAC state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hmaca_init(), ascon_hmaca_finalize()
 */
void ascon_hmaca_update
    (ascon_hmaca_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Finalizes an incremental ASCON-HMACA state.
 *
 * \param state HMAC state to squeeze the output data from.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param out Points to the output buffer to receive the HMAC value;
 * must be at least ASCON_HMAC_SIZE bytes in length.
 *
 * \sa ascon_hmaca_init(), ascon_hmaca_update()
 */
void ascon_hmaca_finalize
    (ascon_hmaca_state_t *state, const unsigned char *key, size_t keylen,
     unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
