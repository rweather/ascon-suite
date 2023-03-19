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

#ifndef ASCON_KDF_H
#define ASCON_KDF_H

#include <ascon/xof.h>

/**
 * \file kdf.h
 * \brief Key derivation function based on ASCON-XOF.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State for incremental generation of key material from ASCON-KDF.
 */
typedef struct
{
    ascon_xof_state_t state;  /**< Internal ASCON-XOF state */

} ascon_kdf_state_t;

/**
 * \brief State for incremental generation of key material from ASCON-KDFA.
 */
typedef struct
{
    ascon_xofa_state_t state; /**< Internal ASCON-XOFA state */

} ascon_kdfa_state_t;

/**
 * \brief Derives key material using ASCON-KDF.
 *
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_kdf_init()
 */
void ascon_kdf
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Initializes an incremental ASCON-KDF state.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * \sa ascon_kdf_update(), ascon_kdf_squeeze()
 */
void ascon_kdf_init
    (ascon_kdf_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Re-initializes an incremental ASCON-KDF state.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * This function is equivalent to calling ascon_kdf_free() and then
 * ascon_kdf_init().
 *
 * \sa ascon_kdf_init()
 */
void ascon_kdf_reinit
    (ascon_kdf_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Frees the ASCON-KDF state and destroys any sensitive material.
 *
 * \param state KDF state to be freed.
 */
void ascon_kdf_free(ascon_kdf_state_t *state);

/**
 * \brief Squeezes output data from an incremental ASCON-KDF state.
 *
 * \param state KDF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa ascon_kdf_init(), ascon_kdf_absorb()
 */
void ascon_kdf_squeeze
    (ascon_kdf_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Derives key material using ASCON-KDFA.
 *
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_kdfa_init()
 */
void ascon_kdfa
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Initializes an incremental ASCON-KDFA state.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * \sa ascon_kdfa_update(), ascon_kdfa_squeeze()
 */
void ascon_kdfa_init
    (ascon_kdfa_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Re-initializes an incremental ASCON-KDFA state.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * This function is equivalent to calling ascon_kdfa_free() and then
 * ascon_kdfa_init().
 *
 * \sa ascon_kdfa_init()
 */
void ascon_kdfa_reinit
    (ascon_kdfa_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Frees the ASCON-KDFA state and destroys any sensitive material.
 *
 * \param state KDFA state to be freed.
 */
void ascon_kdfa_free(ascon_kdfa_state_t *state);

/**
 * \brief Squeezes output data from an incremental ASCON-KDFA state.
 *
 * \param state KDFA state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa ascon_kdfa_init(), ascon_kdfa_absorb()
 */
void ascon_kdfa_squeeze
    (ascon_kdfa_state_t *state, unsigned char *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif
