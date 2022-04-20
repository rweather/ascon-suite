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

#ifndef ASCON_HKDF_H
#define ASCON_HKDF_H

#include <stddef.h>

/**
 * \file hkdf.h
 * \brief HMAC-based key derivation function based on ASCON-HMAC.
 *
 * Reference: https://tools.ietf.org/html/rfc5869
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default output block size for ASCON-HKDF and ASCON-HKDFA.
 * Key material is generated in blocks of this size.
 */
#define ASCON_HKDF_OUTPUT_SIZE 32

/**
 * \brief State for incremental generation of key material from ASCON-HKDF.
 */
typedef struct
{
    /** Hashed key from ascon_hkdf_extract() */
    unsigned char prk[ASCON_HKDF_OUTPUT_SIZE];

    /** Last output block that was generated for ascon_hkdf_expand() */
    unsigned char out[ASCON_HKDF_OUTPUT_SIZE];

    /** Counter for the next output block to generate */
    unsigned char counter;

    /** Current position in the output block */
    unsigned char posn;

} ascon_hkdf_state_t;

/**
 * \brief State for incremental generation of key material from ASCON-HKDFA.
 */
typedef struct
{
    /** Hashed key from ascon_hkdf_extract() */
    unsigned char prk[ASCON_HKDF_OUTPUT_SIZE];

    /** Last output block that was generated for ascon_hkdf_expand() */
    unsigned char out[ASCON_HKDF_OUTPUT_SIZE];

    /** Counter for the next output block to generate */
    unsigned char counter;

    /** Current position in the output block */
    unsigned char posn;

} ascon_hkdfa_state_t;

/**
 * \brief Derives key material using ASCON-HKDF.
 *
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate, maximum of
 * ASCON_HKDF_OUTPUT_SIZE * 255 bytes.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 *
 * \return Zero on success or -1 if \a outlen is out of range.
 *
 * \sa ascon_hkdf_extract(), ascon_hkdf_expand()
 */
int ascon_hkdf
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen);

/**
 * \brief Extracts entropy from a key and salt for ASCON-HKDF.
 *
 * \param state HKDF state to be initialized.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 *
 * \sa ascon_hkdf_expand(), ascon_hkdf()
 */
void ascon_hkdf_extract
    (ascon_hkdf_state_t *state,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen);

/**
 * \brief Expands key material using a ASCON-HKDF state.
 *
 * \param state HKDF state to use to expand key material.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate.
 *
 * \return Zero on success or -1 if too many bytes have been generated so far.
 * There is a limit of ASCON_HKDF_OUTPUT_SIZE * 255 bytes.
 */
int ascon_hkdf_expand
    (ascon_hkdf_state_t *state,
     const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen);

/**
 * \brief Frees all sensitive material in a ASCON-HKDF state.
 *
 * \param state Points to the HKDF state.
 */
void ascon_hkdf_free(ascon_hkdf_state_t *state);

/**
 * \brief Derives key material using ASCON-HKDFA.
 *
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate, maximum of
 * ASCON_HKDF_OUTPUT_SIZE * 255 bytes.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 *
 * \return Zero on success or -1 if \a outlen is out of range.
 *
 * \sa ascon_hkdfa_extract(), ascon_hkdfa_expand()
 */
int ascon_hkdfa
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen);

/**
 * \brief Extracts entropy from a key and salt for ASCON-HKDFA.
 *
 * \param state HKDF state to be initialized.
 * \param key Points to the bytes of the key.
 * \param keylen Number of bytes in the key.
 * \param salt Points to the bytes of the salt.
 * \param saltlen Number of bytes in the salt.
 *
 * \sa ascon_hkdfa_expand(), ascon_hkdfa()
 */
void ascon_hkdfa_extract
    (ascon_hkdfa_state_t *state,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen);

/**
 * \brief Expands key material using a ASCON-HKDFA state.
 *
 * \param state HKDF state to use to expand key material.
 * \param info Points to the bytes of the informational data.
 * \param infolen Number of bytes in the informational data.
 * \param out Points to the output buffer to receive the key material.
 * \param outlen Number of bytes of key material to generate.
 *
 * \return Zero on success or -1 if too many bytes have been generated so far.
 * There is a limit of ASCON_HKDF_OUTPUT_SIZE * 255 bytes.
 */
int ascon_hkdfa_expand
    (ascon_hkdfa_state_t *state,
     const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen);

/**
 * \brief Frees all sensitive material in a ASCON-HKDFA state.
 *
 * \param state Points to the HKDF state.
 */
void ascon_hkdfa_free(ascon_hkdfa_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
