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

#ifndef ASCON_KMAC_H
#define ASCON_KMAC_H

#include <ascon/xof.h>

/**
 * \file kmac.h
 * \brief Keyed Message Authentication Code (KMAC) based on ASCON-XOF.
 *
 * The KMAC mode provides a method to authenticate a sequence of bytes
 * using ASCON in hashing mode.  The output is essentially equivalent to
 * hashing the key followed by the data.
 *
 * NIST SP 800-185 is an extension of the XOF modes SHAKE128 and SHAKE256.
 * The nearest equivalent for us is ASCON-XOF.  We use the same encoding
 * as NIST SP 800-185 to provide domain separation between the key and data.
 *
 * Two versions of KMAC are provided: ASCON-KMAC based around ASCON-XOF,
 * and ASCON-KMACA based around ASCON-XOFA.
 *
 * References: NIST SP 800-185
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Default size of the output for ASCON-KMAC and ASCON-KMACA.
 */
#define ASCON_KMAC_SIZE ASCON_HASH_SIZE

/**
 * \brief State information for the ASCON-KMAC incremental mode.
 */
typedef struct
{
    ascon_xof_state_t xof;  /**< Internal ASCON-XOF state */

} ascon_kmac_state_t;

/**
 * \brief State information for the ASCON-KMACA incremental mode.
 */
typedef struct
{
    ascon_xofa_state_t xof; /**< Internal ASCON-XOFA state */

} ascon_kmaca_state_t;

/**
 * \brief Computes a KMAC value using ASCON-XOF.
 *
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param out Buffer to receive the output KMAC value.
 * \param outlen Length of the output KMAC value.
 *
 * The customization string allows the application to perform domain
 * separation between different uses of the KMAC algorithm.
 */
void ascon_kmac
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);

/**
 * \brief Initializes an incremental KMAC state using ASCON-XOF.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_kmac_update(), ascon_kmac_squeeze()
 */
void ascon_kmac_init
    (ascon_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Re-initializes an incremental KMAC state using ASCON-XOF.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * This function is equivalent to calling ascon_kmac_free() and then
 * ascon_kmac_init().
 *
 * \sa ascon_kmac_init()
 */
void ascon_kmac_reinit
    (ascon_kmac_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Frees the ASCON-KMAC state and destroys any sensitive material.
 *
 * \param state KMAC state to be freed.
 */
void ascon_kmac_free(ascon_kmac_state_t *state);

/**
 * \brief Absorbs more input data into an incremental ASCON-KMAC state.
 *
 * \param state KMAC state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_kmac_init(), ascon_kmac_squeeze()
 */
void ascon_kmac_absorb
    (ascon_kmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Sets the desired output length for an incremental ASCON-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from after the
 * desired output length has been set.
 * \param outlen Desired output length, or zero for arbitrary-length output.
 *
 * \sa ascon_kmac_squeeze()
 */
void ascon_kmac_set_output_length(ascon_kmac_state_t *state, size_t outlen);

/**
 * \brief Squeezes output data from an incremental ASCON-KMAC state.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * The application should call ascon_kmac_set_output_length() before
 * this function to set the desured output length.  If that function
 * has not been called, then this function will assume that the application
 * wants arbitrary-length output.
 *
 * \sa ascon_kmac_init(), ascon_kmac_update(), ascon_kmac_finalize()
 */
void ascon_kmac_squeeze
    (ascon_kmac_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Squeezes fixed-length data from an incremental ASCON-KMAC
 * state and finalizes the KMAC process.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the
 * ASCON_KMAC_SIZE bytes of squeezed data.
 *
 * This function combines the effect of ascon_kmac_set_output_length()
 * and ascon_kmac_squeeze() for convenience.
 *
 * \sa ascon_kmac_squeeze(), ascon_kmac_set_output_length()
 */
void ascon_kmac_finalize
    (ascon_kmac_state_t *state, unsigned char out[ASCON_KMAC_SIZE]);

/**
 * \brief Computes a KMAC value using ASCON-XOFA.
 *
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param out Buffer to receive the output KMAC value.
 * \param outlen Length of the output KMAC value.
 *
 * The customization string allows the application to perform domain
 * separation between different uses of the KMAC algorithm.
 */
void ascon_kmaca
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen);

/**
 * \brief Initializes an incremental KMAC state using ASCON-XOFA.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_kmaca_update(), ascon_kmaca_squeeze()
 */
void ascon_kmaca_init
    (ascon_kmaca_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Re-initializes an incremental KMAC state using ASCON-XOFA.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * This function is equivalent to calling ascon_kmaca_free() and then
 * ascon_kmaca_init().
 *
 * \sa ascon_kmaca_init()
 */
void ascon_kmaca_reinit
    (ascon_kmaca_state_t *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Frees the ASCON-KMACA state and destroys any sensitive material.
 *
 * \param state KMAC state to be freed.
 */
void ascon_kmaca_free(ascon_kmaca_state_t *state);

/**
 * \brief Absorbs more input data into an incremental ASCON-KMACA state.
 *
 * \param state KMAC state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_kmaca_init(), ascon_kmaca_squeeze()
 */
void ascon_kmaca_absorb
    (ascon_kmaca_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Sets the desired output length for an incremental ASCON-KMACA state.
 *
 * \param state KMAC state to squeeze the output data from after the
 * desired output length has been set.
 * \param outlen Desired output length, or zero for arbitrary-length output.
 *
 * \sa ascon_kmaca_squeeze()
 */
void ascon_kmaca_set_output_length(ascon_kmaca_state_t *state, size_t outlen);

/**
 * \brief Squeezes output data from an incremental ASCON-KMACA state.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * The application should call ascon_kmaca_set_output_length() before
 * this function to set the desured output length.  If that function
 * has not been called, then this function will assume that the application
 * wants arbitrary-length output.
 *
 * \sa ascon_kmaca_init(), ascon_kmaca_update(), ascon_kmaca_finalize()
 */
void ascon_kmaca_squeeze
    (ascon_kmaca_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Squeezes fixed-length data from an incremental ASCON-KMACA
 * state and finalizes the KMAC process.
 *
 * \param state KMAC state to squeeze the output data from.
 * \param out Points to the output buffer to receive the
 * ASCON_KMAC_SIZE bytes of squeezed data.
 *
 * This function combines the effect of ascon_kmaca_set_output_length()
 * and ascon_kmaca_squeeze() for convenience.
 *
 * \sa ascon_kmaca_squeeze(), ascon_kmaca_set_output_length()
 */
void ascon_kmaca_finalize
    (ascon_kmaca_state_t *state, unsigned char out[ASCON_KMAC_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
