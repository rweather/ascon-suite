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

#ifndef ASCON_PERMUTATION_H
#define ASCON_PERMUTATION_H

#include <stdint.h>
#include <stddef.h>

/**
 * \file permutation.h
 * \brief Direct access to the ASCON permutation primitive.
 *
 * Normally applications do not need to use the definitions in this
 * file directly.  They would instead use other functions to access
 * AEAD and hashing modes.  However, if the application needs to
 * implement its own mode, then these definitions can help with that.
 *
 * \note This API may not use the most efficient platform-specific
 * implementation of the permuation in the library due to alignment
 * constraints and function call overheads.  The high-level AEAD
 * and hashing modes have access to internal inlined API's with
 * better performance.
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Structure of the internal state of the ASCON permutation.
 *
 * The order of bits and bytes in the state may not match the regular
 * big-endian byte order of standard ASCON.  The bits and bytes are
 * stored in an "operational" form which is more efficient for the
 * back end to process.
 *
 * The functions ascon_to_regular() and ascon_from_regular() can be
 * used to convert to and from the regular form when necessary.
 *
 * This structure should be treated as opaque by calling applications
 * when it is in operational form.  It is declared publicly only to ensure
 * correct alignment for efficient 64-bit word access by the back end.
 */
typedef union
{
    uint64_t S[5];      /**< 64-bit words of the state */
    uint32_t W[10];     /**< 32-bit words of the state */
    uint8_t B[40];      /**< Bytes of the state */

} ascon_state_t;

/**
 * \brief Initializes the words of the ASCON permutation state to zero.
 *
 * \param state The ASCON state to initialize.
 */
void ascon_init(ascon_state_t *state);

/**
 * \brief Converts the ASCON state from the internal "operational" form
 * into the regular big-endian form.
 *
 * \param state The ASCON state to convert.
 *
 * \sa ascon_from_regular()
 */
void ascon_to_regular(ascon_state_t *state);

/**
 * \brief Converts the ASCON state from the regular big-endian form
 * into the internal "operational" form.
 *
 * \param state The ASCON state to convert.
 *
 * \sa ascon_to_regular()
 */
void ascon_from_regular(ascon_state_t *state);

/**
 * \brief Adds bytes to the ASCON state by XOR'ing them with existing bytes.
 *
 * \param state The ASCON state in "operational" form.
 * \param data Points to the data to add to the state.
 * \param offset Offset into the state between 0 and 40 - size.
 * \param size Number of bytes to add to the state between 0 and 40.
 */
void ascon_add_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size);

/**
 * \brief Overwrites existing bytes in the ASCON state.
 *
 * \param state The ASCON state in "operational" form.
 * \param data Points to the data to write to the state.
 * \param offset Offset into the state between 0 and 40 - size.
 * \param size Number of bytes to overwrite between 0 and 40.
 */
void ascon_overwrite_bytes
    (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size);

/**
 * \brief Overwrites a part of the ASCON state with zeroes.
 *
 * \param state The ASCON state in "operational" form.
 * \param offset Offset into the state between 0 and 40 - size.
 * \param size Number of bytes to overwrite between 0 and 40.
 */
void ascon_overwrite_with_zeroes
    (ascon_state_t *state, unsigned offset, unsigned size);

/**
 * \brief Extracts bytes from the ASCON state.
 *
 * \param state The ASCON state in "operational" form.
 * \param data Points to the buffer to receive the extracted bytes.
 * \param offset Offset into the state between 0 and 40 - size.
 * \param size Number of bytes to extract from the state between 0 and 40.
 */
void ascon_extract_bytes
    (const ascon_state_t *state, uint8_t *data, unsigned offset, unsigned size);

/**
 * \brief Extracts bytes from the ASCON state and XOR's them with
 * input bytes to produce output bytes.
 *
 * \param state The ASCON state in "operational" form.
 * \param input Points to the input buffer.
 * \param output Points to the output buffer.
 * \param offset Offset into the state between 0 and 40 - size.
 * \param size Number of bytes to extract from the state between 0 and 40.
 */
void ascon_extract_and_add_bytes
    (const ascon_state_t *state, const uint8_t *input, uint8_t *output,
     unsigned offset, unsigned size);

/**
 * \brief Permutes the ASCON state with a specified number of rounds.
 *
 * \param state The ASCON state in "operational" form.
 * \param first_round The first round to execute, between 0 and 11.
 * The number of rounds will be 12 - first_round.
 */
void ascon_permute(ascon_state_t *state, uint8_t first_round);

/**
 * \brief Permutes the ASCON state with 12 rounds of the permutation.
 *
 * \param state The ASCON state in "operational" form.
 */
#define ascon_permute12(state) ascon_permute((state), 0)

/**
 * \brief Permutes the ASCON state with 8 rounds of the permutation.
 *
 * \param state The ASCON state in "operational" form.
 */
#define ascon_permute8(state) ascon_permute((state), 4)

/**
 * \brief Permutes the ASCON state with 6 rounds of the permutation.
 *
 * \param state The ASCON state in "operational" form.
 */
#define ascon_permute6(state) ascon_permute((state), 6)

#ifdef __cplusplus
}
#endif

#endif
