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
 * This structure should be treated as opaque by calling applications
 * when it is in operational form.  It is declared publicly only to ensure
 * correct alignment for efficient 64-bit word access by the back end.
 *
 * If the back end requires more than 40 bytes for the permutation state,
 * then ascon_init() will allocate a structure and place a pointer to
 * that structure into P.  The application should call ascon_free() to
 * properly free the permutation state when it is no longer required.
 */
typedef union
{
    uint64_t S[5];                  /**< 64-bit words of the state */
    uint32_t W[10];                 /**< 32-bit words of the state */
    uint8_t B[40];                  /**< Bytes of the state */
    void *P[40 / sizeof(void *)];   /**< Private backend state */

} ascon_state_t;

/**
 * \brief Initializes the words of the ASCON permutation state to zero.
 *
 * \param state The ASCON state to initialize.
 *
 * This function might allocate internal state to hold more information
 * than will fit in the ascon_state_t structure to interface with a
 * platform-specific acceleration module.
 *
 * It is always a good idea to call this before using the permutation state.
 * Also make sure to call ascon_free() when the permutation state is no
 * longer required to deallocate the internal state.
 *
 * \sa ascon_free()
 */
void ascon_init(ascon_state_t *state);

/**
 * \brief Frees an ASCON permutation state and attempts to destroy
 * any sensitive material.
 *
 * \param state The ASCON state to be freed.
 *
 * If ascon_init() had to allocate internal structures to interface with a
 * platform-specific acceleration module, then this function will deallocate
 * those structures.
 *
 * There is no guarantee that all traces of the sensitive material will
 * be gone.  Fragments may be left on the stack or in registers from
 * previous permutation calls.  This function will make a best effort
 * given the constraints of the platform.
 *
 * \sa ascon_init()
 */
void ascon_free(ascon_state_t *state);

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
 * \brief Extracts bytes from the ASCON state and XOR's them with
 * input bytes to produce output bytes.  Also write the original
 * input bytes into the ASCON state.
 *
 * \param state The ASCON state in "operational" form.
 * \param input Points to the input buffer.
 * \param output Points to the output buffer.
 * \param offset Offset into the state between 0 and 40 - size.
 * \param size Number of bytes to extract from the state between 0 and 40.
 *
 * This function has the effect of calling ascon_extract_and_add_bytes()
 * and then ascon_overwrite_bytes(), but it also works for the case where
 * \a input and \a output are the same buffer.  This combination is
 * typically used for AEAD decryption where the input ciphertext
 * needs to be incorporated into the state to authenticate it.
 */
void ascon_extract_and_overwrite_bytes
    (ascon_state_t *state, const uint8_t *input, uint8_t *output,
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

/**
 * \brief Temporarily releases access to any shared hardware resources
 * that a permutation state was using.
 *
 * \param state The ASCON state to be released.
 *
 * Operation on the state will resume the next time ascon_acquire()
 * is called.
 *
 * The ascon_free() function implicitly releases the state so it usually
 * isn't necessary to release the state explicitly.  However, if the
 * application will not be using the state for some time then it should
 * call ascon_release() to allow other tasks on the system to access
 * the shared hardware.
 *
 * \sa ascon_acquire()
 */
void ascon_release(ascon_state_t *state);

/**
 * \brief Re-acquires access to any shared hardware resources that a
 * permutation state was using.
 *
 * \param state The ASCON state to be re-acquired.
 *
 * \sa ascon_release()
 */
void ascon_acquire(ascon_state_t *state);

/**
 * \brief Copies the entire ASCON permutation state from a source to a
 * destination.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 *
 * The destination must be acquired and the source must be released.
 */
void ascon_copy(ascon_state_t *dest, const ascon_state_t *src);

#ifdef __cplusplus
}
#endif

#endif
