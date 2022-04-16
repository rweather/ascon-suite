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

#ifndef ASCON_AEAD_COMMON_H
#define ASCON_AEAD_COMMON_H

/* Common utilities for supporting the implementation of AEAD modes */

#include <ascon/aead.h>
#include <ascon/permutation.h>
#include <ascon/utility.h>

/**
 * \brief Check an authentication tag in constant time.
 *
 * \param plaintext Points to the plaintext data.
 * \param plaintext_len Length of the plaintext in bytes.
 * \param tag1 First tag to compare.
 * \param tag2 Second tag to compare.
 * \param size Length of the tags in bytes.
 *
 * \return Returns -1 if the tag check failed or 0 if the check succeeded.
 *
 * If the tag check fails, then the \a plaintext will also be zeroed to
 * prevent it from being used accidentally by the application when the
 * ciphertext was invalid.
 */
int ascon_aead_check_tag
    (unsigned char *plaintext, size_t plaintext_len,
     const unsigned char *tag1, const unsigned char *tag2, size_t size);

/**
 * \brief Absorbs data into an ASCON state with an 8-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 * \param last_permute Non-zero to permute the last block, or zero
 * to delay the permutation.
 */
void ascon_aead_absorb_8
    (ascon_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, int last_permute);

/**
 * \brief Absorbs data into an ASCON state with a 16-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 * \param last_permute Non-zero to permute the last block, or zero
 * to delay the permutation.
 */
void ascon_aead_absorb_16
    (ascon_state_t *state, const unsigned char *data,
     size_t len, uint8_t first_round, int last_permute);

/**
 * \brief Encrypts a block of data with an ASCON state and an 8-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_aead_encrypt_8
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

/**
 * \brief Encrypts a block of data with an ASCON state and a 16-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_aead_encrypt_16
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

/**
 * \brief Decrypts a block of data with an ASCON state and an 8-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_aead_decrypt_8
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

/**
 * \brief Decrypts a block of data with an ASCON state and a 16-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
void ascon_aead_decrypt_16
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, size_t len, uint8_t first_round);

#endif
