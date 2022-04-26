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

#ifndef ASCON_MASKED_STATE_H
#define ASCON_MASKED_STATE_H

#include "ascon-masked-word.h"

/**
 * \file ascon-masked-state.h
 * \brief Utility functions for operating on masked ASCON states with
 * between 2 and 4 shares.
 *
 * The current implementations use ideas from "Protecting against Statistical
 * Ineffective Fault Attacks", J. Daemen, C. Dobraunig, M. Eichlseder,
 * H. Gross, F. Mendel, and R. Primas: https://eprint.iacr.org/2019/536.pdf
 *
 * That paper shows how to implement the 5-bit S-box Chi5 that is used in
 * ASCON with a relatively small amount of randomness.  Because Chi5 uses
 * invertible Toffoli gates, randomness does not need to be injected
 * continuously during the computation of the AND-NOT operations.
 * Randomness can be injected once at the start of each S-box computation.
 *
 * The paper also indicates that the randomness can be reused from
 * round to round.  The state is randomized when it is split into shares,
 * and then fresh random material is generated to mask the first S-box
 * computation.  After that, the S-box randomness can be reused for the
 * S-box computations in all subsequent rounds.
 *
 * What's going on here is that ASCON itself is being used as a PRNG
 * to expand the first S-box mask to additional masks for each
 * subsequent round.  The "t0 ^= (~x0) & x1" term iterates the PRNG
 * using the random input t0 and part of the ASCON state (x0 and x1).
 *
 * If we were to mask every AND-NOT operation individually, then we
 * would need up to 12 rounds x 5 words x 64 bits = 3840 bits of new
 * randomness for each permutation call instead of only 64 bits here.
 *
 * The masked implementation at https://github.com/ascon/simpleserial-ascon
 * goes even further, reusing the randomness from one permutation call
 * to the next.  We are being a little more paranoid here.
 *
 * We also add randomness whenever data is injected into or squeezed
 * from the masked ASCON permutation state.
 *
 * https://github.com/ascon/simpleserial-ascon stores the shares in
 * rotated form.  For a 4-share word, the 2nd, 3rd, and 4th shares are
 * rotated 5, 10, and 15 bits with respect to the 1st share.  After each
 * round, simpleserial-ascon rotates the preserved randomness by 7, 13,
 * or 29 bits for the three preserved shares.  These values are for
 * 32-bit sliced implementations.
 *
 * For 64-bit, we have chosen to use rotations of 11, 22, and 33 for
 * the shares.  Preserved 64-bit words are rotated by 13, 29, and 59.
 * These numbers are the closest primes to double the values used
 * by simpleserial-ascon (29 was rounded up from 2 * 13, as 23 was
 * equally close).
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initializes the words of the ASCON-x2 permutation state.
 *
 * \param state The ASCON-x2 state to initialize.
 *
 * All words will be set to zero with no randomness.  The application
 * must use ascon_x2_overwrite_word() and ascon_x2_overwrite_words()
 * to populate the initial randomized state.
 *
 * \sa ascon_x2_free()
 */
void ascon_x2_init(ascon_masked_state_t *state);

/**
 * \brief Frees an ASCON-x2 permutation state and attempts to destroy
 * any sensitive material.
 *
 * \param state The ASCON-x2 state to be freed.
 *
 * \sa ascon_x2_init()
 */
void ascon_x2_free(ascon_masked_state_t *state);

/**
 * \brief Randomizes an ASCON-x2 permutation state.
 *
 * \param state The ASCON-x2 state to be randomized.
 * \param trng TRNG to use to randomize the state.
 *
 * The state will still have the same effective value, but this function
 * will mix in fresh randomness to all words.
 */
void ascon_x2_randomize(ascon_masked_state_t *state, ascon_trng_state_t *trng);

/**
 * \brief Adds a masked word to the ASCON-x2 state by XOR'ing them it
 * with the state.
 *
 * \param state The ASCON-x2 permutation state.
 * \param word Points to the masked word to add to the state.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The randomness in the masked word will be incorporated into the state.
 */
void ascon_x2_add_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset);

/**
 * \brief Overwrites an existing masked word in the ASCON-x2 state.
 *
 * \param state The ASCON-x2 permutation state.
 * \param word The masked word to write to the state.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The randomness in the masked word will be copied into \a state.
 */
void ascon_x2_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset);

/**
 * \brief Extracts a masked word from the ASCON-x2 state.
 *
 * \param state The ASCON-x2 permutation state.
 * \param word Points to the buffer to receive the masked word.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The masked word is directly copied out of the \a state into \a word.
 * It should be randomized with ascon_x2_word_randomize() if it is
 * likely to be stored for a long period of time.
 */
void ascon_x2_extract_word
    (const ascon_masked_state_t *state, ascon_masked_word_t *word,
     unsigned offset);

/**
 * \brief Permutes the ASCON-x2 state with a specified number of rounds.
 *
 * \param state The ASCON-x2 state in "operational" form.
 * \param first_round The first round to execute, between 0 and 11.
 * The number of rounds will be 12 - first_round.
 * \param preserve Preserved randomness from the previous permutation
 * operation, or a fresh random word if randomness should not be preserved.
 */
void ascon_x2_permute
    (ascon_masked_state_t *state, uint8_t first_round, uint64_t *preserve);

/**
 * \brief Temporarily releases access to any shared hardware resources
 * that a permutation state was using.
 *
 * \param state The ASCON-x2 state to be released.
 *
 * Operation on the state will resume the next time ascon_x2_acquire()
 * is called.
 *
 * \sa ascon_x2_acquire()
 */
void ascon_x2_release(ascon_masked_state_t *state);

/**
 * \brief Re-acquires access to any shared hardware resources that a
 * permutation state was using.
 *
 * \param state The ASCON-x2 state to be re-acquired.
 *
 * \sa ascon_x2_release()
 */
void ascon_x2_acquire(ascon_masked_state_t *state);

/**
 * \brief Copies the entire ASCON-x2 permutation state from a regular
 * ASCON-x1 permutation state.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to mask the original ASCON-x1 state.
 */
void ascon_x2_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x2 permutation state to a regular
 * ASCON-x1 permutation state.
 *
 * \param dest The destination to copy to after unmasking it.
 * \param src The source to copy from.
 */
void ascon_x2_copy_to_x1(ascon_state_t *dest, const ascon_masked_state_t *src);

/**
 * \brief Copies the entire ASCON-x2 permutation state from a source to a
 * destination.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to re-randomize the source state.
 */
void ascon_x2_copy_from_x2
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x3 permutation state to an
 * ASCON-x2 permutation state.
 *
 * \param dest The destination to copy to after unmasking it.
 * \param src The source to copy from.
 * \param trng TRNG to use to randomize the output state.
 */
void ascon_x2_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x4 permutation state to an
 * ASCON-x2 permutation state.
 *
 * \param dest The destination to copy to after unmasking it.
 * \param src The source to copy from.
 * \param trng TRNG to use to randomize the output state.
 */
void ascon_x2_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Initializes the words of the ASCON-x3 permutation state.
 *
 * \param state The ASCON-x3 state to initialize.
 *
 * All words will be set to zero with no randomness.  The application
 * must use ascon_x3_overwrite_word() and ascon_x3_overwrite_words()
 * to populate the initial randomized state.
 *
 * \sa ascon_x3_free()
 */
void ascon_x3_init(ascon_masked_state_t *state);

/**
 * \brief Frees an ASCON-x3 permutation state and attempts to destroy
 * any sensitive material.
 *
 * \param state The ASCON-x3 state to be freed.
 *
 * \sa ascon_x3_init()
 */
void ascon_x3_free(ascon_masked_state_t *state);

/**
 * \brief Randomizes an ASCON-x3 permutation state.
 *
 * \param state The ASCON-x3 state to be randomized.
 * \param trng TRNG to use to randomize the state.
 *
 * The state will still have the same effective value, but this function
 * will mix in fresh randomness to all words.
 */
void ascon_x3_randomize(ascon_masked_state_t *state, ascon_trng_state_t *trng);

/**
 * \brief Adds a masked word to the ASCON-x3 state by XOR'ing them it
 * with the state.
 *
 * \param state The ASCON-x3 permutation state.
 * \param word Points to the masked word to add to the state.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The randomness in the masked word will be incorporated into the state.
 */
void ascon_x3_add_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset);

/**
 * \brief Overwrites an existing masked word in the ASCON-x3 state.
 *
 * \param state The ASCON-x3 permutation state.
 * \param word The masked word to write to the state.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The randomness in the masked word will be copied into \a state.
 */
void ascon_x3_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word,
     unsigned offset);

/**
 * \brief Extracts a masked word from the ASCON-x3 state.
 *
 * \param state The ASCON-x3 permutation state.
 * \param word Points to the buffer to receive the masked word.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The masked word is directly copied out of the \a state into \a word.
 * It should be randomized with ascon_x3_word_randomize() if it is
 * likely to be stored for a long period of time.
 */
void ascon_x3_extract_word
    (const ascon_masked_state_t *state, ascon_masked_word_t *word,
     unsigned offset);

/**
 * \brief Permutes the ASCON-x3 state with a specified number of rounds.
 *
 * \param state The ASCON-x3 state in "operational" form.
 * \param first_round The first round to execute, between 0 and 11.
 * The number of rounds will be 12 - first_round.
 * \param preserve Preserved randomness from the previous permutation
 * operation, or fresh random words if randomness should not be preserved.
 */
void ascon_x3_permute
    (ascon_masked_state_t *state, uint8_t first_round, uint64_t preserve[2]);

/**
 * \brief Temporarily releases access to any shared hardware resources
 * that a permutation state was using.
 *
 * \param state The ASCON-x3 state to be released.
 *
 * Operation on the state will resume the next time ascon_x3_acquire()
 * is called.
 *
 * \sa ascon_x3_acquire()
 */
void ascon_x3_release(ascon_masked_state_t *state);

/**
 * \brief Re-acquires access to any shared hardware resources that a
 * permutation state was using.
 *
 * \param state The ASCON-x3 state to be re-acquired.
 *
 * \sa ascon_x3_release()
 */
void ascon_x3_acquire(ascon_masked_state_t *state);

/**
 * \brief Copies the entire ASCON-x3 permutation state from a regular
 * ASCON-x1 permutation state.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to mask the original ASCON-x1 state.
 */
void ascon_x3_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x3 permutation state to a regular
 * ASCON-x1 permutation state.
 *
 * \param dest The destination to copy to after unmasking it.
 * \param src The source to copy from.
 */
void ascon_x3_copy_to_x1(ascon_state_t *dest, const ascon_masked_state_t *src);

/**
 * \brief Copies the entire ASCON-x3 permutation state from an
 * ASCON-x2 permutation state.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to randomize the output state.
 */
void ascon_x3_copy_from_x2
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x3 permutation state from a source to a
 * destination.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to re-randomize the source state.
 */
void ascon_x3_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x3 permutation state from an
 * ASCON-x4 permutation state.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to randomize the output state.
 */
void ascon_x3_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Initializes the words of the ASCON-x4 permutation state.
 *
 * \param state The ASCON-x4 state to initialize.
 *
 * All words will be set to zero with no randomness.  The application
 * must use ascon_x4_overwrite_word() and ascon_x4_overwrite_words()
 * to populate the initial randomized state.
 *
 * \sa ascon_x4_free()
 */
void ascon_x4_init(ascon_masked_state_t *state);

/**
 * \brief Frees an ASCON-x4 permutation state and attempts to destroy
 * any sensitive material.
 *
 * \param state The ASCON-x4 state to be freed.
 *
 * \sa ascon_x4_init()
 */
void ascon_x4_free(ascon_masked_state_t *state);

/**
 * \brief Randomizes an ASCON-x4 permutation state.
 *
 * \param state The ASCON-x4 state to be randomized.
 * \param trng TRNG to use to randomize the state.
 *
 * The state will still have the same effective value, but this function
 * will mix in fresh randomness to all words.
 */
void ascon_x4_randomize(ascon_masked_state_t *state, ascon_trng_state_t *trng);

/**
 * \brief Adds a masked word to the ASCON-x4 state by XOR'ing them it
 * with the state.
 *
 * \param state The ASCON-x4 permutation state.
 * \param word Points to the masked word to add to the state.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The randomness in the masked word will be incorporated into the state.
 */
void ascon_x4_add_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word, unsigned offset);

/**
 * \brief Overwrites an existing masked word in the ASCON-x4 state.
 *
 * \param state The ASCON-x4 permutation state.
 * \param word The masked word to write to the state.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The randomness in the masked word will be copied into \a state.
 */
void ascon_x4_overwrite_word
    (ascon_masked_state_t *state, const ascon_masked_word_t *word, unsigned offset);

/**
 * \brief Extracts a masked word from the ASCON-x4 state.
 *
 * \param state The ASCON-x4 permutation state.
 * \param word Points to the buffer to receive the masked word.
 * \param offset Offset into the state between 0 and 32; must be a
 * multiple of 8.
 *
 * The masked word is directly copied out of the \a state into \a word.
 * It should be randomized with ascon_x4_word_randomize() if it is
 * likely to be stored for a long period of time.
 */
void ascon_x4_extract_word
    (const ascon_masked_state_t *state, ascon_masked_word_t *word,
     unsigned offset);

/**
 * \brief Permutes the ASCON-x4 state with a specified number of rounds.
 *
 * \param state The ASCON-x4 state in "operational" form.
 * \param first_round The first round to execute, between 0 and 11.
 * The number of rounds will be 12 - first_round.
 * \param preserve Preserved randomness from the previous permutation
 * operation, or fresh random words if randomness should not be preserved.
 */
void ascon_x4_permute
    (ascon_masked_state_t *state, uint8_t first_round, uint64_t preserve[3]);

/**
 * \brief Temporarily releases access to any shared hardware resources
 * that a permutation state was using.
 *
 * \param state The ASCON-x4 state to be released.
 *
 * Operation on the state will resume the next time ascon_x4_acquire()
 * is called.
 *
 * \sa ascon_x4_acquire()
 */
void ascon_x4_release(ascon_masked_state_t *state);

/**
 * \brief Re-acquires access to any shared hardware resources that a
 * permutation state was using.
 *
 * \param state The ASCON-x4 state to be re-acquired.
 *
 * \sa ascon_x4_release()
 */
void ascon_x4_acquire(ascon_masked_state_t *state);

/**
 * \brief Copies the entire ASCON-x4 permutation state from a regular
 * ASCON-x1 permutation state.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to mask the original ASCON-x1 state.
 */
void ascon_x4_copy_from_x1
    (ascon_masked_state_t *dest, const ascon_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x4 permutation state to a regular
 * ASCON-x1 permutation state.
 *
 * \param dest The destination to copy to after unmasking it.
 * \param src The source to copy from.
 */
void ascon_x4_copy_to_x1(ascon_state_t *dest, const ascon_masked_state_t *src);

/**
 * \brief Copies the entire ASCON-x4 permutation state from an
 * ASCON-x2 permutation state.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to randomize the output state.
 */
void ascon_x4_copy_from_x2
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x4 permutation state from an
 * ASCON-x3 permutation state.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to randomize the output state.
 */
void ascon_x4_copy_from_x3
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Copies the entire ASCON-x4 permutation state from a source to a
 * destination.
 *
 * \param dest The destination to copy to.
 * \param src The source to copy from.
 * \param trng TRNG to use to re-randomize the source state.
 */
void ascon_x4_copy_from_x4
    (ascon_masked_state_t *dest, const ascon_masked_state_t *src,
     ascon_trng_state_t *trng);

/**
 * \brief Adds a padding marker to the masked state.
 *
 * \param state The masked state to be padded.
 * \param offset Offset of the padding marker (0 to 39).
 */
void ascon_masked_state_pad(ascon_masked_state_t *state, unsigned offset);

/**
 * \brief Adds a separator marker to the masked state.
 *
 * \param state The masked state to add the separator marker to.
 */
void ascon_masked_state_separator(ascon_masked_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
