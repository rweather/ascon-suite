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

#ifndef ASCON_RANDOM_H
#define ASCON_RANDOM_H

#include <ascon/xof.h>

/**
 * \file random.h
 * \brief Pseudorandom number generator (PRNG) built around ASCON.
 *
 * This PRNG implementation uses the SpongePRNG construction with
 * ASCON as the sponge permutation.
 *
 * Reference: "Sponge-based pseudo-random number generators",
 * Guido Bertoni et al, https://keccak.team/files/SpongePRNG.pdf
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State information for a pseudorandom number generator.
 *
 * The application should treat this structure as opaque.
 */
typedef struct
{
    /** XOF state containing the accumulated SpongePRNG state */
    ascon_xof_state_t xof;

    /** Number of bytes that have been generated since the last re-seed */
    uint32_t counter;

    /** Padding to a 64-bit word boundary.  Reseved for future use */
    uint32_t reserved;

} ascon_random_state_t;

/**
 * \brief Gets a block of random data from the system.
 *
 * \param out Buffer to fill with the random data.
 * \param outlen Number of bytes of random data to generate.
 *
 * \return Non-zero if the system random number source is working;
 * zero if there is no system random number source or it has failed.
 *
 * In the case of a zero return, the returned data may be predictable
 * so the application should probably avoid using it.
 *
 * This function does not directly return the output of the system
 * random number source.  It will process the output with ASCON-XOF to
 * remove any watermarks or bias from untrustworthy TRNG's.  And it
 * will spread the entropy uniformly throughout the returned data.
 *
 * This function is suitable for relatively rare events such as the
 * generation of session keys or password salts.  If you need a large
 * amount of continuous random data, then use ascon_random_init() instead.
 *
 * \sa ascon_random_init()
 */
int ascon_random(unsigned char *out, size_t outlen);

/**
 * \brief Initializes a pseudorandom number generator from the
 * system random number source.
 *
 * \param state The pseudorandom number generator state to initialize.
 *
 * \return Non-zero if the system random number source is working;
 * zero if there is no system random number source or it has failed.
 *
 * In the case of a zero return, the returned data may be predictable
 * so the application should avoid using the pseudorandom number generator
 * unless it has some other source of entropy it can use.
 *
 * \note If this function returns zero, then the \a state is still
 * usable to generate data at a lower level of quality.  The \a state
 * must be freed explicitly with ascon_random_free() regardless of
 * the return value from this function.
 *
 * \sa ascon_random_generate(), ascon_random_add_entropy()
 */
int ascon_random_init(ascon_random_state_t *state);

/**
 * \brief Frees a pseudorandom number generator and destroys any
 * sensitive values.
 *
 * \param state The pseudorandom number generator state to free.
 *
 * \sa ascon_random_init()
 */
void ascon_random_free(ascon_random_state_t *state);

/**
 * \brief Generates data from a pseudorandom number generator.
 *
 * \param state The pseudorandom number generator state to use.
 * \param out Points to a buffer to receive the random data.
 * \param outlen Number of bytes of random data to generate.
 *
 * \sa ascon_random_reseed()
 */
void ascon_random_generate
    (ascon_random_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Explicitly re-seeds a pseudorandom number generator from the
 * system random number source.
 *
 * \param state The pseudorandom number generator to re-seed.
 *
 * \return Non-zero if the system random number source is working;
 * zero if there is no system random number source or it has failed.
 *
 * The pseudorandom number generator will be re-seeded periodically
 * by ascon_random_generate() but the application can choose to re-seed
 * more often if it needs fresh random data.
 *
 * \sa ascon_random_generate()
 */
int ascon_random_reseed(ascon_random_state_t *state);

/**
 * \brief Adds entropy to a pseudorandom number generator.
 *
 * \param state The pseudorandom number generator to add entropy to.
 * \param entropy Points to a buffer containing the entropy.
 * \param size Number of bytes of entropy to add, which can be zero to
 * "stir" the random pool but not introduce any new entropy.
 *
 * This API does not keep track of how much entropy has been collected.
 * Estimating the amount of entropy contained in noise sources is difficult
 * and would make the API very complex.
 *
 * The application can keep track of "entropy credits" itself if that is
 * important.  And then only call ascon_random_generate() when it judges
 * that the entropy pool is sufficiently populated.
 *
 * \sa ascon_random_add_entropy_quick()
 */
void ascon_random_add_entropy
    (ascon_random_state_t *state, const unsigned char *entropy, size_t size);

/**
 * \brief Quickly adds a 64-bit word of entropy to a pseudorandom
 * number generator.
 *
 * \param state The pseudorandom number generator to add entropy to.
 * \param entropy The entropy value.
 *
 * This function is intended for collecting entropy at high frequency
 * from simple sources.  The \a entropy may be an analog reading from a
 * noise source, the timing jitter from input events, or something else.
 *
 * This function incorporates \a entropy into the state and performs
 * two rounds of the ASCON permutation to lightly mix it into the state.
 * This reduces the overhead of entropy collection.
 *
 * If your entropy source is slow or intermittent, then
 * ascon_random_add_entropy() is a better choice.
 *
 * When using this function, it is recommended that ascon_random_add_entropy()
 * be called periodically with zero-length input to "stir" the entropy into
 * the random pool properly.
 *
 * \sa ascon_random_add_entropy()
 */
void ascon_random_add_entropy_quick
    (ascon_random_state_t *state, uint64_t entropy);

#ifdef __cplusplus
}
#endif

#endif
