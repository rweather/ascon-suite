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

#ifndef ASCON_TRNG_H
#define ASCON_TRNG_H

/**
 * \file ascon-trng.h
 * \brief Access to the system's random number source.
 *
 * This is not a public API and should only be used by the library itself.
 * Applications should use the ASCON-PRNG API instead.
 *
 * The data that comes out of the system's random number source may not
 * be very good for direct application use with non-uniform entropy
 * distribution in the output.
 *
 * If the source is embedded in a chip then the user may have reason to
 * distrust the chip vendor.
 *
 * ASCON-PRNG will destroy any watermarks from the chip vendor and spread
 * out the entropy in the source before passing the data to the application.
 *
 * The library uses this API internally for masking, so the functions
 * ascon_trng_generate_32() and ascon_trng_generate_64() should try to
 * generate reasonable values rapidly.
 */

#include <ascon/permutation.h>
#include "ascon-select-trng.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Number of bytes to request from the system TRNG to seed a PRNG.
 */
#define ASCON_SYSTEM_SEED_SIZE 32

/**
 * \brief State of the random number source.
 */
typedef struct
{
    /** Position within the PRNG state to extract the next byte */
    unsigned posn;

#if defined(ASCON_TRNG_X86_64_RDRAND)
    /** Non-zero if RDRAND is working, zero if it is not returning data */
    int rdrand_working;
#endif

#if defined(ASCON_TRNG_MIXER)
    /** PRNG state for whitening poor random number sources.  Also used on
     *  systems without a fast "get random word" operation for masking. */
    ascon_state_t prng;

    /** Rate of squeezing data out of the PRNG state */
    #define ASCON_TRNG_MIXER_RATE 8U
#endif

} ascon_trng_state_t;

/**
 * \brief Generates a buffer of bytes from the system TRNG source.
 *
 * \param out Output buffer to be filled with random bytes.
 * \param outlen Length of the output buffer in bytes.
 *
 * \return Non-zero if the system random number source is working;
 * zero if there is no system random number source or it has failed.
 *
 * This function should try to generate high quality random data even
 * if it is a little slower.
 */
int ascon_trng_generate(unsigned char *out, size_t outlen);

/**
 * \brief Initializes the random number source for generating a sequence
 * of masking material at high speed.
 *
 * \param state Returns state information for accessing the source.
 *
 * \return Non-zero if the random number source was initialized,
 * or zero if there is no random number source available.
 */
int ascon_trng_init(ascon_trng_state_t *state);

/**
 * \brief Frees the random number source and destroys any sensitive material.
 *
 * \param state State information for the source.
 */
void ascon_trng_free(ascon_trng_state_t *state);

/**
 * \brief Generates a 32-bit random value for masking operations.
 *
 * \param state State information for the source.
 *
 * \return A random 32-bit value.
 *
 * This function must operate quickly as it is used in high frequency
 * masking operations.  The source may not be reseeded automatically.
 */
uint32_t ascon_trng_generate_32(ascon_trng_state_t *state);

/**
 * \brief Generates a 64-bit random value for masking operations.
 *
 * \param state State information for the source.
 *
 * \return A random 64-bit value.
 *
 * This function must operate quickly as it is used in high frequency
 * masking operations.  The source may not be reseeded automatically.
 */
uint64_t ascon_trng_generate_64(ascon_trng_state_t *state);

/**
 * \brief Reseeds the random number source.
 *
 * \param state State information for the source.
 *
 * \return Non-zero if we have a random number source, or zero if
 * we don't or it is inoperable.
 *
 * Not all random numbers sources require reseeding, but it is a good
 * idea to call this on a regular basis regardless.
 */
int ascon_trng_reseed(ascon_trng_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
