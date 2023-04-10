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

#include <ascon/random.h>
#include <ascon/utility.h>
#include "random/ascon-trng.h"
#include "core/ascon-util-snp.h"

/**
 * \brief Automatically re-seed after generating more than this many bytes.
 */
#define ASCON_RANDOM_RESEED_LIMIT 16384

/**
 * \brief Re-keys the state of a pseudorandom number generator.
 *
 * \param state The pseudorandom number generator to re-key.
 *
 * According to section 4.3 of the SpongePRNG paper, forward security can
 * be enhanced by fetching a single rate block from the state and then
 * immediately feeding it back in as seed material.
 *
 * The effect of feeding the rate back into itself is to set the rate
 * block to zero.  When we permute the state afterwards, the rate will
 * be set to something else.  An attacker would need to be able to guess
 * the non-zeroed bits in the previous state to roll the state backwards,
 * which should be infeasible with this construction.
 *
 * The SpongePRNG paper recommends repeating the process ceil(c/r) times,
 * which is ceil((40 - ASCON_XOF_RATE) / ASCON_XOF_RATE) in our case.
 */
static void ascon_random_rekey(ascon_random_state_t *state)
{
    int temp;

    /* Zero out part of the state and run the permutation several times.
     * This enforces forward security on the SpongePRNG state. */
    ascon_xof_pad(&(state->xof));
    ascon_acquire(&(state->xof.state));
    for (temp = 0; temp < (40 - ASCON_XOF_RATE); temp += ASCON_XOF_RATE) {
        ascon_overwrite_with_zeroes(&(state->xof.state), 0, ASCON_XOF_RATE);
        ascon_permute(&(state->xof.state), 0);
    }
    ascon_release(&(state->xof.state));
}

int ascon_random_init(ascon_random_state_t *state)
{
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int ok;
    if (!state)
        return 0;
    ascon_xof_init_custom(&(state->xof), "SpongePRNG", 0, 0, 0);
    state->counter = 0;
    state->reserved = 0;
    ok = ascon_trng_generate(seed, sizeof(seed));
    ascon_xof_absorb(&(state->xof), seed, sizeof(seed));
    ascon_clean(seed, sizeof(seed));
    ascon_random_rekey(state);
    return ok;
}

void ascon_random_free(ascon_random_state_t *state)
{
    if (state) {
        state->counter = 0;
        ascon_xof_free(&(state->xof));
    }
}

void ascon_random_fetch
    (ascon_random_state_t *state, unsigned char *out, size_t outlen)
{
    /* If there is no state, use the global ascon_random() function
     * so that we return something.  Safer than returning nothing
     * to the caller by accident and having them use that nothing. */
    if (!state) {
        ascon_random(out, outlen);
        return;
    }

    /* Force a re-seed if we have generated too many bytes so far */
    if (state->counter >= ASCON_RANDOM_RESEED_LIMIT)
        ascon_random_reseed(state);

    /* Squeeze data out of the PRNG state */
    ascon_xof_squeeze(&(state->xof), out, outlen);
    if (outlen < ASCON_RANDOM_RESEED_LIMIT)
        state->counter += outlen;
    else
        state->counter = ASCON_RANDOM_RESEED_LIMIT;

    /* Re-key the PRNG to enforce forward security */
    ascon_random_rekey(state);
}

int ascon_random_reseed(ascon_random_state_t *state)
{
    if (state) {
        /* Generate a new system seed and absorb it into the state */
        unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
        int ok = ascon_trng_generate(seed, sizeof(seed));
        ascon_xof_absorb(&(state->xof), seed, sizeof(seed));
        ascon_clean(seed, sizeof(seed));

        /* Reset the re-seed counter to 0 */
        state->counter = 0;

        /* Re-key the PRNG to enforce forward security */
        ascon_random_rekey(state);
        return ok;
    }
    return 0;
}

void ascon_random_feed
    (ascon_random_state_t *state, const unsigned char *entropy, size_t size)
{
    if (state) {
        ascon_xof_absorb(&(state->xof), entropy, size);
        ascon_xof_pad(&(state->xof));
        ascon_random_rekey(state);
    }
}

int ascon_random_save_seed
    (ascon_random_state_t *state, const ascon_storage_t *storage)
{
    unsigned char seed[ASCON_RANDOM_SAVED_SEED_SIZE];
    int written;

    /* Validate the parameters */
    if (!state || !storage || storage->size < ASCON_RANDOM_SAVED_SEED_SIZE)
        return -1;

    /* Generate some output from the generator to save as the seed */
    ascon_random_fetch(state, seed, sizeof(seed));

    /* Save the seed in the provided non-volatile storage region */
    written = (*(storage->write))
        (storage, 0, seed, sizeof(seed), (storage->erase_size != 0));
    ascon_clean(seed, sizeof(seed));
    return written == ASCON_RANDOM_SAVED_SEED_SIZE;
}

int ascon_random_load_seed
    (ascon_random_state_t *state, const ascon_storage_t *storage)
{
    unsigned char seed[ASCON_RANDOM_SAVED_SEED_SIZE];
    int read;

    /* Validate the parameters */
    if (!state || !storage || storage->size < ASCON_RANDOM_SAVED_SEED_SIZE)
        return -1;

    /* Load the seed from the non-volatile storage region */
    read = (*(storage->read))(storage, 0, seed, sizeof(seed));

    /* Feed the seed into the pseudorandom number generator state */
    if (read == ASCON_RANDOM_SAVED_SEED_SIZE)
        ascon_random_feed(state, seed, sizeof(seed));

    /* Load some new data from the system TRNG to mix things up a bit */
    ascon_random_reseed(state);

    /* Generate and save a new seed.  This ensures that if power is lost
     * before the next explicit save, we won't restart in the same state. */
    ascon_random_fetch(state, seed, sizeof(seed));
    (*(storage->write))
        (storage, 0, seed, sizeof(seed), (storage->erase_size != 0));

    /* Clean up and exit */
    ascon_clean(seed, sizeof(seed));
    return read == ASCON_RANDOM_SAVED_SEED_SIZE;
}
