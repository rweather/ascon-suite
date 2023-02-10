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

#include "ascon-trng.h"
#include "core/ascon-select-backend.h"
#include <ascon/utility.h>

/* Used on platforms that don't have a simple "get random word" primitive.
 * The TRNG calls ascon_trng_generate() to get a seed and then expands it
 * to arbitrary amounts of random data using a PRNG as a "mixer". */

#if defined(ASCON_TRNG_MIXER)

int ascon_trng_init(ascon_trng_state_t *state)
{
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int ok = ascon_trng_generate(seed, sizeof(seed));
    ascon_init(&(state->prng));
    ascon_overwrite_bytes
        (&(state->prng), seed, 40 - sizeof(seed), sizeof(seed));
    ascon_permute12(&(state->prng));
    ascon_release(&(state->prng));
    ascon_clean(seed, sizeof(seed));
    state->posn = 0;
    return ok;
}

void ascon_trng_free(ascon_trng_state_t *state)
{
    ascon_acquire(&(state->prng));
    ascon_free(&(state->prng));
}

uint32_t ascon_trng_generate_32(ascon_trng_state_t *state)
{
    uint32_t x;
    ascon_acquire(&(state->prng));
    if ((state->posn + sizeof(uint32_t)) > ASCON_TRNG_MIXER_RATE) {
        ascon_permute6(&(state->prng));
        state->posn = 0;
    }
#if defined(ASCON_BACKEND_SLICED32) || defined(ASCON_BACKEND_SLICED64) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    /* Pull a word directly out of the state.  It doesn't matter if the
     * word is bit-sliced or not because any bit is as good as any other. */
    x = state->prng.W[state->posn / sizeof(uint32_t)];
#else
    ascon_extract_bytes
        (&(state->prng), (unsigned char *)&x, state->posn, sizeof(x));
#endif
    ascon_release(&(state->prng));
    state->posn += sizeof(uint32_t);
    return x;
}

uint64_t ascon_trng_generate_64(ascon_trng_state_t *state)
{
    uint64_t x;
    ascon_acquire(&(state->prng));
    if ((state->posn + sizeof(uint64_t)) > ASCON_TRNG_MIXER_RATE ||
            (state->posn % 8U) != 0) {
        ascon_permute6(&(state->prng));
        state->posn = 0;
    }
#if defined(ASCON_BACKEND_SLICED32) || defined(ASCON_BACKEND_SLICED64) || \
        defined(ASCON_BACKEND_DIRECT_XOR)
    /* Pull a word directly out of the state.  It doesn't matter if the
     * word is bit-sliced or not because any bit is as good as any other. */
    x = state->prng.S[state->posn / sizeof(uint64_t)];
#else
    ascon_extract_bytes
        (&(state->prng), (unsigned char *)&x, state->posn, sizeof(x));
#endif
    ascon_release(&(state->prng));
    state->posn += sizeof(uint64_t);
    return x;
}

int ascon_trng_reseed(ascon_trng_state_t *state)
{
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int ok = ascon_trng_generate(seed, sizeof(seed));
    ascon_acquire(&(state->prng));
    ascon_add_bytes(&(state->prng), seed, 40 - sizeof(seed), sizeof(seed));
    ascon_overwrite_with_zeroes(&(state->prng), 0, 8); /* Forward security */
    ascon_permute12(&(state->prng));
    ascon_release(&(state->prng));
    ascon_clean(seed, sizeof(seed));
    state->posn = 0;
    return ok;
}

#endif /* ASCON_TRNG_MIXER */
