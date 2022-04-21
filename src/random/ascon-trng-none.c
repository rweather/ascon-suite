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

#include "ascon-trng.h"
#include <ascon/utility.h>
#include <string.h>

#if defined(ASCON_TRNG_NONE)

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#if defined(ARDUINO)
#include <Arduino.h>
#endif
#if defined(HAVE_TIME_H)
#include <time.h>
#endif
#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif

#if !defined(ASCON_TRNG_MIXER)
#error "Mixer is required if there is no known TRNG on the system"
#endif

int ascon_trng_get_bytes(unsigned char *out, size_t outlen) __attribute__((weak));
int ascon_trng_get_bytes_is_good(void) __attribute__((weak));

/**
 * \brief Escape hatch that allows applications to provide their
 * own interface to the system TRNG when the library does not know
 * how to generate random bytes on its own.
 *
 * \param out Buffer to fill with random bytes.
 * \param outlen Number of bytes to provide.
 *
 * \return Non-zero if the application provided the bytes or zero
 * if the application does not know how to generate random bytes.
 */
int ascon_trng_get_bytes(unsigned char *out, size_t outlen)
{
    (void)out;
    (void)outlen;
    return 0;
}

/**
 * \brief Escape hatch that declares that the application's output
 * from ascon_trng_get_bytes() is good and there is no need to run a
 * global PRNG to mix up the data.
 *
 * \return Non-zero if the data from ascon_trng_get_bytes() is good.
 *
 * This escape hatch should only be used if the application knows
 * that it is getting random data from a good source.
 */
int ascon_trng_get_bytes_is_good(void)
{
    return 0;
}

/*
 * Global PRNG that collects what little entropy we can get from timers.
 *
 * Note that this is not thread-safe in the current implementation.
 * If the application returns non-zero from ascon_trng_get_bytes_is_good()
 * then the API will become thread-safe.
 */
static ascon_state_t global_prng;
static int volatile global_prng_initialized = 0;

#if defined(HAVE_CLOCK_GETTIME) || defined(HAVE_GETTIMEOFDAY) || \
    defined(HAVE_TIME)

static void ascon_trng_add_timespec
    (ascon_state_t *state, unsigned offset, uint32_t sec, uint32_t partial_sec)
{
    uint32_t x[2];
    x[0] = sec;
    x[1] = partial_sec;
    ascon_add_bytes(state, (unsigned char *)x, offset, sizeof(x));
    ascon_clean(x, sizeof(x));
}

#endif

/* Add the current time to the PRNG state and then re-key the state */
static void ascon_trng_add_time(ascon_state_t *state)
{
#if defined(ARDUINO)
    /* Add the current Arduino time as a seed to provide some extra jitter */
    {
        uint32_t x[2];
        x[0] = (uint32_t)millis();
        x[1] = (uint32_t)micros();
        ascon_add_bytes(state, (const unsigned char *)x, 0, sizeof(x));
    }
#elif defined(USE_HAL_DRIVER)
    /* Mix in the STM32 millisecond tick counter for some extra jitter */
    {
        uint32_t x = HAL_GetTick();
        ascon_add_bytes(state, (const unsigned char *)&x, 0, sizeof(x));
    }
#elif defined(HAVE_CLOCK_GETTIME)
    /* Mix in the monotonic and real times in nanoseconds */
    {
        struct timespec ts;
#if defined(CLOCK_MONOTONIC)
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ascon_trng_add_timespec
            (state, 0, (uint32_t)(ts.tv_sec), (uint32_t)(ts.tv_nsec));
#endif
        clock_gettime(CLOCK_REALTIME, &ts);
        ascon_trng_add_timespec
            (state, 8, (uint32_t)(ts.tv_sec), (uint32_t)(ts.tv_nsec));
        ascon_clean(&ts, sizeof(ts));
    }
#elif defined(HAVE_GETTIMEOFDAY)
    /* Mix in the current time of day in microseconds */
    {
        struct timeval tv;
        gettimeofday(&tv, 0);
        ascon_trng_add_timespec
            (state, 0, (uint32_t)(tv.tv_sec), (uint32_t)(tv.tv_usec));
        ascon_clean(&tv, sizeof(tv));
    }
#elif defined(HAVE_TIME)
    /* Mix in the current time of day in seconds (very little jitter) */
    ascon_trng_add_timespec(state, 0, (uint32_t)time(0), 0);
#endif

    /* Permute the state for 6 rounds */
    ascon_permute6(state);

    /* Zero out part of the state to provide forward security */
    ascon_overwrite_with_zeroes(state, 0, 8);

    /* Permute the state for another 6 rounds */
    ascon_permute6(state);
}

/* Squeeze data out of a PRNG */
static void ascon_trng_squeeze
    (ascon_state_t *state, unsigned char *out, size_t outlen)
{
    while (outlen >= 8U) {
        ascon_extract_bytes(state, out, 0, 8);
        ascon_permute6(state);
        out += 8;
        outlen -= 8;
    }
    if (outlen > 0U) {
        ascon_extract_bytes(state, out, 0, outlen);
        ascon_permute6(state);
    }
}

/* Make sure that the global PRNG is initialized and seeded */
static int ascon_trng_global_init(unsigned char seed[ASCON_SYSTEM_SEED_SIZE])
{
    int ok = 0;

    /* Acquire access to the global PRNG object */
    if (!global_prng_initialized) {
        global_prng_initialized = 1;
        ascon_init(&global_prng);
    } else {
        ascon_acquire(&global_prng);
    }

    /* See if the application is willing to give us TRNG data */
    if (ascon_trng_get_bytes(seed, ASCON_SYSTEM_SEED_SIZE)) {
        ascon_add_bytes(&global_prng, seed, 8, ASCON_SYSTEM_SEED_SIZE);
        ok = 1;
    }

    /* Add the current time to the global PRNG and re-key */
    ascon_trng_add_time(&global_prng);
    return ok;
}

int ascon_trng_generate(unsigned char *out, size_t outlen)
{
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int ok

    /* If the application has declared ascon_trng_get_bytes() to be good,
     * then use it directly rather than run a global PRNG.  We fall through
     * if ascon_trng_get_bytes() subsequently fails anyway. */
    if (ascon_trng_get_bytes_is_good()) {
        ok = ascon_trng_get_bytes(out, outlen);
        if (ok)
            return 1;
    }

    /* Re-seed and squeeze some data out of the global PRNG */
    ok = ascon_trng_global_init(seed);
    ascon_trng_squeeze(&global_prng, out, outlen);

    /* Re-key the global PRNG after generating the bytes */
    ascon_overwrite_with_zeroes(&global_prng, 0, 8);
    ascon_permute6(&global_prng);
    ascon_release(&global_prng);
    ascon_clean(seed, sizeof(seed));
    return ok;
}

int ascon_trng_init(ascon_trng_state_t *state)
{
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int ok = 0;

    /* Try getting the seed from the application first if its data is good */
    if (ascon_trng_get_bytes_is_good()) {
        ok = ascon_trng_get_bytes(seed, sizeof(seed));
    }
    if (!ok) {
        /* Intialize and re-seed the global PRNG */
        ok = ascon_trng_global_init(seed);

        /* Squeeze out a seed value to use to initialize "state" */
        ascon_trng_squeeze(&global_prng, seed, sizeof(seed));

        /* Re-key the global PRNG to enforce forward security */
        ascon_overwrite_with_zeroes(&global_prng, 0, 8);
        ascon_permute6(&global_prng);
        ascon_release(&global_prng);
    }

    /* Set up the new TRNG state */
    ascon_init(&(state->prng));
    ascon_add_bytes(&(state->prng), seed, 40 - sizeof(seed), sizeof(seed));
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
    int ok = 0;

    /* If the application has declared ascon_trng_get_bytes() to be good,
     * then use it directly rather than run a global PRNG.  We fall through
     * if ascon_trng_get_bytes() subsequently fails anyway. */
    if (ascon_trng_get_bytes_is_good()) {
        ok = ascon_trng_get_bytes(seed, sizeof(seed));
    }
    if (!ok) {
        /* Get a new key for the local PRNG from the global PRNG */
        ok = ascon_trng_global_init(seed);
        ascon_trng_squeeze(&global_prng, seed, ASCON_SYSTEM_SEED_SIZE);

        /* Re-key the global PRNG */
        ascon_overwrite_with_zeroes(&global_prng, 0, 8);
        ascon_permute6(&global_prng);
        ascon_release(&global_prng);
    }

    /* Re-key the local PRNG with the seed data from the global PRNG */
    ascon_acquire(&(state->prng));
    ascon_add_bytes(&(state->prng), seed, 8, ASCON_SYSTEM_SEED_SIZE);
    ascon_permute6(&(state->prng));
    ascon_overwrite_with_zeroes(&(state->prng), 0, 8);
    ascon_permute6(&(state->prng));
    ascon_clean(seed, sizeof(seed));
    state->posn = 0;
    return ok;
}

#endif /* ASCON_TRNG_NONE */
