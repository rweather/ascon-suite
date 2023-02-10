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

#warning "No system random number source found"
#if !defined(ASCON_TRNG_MIXER)
#error "Mixer is required if there is no known TRNG on the system"
#endif

int ascon_trng_get_bytes(unsigned char *out, size_t outlen) __attribute__((weak));

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

/* Try to make the global_prng state thread-safe */
#if defined(HAVE_THREAD_KEYWORD)
#define THREAD_LOCAL __thread
#elif defined(HAVE_THREAD_LOCAL_KEYWORD)
#define THREAD_LOCAL _Thread_local
#else
#define THREAD_LOCAL
#endif

/*
 * Global PRNG that collects what little entropy we can get from timers.
 */
static THREAD_LOCAL ascon_state_t global_prng;
static THREAD_LOCAL int volatile global_prng_initialized = 0;

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
    int ok;

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

#endif /* ASCON_TRNG_NONE */
