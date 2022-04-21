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

#define _GNU_SOURCE
#include "ascon-trng.h"
#include "core/ascon-select-backend.h"
#include <ascon/utility.h>

#if defined(ASCON_TRNG_DEV_RANDOM)

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#if defined(__linux__) || defined(HAVE_SYS_SYSCALL_H)
#include <sys/syscall.h>
#endif
#if defined(HAVE_SYS_RANDOM_H)
#include <sys/random.h>
#endif

/* We prefer /dev/urandom but non-Linux systems may not have that */
#define RANDOM_DEVICE "/dev/urandom"
#define RANDOM_DEVICE_BACKUP "/dev/random"

/* Determine if we have some kind of getrandom() or getentropy() function */
#if defined(HAVE_GETRANDOM)
#define ascon_getrandom(buf, size) getrandom((buf), (size), 0)
#elif defined(HAVE_GETENTROPY)
#define ascon_getrandom(buf, size) getentropy((buf), (size))
#elif defined(SYS_getrandom)
#define ascon_getrandom(buf, size) syscall(SYS_getrandom, (buf), (size), 0)
#endif

#if !defined(ascon_getrandom)
static int ascon_dev_random_open(void)
{
    int fd = open(RANDOM_DEVICE, O_RDONLY);
    if (fd < 0)
        fd = open(RANDOM_DEVICE_BACKUP, O_RDONLY);
    return fd;
}
#else
#define ascon_dev_random_open() -1
#endif

static int ascon_dev_random_read(int fd, unsigned char *out, size_t outlen)
{
#if defined(ascon_getrandom)
    /* Keep looping until we get some data or a permanent error. */
    (void)fd;
    for (;;) {
        int ret = ascon_getrandom(out, outlen);
        if (ret == (int)outlen) {
            return 1;
        } else if (ret < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                /* getrandom() is broken; this is a problem */
                memset(out, 0, outlen);
                break;
            }
        }
    }
    return 0;
#else
    if (fd >= 0) {
        /* Keep looping until we get some data or a permanent error. */
        for (;;) {
            int ret = read(fd, out, outlen);
            if (ret == (int)outlen) {
                return 1;
            } else if (ret < 0) {
                if (errno != EINTR && errno != EAGAIN)
                    break;
            }
        }
    }
    /* /dev/urandom is broken or not open; this is a problem */
    memset(out, 0, outlen);
    return 0;
#endif
}

int ascon_trng_generate(unsigned char *out, size_t outlen)
{
#if defined(ascon_getrandom)
    return ascon_dev_random_read(-1, out, outlen);
#else
    int fd = ascon_dev_random_open();
    int ok = ascon_dev_random_read(fd, out, outlen);
    if (fd >= 0)
        close(fd);
    return ok;
#endif
}

int ascon_trng_init(ascon_trng_state_t *state)
{
#if defined(ASCON_TRNG_MIXER)
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int fd = ascon_dev_random_open();
    int ok = ascon_dev_random_read(fd, seed, sizeof(seed));
    if (fd >= 0)
        close(fd);
    ascon_init(&(state->prng));
    ascon_overwrite_bytes
        (&(state->prng), seed, 40 - sizeof(seed), sizeof(seed));
    ascon_permute12(&(state->prng));
    ascon_release(&(state->prng));
    ascon_clean(seed, sizeof(seed));
    state->posn = 0;
    return ok;
#else
    /* Assume that we have "RDRAND" and that it always works */
    (void)state;
    return 1;
#endif
}

void ascon_trng_free(ascon_trng_state_t *state)
{
#if defined(ASCON_TRNG_MIXER)
    ascon_acquire(&(state->prng));
    ascon_free(&(state->prng));
#else
    (void)state;
#endif
}

uint32_t ascon_trng_generate_32(ascon_trng_state_t *state)
{
#if defined(ASCON_TRNG_X86_64_RDRAND)
    return (uint32_t)ascon_trng_generate_64(state);
#else
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
#endif
}

uint64_t ascon_trng_generate_64(ascon_trng_state_t *state)
{
#if defined(ASCON_TRNG_X86_64_RDRAND)
    /* RDRAND instruction on x86-64 platforms for fast mask generation */
    uint64_t temp = 0;
    uint8_t ok = 0;
    do {
        __asm__ __volatile__ (
            ".byte 0x48,0x0f,0xc7,0xf0 ; setc %1"
            : "=a"(temp), "=q"(ok) :: "cc"
        );
    } while (!ok);
    (void)state;
    return temp;
#else
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
#endif
}

int ascon_trng_reseed(ascon_trng_state_t *state)
{
#if defined(ASCON_TRNG_MIXER)
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int fd = ascon_dev_random_open();
    int ok = ascon_dev_random_read(fd, seed, sizeof(seed));
    if (fd >= 0)
        close(fd);
    ascon_acquire(&(state->prng));
    ascon_add_bytes(&(state->prng), seed, 40 - sizeof(seed), sizeof(seed));
    ascon_overwrite_with_zeroes(&(state->prng), 0, 8); /* Forward security */
    ascon_permute12(&(state->prng));
    ascon_release(&(state->prng));
    ascon_clean(seed, sizeof(seed));
    state->posn = 0;
    return ok;
#else
    (void)state;
    return 1;
#endif
}

#endif /* ASCON_TRNG_DEV_RANDOM */
