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

/* Use /dev/urandom if we don't have getrandom() or getentropy() */
#define RANDOM_DEVICE "/dev/urandom"

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
    return open(RANDOM_DEVICE, O_RDONLY);
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
        if (ret >= 0) {
            /* getentropy() returns 0 on success, getrandom() returns
             * the number of bytes read on success */
            return 1;
        } else {
            if (errno != EINTR && errno != EAGAIN) {
                /* getrandom() or getentropy() is broken; this is a problem */
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

#endif /* ASCON_TRNG_DEV_RANDOM */
