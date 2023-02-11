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
#include <string.h>

#if defined(ASCON_TRNG_ZEPHYR_CSRAND)

#include <zephyr/random/rand32.h>

int ascon_trng_generate(unsigned char *out, size_t outlen)
{
    /* Try to get random data from the Zephyr kernel */
    if (sys_csrand_get(out, outlen) == 0)
        return 1;

    /* Something went wrong in sys_csrand_get(); this is a problem! */
    memset(out, 0, outlen);
    return 0;
}

#elif defined(ASCON_TRNG_ZEPHYR_BTRAND)

#include <zephyr/bluetooth/crypto.h>

int ascon_trng_generate(unsigned char *out, size_t outlen)
{
    /* Try to get random data from the Bluetooth stack */
    if (bt_rand(out, outlen) == 0)
        return 1;

    /* Something went wrong in bt_rand(); this is a problem! */
    memset(out, 0, outlen);
    return 0;
}

#endif /* !ASCON_TRNG_ZEPHYR_CSRAND && !ASCON_TRNG_ZEPHYR_BTRAND */
