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
#include <string.h>

#if defined(ASCON_TRNG_STM32_ENABLED)

extern RNG_HandleTypeDef ASCON_TRNG_STM32;

int ascon_trng_generate(unsigned char *out, size_t outlen)
{
    uint32_t x;
    int ok = 1;
    while (outlen >= sizeof(x)) {
        if (HAL_RNG_GenerateRandomNumber(&ASCON_TRNG_STM32, &x) != HAL_OK) {
            x = 0xABADBEEF; /* This is a problem! */
            ok = 0;
        }
        memcpy(out, &x, sizeof(x));
        out += sizeof(x);
        outlen -= sizeof(x);
    }
    if (outlen > 0) {
        if (HAL_RNG_GenerateRandomNumber(&ASCON_TRNG_STM32, &x) != HAL_OK) {
            x = 0xABADBEEF; /* This is a problem! */
            ok = 0;
        }
        memcpy(out, &x, outlen);
    }
    return ok;
}

int ascon_trng_init(ascon_trng_state_t *state)
{
    /* Test that the TRNG works by generating a single word */
    uint32_t x;
    return HAL_RNG_GenerateRandomNumber(&ASCON_TRNG_STM32, &x) == HAL_OK;
}

void ascon_trng_free(ascon_trng_state_t *state)
{
    (void)state;
}

uint32_t ascon_trng_generate_32(ascon_trng_state_t *state)
{
    uint32_t x;
    (void)state;
    if (HAL_RNG_GenerateRandomNumber(&ASCON_TRNG_STM32, &x) == HAL_OK)
        return x;
    else
        return 0xABADBEEFU; /* This is a problem! */
}

uint64_t ascon_trng_generate_64(ascon_trng_state_t *state)
{
    return ((uint64_t)ascon_trng_generate_32(state)) |
          (((uint64_t)ascon_trng_generate_32(state)) << 32);
}

int ascon_trng_reseed(ascon_trng_state_t *state)
{
    return ascon_trng_init(state);
}

#endif /* ASCON_TRNG_STM32_ENABLED */
