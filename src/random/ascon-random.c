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

int ascon_random(unsigned char *out, size_t outlen)
{
    ascon_xof_state_t xof;
    unsigned char seed[ASCON_SYSTEM_SEED_SIZE];
    int ok = ascon_trng_generate(seed, sizeof(seed));
    ascon_xof_init_fixed(&xof, outlen);
    ascon_xof_absorb(&xof, seed, sizeof(seed));
    ascon_xof_squeeze(&xof, out, outlen);
    ascon_xof_free(&xof);
    ascon_clean(seed, sizeof(seed));
    return ok ? 1 : 0;
}
