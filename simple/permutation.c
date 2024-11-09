/*
 * Copyright (C) 2024 Southern Storm Software, Pty Ltd.
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

#include "permutation.h"
#include <string.h>

/* Read a 64-bit little-endian value */
static uint64_t read_le64(const unsigned char *in)
{
    uint64_t result = in[7];
    result <<= 8;
    result |= in[6];
    result <<= 8;
    result |= in[5];
    result <<= 8;
    result |= in[4];
    result <<= 8;
    result |= in[3];
    result <<= 8;
    result |= in[2];
    result <<= 8;
    result |= in[1];
    result <<= 8;
    return result | in[0];
}

/* Write a 64-bit little-endian value */
static void write_le64(unsigned char *out, uint64_t in)
{
    out[0] = (uint8_t)in;
    out[1] = (uint8_t)(in >> 8);
    out[2] = (uint8_t)(in >> 16);
    out[3] = (uint8_t)(in >> 24);
    out[4] = (uint8_t)(in >> 32);
    out[5] = (uint8_t)(in >> 40);
    out[6] = (uint8_t)(in >> 48);
    out[7] = (uint8_t)(in >> 56);
}

/* Rotate a 64-bit value right */
static uint64_t rotate64(uint64_t x, uint8_t shift)
{
    return (x >> shift) | (x << (64 - shift));
}

void ascon_simple_init(ascon_simple_state_t *state)
{
    memset(state, 0, sizeof(ascon_simple_state_t));
}

void ascon_simple_init_iv(ascon_simple_state_t *state, uint64_t iv)
{
    ascon_simple_init(state);
    write_le64(state->B, iv);
}

void ascon_simple_permute(ascon_simple_state_t *state, uint8_t first_round)
{
    static uint64_t const RC[] = {
        0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3,
        0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
    };
    uint64_t x0, x1, x2, x3, x4;
    uint64_t t0, t1, t2, t3, t4;

    /* Read the initial state */
    x0 = read_le64(state->B);
    x1 = read_le64(state->B + 8);
    x2 = read_le64(state->B + 16);
    x3 = read_le64(state->B + 24);
    x4 = read_le64(state->B + 32);

    /* Perform all permutation rounds */
    for (; first_round < 16; ++first_round) {
        /* Add the round constant to the state */
        x2 ^= RC[first_round];

        /* Substitution layer */
        x0 ^= x4;   x4 ^= x3;   x2 ^= x1;
        t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4;
        t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0;
        x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0;
        x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2;

        /* Linear diffusion layer */
        x0 ^= rotate64(x0, 19) ^ rotate64(x0, 28);
        x1 ^= rotate64(x1, 61) ^ rotate64(x1, 39);
        x2 ^= rotate64(x2, 1)  ^ rotate64(x2, 6);
        x3 ^= rotate64(x3, 10) ^ rotate64(x3, 17);
        x4 ^= rotate64(x4, 7)  ^ rotate64(x4, 41);
    }

    /* Write the final state out */
    write_le64(state->B, x0);
    write_le64(state->B + 8,  x1);
    write_le64(state->B + 16, x2);
    write_le64(state->B + 24, x3);
    write_le64(state->B + 32, x4);
}

void ascon_simple_xor
    (unsigned char *dest, const unsigned char *src1,
     const unsigned char *src2, size_t len)
{
    while (len > 0) {
        *dest++ = *src1++ ^ *src2++;
        --len;
    }
}
