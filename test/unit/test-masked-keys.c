/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
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

#include "masking/ascon-masked-state.h"
#include <ascon/random.h>
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

static void ascon_x4_extract_bytes_all
    (const ascon_masked_state_t *state, uint8_t *data)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8)
        ascon_masked_word_x4_store(data + offset, &(state->M[offset / 8]));
}

int main(int argc, char *argv[])
{
    static unsigned char const zeroes[20] = {0};
    ascon_trng_state_t trng;
    unsigned char key_128[16];
    unsigned char key_160[20];
    unsigned char key_128_out[16];
    unsigned char key_160_out[20];
    ascon_masked_key_128_t masked_128;
    ascon_masked_key_160_t masked_160;
    ascon_state_t state_x1;
    ascon_masked_state_t state_x4;
    unsigned char state_x1_out[40];
    unsigned char state_x4_out[40];
    uint64_t preserve[3];
    int ok;

    (void)argc;
    (void)argv;

    ascon_random(key_128, sizeof(key_128));
    ascon_random(key_160, sizeof(key_160));
    ascon_trng_init(&trng);

    ok = 1;
    printf("Mask 128-bit key ... ");
    fflush(stdout);
    ascon_masked_key_128_init(&masked_128, key_128);
    memset(key_128_out, 0xAA, sizeof(key_128_out));
    ascon_masked_key_128_extract(&masked_128, key_128_out);
    if (memcmp(key_128_out, key_128, sizeof(key_128)) != 0)
        ok = 0;
    ascon_masked_key_128_randomize(&masked_128);
    memset(key_128_out, 0xAA, sizeof(key_128_out));
    ascon_masked_key_128_extract(&masked_128, key_128_out);
    if (memcmp(key_128_out, key_128, sizeof(key_128)) != 0)
        ok = 0;
    ascon_masked_key_128_randomize_with_trng(&masked_128, &trng);
    memset(key_128_out, 0xAA, sizeof(key_128_out));
    ascon_masked_key_128_extract(&masked_128, key_128_out);
    if (memcmp(key_128_out, key_128, sizeof(key_128)) != 0)
        ok = 0;
    ascon_masked_key_128_free(&masked_128);
    ascon_masked_key_128_extract(&masked_128, key_128_out);
    if (memcmp(key_128_out, zeroes, sizeof(key_128)) != 0)
        ok = 0;
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    ok = 1;
    printf("Mask 160-bit key ... ");
    fflush(stdout);
    ascon_masked_key_160_init(&masked_160, key_160);
    memset(key_160_out, 0xAA, sizeof(key_160_out));
    ascon_masked_key_160_extract(&masked_160, key_160_out);
    if (memcmp(key_160_out, key_160, sizeof(key_160)) != 0)
        ok = 0;
    ascon_masked_key_160_randomize(&masked_160);
    memset(key_160_out, 0xAA, sizeof(key_160_out));
    ascon_masked_key_160_extract(&masked_160, key_160_out);
    if (memcmp(key_160_out, key_160, sizeof(key_160)) != 0)
        ok = 0;
    ascon_masked_key_160_randomize_with_trng(&masked_160, &trng);
    memset(key_160_out, 0xAA, sizeof(key_160_out));
    ascon_masked_key_160_extract(&masked_160, key_160_out);
    if (memcmp(key_160_out, key_160, sizeof(key_160)) != 0)
        ok = 0;
    ascon_masked_key_160_free(&masked_160);
    ascon_masked_key_160_extract(&masked_160, key_160_out);
    if (memcmp(key_160_out, zeroes, sizeof(key_160)) != 0)
        ok = 0;
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    /* Note: Keys that are masked with 2 and 3 shares can be absorbed
     * into a x4 state because the extra words are zero.  This makes any
     * 2 or 3 share key into a valid 4 share key. */

    /* ASCON-128 and ASCON-128a keys are initially absorbed at offset 8 */
    printf("Use 128-bit key at offset 8 ... ");
    fflush(stdout);
    ascon_masked_key_128_init(&masked_128, key_128);
    ascon_init(&state_x1);
    ascon_add_bytes(&state_x1, key_128, 8, sizeof(key_128));
    ascon_permute(&state_x1, 0);
    ascon_extract_bytes(&state_x1, state_x1_out, 0, 40);
    ascon_free(&state_x1);
    ascon_masked_state_init(&state_x4);
    ascon_x4_randomize(&state_x4, &trng);
    ascon_masked_word_x4_xor(&(state_x4.M[1]), &(masked_128.k[0]));
    ascon_masked_word_x4_xor(&(state_x4.M[2]), &(masked_128.k[1]));
    preserve[0] = ascon_trng_generate_64(&trng);
    preserve[1] = ascon_trng_generate_64(&trng);
    preserve[2] = ascon_trng_generate_64(&trng);
    ascon_x4_permute(&state_x4, 0, preserve);
    ascon_x4_extract_bytes_all(&state_x4, state_x4_out);
    ascon_masked_key_128_free(&masked_128);
    ascon_masked_state_free(&state_x4);
    if (memcmp(state_x4_out, state_x1_out, sizeof(state_x1_out)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    /* ASCON-80pq keys are absorbed at offset 4 initially and then
     * offset 8 during tag generation */
    printf("Use 160-bit key at offset 4 ... ");
    fflush(stdout);
    ascon_masked_key_160_init(&masked_160, key_160);
    ascon_init(&state_x1);
    ascon_add_bytes(&state_x1, key_160, 4, sizeof(key_160));
    ascon_permute(&state_x1, 0);
    ascon_extract_bytes(&state_x1, state_x1_out, 0, 40);
    ascon_free(&state_x1);
    ascon_masked_state_init(&state_x4);
    ascon_x4_randomize(&state_x4, &trng);
    ascon_masked_word_x4_xor(&(state_x4.M[0]), &(masked_160.k[3]));
    ascon_masked_word_x4_xor(&(state_x4.M[1]), &(masked_160.k[4]));
    ascon_masked_word_x4_xor(&(state_x4.M[2]), &(masked_160.k[5]));
    preserve[0] = ascon_trng_generate_64(&trng);
    preserve[1] = ascon_trng_generate_64(&trng);
    preserve[2] = ascon_trng_generate_64(&trng);
    ascon_x4_permute(&state_x4, 0, preserve);
    ascon_x4_extract_bytes_all(&state_x4, state_x4_out);
    ascon_masked_key_160_free(&masked_160);
    ascon_masked_state_free(&state_x4);
    if (memcmp(state_x4_out, state_x1_out, sizeof(state_x1_out)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Use 160-bit key at offset 8 ... ");
    fflush(stdout);
    ascon_masked_key_160_init(&masked_160, key_160);
    ascon_init(&state_x1);
    ascon_add_bytes(&state_x1, key_160, 8, sizeof(key_160));
    ascon_permute(&state_x1, 0);
    ascon_extract_bytes(&state_x1, state_x1_out, 0, 40);
    ascon_free(&state_x1);
    ascon_masked_state_init(&state_x4);
    ascon_x4_randomize(&state_x4, &trng);
    ascon_masked_word_x4_xor(&(state_x4.M[1]), &(masked_160.k[0]));
    ascon_masked_word_x4_xor(&(state_x4.M[2]), &(masked_160.k[1]));
    ascon_masked_word_x4_xor(&(state_x4.M[3]), &(masked_160.k[2]));
    ascon_x4_permute(&state_x4, 0, preserve);
    ascon_x4_extract_bytes_all(&state_x4, state_x4_out);
    ascon_masked_key_160_free(&masked_160);
    ascon_masked_state_free(&state_x4);
    if (memcmp(state_x4_out, state_x1_out, sizeof(state_x1_out)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    ascon_trng_free(&trng);

    return test_exit_result;
}
