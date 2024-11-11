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
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

#if ASCON_MASKED_MAX_SHARES >= 4

/* Test vectors generated with the reference code */
static uint8_t const ascon_input[40] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};
static uint8_t const ascon_output_12[40] = {
    /* Output after 12 rounds */
    0x79, 0x7b, 0x2e, 0xcb, 0x04, 0x34, 0xb0, 0x94,
    0x7f, 0x23, 0x67, 0x05, 0xe8, 0xa5, 0x22, 0x5a,
    0x3e, 0xd8, 0x4b, 0x50, 0x2f, 0x5a, 0xfb, 0xc8,
    0x86, 0x43, 0x15, 0xd5, 0x8a, 0xc0, 0x16, 0xdc,
    0x76, 0x1b, 0x7a, 0x83, 0x67, 0xad, 0x82, 0x88
};
static uint8_t const ascon_output_8[40] = {
    /* Output after 8 rounds */
    0x5e, 0x07, 0xca, 0xf8, 0x0e, 0x7c, 0xe0, 0xc6,
    0x70, 0x3a, 0x05, 0x3d, 0xac, 0x2a, 0x9d, 0x56,
    0x2d, 0x91, 0x4f, 0x4b, 0xdd, 0xa4, 0xdf, 0x4e,
    0x95, 0x4e, 0xc9, 0xa2, 0x2d, 0x19, 0x7e, 0xfd,
    0x1b, 0x8d, 0x85, 0xae, 0xc2, 0x75, 0x43, 0x24
};

/* Helper functions to load and unload the entire state */

static void ascon_x4_add_bytes_all
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    ascon_masked_word_t word;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x4_load(&word, data + offset, trng);
        ascon_masked_word_x4_xor(&(state->M[offset / 8]), &word);
    }
}

static void ascon_x4_add_bytes_all_load32
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    ascon_masked_word_t word;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x4_load_32
            (&word, data + offset, data + offset + 4, trng);
        ascon_masked_word_x4_xor(&(state->M[offset / 8]), &word);
    }
}

static void ascon_x4_overwrite_bytes_all
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8)
        ascon_masked_word_x4_load(&(state->M[offset / 8]), data + offset, trng);
}

static void ascon_x4_extract_bytes_all
    (const ascon_masked_state_t *state, uint8_t *data)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8)
        ascon_masked_word_x4_store(data + offset, &(state->M[offset / 8]));
}

static void ascon_x3_add_bytes_all
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    ascon_masked_word_t word;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x3_load(&word, data + offset, trng);
        ascon_masked_word_x3_xor(&(state->M[offset / 8]), &word);
    }
}

static void ascon_x3_extract_bytes_all
    (const ascon_masked_state_t *state, uint8_t *data)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8)
        ascon_masked_word_x3_store(data + offset, &(state->M[offset / 8]));
}

static void ascon_x2_add_bytes_all
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    ascon_masked_word_t word;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x2_load(&word, data + offset, trng);
        ascon_masked_word_x2_xor(&(state->M[offset / 8]), &word);
    }
}

static void ascon_x2_extract_bytes_all
    (const ascon_masked_state_t *state, uint8_t *data)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x2_store
            (data + offset, &(state->M[offset / 8]));
    }
}

/* End of helper functions */

void test_ascon_permutation_x4(void)
{
    ascon_masked_state_t state;
    ascon_state_t state_x1;
    ascon_masked_state_t state_x2;
    ascon_masked_state_t state_x3;
    ascon_masked_state_t state_x4;
    ascon_trng_state_t trng;
    ascon_masked_word_t word;
    ascon_masked_word_t word2;
    uint64_t preserve[3];
    uint8_t buffer[40];
    unsigned offset, posn;
    int ok;

    ascon_trng_init(&trng);
    preserve[0] = ascon_trng_generate_64(&trng);
    preserve[1] = ascon_trng_generate_64(&trng);
    preserve[2] = ascon_trng_generate_64(&trng);

    printf("12 Rounds ... ");
    fflush(stdout);
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_add_bytes_all(&state, ascon_input, &trng);
    ascon_x4_permute(&state, 0, preserve);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("8 Rounds ... ");
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_overwrite_bytes_all(&state, ascon_input, &trng);
    ascon_x4_permute(&state, 4, preserve);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    fflush(stdout);
    if (memcmp(buffer, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Init ... ");
    fflush(stdout);
    memset(&state, 0xAA, sizeof(state));
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ok = 1;
    for (posn = 0; posn < 40; ++posn) {
        if (buffer[posn] != 0)
            ok = 0;
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Free ... ");
    fflush(stdout);
    ascon_masked_state_init(&state);
    ascon_x4_add_bytes_all(&state, ascon_input, &trng);
    ascon_x4_randomize(&state, &trng);
    ascon_masked_state_free(&state);
    ok = 1;
    for (posn = 0; posn < sizeof(state); ++posn) {
        /* Check that free sets everything in the state to zero */
        if (((const unsigned char *)&state)[posn] != 0)
            ok = 0;
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Add Words ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_randomize(&state, &trng);
        ascon_x4_add_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x4_load(&word, ascon_input, &trng);
        ascon_masked_word_x4_xor(&(state.M[offset / 8]), &word);
        ascon_x4_randomize(&state, &trng);
        ascon_x4_extract_bytes_all(&state, buffer);
        ascon_masked_state_free(&state);
        for (posn = 0; posn < 40; ++posn) {
            uint8_t value = ascon_output_8[posn];
            if (posn >= offset && posn < (offset + 8))
                value ^= ascon_input[posn - offset];
            if (value != buffer[posn])
                ok = 0;
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Overwrite Words ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_randomize(&state, &trng);
        ascon_x4_overwrite_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x4_load(&word, ascon_input, &trng);
        state.M[offset / 8] = word;
        ascon_x4_extract_bytes_all(&state, buffer);
        ascon_masked_state_free(&state);
        for (posn = 0; posn < 40; ++posn) {
            uint8_t value = ascon_output_8[posn];
            if (posn >= offset && posn < (offset + 8))
                value = ascon_input[posn - offset];
            if (value != buffer[posn])
                ok = 0;
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Overwrite With Zeroes ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_overwrite_bytes_all(&state, ascon_output_12, &trng);
        ascon_masked_word_x4_zero(&word, &trng);
        state.M[offset / 8] = word;
        ascon_x4_extract_bytes_all(&state, buffer);
        ascon_masked_state_free(&state);
        for (posn = 0; posn < 40; ++posn) {
            uint8_t value = ascon_output_12[posn];
            if (posn >= offset && posn < (offset + 8))
                value = 0;
            if (value != buffer[posn])
                ok = 0;
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Extract Words ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_randomize(&state, &trng);
        ascon_x4_add_bytes_all_load32(&state, ascon_output_8, &trng);
        word = state.M[offset / 8];
        ascon_masked_word_x4_store(buffer, &word);
        ascon_masked_word_x4_randomize(&word, &word, &trng);
        ascon_masked_word_x4_store(buffer + 8, &word);
        ascon_masked_state_free(&state);
        for (posn = 0; posn < 8; ++posn) {
            if (buffer[posn] != ascon_output_8[posn + offset])
                ok = 0;
            if (buffer[posn + 8] != ascon_output_8[posn + offset])
                ok = 0;
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Copy From ASCON-x1 ... ");
    fflush(stdout);
    ascon_init(&state_x1);
    ascon_add_bytes(&state_x1, ascon_output_8, 0, sizeof(ascon_output_8));
    ascon_release(&state_x1);
    ascon_x4_copy_from_x1(&state, &state_x1, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_acquire(&state_x1);
    ascon_free(&state_x1);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Copy From ASCON-x2 ... ");
    fflush(stdout);
    ascon_masked_state_init(&state_x2);
    ascon_x2_randomize(&state_x2, &trng);
    ascon_x2_add_bytes_all(&state_x2, ascon_output_8, &trng);
    ascon_x4_copy_from_x2(&state, &state_x2, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x2);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Copy From ASCON-x3 ... ");
    fflush(stdout);
    ascon_masked_state_init(&state_x3);
    ascon_x3_randomize(&state_x3, &trng);
    ascon_x3_add_bytes_all(&state_x3, ascon_output_8, &trng);
    ascon_x4_copy_from_x3(&state, &state_x3, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x3);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Copy From ASCON-x4 ... ");
    fflush(stdout);
    ascon_masked_state_init(&state_x4);
    ascon_x4_randomize(&state_x4, &trng);
    ascon_x3_add_bytes_all(&state_x4, ascon_output_12, &trng);
    ascon_x4_copy_from_x4(&state, &state_x4, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x4);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Copy To ASCON-x1 ... ");
    fflush(stdout);
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x4_copy_to_x1(&state_x1, &state);
    ascon_extract_bytes(&state_x1, buffer, 0, 40);
    ascon_free(&state_x1);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Copy To ASCON-x2 ... ");
    fflush(stdout);
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x2_copy_from_x4(&state_x2, &state, &trng);
    ascon_x2_extract_bytes_all(&state_x2, buffer);
    ascon_masked_state_free(&state_x2);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Copy To ASCON-x3 ... ");
    fflush(stdout);
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x3_copy_from_x4(&state_x3, &state, &trng);
    ascon_x3_extract_bytes_all(&state_x3, buffer);
    ascon_masked_state_free(&state_x3);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Convert Masked Words ... ");
    fflush(stdout);
    ok = 1;
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x2_load(&word, ascon_output_12, &trng);
    ascon_masked_word_x4_from_x2(&word2, &word, &trng);
    ascon_masked_word_x4_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_12, 8) != 0)
        ok = 0;
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x3_load(&word, ascon_output_8, &trng);
    ascon_masked_word_x4_from_x3(&word2, &word, &trng);
    ascon_masked_word_x4_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_8, 8) != 0)
        ok = 0;
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Replace Word ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x4_load(&word, ascon_output_8, &trng);
        ascon_masked_word_x4_load(&word2, ascon_output_12, &trng);
        ascon_masked_word_x4_replace(&word, &word2, offset);
        ascon_masked_word_x4_store(buffer, &word);
        for (posn = 0; posn < 8; ++posn) {
            uint8_t value;
            if (posn < offset)
                value = ascon_output_12[posn];
            else
                value = ascon_output_8[posn];
            if (buffer[posn] != value)
                ok = 0;
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Partial Words ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x4_load_partial(&word, ascon_output_8, offset, &trng);
        ascon_masked_word_x4_store(buffer, &word);
        for (posn = 0; posn < 8; ++posn) {
            uint8_t value;
            if (posn < offset)
                value = ascon_output_8[posn];
            else
                value = 0;
            if (buffer[posn] != value)
                ok = 0;
        }
        ascon_masked_word_x4_load(&word, ascon_output_12, &trng);
        memcpy(buffer, ascon_output_8, sizeof(ascon_output_8));
        ascon_masked_word_x4_store_partial(buffer, offset, &word);
        for (posn = 0; posn < 8; ++posn) {
            uint8_t value;
            if (posn < offset)
                value = ascon_output_12[posn];
            else
                value = ascon_output_8[posn];
            if (buffer[posn] != value)
                ok = 0;
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    ascon_trng_free(&trng);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    test_ascon_permutation_x4();

    return test_exit_result;
}

#else /* ASCON_MASKED_MAX_SHARES < 4 */

int main(int argc, char *argv[])
{
    /* Nothing to test if the library does not support 4 or more shares */
    (void)argc;
    (void)argv;
    return 0;
}

#endif /* ASCON_MASKED_MAX_SHARES < 4 */
