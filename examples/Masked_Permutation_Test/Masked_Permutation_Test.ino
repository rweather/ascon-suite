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

// This sketch tests the masked ASCON permutation to verify correctness.

#include <ASCON.h>
#include "masking/ascon-masked-state.h"

// Test vectors generated with the reference code.
static unsigned char const ascon_input[40] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};
static unsigned char const ascon_output_12[40] = {
    // Output after 12 rounds.
    0x06, 0x05, 0x87, 0xe2, 0xd4, 0x89, 0xdd, 0x43,
    0x1c, 0xc2, 0xb1, 0x7b, 0x0e, 0x3c, 0x17, 0x64,
    0x95, 0x73, 0x42, 0x53, 0x18, 0x44, 0xa6, 0x74,
    0x96, 0xb1, 0x71, 0x75, 0xb4, 0xcb, 0x68, 0x63,
    0x29, 0xb5, 0x12, 0xd6, 0x27, 0xd9, 0x06, 0xe5
};
static unsigned char const ascon_output_8[40] = {
    // Output after 8 rounds.
    0x83, 0x0d, 0x26, 0x0d, 0x33, 0x5f, 0x3b, 0xed,
    0xda, 0x0b, 0xba, 0x91, 0x7b, 0xcf, 0xca, 0xd7,
    0xdd, 0x0d, 0x88, 0xe7, 0xdc, 0xb5, 0xec, 0xd0,
    0x89, 0x2a, 0x02, 0x15, 0x1f, 0x95, 0x94, 0x6e,
    0x3a, 0x69, 0xcb, 0x3c, 0xf9, 0x82, 0xf6, 0xf7
};

/* Helper functions to load and unload the entire state */

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

static void ascon_x2_add_bytes_all_load32
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    ascon_masked_word_t word;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x2_load_32
            (&word, data + offset, data + offset + 4, trng);
        ascon_masked_word_x2_xor(&(state->M[offset / 8]), &word);
    }
}

static void ascon_x2_overwrite_bytes_all
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x2_load
            (&(state->M[offset / 8]), data + offset, trng);
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

#if ASCON_MASKED_MAX_SHARES >= 3

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

static void ascon_x3_add_bytes_all_load32
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    ascon_masked_word_t word;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_word_x3_load_32
            (&word, data + offset, data + offset + 4, trng);
        ascon_masked_word_x3_xor(&(state->M[offset / 8]), &word);
    }
}

static void ascon_x3_overwrite_bytes_all
    (ascon_masked_state_t *state, const uint8_t *data, ascon_trng_state_t *trng)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8)
        ascon_masked_word_x3_load(&(state->M[offset / 8]), data + offset, trng);
}

static void ascon_x3_extract_bytes_all
    (const ascon_masked_state_t *state, uint8_t *data)
{
    unsigned offset;
    for (offset = 0; offset < 40; offset += 8)
        ascon_masked_word_x3_store(data + offset, &(state->M[offset / 8]));
}

#endif

#if ASCON_MASKED_MAX_SHARES >= 4

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

#endif

/* End of helper functions */

ascon_trng_state_t trng;
ascon_masked_state_t state;
ascon_state_t state_x1;
ascon_masked_state_t state_x2;
ascon_masked_state_t state_x3;
ascon_masked_state_t state_x4;
ascon_masked_word_t word1;
ascon_masked_word_t word2;
unsigned char buffer[40];
uint64_t preserve[3];

void test_ascon_x2()
{
    unsigned offset, posn;
    int ok;

    Serial.print("ASCON-x2 12 Rounds ... ");
    preserve[0] = ascon_trng_generate_64(&trng);
    ascon_masked_state_init(&state);
    ascon_x2_overwrite_bytes_all(&state, ascon_input, &trng);
    ascon_x2_permute(&state, 0, preserve);
    ascon_x2_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 8 Rounds ... ");
    preserve[0] = ascon_trng_generate_64(&trng);
    ascon_masked_state_init(&state);
    ascon_x2_overwrite_bytes_all(&state, ascon_input, &trng);
    ascon_x2_permute(&state, 4, preserve);
    ascon_x2_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Init ... ");
    memset(&state, 0xAA, sizeof(state));
    ascon_masked_state_init(&state);
    ascon_x2_randomize(&state, &trng);
    ascon_x2_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ok = 1;
    for (posn = 0; posn < 40; ++posn) {
        if (buffer[posn] != 0)
            ok = 0;
    }
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Free ... ");
    ascon_masked_state_init(&state);
    ascon_x2_add_bytes_all(&state, ascon_input, &trng);
    ascon_x2_randomize(&state, &trng);
    ascon_masked_state_free(&state);
    ok = 1;
    for (posn = 0; posn < sizeof(state); ++posn) {
        /* Check that free sets everything in the state to zero */
        if (((const unsigned char *)&state)[posn] != 0)
            ok = 0;
    }
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Add Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x2_randomize(&state, &trng);
        ascon_x2_add_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x2_load(&word1, ascon_input, &trng);
        ascon_masked_word_x2_xor(&(state.M[offset / 8]), &word1);
        ascon_x2_randomize(&state, &trng);
        ascon_x2_extract_bytes_all(&state, buffer);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Overwrite Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x2_randomize(&state, &trng);
        ascon_x2_overwrite_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x2_load(&word1, ascon_input, &trng);
        state.M[offset / 8] = word1;
        ascon_x2_extract_bytes_all(&state, buffer);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Overwrite With Zeroes ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x2_overwrite_bytes_all(&state, ascon_output_12, &trng);
        ascon_masked_word_x2_zero(&word1, &trng);
        state.M[offset / 8] = word1;
        ascon_x2_extract_bytes_all(&state, buffer);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Extract Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x2_randomize(&state, &trng);
        ascon_x2_add_bytes_all_load32(&state, ascon_output_8, &trng);
        word1 = state.M[offset / 8];
        ascon_masked_word_x2_store(buffer, &word1);
        ascon_masked_word_x2_randomize(&word1, &word1, &trng);
        ascon_masked_word_x2_store(buffer + 8, &word1);
        ascon_masked_state_free(&state);
        for (posn = 0; posn < 8; ++posn) {
            if (buffer[posn] != ascon_output_8[posn + offset])
                ok = 0;
            if (buffer[posn + 8] != ascon_output_8[posn + offset])
                ok = 0;
        }
    }
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Copy From ASCON-x1 ... ");
    ascon_init(&state_x1);
    ascon_add_bytes(&state_x1, ascon_output_8, 0, sizeof(ascon_output_8));
    ascon_release(&state_x1);
    ascon_x2_copy_from_x1(&state, &state_x1, &trng);
    ascon_x2_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_acquire(&state_x1);
    ascon_free(&state_x1);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Copy From ASCON-x2 ... ");
    ascon_masked_state_init(&state_x2);
    ascon_x2_add_bytes_all(&state_x2, ascon_output_12, &trng);
    ascon_x2_copy_from_x2(&state, &state_x2, &trng);
    ascon_x2_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x2);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Copy To ASCON-x1 ... ");
    ascon_masked_state_init(&state);
    ascon_x2_randomize(&state, &trng);
    ascon_x2_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x2_copy_to_x1(&state_x1, &state);
    ascon_extract_bytes(&state_x1, buffer, 0, 40);
    ascon_free(&state_x1);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

#if ASCON_MASKED_MAX_SHARES >= 3
    Serial.print("ASCON-x2 Convert Masked Words ... ");
    ok = 1;
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x3_load(&word1, ascon_output_12, &trng);
    ascon_masked_word_x2_from_x3(&word2, &word1, &trng);
    ascon_masked_word_x2_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_12, 8) != 0)
        ok = 0;
#if ASCON_MASKED_MAX_SHARES >= 4
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x4_load(&word1, ascon_output_8, &trng);
    ascon_masked_word_x2_from_x4(&word2, &word1, &trng);
    ascon_masked_word_x2_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_8, 8) != 0)
        ok = 0;
#endif
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }
#endif

    Serial.print("ASCON-x2 Replace Word ... ");
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x2_load(&word1, ascon_output_8, &trng);
        ascon_masked_word_x2_load(&word2, ascon_output_12, &trng);
        ascon_masked_word_x2_replace(&word1, &word2, offset);
        ascon_masked_word_x2_store(buffer, &word1);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x2 Partial Words ... ");
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x2_load_partial(&word1, ascon_output_8, offset, &trng);
        ascon_masked_word_x2_store(buffer, &word1);
        for (posn = 0; posn < 8; ++posn) {
            uint8_t value;
            if (posn < offset)
                value = ascon_output_8[posn];
            else
                value = 0;
            if (buffer[posn] != value)
                ok = 0;
        }
        ascon_masked_word_x2_load(&word1, ascon_output_12, &trng);
        memcpy(buffer, ascon_output_8, sizeof(ascon_output_8));
        ascon_masked_word_x2_store_partial(buffer, offset, &word1);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.println();
}

void test_ascon_x3()
{
    unsigned offset, posn;
    int ok;

#if ASCON_MASKED_MAX_SHARES >= 3
    Serial.print("ASCON-x3 12 Rounds ... ");
    preserve[0] = ascon_trng_generate_64(&trng);
    preserve[1] = ascon_trng_generate_64(&trng);
    ascon_masked_state_init(&state);
    ascon_x3_overwrite_bytes_all(&state, ascon_input, &trng);
    ascon_x3_permute(&state, 0, preserve);
    ascon_x3_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 8 Rounds ... ");
    preserve[0] = ascon_trng_generate_64(&trng);
    preserve[1] = ascon_trng_generate_64(&trng);
    ascon_masked_state_init(&state);
    ascon_x3_overwrite_bytes_all(&state, ascon_input, &trng);
    ascon_x3_permute(&state, 4, preserve);
    ascon_x3_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Init ... ");
    memset(&state, 0xAA, sizeof(state));
    ascon_masked_state_init(&state);
    ascon_x3_randomize(&state, &trng);
    ascon_x3_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ok = 1;
    for (posn = 0; posn < 40; ++posn) {
        if (buffer[posn] != 0)
            ok = 0;
    }
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Free ... ");
    ascon_masked_state_init(&state);
    ascon_x3_add_bytes_all(&state, ascon_input, &trng);
    ascon_x3_randomize(&state, &trng);
    ascon_masked_state_free(&state);
    ok = 1;
    for (posn = 0; posn < sizeof(state); ++posn) {
        /* Check that free sets everything in the state to zero */
        if (((const unsigned char *)&state)[posn] != 0)
            ok = 0;
    }
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Add Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x3_randomize(&state, &trng);
        ascon_x3_add_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x3_load(&word1, ascon_input, &trng);
        ascon_masked_word_x3_xor(&(state.M[offset / 8]), &word1);
        ascon_x3_randomize(&state, &trng);
        ascon_x3_extract_bytes_all(&state, buffer);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Overwrite Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x3_randomize(&state, &trng);
        ascon_x3_overwrite_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x3_load(&word1, ascon_input, &trng);
        state.M[offset / 8] = word1;
        ascon_x3_extract_bytes_all(&state, buffer);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Overwrite With Zeroes ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x3_overwrite_bytes_all(&state, ascon_output_12, &trng);
        ascon_masked_word_x3_zero(&word1, &trng);
        state.M[offset / 8] = word1;
        ascon_x3_extract_bytes_all(&state, buffer);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Extract Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x3_randomize(&state, &trng);
        ascon_x3_add_bytes_all_load32(&state, ascon_output_8, &trng);
        word1 = state.M[offset / 8];
        ascon_masked_word_x3_store(buffer, &word1);
        ascon_masked_word_x3_randomize(&word1, &word1, &trng);
        ascon_masked_word_x3_store(buffer + 8, &word1);
        ascon_masked_state_free(&state);
        for (posn = 0; posn < 8; ++posn) {
            if (buffer[posn] != ascon_output_8[posn + offset])
                ok = 0;
            if (buffer[posn + 8] != ascon_output_8[posn + offset])
                ok = 0;
        }
    }
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Copy From ASCON-x1 ... ");
    ascon_init(&state_x1);
    ascon_add_bytes(&state_x1, ascon_output_8, 0, sizeof(ascon_output_8));
    ascon_release(&state_x1);
    ascon_x3_copy_from_x1(&state, &state_x1, &trng);
    ascon_x3_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_acquire(&state_x1);
    ascon_free(&state_x1);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Copy From ASCON-x2 ... ");
    ascon_masked_state_init(&state_x2);
    ascon_x2_randomize(&state_x2, &trng);
    ascon_x2_add_bytes_all(&state_x2, ascon_output_8, &trng);
    ascon_x3_copy_from_x2(&state, &state_x2, &trng);
    ascon_x3_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x2);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Copy From ASCON-x3 ... ");
    ascon_masked_state_init(&state_x3);
    ascon_x3_randomize(&state_x3, &trng);
    ascon_x3_add_bytes_all(&state_x3, ascon_output_12, &trng);
    ascon_x3_copy_from_x3(&state, &state_x3, &trng);
    ascon_x3_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x3);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Copy To ASCON-x1 ... ");
    ascon_masked_state_init(&state);
    ascon_x3_randomize(&state, &trng);
    ascon_x3_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x3_copy_to_x1(&state_x1, &state);
    ascon_extract_bytes(&state_x1, buffer, 0, 40);
    ascon_free(&state_x1);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Copy To ASCON-x2 ... ");
    ascon_masked_state_init(&state);
    ascon_x3_randomize(&state, &trng);
    ascon_x3_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x2_copy_from_x3(&state_x2, &state, &trng);
    ascon_x2_extract_bytes_all(&state_x2, buffer);
    ascon_masked_state_free(&state_x2);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Convert Masked Words ... ");
    ok = 1;
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x2_load(&word1, ascon_output_12, &trng);
    ascon_masked_word_x3_from_x2(&word2, &word1, &trng);
    ascon_masked_word_x3_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_12, 8) != 0)
        ok = 0;
#if ASCON_MASKED_MAX_SHARES >= 4
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x4_load(&word1, ascon_output_8, &trng);
    ascon_masked_word_x3_from_x4(&word2, &word1, &trng);
    ascon_masked_word_x3_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_8, 8) != 0)
        ok = 0;
#endif
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Replace Word ... ");
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x3_load(&word1, ascon_output_8, &trng);
        ascon_masked_word_x3_load(&word2, ascon_output_12, &trng);
        ascon_masked_word_x3_replace(&word1, &word2, offset);
        ascon_masked_word_x3_store(buffer, &word1);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x3 Partial Words ... ");
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x3_load_partial(&word1, ascon_output_8, offset, &trng);
        ascon_masked_word_x3_store(buffer, &word1);
        for (posn = 0; posn < 8; ++posn) {
            uint8_t value;
            if (posn < offset)
                value = ascon_output_8[posn];
            else
                value = 0;
            if (buffer[posn] != value)
                ok = 0;
        }
        ascon_masked_word_x3_load(&word1, ascon_output_12, &trng);
        memcpy(buffer, ascon_output_8, sizeof(ascon_output_8));
        ascon_masked_word_x3_store_partial(buffer, offset, &word1);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }
    Serial.println();
#endif
}

void test_ascon_x4()
{
    unsigned offset, posn;
    int ok;

#if ASCON_MASKED_MAX_SHARES >= 4
    Serial.print("ASCON-x4 12 Rounds ... ");
    preserve[0] = ascon_trng_generate_64(&trng);
    preserve[1] = ascon_trng_generate_64(&trng);
    preserve[2] = ascon_trng_generate_64(&trng);
    ascon_masked_state_init(&state);
    ascon_x4_overwrite_bytes_all(&state, ascon_input, &trng);
    ascon_x4_permute(&state, 0, preserve);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 8 Rounds ... ");
    preserve[0] = ascon_trng_generate_64(&trng);
    preserve[1] = ascon_trng_generate_64(&trng);
    preserve[2] = ascon_trng_generate_64(&trng);
    ascon_masked_state_init(&state);
    ascon_x4_overwrite_bytes_all(&state, ascon_input, &trng);
    ascon_x4_permute(&state, 4, preserve);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Init ... ");
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Free ... ");
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Add Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_randomize(&state, &trng);
        ascon_x4_add_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x4_load(&word1, ascon_input, &trng);
        ascon_masked_word_x4_xor(&(state.M[offset / 8]), &word1);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Overwrite Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_randomize(&state, &trng);
        ascon_x4_overwrite_bytes_all(&state, ascon_output_8, &trng);
        ascon_masked_word_x4_load(&word1, ascon_input, &trng);
        state.M[offset / 8] = word1;
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Overwrite With Zeroes ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_overwrite_bytes_all(&state, ascon_output_12, &trng);
        ascon_masked_word_x4_zero(&word1, &trng);
        state.M[offset / 8] = word1;
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Extract Words ... ");
    ok = 1;
    for (offset = 0; offset < 40; offset += 8) {
        ascon_masked_state_init(&state);
        ascon_x4_randomize(&state, &trng);
        ascon_x4_add_bytes_all_load32(&state, ascon_output_8, &trng);
        word1 = state.M[offset / 8];
        ascon_masked_word_x4_store(buffer, &word1);
        ascon_masked_word_x4_randomize(&word1, &word1, &trng);
        ascon_masked_word_x4_store(buffer + 8, &word1);
        ascon_masked_state_free(&state);
        for (posn = 0; posn < 8; ++posn) {
            if (buffer[posn] != ascon_output_8[posn + offset])
                ok = 0;
            if (buffer[posn + 8] != ascon_output_8[posn + offset])
                ok = 0;
        }
    }
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Copy From ASCON-x1 ... ");
    ascon_init(&state_x1);
    ascon_add_bytes(&state_x1, ascon_output_8, 0, sizeof(ascon_output_8));
    ascon_release(&state_x1);
    ascon_x4_copy_from_x1(&state, &state_x1, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_acquire(&state_x1);
    ascon_free(&state_x1);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Copy From ASCON-x2 ... ");
    ascon_masked_state_init(&state_x2);
    ascon_x2_randomize(&state_x2, &trng);
    ascon_x2_add_bytes_all(&state_x2, ascon_output_8, &trng);
    ascon_x4_copy_from_x2(&state, &state_x2, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x2);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Copy From ASCON-x3 ... ");
    ascon_masked_state_init(&state_x3);
    ascon_x3_randomize(&state_x3, &trng);
    ascon_x3_add_bytes_all(&state_x3, ascon_output_8, &trng);
    ascon_x4_copy_from_x3(&state, &state_x3, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x3);
    if (memcmp(buffer, ascon_output_8, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Copy From ASCON-x4 ... ");
    ascon_masked_state_init(&state_x4);
    ascon_x4_randomize(&state_x4, &trng);
    ascon_x3_add_bytes_all(&state_x4, ascon_output_12, &trng);
    ascon_x4_copy_from_x4(&state, &state_x4, &trng);
    ascon_x4_extract_bytes_all(&state, buffer);
    ascon_masked_state_free(&state);
    ascon_masked_state_free(&state_x4);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Copy To ASCON-x1 ... ");
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x4_copy_to_x1(&state_x1, &state);
    ascon_extract_bytes(&state_x1, buffer, 0, 40);
    ascon_free(&state_x1);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Copy To ASCON-x2 ... ");
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x2_copy_from_x4(&state_x2, &state, &trng);
    ascon_x2_extract_bytes_all(&state_x2, buffer);
    ascon_masked_state_free(&state_x2);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Copy To ASCON-x3 ... ");
    ascon_masked_state_init(&state);
    ascon_x4_randomize(&state, &trng);
    ascon_x4_add_bytes_all(&state, ascon_output_12, &trng);
    ascon_x3_copy_from_x4(&state_x3, &state, &trng);
    ascon_x3_extract_bytes_all(&state_x3, buffer);
    ascon_masked_state_free(&state_x3);
    ascon_masked_state_free(&state);
    if (memcmp(buffer, ascon_output_12, 40) != 0) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Convert Masked Words ... ");
    ok = 1;
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x2_load(&word1, ascon_output_12, &trng);
    ascon_masked_word_x4_from_x2(&word2, &word1, &trng);
    ascon_masked_word_x4_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_12, 8) != 0)
        ok = 0;
    memset(&word2, 0, sizeof(word2));
    ascon_masked_word_x3_load(&word1, ascon_output_8, &trng);
    ascon_masked_word_x4_from_x3(&word2, &word1, &trng);
    ascon_masked_word_x4_store(buffer, &word2);
    if (memcmp(buffer, ascon_output_8, 8) != 0)
        ok = 0;
    if (!ok) {
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Replace Word ... ");
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x4_load(&word1, ascon_output_8, &trng);
        ascon_masked_word_x4_load(&word2, ascon_output_12, &trng);
        ascon_masked_word_x4_replace(&word1, &word2, offset);
        ascon_masked_word_x4_store(buffer, &word1);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.print("ASCON-x4 Partial Words ... ");
    ok = 1;
    for (offset = 0; offset < 8; ++offset) {
        ascon_masked_word_x4_load_partial(&word1, ascon_output_8, offset, &trng);
        ascon_masked_word_x4_store(buffer, &word1);
        for (posn = 0; posn < 8; ++posn) {
            uint8_t value;
            if (posn < offset)
                value = ascon_output_8[posn];
            else
                value = 0;
            if (buffer[posn] != value)
                ok = 0;
        }
        ascon_masked_word_x4_load(&word1, ascon_output_12, &trng);
        memcpy(buffer, ascon_output_8, sizeof(ascon_output_8));
        ascon_masked_word_x4_store_partial(buffer, offset, &word1);
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
        Serial.println("failed");
    } else {
        Serial.println("ok");
    }

    Serial.println();
#endif
}

void setup()
{
    unsigned offset, posn;

    Serial.begin(9600);
    Serial.println();

    ascon_trng_init(&trng);

    test_ascon_x2();
    test_ascon_x3();
    test_ascon_x4();

    ascon_trng_free(&trng);
}

void loop()
{
}
