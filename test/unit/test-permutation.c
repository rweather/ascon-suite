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

#include <ascon/permutation.h>
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

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

void test_ascon_permutation(void)
{
    ascon_state_t state;
    uint8_t buffer[40];
    uint8_t buffer2[40];
    unsigned offset, size, posn;
    int ok;

    printf("12 Rounds ... ");
    fflush(stdout);
    ascon_init(&state);
    ascon_add_bytes(&state, ascon_input, 0, sizeof(ascon_input));
    ascon_permute(&state, 0);
    ascon_extract_bytes(&state, buffer, 0, sizeof(buffer));
    ascon_free(&state);
    if (memcmp(buffer, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("8 Rounds ... ");
    fflush(stdout);
    ascon_init(&state);
    ascon_add_bytes(&state, ascon_input, 0, sizeof(ascon_input));
    ascon_permute(&state, 4);
    ascon_extract_bytes(&state, buffer, 0, sizeof(buffer));
    ascon_free(&state);
    if (memcmp(buffer, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Init ... ");
    fflush(stdout);
    memcpy(state.B, ascon_output_12, sizeof(ascon_output_12));
    ascon_init(&state);
    ascon_extract_bytes(&state, buffer, 0, sizeof(buffer));
    ascon_free(&state);
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
    ascon_init(&state);
    ascon_add_bytes(&state, ascon_input, 0, sizeof(ascon_input));
    ascon_free(&state);
    ok = 1;
    for (posn = 0; posn < 40; ++posn) {
        /* Check that ascon_free() sets everything in the state to zero */
        if (state.B[posn] != 0)
            ok = 0;
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Add Bytes ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; ++offset) {
        for (size = 0; size < (40 - offset); ++size) {
            ascon_init(&state);
            ascon_overwrite_bytes
                (&state, ascon_output_12, 0, sizeof(ascon_output_12));
            ascon_add_bytes(&state, ascon_input, offset, size);
            ascon_extract_bytes(&state, buffer, 0, sizeof(buffer));
            ascon_free(&state);
            for (posn = 0; posn < 40; ++posn) {
                uint8_t value = ascon_output_12[posn];
                if (posn >= offset && posn < (offset + size))
                    value ^= ascon_input[posn - offset];
                if (value != buffer[posn])
                    ok = 0;
            }
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Overwrite Bytes ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; ++offset) {
        for (size = 0; size < (40 - offset); ++size) {
            ascon_init(&state);
            ascon_overwrite_bytes
                (&state, ascon_output_12, 0, sizeof(ascon_output_12));
            ascon_overwrite_bytes(&state, ascon_input, offset, size);
            ascon_extract_bytes(&state, buffer, 0, sizeof(buffer));
            ascon_free(&state);
            for (posn = 0; posn < 40; ++posn) {
                uint8_t value = ascon_output_12[posn];
                if (posn >= offset && posn < (offset + size))
                    value = ascon_input[posn - offset];
                if (value != buffer[posn])
                    ok = 0;
            }
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
    for (offset = 0; offset < 40; ++offset) {
        for (size = 0; size < (40 - offset); ++size) {
            ascon_init(&state);
            ascon_overwrite_bytes
                (&state, ascon_output_12, 0, sizeof(ascon_output_12));
            ascon_overwrite_with_zeroes(&state, offset, size);
            ascon_extract_bytes(&state, buffer, 0, sizeof(buffer));
            ascon_free(&state);
            for (posn = 0; posn < 40; ++posn) {
                uint8_t value = ascon_output_12[posn];
                if (posn >= offset && posn < (offset + size))
                    value = 0;
                if (value != buffer[posn])
                    ok = 0;
            }
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Extract Bytes ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; ++offset) {
        for (size = 0; size < (40 - offset); ++size) {
            ascon_init(&state);
            ascon_overwrite_bytes
                (&state, ascon_output_12, 0, sizeof(ascon_output_12));
            ascon_extract_bytes(&state, buffer, offset, size);
            ascon_free(&state);
            for (posn = 0; posn < size; ++posn) {
                if (buffer[posn] != ascon_output_12[posn + offset])
                    ok = 0;
            }
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Extract And Add Bytes ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; ++offset) {
        for (size = 0; size < (40 - offset); ++size) {
            ascon_init(&state);
            ascon_overwrite_bytes
                (&state, ascon_output_12, 0, sizeof(ascon_output_12));
            memset(buffer, 0xAA, sizeof(buffer));
            ascon_extract_and_add_bytes
                (&state, ascon_input, buffer, offset, size);
            ascon_free(&state);
            for (posn = 0; posn < size; ++posn) {
                uint8_t value = ascon_output_12[posn + offset];
                value ^= ascon_input[posn];
                if (value != buffer[posn])
                    ok = 0;
            }
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("Extract And Overwrite Bytes ... ");
    fflush(stdout);
    ok = 1;
    for (offset = 0; offset < 40; ++offset) {
        for (size = 0; size < (40 - offset); ++size) {
            ascon_init(&state);
            ascon_overwrite_bytes
                (&state, ascon_output_12, 0, sizeof(ascon_output_12));
            memset(buffer, 0xAA, sizeof(buffer));
            ascon_extract_and_overwrite_bytes
                (&state, ascon_input, buffer, offset, size);
            ascon_extract_bytes(&state, buffer2, 0, sizeof(buffer2));
            ascon_free(&state);
            for (posn = 0; posn < size; ++posn) {
                uint8_t value = ascon_output_12[posn + offset];
                value ^= ascon_input[posn];
                if (value != buffer[posn])
                    ok = 0;
            }
            for (posn = 0; posn < 40; ++posn) {
                uint8_t value = buffer2[posn];
                if (posn >= offset && posn < (offset + size))
                    value = ascon_input[posn - offset];
                if (value != buffer2[posn])
                    ok = 0;
            }
        }
    }
    if (!ok) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    test_ascon_permutation();

    return test_exit_result;
}
