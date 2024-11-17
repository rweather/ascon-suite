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

#include <ascon/xof.h>
#include <ascon/hash.h>
#include <ascon/permutation.h>
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct
{
    const char *name;
    const char *custom;

} cxof_test_vector_t;

static cxof_test_vector_t const test_vectors[] = {
    {
        .name = 0,
        .custom = 0
    },
    {
        .name = 0,
        .custom = "customization"
    },
    {
        .name = "",
        .custom = ""
    },
    {
        .name = "",
        .custom = "customization"
    },
    {
        .name = "KMAC",
        .custom = 0
    },
    {
        .name = "KMAC",
        .custom = "custom"
    },
    {
        .name = "KMAC",
        .custom = "This is a very long customization string"
    },
    {
        .name = "This is a very long function name string",
        .custom = "This is a very long customization string"
    },
};

/* Simple version of the CXOF128 header formatting in the library */
static void format_header
    (ascon_xof128_state_t *state, const char *function_name)
{
    unsigned char block[40];
    size_t len, size;

    /* Format the first block and permute it */
    memset(block, 0, sizeof(block));
    block[0] = 0x04;
    block[2] = 0xCC;
    block[5] = 0x08;
    state->mode = 0;
    state->count = 0;
    ascon_init(&(state->state));
    ascon_add_bytes(&(state->state), block, 0, 40);
    ascon_permute(&(state->state), 0);

    /* Encode the size of the function name in the stream */
    len = function_name ? strlen(function_name) : 0;
    size = len * 8;
    block[0] = (unsigned char)size;
    block[1] = (unsigned char)(size >> 8);
    ascon_add_bytes(&(state->state), block, 0, 2);
    ascon_permute(&(state->state), 0);
    ascon_release(&(state->state));

    /* Absorb and pad the function name */
    ascon_xof128_absorb(state, (const unsigned char *)function_name, len);
    ascon_xof128_pad(state);
}

static int test_cxof_inner
    (const char *function_name, const char *custom)
{
    const unsigned char *cust = (const unsigned char *)custom;
    size_t custlen = custom ? strlen(custom) : 0;
    ascon_xof128_state_t state1;
    ascon_xof128_state_t state2;
    unsigned char out1[ASCON_HASH256_SIZE];
    unsigned char out2[ASCON_HASH256_SIZE];
    const unsigned char *in = (const unsigned char *)"Payload Data";
    size_t inlen = 12;

    /* Use the library to compute the answer */
    ascon_cxof128_init_named(&state1, function_name, cust, custlen);
    ascon_xof128_absorb(&state1, in, inlen);
    ascon_xof128_squeeze(&state1, out1, sizeof(out1));

    /* Simulate the desired behaviour */
    if (function_name && function_name[0] != '\0') {
        format_header(&state2, function_name);
        if (custlen > 0) {
            ascon_xof128_absorb(&state2, cust, custlen);
            ascon_xof128_pad(&state2);
        }
    } else {
        format_header(&state2, custom);
    }
    ascon_xof128_absorb(&state2, in, inlen);
    ascon_xof128_squeeze(&state2, out2, sizeof(out2));
    ascon_xof128_free(&state2);

    /* Check the result */
    if (test_memcmp(out1, out2, sizeof(out1)) != 0) {
        ascon_xof128_free(&state1);
        return 0;
    }

    /* Re-initialize and test again */
    ascon_cxof128_reinit_named(&state1, function_name, cust, custlen);
    ascon_xof128_absorb(&state1, in, inlen);
    ascon_xof128_squeeze(&state1, out1, sizeof(out1));
    ascon_xof128_free(&state1);
    if (test_memcmp(out1, out2, sizeof(out1)) != 0) {
        return 0;
    }
    return 1;
}

static int test_cxof(void)
{
    size_t index;
    int ok = 1;
    for (index = 0; index < (sizeof(test_vectors) / sizeof(test_vectors[0])); ++index) {
        const cxof_test_vector_t *vec = &(test_vectors[index]);
        printf("ASCON-cXOF %u ... ", (unsigned)(index + 1));
        fflush(stdout);
        if (!test_cxof_inner(vec->name, vec->custom)) {
            printf("failed\n");
            ok = 0;
        } else {
            printf("ok\n");
        }
    }
    return ok;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    if (!hash_sanity_check())
        return 1;

    if (!test_cxof())
        test_exit_result = 1;

    return test_exit_result;
}
