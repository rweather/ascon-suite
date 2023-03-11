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
    size_t outlen;

} cxof_test_vector_t;

static cxof_test_vector_t const test_vectors[] = {
    {
        .name = 0,
        .custom = 0,
        .outlen = 0
    },
    {
        .name = 0,
        .custom = 0,
        .outlen = ASCON_HASH_SIZE
    },
    {
        .name = "",
        .custom = "",
        .outlen = 0
    },
    {
        .name = "",
        .custom = "",
        .outlen = ASCON_HASH_SIZE
    },
    {
        .name = "",
        .custom = "customization",
        .outlen = ASCON_HASH_SIZE
    },
    {
        .name = "KMAC",
        .custom = 0,
        .outlen = ASCON_HASH_SIZE * 4
    },
    {
        .name = "KMAC",
        .custom = "custom",
        .outlen = ASCON_HASH_SIZE
    },
    {
        .name = "KMAC",
        .custom = "This is a very long customization string",
        .outlen = 0
    },
    {
        .name = "This is a very long function name string",
        .custom = "This is a very long customization string",
        .outlen = ASCON_HASH_SIZE / 2
    },
};

/* Simple version of the first block formatting in the library */
static void format_first_block
    (ascon_state_t *state, const char *function_name, size_t outlen,
     int rounds)
{
    unsigned char block[40];
    outlen *= 8;
    memset(block, 0, sizeof(block));
    block[0] = 0;
    block[1] = 64;
    block[2] = 12;
    block[3] = 12 - rounds;
    block[4] = (unsigned char)(outlen >> 24);
    block[5] = (unsigned char)(outlen >> 16);
    block[6] = (unsigned char)(outlen >> 8);
    block[7] = (unsigned char)outlen;
    if (function_name && function_name[0]) {
        size_t len = strlen(function_name);
        if (len <= 32) {
            memcpy(block + 8, function_name, len);
        } else if (rounds == 12) {
            ascon_hash(block + 8, (const unsigned char *)function_name, len);
        } else {
            ascon_hasha(block + 8, (const unsigned char *)function_name, len);
        }
    }
    ascon_init(state);
    ascon_add_bytes(state, block, 0, 40);
    ascon_permute(state, 0);
    ascon_release(state);
}

static int test_cxof_inner
    (const char *function_name, const char *custom, size_t outlen)
{
    const unsigned char *cust = (const unsigned char *)custom;
    size_t custlen = custom ? strlen(custom) : 0;
    ascon_xof_state_t state1;
    ascon_xof_state_t state2;
    unsigned char out1[ASCON_HASH_SIZE];
    unsigned char out2[ASCON_HASH_SIZE];
    const unsigned char *in = (const unsigned char *)"Payload Data";
    size_t inlen = 12;

    /* Use the library to compute the answer */
    ascon_xof_init_custom(&state1, function_name, cust, custlen, outlen);
    ascon_xof_absorb(&state1, in, inlen);
    ascon_xof_squeeze(&state1, out1, sizeof(out1));

    /* Simulate the desired behaviour */
    format_first_block(&(state2.state), function_name, outlen, 12);
    state2.count = 0;
    state2.mode = 0;
    if (custlen > 0) {
        ascon_xof_absorb(&state2, cust, custlen);
        ascon_acquire(&(state2.state));
        out2[0] = 0x80; /* Padding */
        ascon_add_bytes(&(state2.state), out2, state2.count, 1);
        ascon_permute(&(state2.state), 0);
        out2[0] = 0x01; /* Domain separation */
        ascon_add_bytes(&(state2.state), out2, 39, 1);
        ascon_release(&(state2.state));
        state2.count = 0;
        state2.mode = 0;
    }
    ascon_xof_absorb(&state2, in, inlen);
    ascon_xof_squeeze(&state2, out2, sizeof(out2));
    ascon_xof_free(&state2);

    /* Check the result */
    if (test_memcmp(out1, out2, sizeof(out1)) != 0) {
        ascon_xof_free(&state1);
        return 0;
    }

    /* Re-initialize and test again */
    ascon_xof_reinit_custom(&state1, function_name, cust, custlen, outlen);
    ascon_xof_absorb(&state1, in, inlen);
    ascon_xof_squeeze(&state1, out1, sizeof(out1));
    ascon_xof_free(&state1);
    if (test_memcmp(out1, out2, sizeof(out1)) != 0) {
        return 0;
    }
    return 1;
}

static int test_cxofa_inner
    (const char *function_name, const char *custom, size_t outlen)
{
    const unsigned char *cust = (const unsigned char *)custom;
    size_t custlen = custom ? strlen(custom) : 0;
    ascon_xofa_state_t state1;
    ascon_xofa_state_t state2;
    unsigned char out1[ASCON_HASH_SIZE];
    unsigned char out2[ASCON_HASH_SIZE];
    const unsigned char *in = (const unsigned char *)"Payload Data";
    size_t inlen = 12;

    /* Use the library to compute the answer */
    ascon_xofa_init_custom(&state1, function_name, cust, custlen, outlen);
    ascon_xofa_absorb(&state1, in, inlen);
    ascon_xofa_squeeze(&state1, out1, sizeof(out1));

    /* Simulate the desired behaviour */
    format_first_block(&(state2.state), function_name, outlen, 8);
    state2.count = 0;
    state2.mode = 0;
    if (custlen > 0) {
        ascon_xofa_absorb(&state2, cust, custlen);
        ascon_acquire(&(state2.state));
        out2[0] = 0x80; /* Padding */
        ascon_add_bytes(&(state2.state), out2, state2.count, 1);
        ascon_permute(&(state2.state), 4);
        out2[0] = 0x01; /* Domain separation */
        ascon_add_bytes(&(state2.state), out2, 39, 1);
        ascon_release(&(state2.state));
        state2.count = 0;
        state2.mode = 0;
    }
    ascon_xofa_absorb(&state2, in, inlen);
    ascon_xofa_squeeze(&state2, out2, sizeof(out2));
    ascon_xofa_free(&state2);

    /* Check the result */
    if (test_memcmp(out1, out2, sizeof(out1)) != 0) {
        ascon_xofa_free(&state1);
        return 0;
    }

    /* Re-initialize and test again */
    ascon_xofa_reinit_custom(&state1, function_name, cust, custlen, outlen);
    ascon_xofa_absorb(&state1, in, inlen);
    ascon_xofa_squeeze(&state1, out1, sizeof(out1));
    ascon_xofa_free(&state1);
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
        if (!test_cxof_inner(vec->name, vec->custom, vec->outlen)) {
            printf("failed\n");
            ok = 0;
        } else {
            printf("ok\n");
        }
    }
    return ok;
}

static int test_cxofa(void)
{
    size_t index;
    int ok = 1;
    for (index = 0; index < (sizeof(test_vectors) / sizeof(test_vectors[0])); ++index) {
        const cxof_test_vector_t *vec = &(test_vectors[index]);
        printf("ASCON-cXOFA %u ... ", (unsigned)(index + 1));
        fflush(stdout);
        if (!test_cxofa_inner(vec->name, vec->custom, vec->outlen)) {
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
    if (!test_cxofa())
        test_exit_result = 1;

    return test_exit_result;
}
