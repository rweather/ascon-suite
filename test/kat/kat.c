/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "aead-metadata.h"
#include "algorithms.h"
#include "timing.h"
#include "internal-chachapoly.h"
#include "internal-blake2s.h"
#include <ascon/utility.h>

/* Dynamically-allocated test string that was converted from hexadecimal */
typedef struct {
    size_t size;
    unsigned char data[1];
} test_string_t;

/* Create a test string from a hexadecimal string */
static test_string_t *create_test_string(const char *in)
{
    test_string_t *out;
    size_t inlen;
    size_t outlen;
    inlen = strlen(in);
    outlen = inlen / 2;
    out = (test_string_t *)malloc(sizeof(test_string_t) + outlen);
    if (!out)
        exit(2);
    out->size = ascon_bytes_from_hex(out->data, outlen, in, inlen);
    return out;
}

/* Frees a dynamically-allocated test string */
#define free_test_string(str) (free((str)))

/* Maximum number of parameters to a KAT vector */
#define MAX_TEST_PARAMS 16

/* All parameters for a KAT vector */
typedef struct
{
    int test_number;
    char names[MAX_TEST_PARAMS][16];
    test_string_t *values[MAX_TEST_PARAMS];
    size_t count;

} test_vector_t;

/* Reads a dynamically-allocated KAT vector from an input file */
static int test_vector_read(test_vector_t *vec, FILE *file)
{
    char buffer[8192];
    memset(vec, 0, sizeof(test_vector_t));
    while (fgets(buffer, sizeof(buffer), file)) {
        if (buffer[0] == '\n' || buffer[0] == '\r' || buffer[0] == '\0') {
            /* Blank line terminates the vector unless it is the first line */
            if (vec->count > 0)
                return 1;
        } else if (!strncmp(buffer, "Count = ", 8)) {
            /* Number of the test rather than a vector parameter */
            vec->test_number = atoi(buffer + 8);
        } else if (buffer[0] >= 'A' && buffer[0] <= 'Z' && vec->count < MAX_TEST_PARAMS) {
            /* Name = Value test string */
            const char *eq = strchr(buffer, '=');
            if (eq) {
                int posn = eq - buffer;
                while (posn > 0 && buffer[posn - 1] == ' ')
                    --posn;
                if (posn > 15)
                    posn = 15;
                memcpy(vec->names[vec->count], buffer, posn);
                vec->names[vec->count][posn] = '\0';
                vec->values[vec->count] = create_test_string(eq + 1);
                ++(vec->count);
            }
        }
    }
    return vec->count > 0;
}

/* Frees a dynamically-allocated KAT vector */
static void test_vector_free(test_vector_t *vec)
{
    size_t index;
    for (index = 0; index < vec->count; ++index)
        free_test_string(vec->values[index]);
    memset(vec, 0, sizeof(test_vector_t));
}

/* Gets a parameter from a test vector, NULL if parameter is not present */
static test_string_t *get_test_string
    (const test_vector_t *vec, const char *name)
{
    size_t index;
    for (index = 0; index < vec->count; ++index) {
        if (!strcmp(vec->names[index], name))
            return vec->values[index];
    }
    fprintf(stderr, "Could not find '%s' in test vector %d\n",
            name, vec->test_number);
    exit(3);
    return 0;
}

/* Print an error for a failed test */
static void test_print_error
    (const char *alg, const test_vector_t *vec, const char *format, ...)
{
    va_list va;
    printf("%s [%d]: ", alg, vec->test_number);
    va_start(va, format);
    vprintf(format, va);
    va_end(va);
    printf("\n");
}

static void test_print_hex
    (const char *tag, const unsigned char *data, size_t len)
{
    printf("%s =", tag);
    while (len > 0) {
        printf(" %02x", data[0]);
        ++data;
        --len;
    }
    printf("\n");
}

static int test_compare
    (const unsigned char *actual, const unsigned char *expected, size_t len)
{
    int cmp = memcmp(actual, expected, (size_t)len);
    if (cmp == 0)
        return 1;
    printf("\n");
    test_print_hex("actual  ", actual, len);
    test_print_hex("expected", expected, len);
    return 0;
}

/* Determine if the contents of a buffer is all-zero bytes or not */
static int test_all_zeroes(const unsigned char *buf, size_t len)
{
    while (len > 0) {
        if (*buf++ != 0)
            return 0;
        --len;
    }
    return 1;
}

/* Wrap incremental encryption to make it look like an all-in-one cipher */
static void incremental_aead_cipher_encrypt
    (const aead_cipher_t *alg, void *state, size_t increment,
     unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    size_t posn, temp;
    (*(alg->init_inc))(state, npub, k);
    (*(alg->start_inc))(state, ad, adlen);
    if (increment == 0) {
        /* Encrypt everything in one go */
        (*(alg->encrypt_inc))(state, m, c, mlen);
    } else {
        /* Break the request up into chunks */
        for (posn = 0; posn < mlen; posn += increment) {
            temp = mlen - posn;
            if (temp > increment)
                temp = increment;
            (*(alg->encrypt_inc))(state, m + posn, c + posn, temp);
        }
    }
    *clen = mlen + alg->tag_len;
    (*(alg->encrypt_fin))(state, c + mlen);
    (*(alg->pk_free))(state);
}

/* Wrap incremental decryption to make it look like an all-in-one cipher */
static int incremental_aead_cipher_decrypt
    (const aead_cipher_t *alg, void *state, size_t increment,
     unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    size_t posn, temp;
    int result;
    if (clen < alg->tag_len)
        return -1;
    (*(alg->init_inc))(state, npub, k);
    (*(alg->start_inc))(state, ad, adlen);
    *mlen = clen - alg->tag_len;
    if (increment == 0) {
        /* Decrypt everything in one go */
        (*(alg->decrypt_inc))(state, c, m, *mlen);
    } else {
        /* Break the request up into chunks */
        for (posn = 0; posn < *mlen; posn += increment) {
            temp = *mlen - posn;
            if (temp > increment)
                temp = increment;
            (*(alg->decrypt_inc))(state, c + posn, m + posn, temp);
        }
    }
    result = (*(alg->decrypt_fin))(state, c + clen - alg->tag_len);
    (*(alg->pk_free))(state);
    return result;
}

/* Test a cipher algorithm on a specific test vector */
static int test_cipher_inner
    (const aead_cipher_t *alg, const test_vector_t *vec)
{
    static size_t const sizes[] = {1, 2, 3, 5, 8, 6, 16, 17, 21, 0};
    unsigned char *pk = 0;
    const test_string_t *key;
    const test_string_t *nonce;
    const test_string_t *plaintext;
    const test_string_t *ciphertext;
    const test_string_t *ad;
    unsigned char *temp1;
    unsigned char *temp2;
    unsigned char *inc_state = 0;
    const unsigned char *actual_key = 0;
    size_t len;
    int result = 0;
    int exit_val = 1;

    /* Get the parameters for the test */
    key = get_test_string(vec, "Key");
    nonce = get_test_string(vec, "Nonce");
    plaintext = get_test_string(vec, "PT");
    ciphertext = get_test_string(vec, "CT");
    ad = get_test_string(vec, "AD");
    if (key->size != alg->key_len) {
        test_print_error(alg->name, vec, "incorrect key size in test data");
        return 0;
    }
    if (nonce->size != alg->nonce_len) {
        test_print_error(alg->name, vec, "incorrect nonce size in test data");
        return 0;
    }

    /* Allocate temporary buffers */
    temp1 = malloc(ciphertext->size);
    if (!temp1)
        exit(2);
    temp2 = malloc(ciphertext->size);
    if (!temp2)
        exit(2);

    /* Set up a pre-computed key if necessary */
    if (alg->pk_state_len) {
        pk = malloc(alg->pk_state_len);
        if (!pk)
            exit(2);
        (*(alg->pk_init))(pk, key->data);
        actual_key = pk;
    } else {
        actual_key = key->data;
    }

    /* Set up an incremental state object if necessary */
    if (alg->inc_state_len) {
        inc_state = malloc(alg->inc_state_len);
        if (!inc_state)
            exit(2);
    }

    /* Test encryption */
    memset(temp1, 0xAA, ciphertext->size);
    len = 0xBADBEEF;
    if (alg->start_inc) {
        incremental_aead_cipher_encrypt
            (alg, inc_state, 0, temp1, &len,
             plaintext->data, plaintext->size,
             ad->data, ad->size, nonce->data, actual_key);
    } else {
        (*(alg->encrypt))
            (temp1, &len, plaintext->data, plaintext->size,
             ad->data, ad->size, nonce->data, actual_key);
    }
    if (len != ciphertext->size ||
            !test_compare(temp1, ciphertext->data, len)) {
        test_print_error(alg->name, vec, "encryption failed");
        exit_val = 0;
        goto cleanup;
    }

    /* Test incremental encryption with various block sizes */
    if (alg->start_inc) {
        unsigned posn;
        result = 0;
        for (posn = 0; sizes[posn] != 0 && result == 0; ++posn) {
            memset(temp1, 0xAA, ciphertext->size);
            len = 0xBADBEEF;
            incremental_aead_cipher_encrypt
                (alg, inc_state, sizes[posn], temp1, &len,
                 plaintext->data, plaintext->size,
                 ad->data, ad->size, nonce->data, actual_key);
            if (len != ciphertext->size ||
                    !test_compare(temp1, ciphertext->data, len)) {
                test_print_error(alg->name, vec, "incremental encryption failed");
                exit_val = 0;
                goto cleanup;
            }
        }
    }

    /* Test in-place encryption */
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp1, plaintext->data, plaintext->size);
    len = 0xBADBEEF;
    if (alg->start_inc) {
        incremental_aead_cipher_encrypt
            (alg, inc_state, 0, temp1, &len, temp1, plaintext->size,
             ad->size ? ad->data : 0, ad->size, nonce->data, actual_key);
    } else {
        (*(alg->encrypt))
            (temp1, &len, temp1, plaintext->size,
             ad->size ? ad->data : 0, ad->size, nonce->data, actual_key);
    }
    if (len != ciphertext->size ||
            !test_compare(temp1, ciphertext->data, len)) {
        test_print_error(alg->name, vec, "in-place encryption failed");
        exit_val = 0;
        goto cleanup;
    }

    /* Test decryption */
    memset(temp1, 0xAA, ciphertext->size);
    len = 0xBADBEEF;
    if (alg->start_inc) {
        result = incremental_aead_cipher_decrypt
            (alg, inc_state, 0, temp1, &len,
             ciphertext->data, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    } else {
        result = (*(alg->decrypt))
            (temp1, &len, ciphertext->data, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    }
    if (result != 0 || len != plaintext->size ||
            !test_compare(temp1, plaintext->data, len)) {
        test_print_error(alg->name, vec, "decryption failed");
        exit_val = 0;
        goto cleanup;
    }

    /* Test incremental decryption with various block sizes */
    if (alg->start_inc) {
        unsigned posn;
        result = 0;
        for (posn = 0; sizes[posn] != 0 && result == 0; ++posn) {
            memset(temp1, 0xAA, ciphertext->size);
            len = 0xBADBEEF;
            result = incremental_aead_cipher_decrypt
                (alg, inc_state, sizes[posn], temp1, &len,
                 ciphertext->data, ciphertext->size,
                 ad->data, ad->size, nonce->data, actual_key);
            if (result != 0 || len != plaintext->size ||
                    !test_compare(temp1, plaintext->data, len)) {
                test_print_error(alg->name, vec, "decryption failed");
                exit_val = 0;
                goto cleanup;
            }
        }
    }

    /* Test in-place decryption */
    memcpy(temp1, ciphertext->data, ciphertext->size);
    len = 0xBADBEEF;
    if (alg->start_inc) {
        result = incremental_aead_cipher_decrypt
            (alg, inc_state, 0, temp1, &len, temp1, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    } else {
        result = (*(alg->decrypt))
            (temp1, &len, temp1, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    }
    if (result != 0 || len != plaintext->size ||
            !test_compare(temp1, plaintext->data, len)) {
        test_print_error(alg->name, vec, "in-place decryption failed");
        exit_val = 0;
        goto cleanup;
    }

    /* Test decryption with a failed tag check */
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp2, ciphertext->data, ciphertext->size);
    temp2[0] ^= 0x01; /* Corrupt the first byte of the ciphertext */
    len = 0xBADBEEF;
    if (alg->start_inc) {
        result = incremental_aead_cipher_decrypt
            (alg, inc_state, 0, temp1, &len, temp2, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    } else {
        result = (*(alg->decrypt))
            (temp1, &len, temp2, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    }
    if (result != -1) {
        test_print_error(alg->name, vec, "corrupt ciphertext check failed");
        exit_val = 0;
        goto cleanup;
    }
    if (!test_all_zeroes(temp1, plaintext->size) && !(alg->start_inc)) {
        test_print_error(alg->name, vec, "plaintext not destroyed");
        exit_val = 0;
        goto cleanup;
    }
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp2, ciphertext->data, ciphertext->size);
    temp2[ciphertext->size - 1] ^= 0x01; /* Corrupt last byte of the tag */
    len = 0xBADBEEF;
    if (alg->start_inc) {
        result = incremental_aead_cipher_decrypt
            (alg, inc_state, 0, temp1, &len, temp2, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    } else {
        result = (*(alg->decrypt))
            (temp1, &len, temp2, ciphertext->size,
             ad->data, ad->size, nonce->data, actual_key);
    }
    if (result != -1) {
        test_print_error(alg->name, vec, "corrupt tag check failed");
        exit_val = 0;
        goto cleanup;
    }
    if (!test_all_zeroes(temp1, plaintext->size) && !(alg->start_inc)) {
        test_print_error(alg->name, vec, "plaintext not destroyed");
        exit_val = 0;
        goto cleanup;
    }

    /* All tests passed for this test vector */
cleanup:
    free(temp1);
    free(temp2);
    if (pk) {
        (*(alg->pk_free))(pk);
        free(pk);
    }
    if (inc_state) {
        free(inc_state);
    }
    return exit_val;
}

/* Test a cipher algorithm */
static int test_cipher(const aead_cipher_t *alg, FILE *file)
{
    test_vector_t vec;
    int success = 0;
    int fail = 0;
    while (test_vector_read(&vec, file)) {
        if (test_cipher_inner(alg, &vec))
            ++success;
        else
            ++fail;
        test_vector_free(&vec);
    }
    printf("%s: %d tests succeeded, %d tests failed\n",
           alg->name, success, fail);
    return fail != 0;
}

#define MAX_DATA_SIZE 1024
#define MAX_TAG_SIZE 32

#define PERF_LOOPS 1000000
#define PERF_LOOPS_SLOW 10000
#define PERF_LOOPS_WARMUP 100

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

/* Metrics that have been collected for various cipher scenarios */
typedef struct
{
    perf_timer_t encrypt_128;
    perf_timer_t decrypt_128;
    perf_timer_t encrypt_16;
    perf_timer_t decrypt_16;
    perf_timer_t encrypt_1024;
    perf_timer_t decrypt_1024;

} perf_cipher_metrics_t;

/* Reference metrics for the ChaChaPoly cipher */
static perf_cipher_metrics_t cipher_ref_metrics;

#define MODE_ENC128  0
#define MODE_DEC128  1
#define MODE_ENC16   2
#define MODE_DEC16   3
#define MODE_ENC1024 4
#define MODE_DEC1024 5

/* Generate performance metrics for a cipher algorithm: encrypt 128 bytes */
static perf_timer_t perf_cipher_encrypt_decrypt
    (const aead_cipher_t *alg, const char *name,
     int mode, int report, int slow)
{
    unsigned char plaintext[MAX_DATA_SIZE];
    unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];
    size_t plen, clen, len;
    perf_timer_t start, elapsed;
    perf_timer_t ticks_per_second = perf_timer_ticks_per_second();
    perf_timer_t ref_time = 0;
    int count;
    int loops;
    int bytes;

    /* Print what we are doing now */
    if (report) {
        printf("   %s byte packets %s... ", name,
               (mode == MODE_ENC16 || mode == MODE_DEC16) ? " " : "");
        fflush(stdout);
    }

    /* Initialize the plaintext and ciphertext buffer */
    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    if (mode == MODE_ENC128 || mode == MODE_DEC128)
        plen = 128;
    else if (mode == MODE_ENC1024 || mode == MODE_DEC1024)
        plen = 1024;
    else
        plen = 16;
    alg->encrypt(ciphertext, &clen, plaintext, plen, 0, 0, nonce, key);

    /* Run several loops without timing to force the CPU
     * to load the code and data into internal cache to get
     * the best speed when we measure properly later. */
    switch (mode) {
    case MODE_ENC128:
        for (count = 0; count < PERF_LOOPS_WARMUP; ++count) {
            alg->encrypt
                (ciphertext, &len, plaintext, plen, 0, 0, nonce, key);
        }
        ref_time = cipher_ref_metrics.encrypt_128;
        break;

    case MODE_DEC128:
        for (count = 0; count < PERF_LOOPS_WARMUP; ++count) {
            alg->decrypt
                (plaintext, &len, ciphertext, clen, 0, 0, nonce, key);
        }
        ref_time = cipher_ref_metrics.decrypt_128;
        break;

    case MODE_ENC16:
        for (count = 0; count < PERF_LOOPS_WARMUP; ++count) {
            alg->encrypt
                (ciphertext, &len, plaintext, plen, 0, 0, nonce, key);
        }
        ref_time = cipher_ref_metrics.encrypt_16;
        break;

    case MODE_DEC16:
        for (count = 0; count < PERF_LOOPS_WARMUP; ++count) {
            alg->decrypt
                (plaintext, &len, ciphertext, clen, 0, 0, nonce, key);
        }
        ref_time = cipher_ref_metrics.decrypt_16;
        break;

    case MODE_ENC1024:
        for (count = 0; count < PERF_LOOPS_WARMUP; ++count) {
            alg->encrypt
                (ciphertext, &len, plaintext, plen, 0, 0, nonce, key);
        }
        ref_time = cipher_ref_metrics.encrypt_1024;
        break;

    case MODE_DEC1024:
        for (count = 0; count < PERF_LOOPS_WARMUP; ++count) {
            alg->decrypt
                (plaintext, &len, ciphertext, clen, 0, 0, nonce, key);
        }
        ref_time = cipher_ref_metrics.decrypt_1024;
        break;
    }

    /* Reduce the number of loops for slow ciphers */
    if (slow)
        loops = PERF_LOOPS_SLOW;
    else
        loops = PERF_LOOPS;
    bytes = loops * plen;

    /* Now measure the timing for real */
    if (mode == MODE_ENC128 || mode == MODE_ENC16 || mode == MODE_ENC1024) {
        start = perf_timer_get_time();
        for (count = 0; count < loops; ++count) {
            alg->encrypt
                (ciphertext, &len, plaintext, plen, 0, 0, nonce, key);
        }
        elapsed = perf_timer_get_time() - start;
    } else {
        start = perf_timer_get_time();
        for (count = 0; count < loops; ++count) {
            alg->decrypt
                (plaintext, &len, ciphertext, clen, 0, 0, nonce, key);
        }
        elapsed = perf_timer_get_time() - start;
    }

    /* Report the results */
    if (report) {
        if (ref_time != 0 && elapsed != 0)
            printf("%.2fx, ", ((double)ref_time) / elapsed);
        printf(" %.3f ns/byte, %.3f MiB/sec\n",
               (elapsed * 1000000000.0) / (bytes * ticks_per_second),
               (bytes * (double)ticks_per_second) / (elapsed * 1024.0 * 1024.0));
    }

    /* Return the elapsed time to the caller */
    return elapsed;
}

/* Generate performance metrics for a cipher algorithm */
static void perf_cipher_metrics
    (const aead_cipher_t *alg, perf_cipher_metrics_t *metrics,
     int report, int slow)
{
    if (report)
        printf("%s:\n", alg->name);

    metrics->encrypt_128 =
        perf_cipher_encrypt_decrypt
            (alg, "encrypt 128", MODE_ENC128, report, slow);

    metrics->decrypt_128 =
        perf_cipher_encrypt_decrypt
            (alg, "decrypt 128", MODE_DEC128, report, slow);

    metrics->encrypt_16 =
        perf_cipher_encrypt_decrypt
            (alg, "encrypt 16", MODE_ENC16, report, slow);

    metrics->decrypt_16 =
        perf_cipher_encrypt_decrypt
            (alg, "decrypt 16", MODE_DEC16, report, slow);

#if 0
    metrics->encrypt_1024 =
        perf_cipher_encrypt_decrypt
            (alg, "encrypt 1024", MODE_ENC1024, report, slow);

    metrics->decrypt_1024 =
        perf_cipher_encrypt_decrypt
            (alg, "decrypt 1024", MODE_DEC1024, report, slow);
#endif

    if (report) {
        if (metrics->encrypt_128 != 0) {
            /* For fair comparison with the Arduino performance framework,
             * we don't include 1024 byte runs in the overall average. */
            perf_timer_t ref_total, act_total;
            ref_total = cipher_ref_metrics.encrypt_128 +
                        cipher_ref_metrics.decrypt_128 +
                        cipher_ref_metrics.encrypt_16  +
                        cipher_ref_metrics.encrypt_16;
            act_total = metrics->encrypt_128 +
                        metrics->decrypt_128 +
                        metrics->encrypt_16  +
                        metrics->encrypt_16;
            printf("   average ... %.2fx\n", ((double)ref_total) / act_total);
        }
        printf("\n");
    }
}

/* Compare the performance of a cipher against ChaChaPoly */
static int perf_cipher(const aead_cipher_t *alg)
{
    perf_cipher_metrics_t metrics;
    int slow;

    slow = (alg->flags & (AEAD_FLAG_SLOW | AEAD_FLAG_MASKED)) != 0;

    perf_cipher_metrics(&internal_chachapoly_cipher, &cipher_ref_metrics, 0, slow);
    perf_cipher_metrics(alg, &metrics, 1, slow);

    return 0;
}

/* Test a hash algorithm on a specific test vector */
static int test_hash_inner
    (const aead_hash_algorithm_t *alg, const test_vector_t *vec)
{
    unsigned char *out;
    void *state;
    const test_string_t *msg;
    const test_string_t *md;
    unsigned hash_len;
    size_t index;
    size_t inc;

    /* Get the parameters for the test */
    msg = get_test_string(vec, "Msg");
    md = get_test_string(vec, "MD");

    /* Allocate the output buffer */
    hash_len = md->size;
    if (!alg->squeeze) {
        if (hash_len != alg->hash_len) {
            test_print_error
                (alg->name, vec, "incorrect hash size in test data");
            return 0;
        }
    }
    out = malloc(hash_len);
    if (!out)
        exit(2);

    /* Hash the input message with the all-in-one function */
    if (!alg->init_fixed && hash_len == alg->hash_len) {
        memset(out, 0xAA, alg->hash_len);
        (*(alg->hash))(out, msg->data, msg->size);
        if (!test_compare(out, md->data, md->size)) {
            test_print_error(alg->name, vec, "all-in-one hash failed");
            free(out);
            return 0;
        }
    }

    /*#define ADVANCE_INC(inc)    (++(inc))*/
    #define ADVANCE_INC(inc)    ((inc) *= 2)

    /* Do we have incremental hash functions? */
    state = malloc(alg->state_size);
    if (!state)
        exit(2);
    if (alg->init && alg->update && alg->finalize &&
            hash_len == alg->hash_len) {
        /* Incremental hashing with single finalize step */
        for (inc = 1; inc <= msg->size; ADVANCE_INC(inc)) {
            (*(alg->init))(state);
            for (index = 0; index < msg->size; index += inc) {
                size_t temp = msg->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->update))(state, msg->data + index, temp);
            }
            memset(out, 0xAA, hash_len);
            (*(alg->finalize))(state, out);
            if (alg->free)
                (*(alg->free))(state);
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental hash failed");
                free(state);
                free(out);
                return 0;
            }
        }
    }
    if (alg->init && alg->absorb && alg->squeeze) {
        /* Incremental absorb with all-in-one squeeze output */
        for (inc = 1; inc <= msg->size; ADVANCE_INC(inc)) {
            if (alg->init_fixed)
                (*(alg->init_fixed))(state, hash_len);
            else
                (*(alg->init))(state);
            for (index = 0; index < msg->size; index += inc) {
                size_t temp = msg->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->absorb))(state, msg->data + index, temp);
            }
            memset(out, 0xAA, hash_len);
            (*(alg->squeeze))(state, out, hash_len);
            if (alg->free)
                (*(alg->free))(state);
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental absorb failed");
                free(state);
                free(out);
                return 0;
            }
        }

        /* All-in-one absorb with incremental squeeze output */
        for (inc = 1; inc <= md->size; ADVANCE_INC(inc)) {
            if (alg->init_fixed)
                (*(alg->init_fixed))(state, hash_len);
            else
                (*(alg->init))(state);
            (*(alg->absorb))(state, msg->data, msg->size);
            memset(out, 0xAA, hash_len);
            for (index = 0; index < md->size; index += inc) {
                size_t temp = md->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->squeeze))(state, out + index, temp);
            }
            if (alg->free)
                (*(alg->free))(state);
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental squeeze failed");
                free(state);
                free(out);
                return 0;
            }
        }
    }
    free(state);
    free(out);

    /* All tests passed for this test vector */
    return 1;
}

/* Test a hash algorithm */
static int test_hash(const aead_hash_algorithm_t *alg, FILE *file)
{
    test_vector_t vec;
    int success = 0;
    int fail = 0;
    while (test_vector_read(&vec, file)) {
        if (test_hash_inner(alg, &vec))
            ++success;
        else
            ++fail;
        test_vector_free(&vec);
    }
    printf("%s: %d tests succeeded, %d tests failed\n",
           alg->name, success, fail);
    return fail != 0;
}

/* Metrics that have been collected for various hashing scenarios */
typedef struct
{
    perf_timer_t hash_1024;
    perf_timer_t hash_128;
    perf_timer_t hash_16;

} perf_hash_metrics_t;

/* Reference metrics for the BLAKE2s hash algorithm */
static perf_hash_metrics_t hash_ref_metrics;

#define MAX_HASH_SIZE 64
#define MAX_HASH_DATA_SIZE 1024
#define PERF_HASH_LOOPS 100000

/* Generate performance metrics for a cipher algorithm: encrypt 128 bytes */
static perf_timer_t perf_hash_N
    (const aead_hash_algorithm_t *alg, perf_timer_t ref_time,
     int size, int report)
{
    unsigned char hash_buffer[MAX_HASH_DATA_SIZE];
    unsigned char hash_output[MAX_HASH_SIZE];
    perf_timer_t start, elapsed;
    perf_timer_t ticks_per_second = perf_timer_ticks_per_second();
    int count;
    int loops;
    int bytes;

    /* Print what we are doing now */
    if (report) {
        printf("   hash %4d bytes ... ", size);
        fflush(stdout);
    }

    /* Initialize the hash input buffer */
    for (count = 0; count < MAX_HASH_DATA_SIZE; ++count)
        hash_buffer[count] = (unsigned char)count;

    /* Run several loops without timing to force the CPU
     * to load the code and data into internal cache to get
     * the best speed when we measure properly later. */
    for (count = 0; count < PERF_LOOPS_WARMUP; ++count)
        alg->hash(hash_output, hash_buffer, size);

    /* Determine how many loops to do; more on the smaller sizes */
    if (size < 1024)
        loops = PERF_HASH_LOOPS * 4;
    else
        loops = PERF_HASH_LOOPS;

    /* Now measure the timing for real */
    start = perf_timer_get_time();
    for (count = 0; count < loops; ++count)
        alg->hash(hash_output, hash_buffer, size);
    elapsed = perf_timer_get_time() - start;
    bytes = size * loops;

    /* Report the results */
    if (report) {
        if (ref_time != 0 && elapsed != 0)
            printf("%.2fx, ", ((double)ref_time) / elapsed);
        printf(" %.3f ns/byte, %.3f MiB/sec\n",
               (elapsed * 1000000000.0) / (bytes * ticks_per_second),
               (bytes * (double)ticks_per_second) / (elapsed * 1024.0 * 1024.0));
    }

    /* Return the elapsed time to the caller */
    return elapsed;
}

/* Generate performance metrics for a hash algorithm */
static void perf_hash_metrics
    (const aead_hash_algorithm_t *alg, perf_hash_metrics_t *metrics, int report)
{
    if (report)
        printf("%s:\n", alg->name);

    metrics->hash_1024 =
        perf_hash_N(alg, hash_ref_metrics.hash_1024, 1024, report);
    metrics->hash_128 =
        perf_hash_N(alg, hash_ref_metrics.hash_128, 128, report);
    metrics->hash_16 =
        perf_hash_N(alg, hash_ref_metrics.hash_16, 16, report);

    if (report) {
        if (metrics->hash_1024 != 0) {
            double avg =
                ((double)(hash_ref_metrics.hash_1024)) / metrics->hash_1024;
            avg += ((double)(hash_ref_metrics.hash_128)) / metrics->hash_128;
            avg += ((double)(hash_ref_metrics.hash_16)) / metrics->hash_16;
            avg /= 3.0;
            printf("   average ... %.2fx\n", avg);
        }
        printf("\n");
    }
}

/* Generate performance metrics for a hash algorithm */
static int perf_hash(const aead_hash_algorithm_t *alg)
{
    perf_hash_metrics_t metrics;

    perf_hash_metrics(&internal_blake2s_hash_algorithm, &hash_ref_metrics, 0);
    perf_hash_metrics(alg, &metrics, 1);

    return 0;
}

/* Test an authentication algorithm on a specific test vector */
static int test_auth_inner
    (const aead_auth_algorithm_t *alg, const test_vector_t *vec)
{
    unsigned char *out;
    void *state;
    const test_string_t *key;
    const test_string_t *msg;
    const test_string_t *tag;
    const unsigned char *custom = 0;
    size_t customlen = 0;
    size_t outlen;
    size_t index;
    size_t inc;

    /* Get the parameters for the test */
    key = get_test_string(vec, "Key");
    msg = get_test_string(vec, "Msg");
    tag = get_test_string(vec, "Tag");
    if (alg->flags & AEAD_FLAG_CUSTOMIZATION) {
        /* We require a customization string for this algorithm */
        const test_string_t *cust = get_test_string(vec, "Custom");
        custom = cust->data;
        customlen = cust->size;
    }
    if (key->size != alg->key_len) {
        test_print_error(alg->name, vec, "incorrect key size in test data");
        return 0;
    }
    outlen = tag->size;
    if (outlen < alg->tag_len) {
        test_print_error(alg->name, vec, "incorrect tag size in test data");
        return 0;
    }
    out = malloc(outlen);
    if (!out)
        exit(2);

    /* Compute the result with the all-in-one function */
    memset(out, 0xAA, outlen);
    (*(alg->compute))
        (out, tag->size, key->data, key->size, msg->data, msg->size,
         custom, customlen);
    if (!test_compare(out, tag->data, tag->size)) {
        test_print_error(alg->name, vec, "all-in-one auth failed");
        free(out);
        return 0;
    }

    /* Verify the result with the all-in-one function */
    if (alg->verify) {
        if ((*(alg->verify))
                (out, tag->size, key->data, key->size,
                 msg->data, msg->size, custom, customlen) != 0) {
            test_print_error(alg->name, vec, "all-in-one auth verify failed");
            free(out);
            return 0;
        }
        out[2] ^= 0x01; /* Deliberately corrupt the tag */
        if ((*(alg->verify))
                (out, tag->size, key->data, key->size,
                 msg->data, msg->size, custom, customlen) == 0) {
            test_print_error(alg->name, vec, "all-in-one auth verify succeeded when it should not have");
            free(out);
            return 0;
        }
    }

    /* Do we have incremental PRF functions? */
    state = malloc(alg->state_size);
    if (!state)
        exit(2);
    if ((alg->init || alg->init_fixed || alg->init_custom) && alg->absorb &&
            (alg->squeeze || alg->hmac_finalize)) {
        /* Incremental absorb with single squeeze step */
        for (inc = 1; inc <= msg->size; ADVANCE_INC(inc)) {
            if (alg->init_custom) {
                (*(alg->init_custom))
                    (state, key->data, key->size, custom, customlen, outlen);
            } else if (alg->init_fixed) {
                (*(alg->init_fixed))(state, key->data, key->size, outlen);
            } else {
                (*(alg->init))(state, key->data, key->size);
            }
            for (index = 0; index < msg->size; index += inc) {
                size_t temp = msg->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->absorb))(state, msg->data + index, temp);
            }
            memset(out, 0xAA, outlen);
            if (alg->hmac_finalize)
                (*(alg->hmac_finalize))(state, key->data, key->size, out);
            else
                (*(alg->squeeze))(state, out, outlen);
            if (alg->free)
                (*(alg->free))(state);
            if (!test_compare(out, tag->data, tag->size)) {
                test_print_error(alg->name, vec, "incremental absorb failed");
                free(out);
                free(state);
                return 0;
            }
        }

        /* All-in-one absorb with incremental squeeze output */
        for (inc = 1; inc <= outlen && alg->squeeze; ADVANCE_INC(inc)) {
            if (alg->init_custom) {
                (*(alg->init_custom))
                    (state, key->data, key->size, custom, customlen, outlen);
            } else if (alg->init_fixed) {
                (*(alg->init_fixed))(state, key->data, key->size, outlen);
            } else {
                (*(alg->init))(state, key->data, key->size);
            }
            (*(alg->absorb))(state, msg->data, msg->size);
            memset(out, 0xAA, outlen);
            for (index = 0; index < outlen; index += inc) {
                size_t temp = tag->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->squeeze))(state, out + index, temp);
            }
            if (alg->free)
                (*(alg->free))(state);
            if (!test_compare(out, tag->data, tag->size)) {
                test_print_error(alg->name, vec, "incremental squeeze failed");
                free(out);
                free(state);
                return 0;
            }
        }
    }
    free(out);
    free(state);

    /* All tests passed for this test vector */
    return 1;
}

/* Test an authentication algorithm */
static int test_auth(const aead_auth_algorithm_t *alg, FILE *file)
{
    test_vector_t vec;
    int success = 0;
    int fail = 0;
    while (test_vector_read(&vec, file)) {
        if (test_auth_inner(alg, &vec))
            ++success;
        else
            ++fail;
        test_vector_free(&vec);
    }
    printf("%s: %d tests succeeded, %d tests failed\n",
           alg->name, success, fail);
    return fail != 0;
}

/* Generate performance metrics for an authentication algorithm */
static int perf_auth(const aead_auth_algorithm_t *alg)
{
    /* TODO */
    (void)alg;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *progname = argv[0];
    const aead_cipher_t *cipher;
    const aead_hash_algorithm_t *hash;
    const aead_auth_algorithm_t *auth;
    int exit_val;
    int performance = 0;
    FILE *file;

    /* If "--algorithms" is supplied, then list all supported algorithms */
    if (argc > 1 && !strcmp(argv[1], "--algorithms")) {
        print_algorithm_names();
        return 0;
    }

    /* Check that we have all command-line arguments that we need */
    if (argc > 3 && !strcmp(argv[1], "--performance")) {
        performance = 1;
        if (!perf_timer_init()) {
            fprintf(stderr, "%s: do not know how to time events on this system\n", progname);
            return 1;
        }
        --argc;
        ++argv;
    }
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [--performance] Algorithm KAT-file\n", progname);
        return 1;
    }

    /* Open the KAT input file */
    if (!strcmp(argv[2], "-")) {
        file = stdin;
    } else if ((file = fopen(argv[2], "r")) == NULL) {
        perror(argv[2]);
        return 1;
    }

    /* Look for a cipher with the specified name */
    cipher = find_cipher(argv[1]);
    if (cipher) {
        if (performance) {
            if (file != stdin)
                fclose(file);
            exit_val = perf_cipher(cipher);
        } else {
            exit_val = test_cipher(cipher, file);
            if (file != stdin)
                fclose(file);
        }
        return exit_val;
    }

    /* Look for a hash algorithm with the specified name */
    hash = find_hash_algorithm(argv[1]);
    if (hash) {
        if (performance) {
            if (file != stdin)
                fclose(file);
            exit_val = perf_hash(hash);
        } else {
            exit_val = test_hash(hash, file);
            if (file != stdin)
                fclose(file);
        }
        return exit_val;
    }

    /* Look for an authentication algorithm with the specified name */
    auth = find_auth_algorithm(argv[1]);
    if (auth) {
        if (performance) {
            if (file != stdin)
                fclose(file);
            exit_val = perf_auth(auth);
        } else {
            exit_val = test_auth(auth, file);
            if (file != stdin)
                fclose(file);
        }
        return exit_val;
    }

    /* Unknown algorithm name */
    if (file != stdin)
        fclose(file);
    fprintf(stderr, "Unknown algorithm '%s'\n", argv[1]);
    print_algorithm_names();
    return 1;
}
