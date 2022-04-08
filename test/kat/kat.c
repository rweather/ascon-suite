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

/* Dynamically-allocated test string that was converted from hexadecimal */
typedef struct {
    size_t size;
    unsigned char data[1];
} test_string_t;

/* Create a test string from a hexadecimal string */
static test_string_t *create_test_string(const char *in)
{
    int value;
    int nibble;
    int phase;
    test_string_t *out;
    out = (test_string_t *)malloc(sizeof(test_string_t) + (strlen(in) / 2));
    if (!out)
        exit(2);
    out->size = 0;
    value = 0;
    phase = 0;
    while (*in != '\0') {
        int ch = *in++;
        if (ch >= '0' && ch <= '9')
            nibble = ch - '0';
        else if (ch >= 'A' && ch <= 'F')
            nibble = ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'f')
            nibble = ch - 'a' + 10;
        else
            continue; /* skip whitespace and other separators */
        if (!phase) {
            value = nibble << 4;
            phase = 1;
        } else {
            out->data[(out->size)++] = value | nibble;
            phase = 0;
        }
    }
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

/* Test a cipher algorithm on a specific test vector */
static int test_cipher_inner
    (const aead_cipher_t *alg, const test_vector_t *vec)
{
    unsigned char *pk = 0;
    const test_string_t *key;
    const test_string_t *nonce;
    const test_string_t *plaintext;
    const test_string_t *ciphertext;
    const test_string_t *ad;
    unsigned char *temp1;
    unsigned char *temp2;
    const unsigned char *actual_key = 0;
    size_t len;
    int result;

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

    /* Test encryption */
    memset(temp1, 0xAA, ciphertext->size);
    len = 0xBADBEEF;
    result = (*(alg->encrypt))
        (temp1, &len, plaintext->data, plaintext->size,
         ad->data, ad->size, nonce->data, actual_key);
    if (result != 0 || len != ciphertext->size ||
            !test_compare(temp1, ciphertext->data, len)) {
        test_print_error(alg->name, vec, "encryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test in-place encryption */
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp1, plaintext->data, plaintext->size);
    len = 0xBADBEEF;
    result = (*(alg->encrypt))
        (temp1, &len, temp1, plaintext->size,
         ad->size ? ad->data : 0, ad->size, nonce->data, actual_key);
    if (result != 0 || len != ciphertext->size ||
            !test_compare(temp1, ciphertext->data, len)) {
        test_print_error(alg->name, vec, "in-place encryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test decryption */
    memset(temp1, 0xAA, ciphertext->size);
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, ciphertext->data, ciphertext->size,
         ad->data, ad->size, nonce->data, actual_key);
    if (result != 0 || len != plaintext->size ||
            !test_compare(temp1, plaintext->data, len)) {
        test_print_error(alg->name, vec, "decryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test in-place decryption */
    memcpy(temp1, ciphertext->data, ciphertext->size);
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, temp1, ciphertext->size,
         ad->data, ad->size, nonce->data, actual_key);
    if (result != 0 || len != plaintext->size ||
            !test_compare(temp1, plaintext->data, len)) {
        test_print_error(alg->name, vec, "in-place decryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test decryption with a failed tag check */
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp2, ciphertext->data, ciphertext->size);
    temp2[0] ^= 0x01; /* Corrupt the first byte of the ciphertext */
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, temp2, ciphertext->size,
         ad->data, ad->size, nonce->data, actual_key);
    if (result != -1) {
        test_print_error(alg->name, vec, "corrupt ciphertext check failed");
        free(temp1);
        free(temp2);
        return 0;
    }
    if (!test_all_zeroes(temp1, plaintext->size)) {
        test_print_error(alg->name, vec, "plaintext not destroyed");
        free(temp1);
        free(temp2);
        return 0;
    }
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp2, ciphertext->data, ciphertext->size);
    temp2[ciphertext->size - 1] ^= 0x01; /* Corrupt last byte of the tag */
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, temp2, ciphertext->size,
         ad->data, ad->size, nonce->data, actual_key);
    if (result != -1) {
        test_print_error(alg->name, vec, "corrupt tag check failed");
        free(temp1);
        free(temp2);
        return 0;
    }
    if (!test_all_zeroes(temp1, plaintext->size)) {
        test_print_error(alg->name, vec, "plaintext not destroyed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* All tests passed for this test vector */
    free(temp1);
    free(temp2);
    if (pk)
        free(pk);
    return 1;
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
    unsigned char out[alg->hash_len];
    void *state;
    const test_string_t *msg;
    const test_string_t *md;
    int result;
    size_t index;
    size_t inc;

    /* Get the parameters for the test */
    msg = get_test_string(vec, "Msg");
    md = get_test_string(vec, "MD");
    if (md->size != alg->hash_len) {
        test_print_error(alg->name, vec, "incorrect hash size in test data");
        return 0;
    }

    /* Hash the input message with the all-in-one function */
    memset(out, 0xAA, alg->hash_len);
    result = (*(alg->hash))(out, msg->data, msg->size);
    if (result != 0) {
        test_print_error(alg->name, vec, "all-in-one hash returned %d", result);
        return 0;
    }
    if (!test_compare(out, md->data, md->size)) {
        test_print_error(alg->name, vec, "all-in-one hash failed");
        return 0;
    }

    /*#define ADVANCE_INC(inc)    (++(inc))*/
    #define ADVANCE_INC(inc)    ((inc) *= 2)

    /* Do we have incremental hash functions? */
    state = malloc(alg->state_size);
    if (!state)
        exit(2);
    if (alg->init && alg->update && alg->finalize) {
        /* Incremental hashing with single finalize step */
        for (inc = 1; inc <= msg->size; ADVANCE_INC(inc)) {
            (*(alg->init))(state);
            for (index = 0; index < msg->size; index += inc) {
                size_t temp = msg->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->update))(state, msg->data + index, temp);
            }
            memset(out, 0xAA, alg->hash_len);
            (*(alg->finalize))(state, out);
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental hash failed");
                free(state);
                return 0;
            }
        }
    }
    if (alg->init && alg->absorb && alg->squeeze) {
        /* Incremental absorb with all-in-one squeeze output */
        for (inc = 1; inc <= msg->size; ADVANCE_INC(inc)) {
            (*(alg->init))(state);
            for (index = 0; index < msg->size; index += inc) {
                size_t temp = msg->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->absorb))(state, msg->data + index, temp);
            }
            memset(out, 0xAA, alg->hash_len);
            (*(alg->squeeze))(state, out, alg->hash_len);
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental absorb failed");
                free(state);
                return 0;
            }
        }

        /* All-in-one absorb with incremental squeeze output */
        for (inc = 1; inc <= md->size; ADVANCE_INC(inc)) {
            (*(alg->init))(state);
            (*(alg->absorb))(state, msg->data, msg->size);
            memset(out, 0xAA, alg->hash_len);
            for (index = 0; index < md->size; index += inc) {
                size_t temp = md->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->squeeze))(state, out + index, temp);
            }
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental squeeze failed");
                free(state);
                return 0;
            }
        }
    }
    free(state);

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

int main(int argc, char *argv[])
{
    const char *progname = argv[0];
    const aead_cipher_t *cipher;
    const aead_hash_algorithm_t *hash;
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
        fprintf(stderr, "Usage: %s Algorithm KAT-file [perf]\n", progname);
        return 1;
    }

    /* Open the KAT input file */
    if ((file = fopen(argv[2], "r")) == NULL) {
        perror(argv[2]);
        return 1;
    }

    /* Look for a cipher with the specified name */
    cipher = find_cipher(argv[1]);
    if (cipher) {
        if (performance) {
            fclose(file);
            exit_val = perf_cipher(cipher);
        } else {
            exit_val = test_cipher(cipher, file);
            fclose(file);
        }
        return exit_val;
    }

    /* Look for a hash algorithm with the specified name */
    hash = find_hash_algorithm(argv[1]);
    if (hash) {
        if (performance) {
            fclose(file);
            exit_val = perf_hash(hash);
        } else {
            exit_val = test_hash(hash, file);
            fclose(file);
        }
        return exit_val;
    }

    /* Unknown algorithm name */
    fclose(file);
    fprintf(stderr, "Unknown algorithm '%s'\n", argv[1]);
    print_algorithm_names();
    return 1;
}
