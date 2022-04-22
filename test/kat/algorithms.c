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

#include "algorithms.h"
#include <ascon/aead.h>
#include <ascon/isap.h>
#include <ascon/siv.h>
#include <ascon/hash.h>
#include <ascon/xof.h>
#include <string.h>
#include <stdio.h>

aead_cipher_t const ascon128_cipher = {
    "ASCON-128",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_aead_encrypt,
    ascon128_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128a_cipher = {
    "ASCON-128a",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_aead_encrypt,
    ascon128a_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon80pq_cipher = {
    "ASCON-80pq",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_aead_encrypt,
    ascon80pq_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_hash_algorithm_t const ascon_hash_algorithm = {
    "ASCON-HASH",
    sizeof(ascon_hash_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_hash,
    (aead_hash_init_t)ascon_hash_init,
    0, /* init_fixed */
    (aead_hash_update_t)ascon_hash_update,
    (aead_hash_finalize_t)ascon_hash_finalize,
    0, /* absorb */
    0  /* squeeze */
};

aead_hash_algorithm_t const ascon_hasha_algorithm = {
    "ASCON-HASHA",
    sizeof(ascon_hash_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_hasha,
    (aead_hash_init_t)ascon_hasha_init,
    0, /* init_fixed */
    (aead_hash_update_t)ascon_hasha_update,
    (aead_hash_finalize_t)ascon_hasha_finalize,
    0, /* absorb */
    0  /* squeeze */
};

aead_hash_algorithm_t const ascon_xof_algorithm = {
    "ASCON-XOF",
    sizeof(ascon_xof_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xof,
    (aead_hash_init_t)ascon_xof_init,
    0, /* init_fixed */
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xof_absorb,
    (aead_xof_squeeze_t)ascon_xof_squeeze
};

aead_hash_algorithm_t const ascon_xofa_algorithm = {
    "ASCON-XOFA",
    sizeof(ascon_xofa_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xofa,
    (aead_hash_init_t)ascon_xofa_init,
    0, /* init_fixed */
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xofa_absorb,
    (aead_xof_squeeze_t)ascon_xofa_squeeze
};

aead_hash_algorithm_t const ascon_xof_fixed_length_algorithm = {
    "ASCON-XOF-fixed-length",
    sizeof(ascon_xof_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xof,
    (aead_hash_init_t)ascon_xof_init,
    (aead_hash_init_fixed_t)ascon_xof_init_fixed,
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xof_absorb,
    (aead_xof_squeeze_t)ascon_xof_squeeze
};

aead_hash_algorithm_t const ascon_xofa_fixed_length_algorithm = {
    "ASCON-XOFA-fixed-length",
    sizeof(ascon_xofa_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xofa,
    (aead_hash_init_t)ascon_xofa_init,
    (aead_hash_init_fixed_t)ascon_xofa_init_fixed,
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xofa_absorb,
    (aead_xof_squeeze_t)ascon_xofa_squeeze
};

aead_cipher_t const ascon128_siv_cipher = {
    "ASCON-128-SIV",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_siv_encrypt,
    ascon128_siv_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128a_siv_cipher = {
    "ASCON-128a-SIV",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_siv_encrypt,
    ascon128a_siv_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon80pq_siv_cipher = {
    "ASCON-80pq-SIV",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_siv_encrypt,
    ascon80pq_siv_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128a_isap_cipher = {
    "ISAP-A-128A",
    ASCON_ISAP_KEY_SIZE,
    ASCON_ISAP_NONCE_SIZE,
    ASCON_ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)ascon128a_isap_aead_encrypt,
    (aead_cipher_decrypt_t)ascon128a_isap_aead_decrypt,
    sizeof(ascon128a_isap_aead_key_t),
    (aead_cipher_pk_init_t)ascon128a_isap_aead_init,
    (aead_cipher_pk_free_t)ascon128a_isap_aead_free,
    0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128_isap_cipher = {
    "ISAP-A-128",
    ASCON_ISAP_KEY_SIZE,
    ASCON_ISAP_NONCE_SIZE,
    ASCON_ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)ascon128_isap_aead_encrypt,
    (aead_cipher_decrypt_t)ascon128_isap_aead_decrypt,
    sizeof(ascon128_isap_aead_key_t),
    (aead_cipher_pk_init_t)ascon128_isap_aead_init,
    (aead_cipher_pk_free_t)ascon128_isap_aead_free,
    0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128_inc_cipher = {
    "ASCON-128-incremental",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_aead_encrypt,
    ascon128_aead_decrypt,
    0, 0, 0,
    sizeof(ascon128_state_t),
    (aead_cipher_inc_start_t)ascon128_aead_start,
    (aead_cipher_enc_inc_t)ascon128_aead_encrypt_block,
    (aead_cipher_enc_fin_t)ascon128_aead_encrypt_finalize,
    (aead_cipher_dec_inc_t)ascon128_aead_decrypt_block,
    (aead_cipher_dec_fin_t)ascon128_aead_decrypt_finalize
};

aead_cipher_t const ascon128a_inc_cipher = {
    "ASCON-128a-incremental",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_aead_encrypt,
    ascon128a_aead_decrypt,
    0, 0, 0,
    sizeof(ascon128a_state_t),
    (aead_cipher_inc_start_t)ascon128a_aead_start,
    (aead_cipher_enc_inc_t)ascon128a_aead_encrypt_block,
    (aead_cipher_enc_fin_t)ascon128a_aead_encrypt_finalize,
    (aead_cipher_dec_inc_t)ascon128a_aead_decrypt_block,
    (aead_cipher_dec_fin_t)ascon128a_aead_decrypt_finalize
};

aead_cipher_t const ascon80pq_inc_cipher = {
    "ASCON-80pq-incremental",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_aead_encrypt,
    ascon80pq_aead_decrypt,
    0, 0, 0,
    sizeof(ascon80pq_state_t),
    (aead_cipher_inc_start_t)ascon80pq_aead_start,
    (aead_cipher_enc_inc_t)ascon80pq_aead_encrypt_block,
    (aead_cipher_enc_fin_t)ascon80pq_aead_encrypt_finalize,
    (aead_cipher_dec_inc_t)ascon80pq_aead_decrypt_block,
    (aead_cipher_dec_fin_t)ascon80pq_aead_decrypt_finalize
};

/* List of all AEAD ciphers that we can run KAT tests for */
static const aead_cipher_t *const ciphers[] = {
    &ascon128_cipher,
    &ascon128a_cipher,
    &ascon80pq_cipher,
    &ascon128_siv_cipher,
    &ascon128a_siv_cipher,
    &ascon80pq_siv_cipher,
    &ascon128a_isap_cipher,
    &ascon128_isap_cipher,
    &ascon128_inc_cipher,
    &ascon128a_inc_cipher,
    &ascon80pq_inc_cipher,
    0
};

/* List of all hash algorithms that we can run KAT tests for */
static const aead_hash_algorithm_t *const hashes[] = {
    &ascon_hash_algorithm,
    &ascon_hasha_algorithm,
    &ascon_xof_algorithm,
    &ascon_xofa_algorithm,
    &ascon_xof_fixed_length_algorithm,
    &ascon_xofa_fixed_length_algorithm,
    0
};

const aead_cipher_t *find_cipher(const char *name)
{
    int index;
    for (index = 0; ciphers[index] != 0; ++index) {
        if (!strcmp(ciphers[index]->name, name))
            return ciphers[index];
    }
    return 0;
}

const aead_hash_algorithm_t *find_hash_algorithm(const char *name)
{
    int index;
    for (index = 0; hashes[index] != 0; ++index) {
        if (!strcmp(hashes[index]->name, name))
            return hashes[index];
    }
    return 0;
}

static void print_cipher_details(const aead_cipher_t *cipher)
{
    printf("%-30s %8u   %8u   %8u\n",
           cipher->name,
           cipher->key_len * 8,
           cipher->nonce_len * 8,
           cipher->tag_len * 8);
}

static void print_hash_details(const aead_hash_algorithm_t *hash)
{
    printf("%-30s %8u\n", hash->name, hash->hash_len * 8);
}

void print_algorithm_names(void)
{
    int index;
    printf("\nCipher                           Key Bits");
    printf("  Nonce Bits  Tag Bits\n");
    for (index = 0; ciphers[index] != 0; ++index)
        print_cipher_details(ciphers[index]);
    printf("\nHash Algorithm                   Hash Bits\n");
    for (index = 0; hashes[index] != 0; ++index)
        print_hash_details(hashes[index]);
}
