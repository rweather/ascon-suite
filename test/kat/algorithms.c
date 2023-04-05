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
#include <ascon/aead-masked.h>
#include <ascon/isap.h>
#include <ascon/siv.h>
#include <ascon/hash.h>
#include <ascon/xof.h>
#include <ascon/prf.h>
#include <ascon/hmac.h>
#include <ascon/kmac.h>
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
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128a_cipher = {
    "ASCON-128a",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_aead_encrypt,
    ascon128a_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon80pq_cipher = {
    "ASCON-80pq",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_aead_encrypt,
    ascon80pq_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
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
    0, /* squeeze */
    (aead_hash_free_t)ascon_hash_free
};

aead_hash_algorithm_t const ascon_hasha_algorithm = {
    "ASCON-HASHA",
    sizeof(ascon_hash_state_t),
    ASCON_HASHA_SIZE,
    AEAD_FLAG_NONE,
    ascon_hasha,
    (aead_hash_init_t)ascon_hasha_init,
    0, /* init_fixed */
    (aead_hash_update_t)ascon_hasha_update,
    (aead_hash_finalize_t)ascon_hasha_finalize,
    0, /* absorb */
    0, /* squeeze */
    (aead_hash_free_t)ascon_hasha_free
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
    (aead_xof_squeeze_t)ascon_xof_squeeze,
    (aead_hash_free_t)ascon_xof_free
};

aead_hash_algorithm_t const ascon_xofa_algorithm = {
    "ASCON-XOFA",
    sizeof(ascon_xofa_state_t),
    ASCON_HASHA_SIZE,
    AEAD_FLAG_NONE,
    ascon_xofa,
    (aead_hash_init_t)ascon_xofa_init,
    0, /* init_fixed */
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xofa_absorb,
    (aead_xof_squeeze_t)ascon_xofa_squeeze,
    (aead_hash_free_t)ascon_xofa_free
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
    (aead_xof_squeeze_t)ascon_xof_squeeze,
    (aead_hash_free_t)ascon_xof_free
};

aead_hash_algorithm_t const ascon_xofa_fixed_length_algorithm = {
    "ASCON-XOFA-fixed-length",
    sizeof(ascon_xofa_state_t),
    ASCON_HASHA_SIZE,
    AEAD_FLAG_NONE,
    ascon_xofa,
    (aead_hash_init_t)ascon_xofa_init,
    (aead_hash_init_fixed_t)ascon_xofa_init_fixed,
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xofa_absorb,
    (aead_xof_squeeze_t)ascon_xofa_squeeze,
    (aead_hash_free_t)ascon_xofa_free
};

aead_cipher_t const ascon128_siv_cipher = {
    "ASCON-128-SIV",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_siv_encrypt,
    ascon128_siv_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128a_siv_cipher = {
    "ASCON-128a-SIV",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_siv_encrypt,
    ascon128a_siv_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon80pq_siv_cipher = {
    "ASCON-80pq-SIV",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_siv_encrypt,
    ascon80pq_siv_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128a_isap_cipher = {
    "ISAP-A-128A",
    ASCON128_ISAP_KEY_SIZE,
    ASCON_ISAP_NONCE_SIZE,
    ASCON_ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)ascon128a_isap_aead_encrypt,
    (aead_cipher_decrypt_t)ascon128a_isap_aead_decrypt,
    sizeof(ascon128a_isap_aead_key_t),
    (aead_cipher_pk_init_t)ascon128a_isap_aead_init,
    (aead_cipher_pk_free_t)ascon128a_isap_aead_free,
    0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128_isap_cipher = {
    "ISAP-A-128",
    ASCON128_ISAP_KEY_SIZE,
    ASCON_ISAP_NONCE_SIZE,
    ASCON_ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)ascon128_isap_aead_encrypt,
    (aead_cipher_decrypt_t)ascon128_isap_aead_decrypt,
    sizeof(ascon128_isap_aead_key_t),
    (aead_cipher_pk_init_t)ascon128_isap_aead_init,
    (aead_cipher_pk_free_t)ascon128_isap_aead_free,
    0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon80pq_isap_cipher = {
    "ISAP-A-80PQ",
    ASCON80PQ_ISAP_KEY_SIZE,
    ASCON_ISAP_NONCE_SIZE,
    ASCON_ISAP_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_KEY | AEAD_FLAG_SLOW,
    (aead_cipher_encrypt_t)ascon80pq_isap_aead_encrypt,
    (aead_cipher_decrypt_t)ascon80pq_isap_aead_decrypt,
    sizeof(ascon80pq_isap_aead_key_t),
    (aead_cipher_pk_init_t)ascon80pq_isap_aead_init,
    (aead_cipher_pk_free_t)ascon80pq_isap_aead_free,
    0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128_inc_cipher = {
    "ASCON-128-incremental",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_aead_encrypt,
    ascon128_aead_decrypt,
    0, 0,
    (aead_cipher_pk_free_t)ascon128_aead_free,
    sizeof(ascon128_state_t),
    (aead_cipher_inc_init_t)ascon128_aead_init,
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
    0, 0,
    (aead_cipher_pk_free_t)ascon128a_aead_free,
    sizeof(ascon128a_state_t),
    (aead_cipher_inc_init_t)ascon128a_aead_init,
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
    0, 0,
    (aead_cipher_pk_free_t)ascon80pq_aead_free,
    sizeof(ascon80pq_state_t),
    (aead_cipher_inc_init_t)ascon80pq_aead_init,
    (aead_cipher_inc_start_t)ascon80pq_aead_start,
    (aead_cipher_enc_inc_t)ascon80pq_aead_encrypt_block,
    (aead_cipher_enc_fin_t)ascon80pq_aead_encrypt_finalize,
    (aead_cipher_dec_inc_t)ascon80pq_aead_decrypt_block,
    (aead_cipher_dec_fin_t)ascon80pq_aead_decrypt_finalize
};

aead_cipher_t const ascon128_masked_cipher = {
    "ASCON-128-masked",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL,
    (aead_cipher_encrypt_t)ascon128_masked_aead_encrypt,
    (aead_cipher_decrypt_t)ascon128_masked_aead_decrypt,
    sizeof(ascon_masked_key_128_t),
    (aead_cipher_pk_init_t)ascon_masked_key_128_init,
    (aead_cipher_pk_free_t)ascon_masked_key_128_free,
    0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon128a_masked_cipher = {
    "ASCON-128a-masked",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL,
    (aead_cipher_encrypt_t)ascon128a_masked_aead_encrypt,
    (aead_cipher_decrypt_t)ascon128a_masked_aead_decrypt,
    sizeof(ascon_masked_key_128_t),
    (aead_cipher_pk_init_t)ascon_masked_key_128_init,
    (aead_cipher_pk_free_t)ascon_masked_key_128_free,
    0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const ascon80pq_masked_cipher = {
    "ASCON-80pq-masked",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL,
    (aead_cipher_encrypt_t)ascon80pq_masked_aead_encrypt,
    (aead_cipher_decrypt_t)ascon80pq_masked_aead_decrypt,
    sizeof(ascon_masked_key_160_t),
    (aead_cipher_pk_init_t)ascon_masked_key_160_init,
    (aead_cipher_pk_free_t)ascon_masked_key_160_free,
    0, 0, 0, 0, 0, 0, 0
};

static void ascon_prf_compute_wrapper
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    (void)keylen;
    (void)custom;
    (void)customlen;
    ascon_prf(tag, taglen, in, inlen, key);
}

static void ascon_prf_short_compute_wrapper
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    (void)keylen;
    (void)custom;
    (void)customlen;
    ascon_prf_short(tag, taglen, in, inlen, key);
}

static void ascon_mac_compute_wrapper
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    (void)keylen;
    (void)taglen;
    (void)custom;
    (void)customlen;
    ascon_mac(tag, in, inlen, key);
}

static int ascon_mac_verify_wrapper
    (const unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    (void)keylen;
    (void)taglen;
    (void)custom;
    (void)customlen;
    return ascon_mac_verify(tag, in, inlen, key);
}

static void ascon_prf_init_wrapper
    (void *state, const unsigned char *key, size_t keylen)
{
    (void)keylen;
    ascon_prf_init(state, key);
}

static void ascon_prf_fixed_init_wrapper
    (void *state, const unsigned char *key, size_t keylen, size_t length)
{
    (void)keylen;
    ascon_prf_fixed_init(state, key, length);
}

static void ascon_hmac_compute_wrapper
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    (void)taglen;
    (void)custom;
    (void)customlen;
    ascon_hmac(tag, key, keylen, in, inlen);
}

static void ascon_hmaca_compute_wrapper
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    (void)taglen;
    (void)custom;
    (void)customlen;
    ascon_hmaca(tag, key, keylen, in, inlen);
}

static void ascon_kmac_compute_wrapper
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    ascon_kmac(key, keylen, in, inlen, custom, customlen, tag, taglen);
}

static void ascon_kmaca_compute_wrapper
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen)
{
    ascon_kmaca(key, keylen, in, inlen, custom, customlen, tag, taglen);
}

aead_auth_algorithm_t const ascon_prf_auth = {
    "ASCON-Prf",
    sizeof(ascon_prf_state_t),
    ASCON_PRF_KEY_SIZE,
    ASCON_PRF_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon_prf_compute_wrapper,
    0,
    (auth_init_t)ascon_prf_init_wrapper,
    0,
    0,
    (aead_xof_absorb_t)ascon_prf_absorb,
    (aead_xof_squeeze_t)ascon_prf_squeeze,
    0,
    (aead_hash_free_t)ascon_prf_free
};

aead_auth_algorithm_t const ascon_prf_short_auth = {
    "ASCON-PrfShort",
    sizeof(ascon_prf_state_t),
    ASCON_PRF_SHORT_KEY_SIZE,
    ASCON_PRF_SHORT_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon_prf_short_compute_wrapper,
    0, 0, 0, 0, 0, 0, 0, 0
};

aead_auth_algorithm_t const ascon_mac_auth = {
    "ASCON-Mac",
    sizeof(ascon_prf_state_t),
    ASCON_MAC_KEY_SIZE,
    ASCON_MAC_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon_mac_compute_wrapper,
    ascon_mac_verify_wrapper,
    0,
    (auth_init_fixed_t)ascon_prf_fixed_init_wrapper,
    0,
    (aead_xof_absorb_t)ascon_prf_absorb,
    (aead_xof_squeeze_t)ascon_prf_squeeze,
    0,
    (aead_hash_free_t)ascon_prf_free
};

aead_auth_algorithm_t const ascon_hmac_auth = {
    "ASCON-HMAC",
    sizeof(ascon_hmac_state_t),
    ASCON_HMAC_SIZE,
    ASCON_HMAC_SIZE,
    AEAD_FLAG_NONE,
    ascon_hmac_compute_wrapper,
    0,
    (auth_init_t)ascon_hmac_init,
    0,
    0,
    (aead_xof_absorb_t)ascon_hmac_update,
    0,
    (auth_hmac_finalize_t)ascon_hmac_finalize,
    (aead_hash_free_t)ascon_hmac_free
};

aead_auth_algorithm_t const ascon_hmaca_auth = {
    "ASCON-HMACA",
    sizeof(ascon_hmaca_state_t),
    ASCON_HMACA_SIZE,
    ASCON_HMACA_SIZE,
    AEAD_FLAG_NONE,
    ascon_hmaca_compute_wrapper,
    0,
    (auth_init_t)ascon_hmaca_init,
    0,
    0,
    (aead_xof_absorb_t)ascon_hmaca_update,
    0,
    (auth_hmac_finalize_t)ascon_hmaca_finalize,
    (aead_hash_free_t)ascon_hmac_free
};

aead_auth_algorithm_t const ascon_kmac_auth = {
    "ASCON-KMAC",
    sizeof(ascon_kmac_state_t),
    ASCON_KMAC_SIZE,
    ASCON_KMAC_SIZE,
    AEAD_FLAG_CUSTOMIZATION,
    ascon_kmac_compute_wrapper,
    0,
    0,
    0,
    (auth_init_custom_t)ascon_kmac_init,
    (aead_xof_absorb_t)ascon_kmac_absorb,
    (aead_xof_squeeze_t)ascon_kmac_squeeze,
    0,
    (aead_hash_free_t)ascon_kmac_free
};

aead_auth_algorithm_t const ascon_kmaca_auth = {
    "ASCON-KMACA",
    sizeof(ascon_kmaca_state_t),
    ASCON_KMACA_SIZE,
    ASCON_KMACA_SIZE,
    AEAD_FLAG_CUSTOMIZATION,
    ascon_kmaca_compute_wrapper,
    0,
    0,
    0,
    (auth_init_custom_t)ascon_kmaca_init,
    (aead_xof_absorb_t)ascon_kmaca_absorb,
    (aead_xof_squeeze_t)ascon_kmaca_squeeze,
    0,
    (aead_hash_free_t)ascon_kmaca_free
};

/* Test the C++ bindings for the algorithms */

extern void ascon_hash_cpp
    (unsigned char *out, const unsigned char *in, size_t inlen);
extern void ascon_hash_init_cpp(void *state);
extern void ascon_hash_free_cpp(void *state);
extern void ascon_hash_update_cpp
    (void *state, const unsigned char *in, size_t inlen);
extern void ascon_hash_finalize_cpp(void *state, unsigned char *out);

extern void ascon_hasha_cpp
    (unsigned char *out, const unsigned char *in, size_t inlen);
extern void ascon_hasha_init_cpp(void *state);
extern void ascon_hasha_free_cpp(void *state);
extern void ascon_hasha_update_cpp
    (void *state, const unsigned char *in, size_t inlen);
extern void ascon_hasha_finalize_cpp(void *state, unsigned char *out);

extern void ascon_xof_cpp
    (unsigned char *out, const unsigned char *in, size_t inlen);
extern void ascon_xof_init_cpp(void *state);
extern void ascon_xof_free_cpp(void *state);
extern void ascon_xof_absorb_cpp
    (void *state, const unsigned char *in, size_t inlen);
extern void ascon_xof_squeeze_cpp
    (void *state, unsigned char *out, size_t outlen);

extern void ascon_xofa_cpp
    (unsigned char *out, const unsigned char *in, size_t inlen);
extern void ascon_xofa_init_cpp(void *state);
extern void ascon_xofa_free_cpp(void *state);
extern void ascon_xofa_absorb_cpp
    (void *state, const unsigned char *in, size_t inlen);
extern void ascon_xofa_squeeze_cpp
    (void *state, unsigned char *out, size_t outlen);

aead_hash_algorithm_t const ascon_hash_cpp_algorithm = {
    "ASCON-HASH-cpp",
    sizeof(void **),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_hash_cpp,
    (aead_hash_init_t)ascon_hash_init_cpp,
    0, /* init_fixed */
    (aead_hash_update_t)ascon_hash_update_cpp,
    (aead_hash_finalize_t)ascon_hash_finalize_cpp,
    0, /* absorb */
    0, /* squeeze */
    (aead_hash_free_t)ascon_hash_free_cpp
};

aead_hash_algorithm_t const ascon_hasha_cpp_algorithm = {
    "ASCON-HASHA-cpp",
    sizeof(void **),
    ASCON_HASHA_SIZE,
    AEAD_FLAG_NONE,
    ascon_hasha_cpp,
    (aead_hash_init_t)ascon_hasha_init_cpp,
    0, /* init_fixed */
    (aead_hash_update_t)ascon_hasha_update_cpp,
    (aead_hash_finalize_t)ascon_hasha_finalize_cpp,
    0, /* absorb */
    0, /* squeeze */
    (aead_hash_free_t)ascon_hasha_free_cpp
};

aead_hash_algorithm_t const ascon_xof_cpp_algorithm = {
    "ASCON-XOF-cpp",
    sizeof(void **),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xof_cpp,
    (aead_hash_init_t)ascon_xof_init_cpp,
    0, /* init_fixed */
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xof_absorb_cpp,
    (aead_xof_squeeze_t)ascon_xof_squeeze_cpp,
    (aead_hash_free_t)ascon_xof_free_cpp
};

aead_hash_algorithm_t const ascon_xofa_cpp_algorithm = {
    "ASCON-XOFA-cpp",
    sizeof(void **),
    ASCON_HASHA_SIZE,
    AEAD_FLAG_NONE,
    ascon_xofa_cpp,
    (aead_hash_init_t)ascon_xofa_init_cpp,
    0, /* init_fixed */
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xofa_absorb_cpp,
    (aead_xof_squeeze_t)ascon_xofa_squeeze_cpp,
    (aead_hash_free_t)ascon_xofa_free_cpp
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
    &ascon80pq_isap_cipher,
    &ascon128_inc_cipher,
    &ascon128a_inc_cipher,
    &ascon80pq_inc_cipher,
    &ascon128_masked_cipher,
    &ascon128a_masked_cipher,
    &ascon80pq_masked_cipher,
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
    &ascon_hash_cpp_algorithm,
    &ascon_hasha_cpp_algorithm,
    &ascon_xof_cpp_algorithm,
    &ascon_xofa_cpp_algorithm,
    0
};

/* List of all authentication algorithms that we can run KAT tests for */
static const aead_auth_algorithm_t *const auths[] = {
    &ascon_prf_auth,
    &ascon_prf_short_auth,
    &ascon_mac_auth,
    &ascon_hmac_auth,
    &ascon_hmaca_auth,
    &ascon_kmac_auth,
    &ascon_kmaca_auth,
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

const aead_auth_algorithm_t *find_auth_algorithm(const char *name)
{
    int index;
    for (index = 0; auths[index] != 0; ++index) {
        if (!strcmp(auths[index]->name, name))
            return auths[index];
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

static void print_auth_details(const aead_auth_algorithm_t *auth)
{
    printf("%-30s %8u   %8u\n",
           auth->name, auth->key_len * 8, auth->tag_len * 8);
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
    printf("\nAuthentication Algorithm         Key Bits");
    printf("   Tag Bits\n");
    for (index = 0; auths[index] != 0; ++index)
        print_auth_details(auths[index]);
}
