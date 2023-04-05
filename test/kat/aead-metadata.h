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

#ifndef LWCRYPTO_AEAD_METADATA_H
#define LWCRYPTO_AEAD_METADATA_H

#include <stddef.h>

/**
 * \file aead-metadata.h
 * \brief Metadata defintions for AEAD and hashing schemes.
 *
 * This module provides metadata about the other implementations that
 * is useful for testing and benchmarking frameworks, but isn't part
 * of the main code for the algorithms.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Encrypts and authenticates a packet with an AEAD scheme.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet.
 * \param k Points to the key to use to encrypt the packet.
 */
typedef void (*aead_cipher_encrypt_t)
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with an AEAD scheme.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet.
 * \param k Points to the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 */
typedef int (*aead_cipher_decrypt_t)
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Initializes a pre-computed key for an AEAD scheme.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the bytes of the key.
 */
typedef void (*aead_cipher_pk_init_t)
    (unsigned char *pk, const unsigned char *k);

/**
 * \brief Frees a pre-computed key for an AEAD scheme.
 *
 * \param pk Points to the pre-computed key to free.
 */
typedef void (*aead_cipher_pk_free_t)(unsigned char *pk);

/**
 * \brief Initialises encrypting or decrypting a packet in
 * incremental mode.
 *
 * \param state State to initialize for incremental operations.
 * \param npub Points to the public nonce for the packet.
 * \param k Points to the key.
 */
typedef void (*aead_cipher_inc_init_t)
    (void *state, const unsigned char *npub, const unsigned char *k);

/**
 * \brief Starts encrypting or decrypting a packet in incremental mode.
 *
 * \param state State to initialize for incremental operations.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 */
typedef void (*aead_cipher_inc_start_t)
    (void *state, const unsigned char *ad, size_t adlen);

/**
 * \brief Encrypts a block of data incremental mode.
 *
 * \param state State to use for incremental operations.
 * \param in Buffer that contains the plaintext to encrypt.
 * \param out Buffer to receive the ciphertext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 */
typedef void (*aead_cipher_enc_inc_t)
    (void *state, const unsigned char *in, unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental encryption operation and
 * generates the authentication tag.
 *
 * \param state State to use for incremental encryption.
 * \param tag Points to the buffer to receive the authentication tag.
 */
typedef void (*aead_cipher_enc_fin_t)(void *state, unsigned char *tag);

/**
 * \brief Decrypts a block of data in incremental mode.
 *
 * \param state State to use for incremental operations.
 * \param in Buffer that contains the ciphertext to decrypt.
 * \param out Buffer to receive the plaintext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 */
typedef void (*aead_cipher_dec_inc_t)
    (void *state, const unsigned char *in, unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental decryption operation and
 * checks the authentication tag.
 *
 * \param state State to use for ASCON-80pq encryption operations.
 * \param tag Points to the buffer containing the ciphertext's
 * authentication tag.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 */
typedef int (*aead_cipher_dec_fin_t)(void *state, const unsigned char *tag);

/**
 * \brief Frees the state of a hashing function.
 *
 * \param state XOF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 */
typedef void (*aead_hash_free_t)(void *state);

/**
 * \brief Hashes a block of input data.
 *
 * \param out Buffer to receive the hash output.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 */
typedef void (*aead_hash_t)
    (unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for a hashing operation.
 *
 * \param state Hash state to be initialized.
 */
typedef void (*aead_hash_init_t)(void *state);

/**
 * \brief Initializes the state for an XOF algorithm with a fixed output length.
 *
 * \param state Hash state to be initialized.
 * \param length Desired output length.
 */
typedef void (*aead_hash_init_fixed_t)(void *state, size_t length);

/**
 * \brief Updates a hash state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 */
typedef void (*aead_hash_update_t)
    (void *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from a hashing operation.
 *
 * \param Hash state to be finalized.
 * \param out Points to the output buffer to receive the hash value.
 */
typedef void (*aead_hash_finalize_t)(void *state, unsigned char *out);

/**
 * \brief Aborbs more input data into an XOF state.
 *
 * \param state XOF state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_xof_init(), ascon_xof_squeeze()
 */
typedef void (*aead_xof_absorb_t)
    (void *state, const unsigned char *in, size_t inlen);

/**
 * \brief Squeezes output data from an XOF state.
 *
 * \param state XOF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 */
typedef void (*aead_xof_squeeze_t)
    (void *state, unsigned char *out, size_t outlen);

/**
 * \brief All-in-one computation for authentication functions.
 *
 * \param tag Output buffer for the tag.
 * \param taglen Length of the output tag in bytes.
 * \param key Points to the key.
 * \param keylen Length of the key in bytes.
 * \param in Points to the input data.
 * \param inlen Length of the input data in bytes.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 */
typedef void (*auth_compute_t)
    (unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief All-in-one verification for authentication functions.
 *
 * \param tag Points to the tag to be checked.
 * \param taglen Length of the output tag in bytes.
 * \param key Points to the key.
 * \param keylen Length of the key in bytes.
 * \param in Points to the input data.
 * \param inlen Length of the input data in bytes.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \return 0 on success, -1 for a verification failure.
 */
typedef int (*auth_verify_t)
    (const unsigned char *tag, size_t taglen,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Initializes the state for an incremental PRF operation.
 *
 * \param state PRF state to be initialized.
 * \param key Points to the key.
 * \param keylen Length of the key in bytes.
 */
typedef void (*auth_init_t)
    (void *state, const unsigned char *key, size_t keylen);

/**
 * \brief Initializes the state for an incremental PRF operation with a
 * fixed output length.
 *
 * \param state PRF state to be initialized.
 * \param key Points to the key.
 * \param keylen Length of the key in bytes.
 * \param length Desired output length.
 */
typedef void (*auth_init_fixed_t)
    (void *state, const unsigned char *key, size_t keylen, size_t length);

/**
 * \brief Initializes the state for an incremental authentication operation
 * with a customization string.
 *
 * \param state Authentication state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 */
typedef void (*auth_init_custom_t)
    (void *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Returns the final tag value from an incremental HMAC operation.
 *
 * \param state HMAC state to be finalized.
 * \param key Points to the key.
 * \param keylen Length of the key in bytes.
 * \param out Points to the output buffer to receive the tag value.
 */
typedef void (*auth_hmac_finalize_t)
    (void *state, const unsigned char *key, size_t keylen, unsigned char *out);

/**
 * \brief No special AEAD features.
 */
#define AEAD_FLAG_NONE              0x0000

/**
 * \brief The natural byte order of the AEAD cipher is little-endian.
 *
 * If this flag is not present, then the natural byte order of the
 * AEAD cipher should be assumed to be big-endian.
 *
 * The natural byte order may be useful when formatting packet sequence
 * numbers as nonces.  The application needs to know whether the sequence
 * number should be packed into the leading or trailing bytes of the nonce.
 */
#define AEAD_FLAG_LITTLE_ENDIAN     0x0001

/**
 * \brief The AEAD mode provides side-channel protection for the key.
 */
#define AEAD_FLAG_SC_PROTECT_KEY    0x0002

/**
 * \brief The AEAD mode provides side-channel protection for all block
 * operations.
 */
#define AEAD_FLAG_SC_PROTECT_ALL    0x0004

/**
 * \brief Algorithm is very slow in software, so performance frameworks
 * may want to use a different testing approach to avoid taking too long.
 */
#define AEAD_FLAG_SLOW              0x0008

/**
 * \brief Algorithm uses masking to protect sensitive material.
 */
#define AEAD_FLAG_MASKED            0x0010

/**
 * \brief Customization strings are required for this algorithm.
 */
#define AEAD_FLAG_CUSTOMIZATION     0x0020

/**
 * \brief Meta-information about an AEAD cipher.
 */
typedef struct
{
    const char *name;               /**< Name of the cipher */
    unsigned key_len;               /**< Length of the key in bytes */
    unsigned nonce_len;             /**< Length of the nonce in bytes */
    unsigned tag_len;               /**< Length of the tag in bytes */
    unsigned flags;                 /**< Flags for extra features */
    aead_cipher_encrypt_t encrypt;  /**< AEAD encryption function */
    aead_cipher_decrypt_t decrypt;  /**< AEAD decryption function */
    unsigned pk_state_len;          /**< Length of the pre-computed state */
    aead_cipher_pk_init_t pk_init;  /**< AEAD pre-computed init function */
    aead_cipher_pk_free_t pk_free;  /**< Free pre-computed AEAD key */
    unsigned inc_state_len;         /**< Length of the incremental state */
    aead_cipher_inc_init_t init_inc;   /**< Initialize incremental mode */
    aead_cipher_inc_start_t start_inc; /**< Start incremental mode */
    aead_cipher_enc_inc_t encrypt_inc; /**< Incremental encryption */
    aead_cipher_enc_fin_t encrypt_fin; /**< Finalize encryption */
    aead_cipher_dec_inc_t decrypt_inc; /**< Incremental decryption */
    aead_cipher_dec_fin_t decrypt_fin; /**< Finalize decryption */

} aead_cipher_t;

/**
 * \brief Meta-information about a hash algorithm that is related to an AEAD.
 *
 * Regular hash algorithms should provide the "hash", "init", "update",
 * and "finalize" functions.  Extensible Output Functions (XOF's) should
 * proivde the "hash", "init", "absorb", and "squeeze" functions.
 */
typedef struct
{
    const char *name;           /**< Name of the hash algorithm */
    size_t state_size;          /**< Size of the incremental state structure */
    unsigned hash_len;          /**< Length of the hash in bytes */
    unsigned flags;             /**< Flags for extra features */
    aead_hash_t hash;           /**< All in one hashing function */
    aead_hash_init_t init;      /**< Incremental hash/XOF init function */
    aead_hash_init_fixed_t init_fixed; /**< XOF with fixed output length */
    aead_hash_update_t update;  /**< Incremental hash update function */
    aead_hash_finalize_t finalize; /**< Incremental hash finalize function */
    aead_xof_absorb_t absorb;   /**< Incremental XOF absorb function */
    aead_xof_squeeze_t squeeze; /**< Incremental XOF squeeze function */
    aead_hash_free_t free;      /**< Function to free the state */

} aead_hash_algorithm_t;

/**
 * \brief Meta-information about a keyed authentication algorithm.
 */
typedef struct
{
    const char *name;           /**< Name of the authentication algorithm */
    size_t state_size;          /**< Size of the incremental state structure */
    unsigned key_len;           /**< Length of the key in bytes */
    unsigned tag_len;           /**< Length of the output tag in bytes */
    unsigned flags;             /**< Flags for extra features */
    auth_compute_t compute;     /**< All in one computation function */
    auth_verify_t verify;       /**< All in one verification function */
    auth_init_t init;           /**< Initialize incremental operation */
    auth_init_fixed_t init_fixed; /**< Incremental with fixed output length */
    auth_init_custom_t init_custom; /**< Initialize with customization string */
    aead_xof_absorb_t absorb;   /**< Incremental absorb function */
    aead_xof_squeeze_t squeeze; /**< Incremental squeeze function */
    auth_hmac_finalize_t hmac_finalize; /**< HMAC finalize function */
    aead_hash_free_t free;      /**< Function to free the state */

} aead_auth_algorithm_t;

/**
 * \brief Meta-information block for the ASCON-128 cipher.
 */
extern aead_cipher_t const ascon128_cipher;

/**
 * \brief Meta-information block for the ASCON-128a cipher.
 */
extern aead_cipher_t const ascon128a_cipher;

/**
 * \brief Meta-information block for the ASCON-80pq cipher.
 */
extern aead_cipher_t const ascon80pq_cipher;

/**
 * \brief Meta-information block for the ASCON-HASH algorithm.
 */
extern aead_hash_algorithm_t const ascon_hash_algorithm;

/**
 * \brief Meta-information block for the ASCON-HASHA algorithm.
 */
extern aead_hash_algorithm_t const ascon_hasha_algorithm;

/**
 * \brief Meta-information block for the ASCON-XOF algorithm.
 */
extern aead_hash_algorithm_t const ascon_xof_algorithm;

/**
 * \brief Meta-information block for the ASCON-XOFA algorithm.
 */
extern aead_hash_algorithm_t const ascon_xofa_algorithm;

/**
 * \brief Meta-information block for the masked ASCON-128 cipher.
 */
extern aead_cipher_t const ascon128_masked_cipher;

/**
 * \brief Meta-information block for the masked ASCON-128a cipher.
 */
extern aead_cipher_t const ascon128a_masked_cipher;

/**
 * \brief Meta-information block for the masked ASCON-80pq cipher.
 */
extern aead_cipher_t const ascon80pq_masked_cipher;

/**
 * \brief Meta-information block for the ASCON-128-SIV cipher.
 */
extern aead_cipher_t const ascon128_siv_cipher;

/**
 * \brief Meta-information block for the ASCON-128a-SIV cipher.
 */
extern aead_cipher_t const ascon128a_siv_cipher;

/**
 * \brief Meta-information block for the ASCON-80pq-SIV cipher.
 */
extern aead_cipher_t const ascon80pq_siv_cipher;

/**
 * \brief Meta-information block for the ASCON-Prf pseudorandom function.
 */
extern aead_auth_algorithm_t const ascon_prf_auth;

/**
 * \brief Meta-information block for the ASCON-PrfShort pseudorandom function.
 */
extern aead_auth_algorithm_t const ascon_prf_short_auth;

/**
 * \brief Meta-information block for the ASCON-Mac authentication function.
 */
extern aead_auth_algorithm_t const ascon_mac_auth;

#ifdef __cplusplus
}
#endif

#endif
