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

#ifndef ASCON_ISAP_H
#define ASCON_ISAP_H

#include <ascon/permutation.h>

/**
 * \file isap.h
 * \brief ISAP authenticated encryption algorithm for ASCON.
 *
 * ISAP is a family of authenticated encryption algorithms that were built
 * around the Keccak-p[400] and ASCON permutations.  This API implements
 * the versions that were built around ASCON: ISAP-A-128 and ISAP-A-128A.
 *
 * ISAP is designed to provide some protection against adversaries
 * using differential power analysis to determine the key.  The
 * downside is that key setup is very slow.
 *
 * To alleviate slow key setup, the ascon128_isap_aead_init() and
 * ascon128a_isap_aead_init() functions pre-compute the key setup
 * so that the same pre-computed key can be reused on multiple packets.
 *
 * If a device has a long-lived key, then the pre-computed key can be
 * stored in ROM or flash memory using ascon128_isap_aead_save_key() or
 * ascon128a_isap_aead_save_key().  The long-lived key is reloaded later
 * using ascon128_isap_aead_load_key() or ascon128a_isap_aead_load_key().
 * This may avoid leakage when loading the key bits at runtime.
 *
 * References: https://isap.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for all ISAP-A family members.
 */
#define ASCON_ISAP_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for all ISAP-A family members.
 */
#define ASCON_ISAP_TAG_SIZE 16

/**
 * \brief Size of the nonce for all ISAP-A family members.
 */
#define ASCON_ISAP_NONCE_SIZE 16

/**
 * \brief Size of a pre-computed key in its save format.
 */
#define ASCON_ISAP_SAVED_KEY_SIZE 80

/**
 * \brief Pre-computed key information for ISAP-A-128A.
 */
typedef struct
{
    ascon_state_t ke;   /**< Pre-computed key for encryption */
    ascon_state_t ka;   /**< Pre-computed key for authentication */

} ascon128a_isap_aead_key_t;

/**
 * \brief Pre-computed key information for ISAP-A-128.
 */
typedef struct
{
    ascon_state_t ke;   /**< Pre-computed key for encryption */
    ascon_state_t ka;   /**< Pre-computed key for authentication */

} ascon128_isap_aead_key_t;

/**
 * \brief Initializes a pre-computed key for ISAP-A-128A.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the 16 bytes of the key.
 *
 * The ascon128a_isap_aead_load_key() function can be used to
 * initialize the pre-computed key from a value that was previously
 * saved with ascon128a_isap_aead_save_key().
 *
 * \sa ascon128a_isap_aead_free(), ascon128a_isap_aead_encrypt(),
 * ascon128a_isap_aead_decrypt(), ascon128a_isap_aead_load_key()
 */
void ascon128a_isap_aead_init
    (ascon128a_isap_aead_key_t *pk, const unsigned char *k);

/**
 * \brief Initializes a pre-computed key for ISAP-A-128A from a
 * previously-saved key value.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the bytes of the previously-saved key.
 *
 * \sa ascon128a_isap_aead_free(), ascon128a_isap_aead_encrypt(),
 * ascon128a_isap_aead_decrypt(), ascon128a_isap_aead_save_key()
 */
void ascon128a_isap_aead_load_key
    (ascon128a_isap_aead_key_t *pk,
     const unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE]);

/**
 * \brief Saves a previously pre-computed key for ISAP-A-128A to a buffer.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the buffer to save the pre-computed key in.
 *
 * \sa ascon128a_isap_aead_free(), ascon128a_isap_aead_encrypt(),
 * ascon128a_isap_aead_decrypt(), ascon128a_isap_aead_load_key()
 */
void ascon128a_isap_aead_save_key
    (ascon128a_isap_aead_key_t *pk,
     unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE]);

/**
 * \brief Frees a pre-computed key for ISAP-A-128A.
 *
 * \param pk Points to the pre-computed key value.
 *
 * \sa ascon128a_isap_aead_init()
 */
void ascon128a_isap_aead_free(ascon128a_isap_aead_key_t *pk);

/**
 * \brief Encrypts and authenticates a packet with ISAP-A-128A and
 * pre-computed keys.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \sa ascon128a_isap_aead_decrypt(), ascon128a_isap_aead_init()
 */
void ascon128a_isap_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon128a_isap_aead_key_t *pk);

/**
 * \brief Decrypts and authenticates a packet with ISAP-A-128A and
 * pre-computed keys.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128a_isap_aead_encrypt(), ascon128a_isap_aead_init()
 */
int ascon128a_isap_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon128a_isap_aead_key_t *pk);

/**
 * \brief Initializes a pre-computed key for ISAP-A-128.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the 16 bytes of the key.
 *
 * The ascon128_isap_aead_load_key() function can be used to
 * initialize the pre-computed key from a value that was previously
 * saved with ascon128_isap_aead_save_key().
 *
 * \sa ascon128_isap_aead_free(), ascon128_isap_aead_encrypt(),
 * ascon128_isap_aead_decrypt(), ascon128_isap_aead_load_key()
 */
void ascon128_isap_aead_init
    (ascon128_isap_aead_key_t *pk, const unsigned char *k);

/**
 * \brief Initializes a pre-computed key for ISAP-A-128 from a
 * previously-saved key value.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the bytes of the previously-saved key.
 *
 * \sa ascon128_isap_aead_free(), ascon128_isap_aead_encrypt(),
 * ascon128_isap_aead_decrypt(), ascon128_isap_aead_save_key()
 */
void ascon128_isap_aead_load_key
    (ascon128_isap_aead_key_t *pk,
     const unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE]);

/**
 * \brief Saves a previously pre-computed key for ISAP-A-128 to a buffer.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the buffer to save the pre-computed key in.
 *
 * \sa ascon128_isap_aead_free(), ascon128_isap_aead_encrypt(),
 * ascon128_isap_aead_decrypt(), ascon128_isap_aead_load_key()
 */
void ascon128_isap_aead_save_key
    (ascon128_isap_aead_key_t *pk,
     unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE]);

/**
 * \brief Frees a pre-computed key for ISAP-A-128.
 *
 * \param pk Points to the pre-computed key value.
 *
 * \sa ascon128_isap_aead_init()
 */
void ascon128_isap_aead_free(ascon128_isap_aead_key_t *pk);

/**
 * \brief Encrypts and authenticates a packet with ISAP-A-128 and
 * pre-computed keys.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \sa ascon128_isap_aead_decrypt(), ascon128_isap_aead_init()
 */
void ascon128_isap_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon128_isap_aead_key_t *pk);

/**
 * \brief Decrypts and authenticates a packet with ISAP-A-128 and
 * pre-computed keys.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param pk Points to the pre-computed key value.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128_isap_aead_encrypt(), ascon128_isap_aead_init()
 */
int ascon128_isap_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon128_isap_aead_key_t *pk);

#ifdef __cplusplus
}
#endif

#endif
