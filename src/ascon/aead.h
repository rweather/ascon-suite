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

#ifndef ASCON_AEAD_H
#define ASCON_AEAD_H

#include <ascon/permutation.h>

/**
 * \file aead.h
 * \brief ASCON-128 encryption algorithm and related family members.
 *
 * The ASCON family consists of several related algorithms:
 *
 * \li ASCON-128 with a 128-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 64 bits.
 * \li ASCON-128a with a 128-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 128 bits.  This is faster than ASCON-128 but may
 * not be as secure.
 * \li ASCON-80pq with a 160-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 64 bits.  This is similar to ASCON-128 but has a
 * 160-bit key instead which may be more resistant against quantum computers.
 * \li ASCON-HASH and ASCON-HASHA with a 256-bit hash output.
 * \li ASCON-XOF and ASCON-XOFA with extensible hash output (XOF mode).
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for ASCON-128 and ASCON-128a.
 */
#define ASCON128_KEY_SIZE 16

/**
 * \brief Size of the nonce for ASCON-128 and ASCON-128a.
 */
#define ASCON128_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for ASCON-128 and ASCON-128a.
 */
#define ASCON128_TAG_SIZE 16

/**
 * \brief Size of the key for ASCON-80pq.
 */
#define ASCON80PQ_KEY_SIZE 20

/**
 * \brief Size of the nonce for ASCON-80pq.
 */
#define ASCON80PQ_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for ASCON-80pq.
 */
#define ASCON80PQ_TAG_SIZE 16

/**
 * \brief Rate of absorbing and squeezing for ASCON-128.
 */
#define ASCON128_RATE 8

/**
 * \brief Rate of absorbing and squeezing for ASCON-128a.
 */
#define ASCON128A_RATE 16

/**
 * \brief Rate of absorbing and squeezing for ASCON-80pq.
 */
#define ASCON80PQ_RATE 8

/**
 * \brief Encrypts and authenticates a packet with ASCON-128.
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
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \sa ascon128_aead_decrypt()
 */
void ascon128_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-128.
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
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128_aead_encrypt()
 */
int ascon128_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ASCON-128a.
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
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \sa ascon128a_aead_decrypt()
 */
void ascon128a_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-128a.
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
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128a_aead_encrypt()
 */
int ascon128a_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ASCON-80pq.
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
 * \param k Points to the 20 bytes of the key to use to encrypt the packet.
 *
 * \sa ascon80pq_aead_decrypt()
 */
void ascon80pq_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-80pq.
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
 * \param k Points to the 20 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon80pq_aead_encrypt()
 */
int ascon80pq_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/* ---------------------------------------------------------------- */
/*            Utility functions for use with AEAD modes             */
/* ---------------------------------------------------------------- */

/**
 * \brief Sets a 128-bit nonce value to a 64-bit packet sequence counter.
 *
 * \param npub The nonce value to be set.
 * \param n The 64-bit packet sequence counter to set.
 *
 * The value in \a npub is written in big-endian byte order with the
 * leading 8 bytes set to zero.
 */
void ascon_aead_set_counter
    (unsigned char npub[ASCON128_NONCE_SIZE], uint64_t n);

/**
 * \brief Increments a 128-bit nonce value as a packet sequence counter.
 *
 * \param npub The nonce value to be incremented.
 *
 * The value in \a npub is interpreted in big-endian byte order.
 */
void ascon_aead_increment_nonce(unsigned char npub[ASCON128_NONCE_SIZE]);

/* ---------------------------------------------------------------- */
/*            Incremental API's for the AEAD modes below            */
/* ---------------------------------------------------------------- */

/**
 * \brief State information for the incremental version of ASCON-128.
 *
 * Except for the "nonce" field, this structure should be treated as
 * opaque by the application.  The application can update the "nonce"
 * field between packets if the simple incrementing algorithm is
 * not sufficient; e.g. for datagram transports.
 */
typedef struct
{
    /** ASCON permutation state */
    ascon_state_t state;

    /** Key to use to encrypt and decrypt packets using this state */
    unsigned char key[ASCON128_KEY_SIZE];

    /** Nonce value for the next packet */
    unsigned char nonce[ASCON128_NONCE_SIZE];

    /** Position within the current block for partial blocks */
    unsigned char posn;

} ascon128_state_t;

/**
 * \brief State information for the incremental version of ASCON-128a.
 *
 * Except for the "nonce" field, this structure should be treated as
 * opaque by the application.  The application can update the "nonce"
 * field between packets if the simple incrementing algorithm is
 * not sufficient; e.g. for datagram transports.
 */
typedef struct
{
    /** ASCON permutation state */
    ascon_state_t state;

    /** Key to use to encrypt and decrypt packets using this state */
    unsigned char key[ASCON128_KEY_SIZE];

    /** Nonce value for the next packet */
    unsigned char nonce[ASCON128_NONCE_SIZE];

    /** Position within the current block for partial blocks */
    unsigned char posn;

} ascon128a_state_t;

/**
 * \brief State information for the incremental version of ASCON-80pq.
 *
 * Except for the "nonce" field, this structure should be treated as
 * opaque by the application.  The application can update the "nonce"
 * field between packets if the simple incrementing algorithm is
 * not sufficient; e.g. for datagram transports.
 */
typedef struct
{
    /** ASCON permutation state */
    ascon_state_t state;

    /** Key to use to encrypt and decrypt packets using this state */
    unsigned char key[ASCON80PQ_KEY_SIZE];

    /** Nonce value for the next packet */
    unsigned char nonce[ASCON80PQ_NONCE_SIZE];

    /** Position within the current block for partial blocks */
    unsigned char posn;

} ascon80pq_state_t;

/**
 * \brief Initializes ASCON-128 for encrypting or decrypting packets in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-128 operations.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * If \a npub is NULL, then the initial nonce will be set to all-zeroes.
 * If \a k is NULL, then the initial key will be set to all-zeroes.
 *
 * The following sequence can be used to encrypt a list of i plaintext
 * message blocks (m) to produce i ciphertext message blocks (c)
 * and an authentication tag (t).
 *
 * \code
 * ascon128_state_t state;
 * ascon128_aead_init(&state, npub, k);
 * ascon128_aead_start(&state, ad, adlen);
 * ascon128_aead_encrypt_block(&state, m1, c1, m1_len);
 * ascon128_aead_encrypt_block(&state, m2, c2, m2_len);
 * ...;
 * ascon128_aead_encrypt_block(&state, mi, ci, mi_len);
 * ascon128_aead_encrypt_finalize(&state, t);
 * \endcode
 *
 * Subsequent packets can be encrypted by calling ascon128_aead_start() again.
 * The nonce is automatically incremented by ascon128_aead_start() so
 * that the caller doesn't accidentally encrypt two or more packets with the
 * same nonce.
 *
 * \code
 * ascon128_aead_start(&state, ad2, ad2len);
 * ascon128_aead_encrypt_block(&state, mj, cj, mj_len);
 * ascon128_aead_encrypt_finalize(&state, t2);
 * \endcode
 *
 * Decryption follows a similar sequence:
 *
 * \code
 * ascon128_state_t state;
 * ascon128_aead_init(&state, npub, k);
 * ascon128_aead_start(&state, ad, adlen);
 * ascon128_aead_decrypt_block(&state, c1, m1, c1_len);
 * ascon128_aead_decrypt_block(&state, c2, m2, c2_len);
 * ...;
 * ascon128_aead_decrypt_block(&state, ci, mi, ci_len);
 * if (ascon128_aead_decrypt_finalize(&state, t) < 0)
 *     ...; // decryption has failed!
 * \endcode
 *
 * It is very important that the plaintext output from decryption be
 * discarded if the authentication tag fails to verify.  Applications
 * should not use any of the data before verifying the tag.
 *
 * When there are no more packets left to encrypt or decrypt,
 * call ascon128_aead_free():
 *
 * \code
 * ascon128_aead_free(&state);
 * \endcode
 *
 * \sa ascon128_aead_start(), ascon128_aead_free(), ascon128_aead_reinit()
 */
void ascon128_aead_init
    (ascon128_state_t *state, const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Re-initializes ASCON-128 incremental mode with a new key and nonce.
 *
 * \param state State to initialize for ASCON-128 operations.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * If \a npub is NULL, then the initial nonce will be set to all-zeroes.
 * If \a k is NULL, then the initial key will be set to all-zeroes.
 *
 * \sa ascon128_aead_init()
 */
void ascon128_aead_reinit
    (ascon128_state_t *state, const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Starts encrypting or decrypting a packet with ASCON-128 in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-128 operations.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 *
 * \sa ascon128_aead_encrypt_block(), ascon128_aead_decrypt_block(),
 * ascon128_aead_encrypt_finalize(), ascon128_aead_decrypt_finalize()
 */
void ascon128_aead_start
    (ascon128_state_t *state, const unsigned char *ad, size_t adlen);

/**
 * \brief Frees an incremental ASCON-128 state, destroying any sensitive
 * material in the state.
 *
 * \param state The state to free.
 *
 * \sa ascon128_aead_init()
 */
void ascon128_aead_free(ascon128_state_t *state);

/**
 * \brief Encrypts a block of data with ASCON-128 in incremental mode.
 *
 * \param state State to use for ASCON-128 encryption operations.
 * \param in Buffer that contains the plaintext to encrypt.
 * \param out Buffer to receive the ciphertext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 *
 * \sa ascon128_aead_decrypt_block(), ascon128_aead_start(),
 * ascon128_aead_encrypt_finalize()
 */
void ascon128_aead_encrypt_block
    (ascon128_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental ASCON-128 encryption operation and
 * generates the authentication tag.
 *
 * \param state State to use for ASCON-128 encryption operations.
 * \param tag Points to the buffer to receive the authentication tag.
 * Must be at least ASCON128_TAG_SIZE bytes in length.
 *
 * \sa ascon128_aead_encrypt_block(), ascon128_aead_start()
 */
void ascon128_aead_encrypt_finalize
    (ascon128_state_t *state, unsigned char *tag);

/**
 * \brief Decrypts a block of data with ASCON-128 in incremental mode.
 *
 * \param state State to use for ASCON-128 encryption operations.
 * \param in Buffer that contains the ciphertext to decrypt.
 * \param out Buffer to receive the plaintext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 *
 * \sa ascon128_aead_encrypt_block(), ascon128_aead_start(),
 * ascon128_aead_decrypt_finalize()
 */
void ascon128_aead_decrypt_block
    (ascon128_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental ASCON-128 decryption operation and
 * checks the authentication tag.
 *
 * \param state State to use for ASCON-128 encryption operations.
 * \param tag Points to the buffer containing the ciphertext's
 * authentication tag.  Must be at least ASCON128_TAG_SIZE bytes in length.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128_aead_decrypt_block(), ascon128_aead_start()
 */
int ascon128_aead_decrypt_finalize
    (ascon128_state_t *state, const unsigned char *tag);

/**
 * \brief Initializes ASCON-128a for encrypting or decrypting packets in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-128a operations.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * If \a npub is NULL, then the initial nonce will be set to all-zeroes.
 * If \a k is NULL, then the initial key will be set to all-zeroes.
 *
 * The following sequence can be used to encrypt a list of i plaintext
 * message blocks (m) to produce i ciphertext message blocks (c)
 * and an authentication tag (t).
 *
 * \code
 * ascon128a_state_t state;
 * ascon128a_aead_init(&state, npub, k);
 * ascon128a_aead_start(&state, ad, adlen);
 * ascon128a_aead_encrypt_block(&state, m1, c1, m1_len);
 * ascon128a_aead_encrypt_block(&state, m2, c2, m2_len);
 * ...;
 * ascon128a_aead_encrypt_block(&state, mi, ci, mi_len);
 * ascon128a_aead_encrypt_finalize(&state, t);
 * \endcode
 *
 * Subsequent packets can be encrypted by calling ascon128_aead_start() again.
 * The nonce is automatically incremented by ascon128_aead_start() so
 * that the caller doesn't accidentally encrypt two or more packets with the
 * same nonce.
 *
 * \code
 * ascon128a_aead_start(&state, ad2, ad2len);
 * ascon128a_aead_encrypt_block(&state, mj, cj, mj_len);
 * ascon128a_aead_encrypt_finalize(&state, t2);
 * \endcode
 *
 * Decryption follows a similar sequence:
 *
 * \code
 * ascon128a_state_t state;
 * ascon128a_aead_init(&state, npub, k);
 * ascon128a_aead_start(&state, ad, adlen);
 * ascon128a_aead_decrypt_block(&state, c1, m1, c1_len);
 * ascon128a_aead_decrypt_block(&state, c2, m2, c2_len);
 * ...;
 * ascon128a_aead_decrypt_block(&state, ci, mi, ci_len);
 * if (ascon128a_aead_decrypt_finalize(&state, t) < 0)
 *     ...; // decryption has failed!
 * \endcode
 *
 * It is very important that the plaintext output from decryption be
 * discarded if the authentication tag fails to verify.  Applications
 * should not use any of the data before verifying the tag.
 *
 * When there are no more packets left to encrypt or decrypt,
 * call ascon128a_aead_free():
 *
 * \code
 * ascon128a_aead_free(&state);
 * \endcode
 *
 * \sa ascon128a_aead_start(), ascon128a_aead_free(), ascon128a_aead_reinit()
 */
void ascon128a_aead_init
    (ascon128a_state_t *state, const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Re-initializes ASCON-128a incremental mode with a new key and nonce.
 *
 * \param state State to initialize for ASCON-128a operations.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * If \a npub is NULL, then the initial nonce will be set to all-zeroes.
 * If \a k is NULL, then the initial key will be set to all-zeroes.
 *
 * \sa ascon128a_aead_init()
 */
void ascon128a_aead_reinit
    (ascon128a_state_t *state, const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Starts encrypting or decrypting a packet with ASCON-128a in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-128a operations.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 *
 * \sa ascon128a_aead_encrypt_block(), ascon128a_aead_decrypt_block(),
 * ascon128a_aead_encrypt_finalize(), ascon128a_aead_decrypt_finalize()
 */
void ascon128a_aead_start
    (ascon128a_state_t *state, const unsigned char *ad, size_t adlen);

/**
 * \brief Frees an incremental ASCON-128a state, destroying any sensitive
 * material in the state.
 *
 * \param state The state to free.
 *
 * \sa ascon128a_aead_init()
 */
void ascon128a_aead_free(ascon128a_state_t *state);

/**
 * \brief Encrypts a block of data with ASCON-128a in incremental mode.
 *
 * \param state State to use for ASCON-128a encryption operations.
 * \param in Buffer that contains the plaintext to encrypt.
 * \param out Buffer to receive the ciphertext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 *
 * \sa ascon128a_aead_decrypt_block(), ascon128a_aead_start(),
 * ascon128a_aead_encrypt_finalize()
 */
void ascon128a_aead_encrypt_block
    (ascon128a_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental ASCON-128a encryption operation and
 * generates the authentication tag.
 *
 * \param state State to use for ASCON-128a encryption operations.
 * \param tag Points to the buffer to receive the authentication tag.
 * Must be at least ASCON128_TAG_SIZE bytes in length.
 *
 * The contents of \a state will be freed by this function, destroying
 * any sensitive material that may be present.
 *
 * \sa ascon128a_aead_encrypt_block(), ascon128a_aead_start()
 */
void ascon128a_aead_encrypt_finalize
    (ascon128a_state_t *state, unsigned char *tag);

/**
 * \brief Decrypts a block of data with ASCON-128a in incremental mode.
 *
 * \param state State to use for ASCON-128a encryption operations.
 * \param in Buffer that contains the ciphertext to decrypt.
 * \param out Buffer to receive the plaintext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 *
 * \sa ascon128a_aead_encrypt_block(), ascon128a_aead_start(),
 * ascon128a_aead_decrypt_finalize()
 */
void ascon128a_aead_decrypt_block
    (ascon128a_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental ASCON-128a decryption operation and
 * checks the authentication tag.
 *
 * \param state State to use for ASCON-128a encryption operations.
 * \param tag Points to the buffer containing the ciphertext's
 * authentication tag.  Must be at least ASCON128_TAG_SIZE bytes in length.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * The contents of \a state will be freed by this function, destroying
 * any sensitive material that may be present.
 *
 * \sa ascon128a_aead_decrypt_block(), ascon128a_aead_start()
 */
int ascon128a_aead_decrypt_finalize
    (ascon128a_state_t *state, const unsigned char *tag);

/**
 * \brief Starts encrypting or decrypting a packet with ASCON-80pq in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-80pq operations.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 20 bytes of the key to use to encrypt the packet.
 *
 * If \a npub is NULL, then the initial nonce will be set to all-zeroes.
 * If \a k is NULL, then the initial key will be set to all-zeroes.
 *
 * The following sequence can be used to encrypt a list of i plaintext
 * message blocks (m) to produce i ciphertext message blocks (c)
 * and an authentication tag (t).
 *
 * \code
 * ascon80pq_state_t state;
 * ascon80pq_aead_init(&state, npub, k);
 * ascon80pq_aead_start(&state, ad, adlen);
 * ascon80pq_aead_encrypt_block(&state, m1, c1, m1_len);
 * ascon80pq_aead_encrypt_block(&state, m2, c2, m2_len);
 * ...;
 * ascon80pq_aead_encrypt_block(&state, mi, ci, mi_len);
 * ascon80pq_aead_encrypt_finalize(&state, t);
 * \endcode
 *
 * Subsequent packets can be encrypted by calling ascon128_aead_start() again.
 * The nonce is automatically incremented by ascon128_aead_start() so
 * that the caller doesn't accidentally encrypt two or more packets with the
 * same nonce.
 *
 * \code
 * ascon80pq_aead_start(&state, ad2, ad2len);
 * ascon80pq_aead_encrypt_block(&state, mj, cj, mj_len);
 * ascon80pq_aead_encrypt_finalize(&state, t2);
 * \endcode
 *
 * Decryption follows a similar sequence:
 *
 * \code
 * ascon80pq_state_t state;
 * ascon80pq_aead_init(&state, npub, k);
 * ascon80pq_aead_start(&state, ad, adlen);
 * ascon80pq_aead_decrypt_block(&state, c1, m1, c1_len);
 * ascon80pq_aead_decrypt_block(&state, c2, m2, c2_len);
 * ...;
 * ascon80pq_aead_decrypt_block(&state, ci, mi, ci_len);
 * if (ascon80pq_aead_decrypt_finalize(&state, t) < 0)
 *     ...; // decryption has failed!
 * \endcode
 *
 * It is very important that the plaintext output from decryption be
 * discarded if the authentication tag fails to verify.  Applications
 * should not use any of the data before verifying the tag.
 *
 * When there are no more packets left to encrypt or decrypt,
 * call ascon80pq_aead_free():
 *
 * \code
 * ascon80pq_aead_free(&state);
 * \endcode
 *
 * \sa ascon80pq_aead_start(), ascon80pq_aead_free(), ascon80pq_aead_reinit()
 */
void ascon80pq_aead_init
    (ascon80pq_state_t *state, const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Re-initializes ASCON-80pq incremental mode with a new key and nonce.
 *
 * \param state State to initialize for ASCON-80pq operations.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 20 bytes of the key to use to encrypt the packet.
 *
 * If \a npub is NULL, then the initial nonce will be set to all-zeroes.
 * If \a k is NULL, then the initial key will be set to all-zeroes.
 *
 * \sa ascon80pq_aead_init()
 */
void ascon80pq_aead_reinit
    (ascon80pq_state_t *state, const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Starts encrypting or decrypting a packet with ASCON-80pq in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-80pq operations.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 *
 * \sa ascon80pq_aead_encrypt_block(), ascon80pq_aead_decrypt_block(),
 * ascon80pq_aead_encrypt_finalize(), ascon80pq_aead_decrypt_finalize()
 */
void ascon80pq_aead_start
    (ascon80pq_state_t *state, const unsigned char *ad, size_t adlen);

/**
 * \brief Frees an incremental ASCON-80pq state, destroying any sensitive
 * material in the state.
 *
 * \param state The state to free.
 *
 * \sa ascon80pq_aead_init()
 */
void ascon80pq_aead_free(ascon80pq_state_t *state);

/**
 * \brief Encrypts a block of data with ASCON-80pq in incremental mode.
 *
 * \param state State to use for ASCON-80pq encryption operations.
 * \param in Buffer that contains the plaintext to encrypt.
 * \param out Buffer to receive the ciphertext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 *
 * \sa ascon80pq_aead_decrypt_block(), ascon80pq_aead_start(),
 * ascon80pq_aead_encrypt_finalize()
 */
void ascon80pq_aead_encrypt_block
    (ascon80pq_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental ASCON-80pq encryption operation and
 * generates the authentication tag.
 *
 * \param state State to use for ASCON-80pq encryption operations.
 * \param tag Points to the buffer to receive the authentication tag.
 * Must be at least ASCON80PQ_TAG_SIZE bytes in length.
 *
 * The contents of \a state will be freed by this function, destroying
 * any sensitive material that may be present.
 *
 * \sa ascon80pq_aead_encrypt_block(), ascon80pq_aead_start()
 */
void ascon80pq_aead_encrypt_finalize
    (ascon80pq_state_t *state, unsigned char *tag);

/**
 * \brief Decrypts a block of data with ASCON-80pq in incremental mode.
 *
 * \param state State to use for ASCON-80pq encryption operations.
 * \param in Buffer that contains the ciphertext to decrypt.
 * \param out Buffer to receive the plaintext output.  Can be the
 * same buffer as \a in.
 * \param len Length of the plaintext and ciphertext in bytes.
 *
 * \sa ascon80pq_aead_encrypt_block(), ascon80pq_aead_start(),
 * ascon80pq_aead_decrypt_finalize()
 */
void ascon80pq_aead_decrypt_block
    (ascon80pq_state_t *state, const unsigned char *in,
     unsigned char *out, size_t len);

/**
 * \brief Finalizes an incremental ASCON-80pq decryption operation and
 * checks the authentication tag.
 *
 * \param state State to use for ASCON-80pq encryption operations.
 * \param tag Points to the buffer containing the ciphertext's
 * authentication tag.  Must be at least ASCON80PQ_TAG_SIZE bytes in length.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * The contents of \a state will be freed by this function, destroying
 * any sensitive material that may be present.
 *
 * \sa ascon80pq_aead_decrypt_block(), ascon80pq_aead_start()
 */
int ascon80pq_aead_decrypt_finalize
    (ascon80pq_state_t *state, const unsigned char *tag);

#ifdef __cplusplus
}

#include <ascon/utility.h>

namespace ascon
{

/**
 * \brief Common base class for encrypting or decrypting sequential
 * packets with ASCON.
 *
 * Subclasses of this class provide a convenient API for encrypting
 * sequential packets in a session using ASCON.  The state consists of
 * the key and a nonce.  After each packet is encrypted or decrypted,
 * the nonce is incremented for the next packet automatically.
 *
 * The following example demonstrates encrypting three packets in a
 * session starting with a nonce value of zero:
 *
 * \code
 * unsigned char key[16] = {...};
 *
 * ascon::aead128 cipher;
 * cipher.set_key(key, sizeof(key));
 *
 * // nonce = 0
 * ascon::byte_array m1 = ascon::bytes_from_data(plaintext1, plaintext1_len);
 * cipher.encrypt(c1, m1);
 *
 * // nonce = 1
 * ascon::byte_array m2 = ascon::bytes_from_data(plaintext2, plaintext2_len);
 * cipher.encrypt(c2, m2);
 *
 * // nonce = 2
 * ascon::byte_array m3 = ascon::bytes_from_data(plaintext3, plaintext3_len);
 * cipher.encrypt(c3, m3);
 * \endcode
 *
 * To decrypt the above packets, the object must be re-initialised
 * with the starting nonce / counter value:
 *
 * \code
 * cipher.set_counter(0);
 *
 * // nonce = 0
 * ascon::byte_array p1;
 * cipher.encrypt(p1, c1);
 *
 * // nonce = 1
 * cipher.encrypt(p2, c2);
 *
 * // nonce = 2
 * cipher.encrypt(p3, c3);
 * \endcode
 *
 * The set_counter() function provides a convenient method to set the
 * nonce to a 64-bit counter value.
 *
 * The above example is for sequential packets on reliable transports
 * where the nonce is always incrementing.  For unreliable datagram
 * transports, the application will need to explicitly call set_nonce()
 * or set_counter() for each packet.
 */
class aead
{
    /* Disable copy operations */
    inline aead(const aead &) {}
    inline aead& operator=(const aead &) { return *this; }
public:
    /**
     * \brief Destroys this AEAD object and all sensitive material within.
     */
    virtual ~aead();

    /**
     * \brief Gets the size of the key for this AEAD object.
     *
     * \return The size of the key in bytes.
     */
    virtual size_t key_size() const = 0;

    /**
     * \brief Gets the size of the tag for this AEAD object.
     *
     * \return The size of the tag in bytes.
     */
    virtual size_t tag_size() const = 0;

    /**
     * \brief Gets the size of the nonce for this AEAD object.
     *
     * \return The size of the nonce in bytes.
     */
    virtual size_t nonce_size() const = 0;

    /**
     * \brief Sets a new key for this AEAD object while leaving the
     * nonce value as-is.
     *
     * \param key Points to the key to use to encrypt or decrypt packets.
     * \param len Length of the key in bytes.
     *
     * \return Returns true if the key was set, or false if \a key or
     * \a len are invalid.
     *
     * All subclasses must support a key length of zero to mean
     * "set the key to all-zeroes".  Otherwise the key length is
     * expected to be the same as key_size().  The subclass may
     * support other key sizes but this isn't guaranteed.
     *
     * \sa set_nonce()
     */
    virtual bool set_key(const unsigned char *key, size_t len) = 0;

    /**
     * \brief Sets a new nonce for this AEAD object while leaving the
     * key value as-is.
     *
     * \param nonce Points to the nonce to use to encrypt or decrypt the
     * next packet.
     * \param len The length of the nonce in bytes.
     *
     * If \a len is less than nonce_size(), then the value will be padded
     * on the left with zero bytes.  If \a len is greater than nonce_size(),
     * then the value will be truncated to the first nonce_size() bytes.
     *
     * \sa set_key(), set_counter()
     */
    virtual void set_nonce(const unsigned char *nonce, size_t len) = 0;

    /**
     * \brief Sets the nonce in this AEAD object to a 64-bit counter
     * value while leaving the key value as-is.
     *
     * \param n The 64-bit counter value to set.
     *
     * The \a n value will be formatted into the nonce as a big-endian
     * value with leading zeroes to make up the full nonce_size() bytes.
     *
     * \sa set_key(), set_nonce()
     */
    virtual void set_counter(uint64_t n) = 0;

    /**
     * \brief Encrypts and authenticates a packet with ASCON.
     *
     * \param c Buffer to receive the output ciphertext, which must be
     * large enough to hold \a len + 16 bytes.
     * \param m Buffer that contains the plaintext message to encrypt.
     * \param len Length of the plaintext message in bytes.
     * \param ad Buffer that contains associated data to authenticate
     * along with the packet but which does not need to be encrypted.
     * \param adlen Length of the associated data in bytes.
     *
     * \return The number of ciphertext bytes that were written to \a c.
     *
     * This function will increment the nonce value so that the next
     * packet will be encrypted (or decrypted) with the next nonce value.
     *
     * \sa decrypt()
     */
    inline int encrypt(unsigned char *c, const unsigned char *m, size_t len,
                       const unsigned char *ad = 0, size_t adlen = 0)
    {
        return do_encrypt(c, m, len, ad, adlen);
    }

    /**
     * \brief Encrypts and authenticates a packet with ASCON.
     *
     * \param c Byte array to receive the ciphertext output.  This array
     * will be resized to the correct size by this function.
     * \param m Byte array that contains the plaintext message to be encrypted.
     *
     * This function will increment the nonce value so that the next
     * packet will be encrypted (or decrypted) with the next nonce value.
     *
     * The \a c object should not be the same as \a m.
     *
     * \sa decrypt()
     */
    void encrypt(ascon::byte_array &c, const ascon::byte_array &m);

    /**
     * \brief Encrypts and authenticates a packet with ASCON.
     *
     * \param c Byte array to receive the ciphertext output.  This array
     * will be resized to the correct size by this function.
     * \param m Byte array that contains the plaintext message to be encrypted.
     * \param ad Byte array that contains the associated data.
     *
     * This function will increment the nonce value so that the next
     * packet will be encrypted (or decrypted) with the next nonce value.
     *
     * The \a c object should not be the same as either \a m or \a ad.
     *
     * \sa decrypt()
     */
    void encrypt(ascon::byte_array &c, const ascon::byte_array &m,
                 const ascon::byte_array &ad);

    /**
     * \brief Decrypts and authenticates a packet with ASCON.
     *
     * \param m Buffer to receive the plaintext message on output.
     * \param c Buffer that contains the ciphertext and authentication
     * tag to decrypt.
     * \param len Length of the input data in bytes, which includes the
     * ciphertext and the 16 byte authentication tag.
     * \param ad Buffer that contains associated data to authenticate
     * along with the packet but which does not need to be encrypted.
     * \param adlen Length of the associated data in bytes.
     *
     * \return The length of the plaintext on success.  Returns -1 if the
     * authentication tag was incorrect or \a len is too short to be a
     * valid ciphertext.
     *
     * On success, this function will increment the nonce value so that the
     * next packet will be decrypted (or encrypted) with the next nonce value.
     * The nonce will not be incremented if decryption fails.
     *
     * \sa encrypt()
     */
    inline int decrypt(unsigned char *m, const unsigned char *c, size_t len,
                       const unsigned char *ad = 0, size_t adlen = 0)
    {
        return do_decrypt(m, c, len, ad, adlen);
    }

    /**
     * \brief Decrypts and authenticates a packet with ASCON.
     *
     * \param m Byte array to receive the plaintext output.  This array
     * will be resized to the correct size by this function.
     * \param c Byte array that contains the ciphertext to be decrypted.
     *
     * \return Returns true if \a c was decrypted successfully or false
     * if the ciphertext is invalid.
     *
     * On success, this function will increment the nonce value so that the
     * next packet will be decrypted (or encrypted) with the next nonce value.
     * The nonce will not be incremented if decryption fails.
     *
     * The \a m object should not be the same as \a c.
     *
     * \sa encrypt()
     */
    bool decrypt(ascon::byte_array &m, const ascon::byte_array &c);

    /**
     * \brief Decrypts and authenticates a packet with ASCON.
     *
     * \param m Byte array to receive the plaintext output.  This array
     * will be resized to the correct size by this function.
     * \param c Byte array that contains the ciphertext to be decrypted.
     * \param ad Byte array that contains the associated data.
     *
     * \return Returns true if \a c was decrypted successfully or false
     * if the ciphertext is invalid.
     *
     * On success, this function will increment the nonce value so that the
     * next packet will be decrypted (or encrypted) with the next nonce value.
     * The nonce will not be incremented if decryption fails.
     *
     * The \a m object should not be the same as either \a c or \a ad.
     *
     * \sa encrypt()
     */
    bool decrypt(ascon::byte_array &m, const ascon::byte_array &c,
                 const ascon::byte_array &ad);

    /**
     * \brief Clears all sensitive material from this AEAD object.
     *
     * The key and nonce will be in an unknown state after calling this
     * function.  The application must call set_key() and set_nonce()
     * to be able to use this object again.
     */
    virtual void clear() = 0;

protected:
    /**
     * \brief Constructs a new AEAD object.
     */
    inline aead() {}

    /**
     * \brief Subclass implementation of ASCON encryption.
     *
     * \param c Buffer to receive the output ciphertext, which must be
     * large enough to hold \a len + 16 bytes.
     * \param m Buffer that contains the plaintext message to encrypt.
     * \param len Length of the plaintext message in bytes.
     * \param ad Buffer that contains associated data to authenticate
     * along with the packet but which does not need to be encrypted.
     * \param adlen Length of the associated data in bytes.
     *
     * \return The number of ciphertext bytes that were written to \a c.
     *
     * \sa do_decrypt()
     */
    virtual int do_encrypt
        (unsigned char *c, const unsigned char *m, size_t len,
         const unsigned char *ad, size_t adlen) = 0;

    /**
     * \brief Subclass implementation of ASCON decryption.
     *
     * \param m Buffer to receive the plaintext message on output.
     * \param c Buffer that contains the ciphertext and authentication
     * tag to decrypt.
     * \param len Length of the input data in bytes, which includes the
     * ciphertext and the 16 byte authentication tag.
     * \param ad Buffer that contains associated data to authenticate
     * along with the packet but which does not need to be encrypted.
     * \param adlen Length of the associated data in bytes.
     *
     * \return The length of the plaintext on success.  Returns -1 if the
     * authentication tag was incorrect or \a len is too short to be a
     * valid ciphertext.
     *
     * \sa do_encrypt()
     */
    virtual int do_decrypt
        (unsigned char *m, const unsigned char *c, size_t len,
         const unsigned char *ad, size_t adlen) = 0;
};

/**
 * \brief Encrypts or decrypts sequential packets with ASCON-128.
 */
class aead128 : public aead
{
    /* Disable copy operations */
    inline aead128(const aead128 &) : aead() {}
    inline aead128& operator=(const aead128 &) { return *this; }
public:
    /**
     * \brief Constructs a new ASCON-128 object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    aead128();

    /**
     * \brief Constructs a new ASCON-128 object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a key is NULL.
     */
    explicit aead128(const unsigned char key[ASCON128_KEY_SIZE]);

    /**
     * \brief Destroys this ASCON-128 object and all sensitive material within.
     */
    ~aead128();

    /* Override virtual methods */
    size_t key_size() const;
    size_t tag_size() const;
    size_t nonce_size() const;
    bool set_key(const unsigned char *key, size_t len);
    void set_nonce(const unsigned char *nonce, size_t len);
    void set_counter(uint64_t n);
    void clear();

protected:
    int do_encrypt(unsigned char *c, const unsigned char *m, size_t len,
                   const unsigned char *ad, size_t adlen);
    int do_decrypt(unsigned char *m, const unsigned char *c, size_t len,
                   const unsigned char *ad, size_t adlen);

private:
    struct {
        unsigned char key[ASCON128_KEY_SIZE];       /**< Key */
        unsigned char nonce[ASCON128_NONCE_SIZE];   /**< Nonce */
    } m_state; /**< Internal AEAD state */
};

/**
 * \brief Encrypts or decrypts sequential packets with ASCON-128a.
 */
class aead128a : public aead
{
    /* Disable copy operations */
    inline aead128a(const aead128a &) : aead() {}
    inline aead128a& operator=(const aead128a &) { return *this; }
public:
    /**
     * \brief Constructs a new ASCON-128a object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    aead128a();

    /**
     * \brief Constructs a new ASCON-128a object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a key is NULL.
     */
    explicit aead128a(const unsigned char key[ASCON128_KEY_SIZE]);

    /**
     * \brief Destroys this ASCON-128a object and all sensitive material within.
     */
    ~aead128a();

    /* Override virtual methods */
    size_t key_size() const;
    size_t tag_size() const;
    size_t nonce_size() const;
    bool set_key(const unsigned char *key, size_t len);
    void set_nonce(const unsigned char *nonce, size_t len);
    void set_counter(uint64_t n);
    void clear();

protected:
    int do_encrypt(unsigned char *c, const unsigned char *m, size_t len,
                   const unsigned char *ad, size_t adlen);
    int do_decrypt(unsigned char *m, const unsigned char *c, size_t len,
                   const unsigned char *ad, size_t adlen);

private:
    struct {
        unsigned char key[ASCON128_KEY_SIZE];       /**< Key */
        unsigned char nonce[ASCON128_NONCE_SIZE];   /**< Nonce */
    } m_state; /**< Internal AEAD state */
};

/**
 * \brief Encrypts or decrypts sequential packets with ASCON-80pq.
 */
class aead80pq : public aead
{
    /* Disable copy operations */
    inline aead80pq(const aead80pq &) : aead() {}
    inline aead80pq& operator=(const aead80pq &) { return *this; }
public:
    /**
     * \brief Constructs a new ASCON-80pq object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    aead80pq();

    /**
     * \brief Constructs a new ASCON-80pq object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a key is NULL.
     */
    explicit aead80pq(const unsigned char key[ASCON80PQ_KEY_SIZE]);

    /**
     * \brief Destroys this ASCON-80pq object and all sensitive material within.
     */
    ~aead80pq();

    /* Override virtual methods */
    size_t key_size() const;
    size_t tag_size() const;
    size_t nonce_size() const;
    bool set_key(const unsigned char *key, size_t len);
    void set_nonce(const unsigned char *nonce, size_t len);
    void set_counter(uint64_t n);
    void clear();

protected:
    int do_encrypt(unsigned char *c, const unsigned char *m, size_t len,
                   const unsigned char *ad, size_t adlen);
    int do_decrypt(unsigned char *m, const unsigned char *c, size_t len,
                   const unsigned char *ad, size_t adlen);

private:
    struct {
        unsigned char key[ASCON80PQ_KEY_SIZE];      /**< Key */
        unsigned char nonce[ASCON80PQ_NONCE_SIZE];  /**< Nonce */
    } m_state; /**< Internal AEAD state */
};

} /* namespace ascon */

#endif /* __cplusplus */

#endif
