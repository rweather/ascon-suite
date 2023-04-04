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
 * This structure should be treated as opaque by the application.
 */
typedef struct
{
    /** ASCON permutation state */
    ascon_state_t state;

    /** Key to use to authenticate the payload during finalization */
    unsigned char key[ASCON128_KEY_SIZE];

    /** Position within the current block for partial blocks */
    unsigned char posn;

} ascon128_state_t;

/**
 * \brief State information for the incremental version of ASCON-128a.
 *
 * This structure should be treated as opaque by the application.
 */
typedef struct
{
    /** ASCON permutation state */
    ascon_state_t state;

    /** Key to use to authenticate the payload during finalization */
    unsigned char key[ASCON128_KEY_SIZE];

    /** Position within the current block for partial blocks */
    unsigned char posn;

} ascon128a_state_t;

/**
 * \brief State information for the incremental version of ASCON-80pq.
 *
 * This structure should be treated as opaque by the application.
 */
typedef struct
{
    /** ASCON permutation state */
    ascon_state_t state;

    /** Key to use to authenticate the payload during finalization */
    unsigned char key[ASCON80PQ_KEY_SIZE];

    /** Position within the current block for partial blocks */
    unsigned char posn;

} ascon80pq_state_t;

/**
 * \brief Starts encrypting or decrypting a packet with ASCON-128 in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-128 operations.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * The following sequence can be used to encrypt a list of i plaintext
 * message blocks (m) to produce i ciphertext message blocks (c)
 * and an authentication tag (t).
 *
 * \code
 * ascon128_state_t state;
 * ascon128_aead_start(&state, ad, adlen, npub, k);
 * ascon128_aead_encrypt_block(&state, m1, c1, m1_len);
 * ascon128_aead_encrypt_block(&state, m2, c2, m2_len);
 * ...;
 * ascon128_aead_encrypt_block(&state, mi, ci, mi_len);
 * ascon128_aead_encrypt_finalize(&state, t);
 * \endcode
 *
 * Decryption uses a similar sequence:
 *
 * \code
 * ascon128_state_t state;
 * ascon128_aead_start(&state, ad, adlen, npub, k);
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
 * \sa ascon128_aead_encrypt_block(), ascon128_aead_decrypt_block(),
 * ascon128_aead_encrypt_finalize(), ascon128_aead_decrypt_finalize()
 */
void ascon128_aead_start
    (ascon128_state_t *state, const unsigned char *ad, size_t adlen,
     const unsigned char *npub, const unsigned char *k);

/**
 * \brief Aborts use of ASCON-128 in incremental mode.
 *
 * \param state State to abort.
 *
 * This function may be used any time after ascon128_aead_start() and
 * before the encryption or decryption process is finalized to abort
 * the process entirely and free the \a state.
 */
void ascon128_aead_abort(ascon128_state_t *state);

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
 * The contents of \a state will be freed by this function, destroying
 * any sensitive material that may be present.
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
 * The contents of \a state will be freed by this function, destroying
 * any sensitive material that may be present.
 *
 * \sa ascon128_aead_decrypt_block(), ascon128_aead_start()
 */
int ascon128_aead_decrypt_finalize
    (ascon128_state_t *state, const unsigned char *tag);

/**
 * \brief Starts encrypting or decrypting a packet with ASCON-128a in
 * incremental mode.
 *
 * \param state State to initialize for ASCON-128a operations.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * The following sequence can be used to encrypt a list of i plaintext
 * message blocks (m) to produce i ciphertext message blocks (c)
 * and an authentication tag (t).
 *
 * \code
 * ascon128a_state_t state;
 * ascon128a_aead_start(&state, ad, adlen, npub, k);
 * ascon128a_aead_encrypt_block(&state, m1, c1, m1_len);
 * ascon128a_aead_encrypt_block(&state, m2, c2, m2_len);
 * ...;
 * ascon128a_aead_encrypt_block(&state, mi, ci, mi_len);
 * ascon128a_aead_encrypt_finalize(&state, t);
 * \endcode
 *
 * Decryption uses a similar sequence:
 *
 * \code
 * ascon128a_state_t state;
 * ascon128a_aead_start(&state, ad, adlen, npub, k);
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
 * \sa ascon128a_aead_encrypt_block(), ascon128a_aead_decrypt_block(),
 * ascon128a_aead_encrypt_finalize(), ascon128a_aead_decrypt_finalize()
 */
void ascon128a_aead_start
    (ascon128a_state_t *state, const unsigned char *ad, size_t adlen,
     const unsigned char *npub, const unsigned char *k);

/**
 * \brief Aborts use of ASCON-128a in incremental mode.
 *
 * \param state State to abort.
 *
 * This function may be used any time after ascon128a_aead_start() and
 * before the encryption or decryption process is finalized to abort
 * the process entirely and free the \a state.
 */
void ascon128a_aead_abort(ascon128a_state_t *state);

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
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 20 bytes of the key to use to encrypt the packet.
 *
 * The following sequence can be used to encrypt a list of i plaintext
 * message blocks (m) to produce i ciphertext message blocks (c)
 * and an authentication tag (t).
 *
 * \code
 * ascon80pq_state_t state;
 * ascon80pq_aead_start(&state, ad, adlen, npub, k);
 * ascon80pq_aead_encrypt_block(&state, m1, c1, m1_len);
 * ascon80pq_aead_encrypt_block(&state, m2, c2, m2_len);
 * ...;
 * ascon80pq_aead_encrypt_block(&state, mi, ci, mi_len);
 * ascon80pq_aead_encrypt_finalize(&state, t);
 * \endcode
 *
 * Decryption uses a similar sequence:
 *
 * \code
 * ascon80pq_state_t state;
 * ascon80pq_aead_start(&state, ad, adlen, npub, k);
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
 * \sa ascon80pq_aead_encrypt_block(), ascon80pq_aead_decrypt_block(),
 * ascon80pq_aead_encrypt_finalize(), ascon80pq_aead_decrypt_finalize()
 */
void ascon80pq_aead_start
    (ascon80pq_state_t *state, const unsigned char *ad, size_t adlen,
     const unsigned char *npub, const unsigned char *k);

/**
 * \brief Aborts use of ASCON-80pq in incremental mode.
 *
 * \param state State to abort.
 *
 * This function may be used any time after ascon80pq_aead_start() and
 * before the encryption or decryption process is finalized to abort
 * the process entirely and free the \a state.
 */
void ascon80pq_aead_abort(ascon80pq_state_t *state);

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
#endif

#endif
