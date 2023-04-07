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

#ifndef ASCON_SIV_H
#define ASCON_SIV_H

#include <ascon/aead.h>

/**
 * \file siv.h
 * \brief SIV encryption primitives built around the ASCON permutation.
 *
 * This API provides support for SIV mode (Synthetic Initialization
 * Vector).  SIV mode authenticates the associated data and the plaintext
 * before encrypting the plaintext.
 *
 * The SIV construction makes the result resistant against reuse of the
 * nonce as long as the combination of the associated data and plaintext
 * is unique.  If the combination is not unique, then the algorithm leaks
 * that the same plaintext has been encrypted again but does not reveal
 * the plaintext itself.
 *
 * SIV mode can be useful when encrypting data in memory, such as
 * encrypting a key pair for storage in non-volatile memory.  The nonce or
 * the associated data is set to the address in memory of the encrypted data,
 * so that encrypting the same data in different locations will give
 * different results.
 *
 * SIV mode increases the size of the data by 16 bytes, which provides
 * the authentication tag.  This tag must not be discarded because the
 * data cannot be successfully decrypted without it.
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Encrypts and authenticates a packet with ASCON-128-SIV.
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
 * \sa ascon128_siv_decrypt()
 */
void ascon128_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-128-SIV.
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
 * \sa ascon128_siv_encrypt()
 */
int ascon128_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ASCON-128a-SIV.
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
 * \sa ascon128a_siv_decrypt()
 */
void ascon128a_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-128a-SIV.
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
 * \sa ascon128a_siv_encrypt()
 */
int ascon128a_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with ASCON-80pq-SIV.
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
 * \sa ascon80pq_siv_decrypt()
 */
void ascon80pq_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ASCON-80pq-SIV.
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
 * \sa ascon80pq_siv_encrypt()
 */
int ascon80pq_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

#ifdef __cplusplus
}

namespace ascon
{

/**
 * \brief Encrypts or decrypts sequential packets with ASCON-128-SIV.
 */
class siv128 : public aead
{
    /* Disable copy operations */
    inline siv128(const siv128 &) : aead() {}
    inline siv128& operator=(const siv128 &) { return *this; }
public:
    /**
     * \brief Constructs a new ASCON-128-SIV object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    siv128();

    /**
     * \brief Constructs a new ASCON-128-SIV object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a key is NULL.
     */
    explicit siv128(const unsigned char key[ASCON128_KEY_SIZE]);

    /**
     * \brief Destroys this ASCON-128-SIV object and all sensitive
     * material within.
     */
    ~siv128();

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
 * \brief Encrypts or decrypts sequential packets with ASCON-128a-SIV.
 */
class siv128a : public aead
{
    /* Disable copy operations */
    inline siv128a(const siv128a &) : aead() {}
    inline siv128a& operator=(const siv128a &) { return *this; }
public:
    /**
     * \brief Constructs a new ASCON-128a-SIV object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    siv128a();

    /**
     * \brief Constructs a new ASCON-128a-SIV object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a key is NULL.
     */
    explicit siv128a(const unsigned char key[ASCON128_KEY_SIZE]);

    /**
     * \brief Destroys this ASCON-128a-SIV object and all sensitive
     * material within.
     */
    ~siv128a();

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
 * \brief Encrypts or decrypts sequential packets with ASCON-80pq-SIV.
 */
class siv80pq : public aead
{
    /* Disable copy operations */
    inline siv80pq(const siv80pq &) : aead() {}
    inline siv80pq& operator=(const siv80pq &) { return *this; }
public:
    /**
     * \brief Constructs a new ASCON-80pq-SIV object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    siv80pq();

    /**
     * \brief Constructs a new ASCON-80pq-SIV object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a key is NULL.
     */
    explicit siv80pq(const unsigned char key[ASCON80PQ_KEY_SIZE]);

    /**
     * \brief Destroys this ASCON-80pq-SIV object and all sensitive
     * material within.
     */
    ~siv80pq();

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
