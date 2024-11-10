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

#ifndef ASCON_AEAD_MASKED_H
#define ASCON_AEAD_MASKED_H

#include <ascon/aead.h>
#include <ascon/masking.h>

/**
 * \file aead-masked.h
 * \brief Masked ASCON-128 encryption algorithm and related family members.
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Encrypts and authenticates a packet with masked ASCON-128a.
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
 * \param k Points to the masked 128-bit key.
 *
 * \sa ascon128a_masked_aead_decrypt()
 */
void ascon128a_masked_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon_masked_key_128_t *k);

/**
 * \brief Decrypts and authenticates a packet with masked ASCON-128a.
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
 * \param k Points to the masked 128-bit key.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa ascon128a_masked_aead_encrypt()
 */
int ascon128a_masked_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon_masked_key_128_t *k);

#ifdef __cplusplus
}

namespace ascon
{

/**
 * \brief Base classes for masked versions of ASCON AEAD modes.
 */
class aead_masked : public aead
{
    /* Disable copy operations */
    inline aead_masked(const aead_masked &) : aead() {}
    inline aead_masked& operator=(const aead_masked &) { return *this; }
public:
    /**
     * \brief Destroys this masked AEAD object.
     */
    ~aead_masked();

    /**
     * \brief Randomizes the masked key by mixing in fresh random material.
     *
     * Long-lived keys should be randomized regularly to mix in fresh
     * randomness.
     */
    virtual void randomize_key() = 0;

protected:
    /**
     * \brief Constructs a new masked AEAD object.
     */
    inline aead_masked() {}
};

/**
 * \brief Encrypts or decrypts sequential packets with the masked
 * version of ASCON-128a.
 */
class aead128a_masked : public aead_masked
{
    /* Disable copy operations */
    inline aead128a_masked(const aead128a_masked &) : aead_masked() {}
    inline aead128a_masked& operator=(const aead128a_masked &) { return *this; }
public:
    /**
     * \brief Constructs a new masked ASCON-128a object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    aead128a_masked();

    /**
     * \brief Constructs a new masked ASCON-128a object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a key is NULL.
     */
    explicit aead128a_masked(const unsigned char key[ASCON128_KEY_SIZE]);

    /**
     * \brief Destroys this masked ASCON-128a object and all sensitive
     * material within.
     */
    ~aead128a_masked();

    /* Override virtual methods */
    size_t key_size() const;
    size_t tag_size() const;
    size_t nonce_size() const;
    bool set_key(const unsigned char *key, size_t len);
    void set_nonce(const unsigned char *nonce, size_t len);
    void set_counter(uint64_t n);
    void clear();
    void randomize_key();

protected:
    int do_encrypt(unsigned char *c, const unsigned char *m, size_t len,
                   const unsigned char *ad, size_t adlen);
    int do_decrypt(unsigned char *m, const unsigned char *c, size_t len,
                   const unsigned char *ad, size_t adlen);

private:
    ascon_masked_key_128_t m_key; /**< Key */
    unsigned char m_nonce[ASCON128_NONCE_SIZE]; /**< Nonce */
};

} /* namespace ascon */

#endif /* __cplusplus */

#endif
