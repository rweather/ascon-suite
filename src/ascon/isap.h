/*
 * Copyright (C) 2023 Southern Storm Software, Pty Ltd.
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
 * This API also provides ISAP-A-80PQ which is almost identical to ISAP-A-128,
 * except that it uses a 160-bit key instead of the default 128-bit key.
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
 * \brief Size of the key for all ISAP-A family members with 128-bit keys.
 */
#define ASCON128_ISAP_KEY_SIZE 16

/**
 * \brief Size of the key for all ISAP-A family members with 160-bit keys.
 */
#define ASCON80PQ_ISAP_KEY_SIZE 20

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
 * \brief Pre-computed key information for ISAP-A-80PQ.
 */
typedef struct
{
    ascon_state_t ke;   /**< Pre-computed key for encryption */
    ascon_state_t ka;   /**< Pre-computed key for authentication */

} ascon80pq_isap_aead_key_t;

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

/**
 * \brief Initializes a pre-computed key for ISAP-A-80PQ.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the 20 bytes of the key.
 *
 * The ascon80pq_isap_aead_load_key() function can be used to
 * initialize the pre-computed key from a value that was previously
 * saved with ascon80pq_isap_aead_save_key().
 *
 * \sa ascon80pq_isap_aead_free(), ascon80pq_isap_aead_encrypt(),
 * ascon80pq_isap_aead_decrypt(), ascon80pq_isap_aead_load_key()
 */
void ascon80pq_isap_aead_init
    (ascon80pq_isap_aead_key_t *pk, const unsigned char *k);

/**
 * \brief Initializes a pre-computed key for ISAP-A-80PQ from a
 * previously-saved key value.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the bytes of the previously-saved key.
 *
 * \sa ascon80pq_isap_aead_free(), ascon80pq_isap_aead_encrypt(),
 * ascon80pq_isap_aead_decrypt(), ascon80pq_isap_aead_save_key()
 */
void ascon80pq_isap_aead_load_key
    (ascon80pq_isap_aead_key_t *pk,
     const unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE]);

/**
 * \brief Saves a previously pre-computed key for ISAP-A-80PQ to a buffer.
 *
 * \param pk Points to the object to receive the pre-computed key value.
 * \param k Points to the buffer to save the pre-computed key in.
 *
 * \sa ascon80pq_isap_aead_free(), ascon80pq_isap_aead_encrypt(),
 * ascon80pq_isap_aead_decrypt(), ascon80pq_isap_aead_load_key()
 */
void ascon80pq_isap_aead_save_key
    (ascon80pq_isap_aead_key_t *pk,
     unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE]);

/**
 * \brief Frees a pre-computed key for ISAP-A-80PQ.
 *
 * \param pk Points to the pre-computed key value.
 *
 * \sa ascon80pq_isap_aead_init()
 */
void ascon80pq_isap_aead_free(ascon80pq_isap_aead_key_t *pk);

/**
 * \brief Encrypts and authenticates a packet with ISAP-A-80PQ and
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
 * \sa ascon80pq_isap_aead_decrypt(), ascon80pq_isap_aead_init()
 */
void ascon80pq_isap_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon80pq_isap_aead_key_t *pk);

/**
 * \brief Decrypts and authenticates a packet with ISAP-A-80PQ and
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
 * \sa ascon80pq_isap_aead_encrypt(), ascon80pq_isap_aead_init()
 */
int ascon80pq_isap_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ascon80pq_isap_aead_key_t *pk);

#ifdef __cplusplus
}

#include <ascon/aead.h>

namespace ascon
{

/**
 * \brief Encrypts or decrypts sequential packets with ISAP-A-128.
 */
class isap128 : public aead
{
    /* Disable copy operations */
    inline isap128(const isap128 &) : aead() {}
    inline isap128& operator=(const isap128 &) { return *this; }
public:
    /**
     * \brief Constructs a new ISAP-A-128 object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    isap128();

    /**
     * \brief Constructs a new ISAP-A-128 object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     * \param len The length of the key in bytes, 16 or 80.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a len is 0.
     *
     * If \a len is 80, then it indicates the ISAP "save key" format.
     */
    explicit isap128(const unsigned char *key, size_t len);

    /**
     * \brief Destroys this ISAP-A-128 object and all sensitive
     * material within.
     */
    ~isap128();

    /**
     * \brief Gets the key value from this object as a "save key".
     *
     * \param key Buffer to fill with the save key.
     *
     * Save keys can be set using set_key().
     */
    void save_key(unsigned char key[ASCON_ISAP_SAVED_KEY_SIZE]);

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
    ascon128_isap_aead_key_t m_key; /**< Key */
    unsigned char m_nonce[ASCON_ISAP_NONCE_SIZE]; /**< Nonce */
};

/**
 * \brief Encrypts or decrypts sequential packets with ISAP-A-128A.
 */
class isap128a : public aead
{
    /* Disable copy operations */
    inline isap128a(const isap128a &) : aead() {}
    inline isap128a& operator=(const isap128a &) { return *this; }
public:
    /**
     * \brief Constructs a new ISAP-A-128A object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    isap128a();

    /**
     * \brief Constructs a new ISAP-A-128A object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     * \param len The length of the key in bytes, 16 or 80.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a len is 0.
     *
     * If \a len is 80, then it indicates the ISAP "save key" format.
     */
    explicit isap128a(const unsigned char *key, size_t len);

    /**
     * \brief Destroys this ISAP-A-128A object and all sensitive
     * material within.
     */
    ~isap128a();

    /**
     * \brief Gets the key value from this object as a "save key".
     *
     * \param key Buffer to fill with the save key.
     *
     * Save keys can be set using set_key().
     */
    void save_key(unsigned char key[ASCON_ISAP_SAVED_KEY_SIZE]);

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
    ascon128a_isap_aead_key_t m_key; /**< Key */
    unsigned char m_nonce[ASCON_ISAP_NONCE_SIZE]; /**< Nonce */
};

/**
 * \brief Encrypts or decrypts sequential packets with ISAP-A-80PQ.
 */
class isap80pq : public aead
{
    /* Disable copy operations */
    inline isap80pq(const isap80pq &) : aead() {}
    inline isap80pq& operator=(const isap80pq &) { return *this; }
public:
    /**
     * \brief Constructs a new ISAP-A-80PQ object.
     *
     * The key and nonce will be initially set to all-zeroes.  Use set_key()
     * and set_nonce() to set specific key and nonce values.
     */
    isap80pq();

    /**
     * \brief Constructs a new ISAP-A-80PQ object with an initial key.
     *
     * \param key The key to use to encrypt or decrypt packets.
     * \param len The length of the key in bytes, 16 or 80.
     *
     * The nonce will be initially set to all-zeroes.  Use set_nonce() or
     * set_counter() to set a specific nonce value.
     *
     * The key will be set to all-zeroes if \a len is 0.
     *
     * If \a len is 80, then it indicates the ISAP "save key" format.
     */
    explicit isap80pq(const unsigned char *key, size_t len);

    /**
     * \brief Destroys this ISAP-A-80PQ object and all sensitive
     * material within.
     */
    ~isap80pq();

    /**
     * \brief Gets the key value from this object as a "save key".
     *
     * \param key Buffer to fill with the save key.
     *
     * Save keys can be set using set_key().
     */
    void save_key(unsigned char key[ASCON_ISAP_SAVED_KEY_SIZE]);

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
    ascon80pq_isap_aead_key_t m_key; /**< Key */
    unsigned char m_nonce[ASCON_ISAP_NONCE_SIZE]; /**< Nonce */
};

} /* namespace ascon */

#endif /* __cplusplus */

#endif
