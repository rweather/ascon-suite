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

#ifndef ASCON_HASH_H
#define ASCON_HASH_H

/**
 * \file hash.h
 * \brief Ascon-Hash256 hash algorithm.
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#include <ascon/xof.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash output for Ascon-Hash256 and the default hash
 * output size for Ascon-XOF128.
 */
#define ASCON_HASH256_SIZE 32

/**
 * \brief State information for the Ascon-Hash256 incremental mode.
 */
typedef struct
{
    ascon_xof128_state_t xof;  /**< Internal ASCON-XOF state */

} ascon_hash256_state_t;

/**
 * \brief Hashes a block of input data with Ascon-Hash256.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ASCON_HASH256_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \sa ascon_hash256_init(), ascon_hash256_absorb(), ascon_hash256_squeeze()
 */
void ascon_hash256(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an Ascon-Hash256 hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ascon_hash256_update(), ascon_hash256_finalize(), ascon_hash256()
 */
void ascon_hash256_init(ascon_hash256_state_t *state);

/**
 * \brief Re-initializes the state for an Ascon-Hash256 hashing operation.
 *
 * \param state Hash state to be re-initialized.
 *
 * This function is equivalent to calling ascon_hash256_free() and then
 * ascon_hash256_init() to restart the hashing process.
 *
 * \sa ascon_hash256_init()
 */
void ascon_hash256_reinit(ascon_hash256_state_t *state);

/**
 * \brief Frees the Ascon-Hash256 state and destroys any sensitive material.
 *
 * \param state Hash state to be freed.
 */
void ascon_hash256_free(ascon_hash256_state_t *state);

/**
 * \brief Updates an Ascon-Hash256 state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hash256_init(), ascon_hash256_finalize()
 */
void ascon_hash256_update
    (ascon_hash256_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from an Ascon-Hash256 hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa ascon_hash256_init(), ascon_hash256_update()
 */
void ascon_hash256_finalize(ascon_hash256_state_t *state, unsigned char *out);

/**
 * \brief Clones a copy of an Ascon-Hash256 state.
 *
 * \param dest Destination hash state to copy into.
 * \param src Source hash state to copy from.
 *
 * The destination will be initialized by this operation, so it must
 * not previously have been initialized or it has already been freed.
 * The source must be already initialized.
 */
void ascon_hash256_copy
    (ascon_hash256_state_t *dest, const ascon_hash256_state_t *src);

#ifdef __cplusplus
} /* extern "C" */

namespace ascon
{

/**
 * \brief Ascon-Hash256 digest algorithm.
 */
class hash256
{
public:
    /**
     * \brief Constructs a new Ascon-Hash256 object.
     */
    inline hash256()
    {
        ::ascon_hash256_init(&m_state);
    }

    /**
     * \brief Constructs a copy of another Ascon-Hash256 object.
     *
     * \param other The other Ascon-Hash256 digest object.
     */
    inline hash256(const ascon::hash256 &other)
    {
        ::ascon_hash256_copy(&m_state, &other.m_state);
    }

    /**
     * \brief Destroys this Ascon-Hash256 object.
     */
    inline ~hash256()
    {
        ::ascon_hash256_free(&m_state);
    }

    /**
     * \brief Copies the state of another Ascon-Hash256 object into this one.
     *
     * \param other The other object to copy.
     *
     * \return A reference to this Ascon-Hash256 object.
     */
    inline hash256 &operator=(const ascon::hash256 &other)
    {
        if (this != &other) {
            ::ascon_hash256_free(&m_state);
            ::ascon_hash256_copy(&m_state, &other.m_state);
        }
        return *this;
    }

    /**
     * \brief Resets this Ascon-Hash256 object back to its initial state.
     */
    inline void reset()
    {
        ::ascon_hash256_reinit(&m_state);
    }

    /**
     * \brief Updates this Ascon-Hash256 object with new input data.
     *
     * \param data Points to the input data to be absorbed into the state.
     * \param len Length of the input data to be absorbed into the state.
     */
    inline void update(const unsigned char *data, size_t len)
    {
        ::ascon_hash256_update(&m_state, data, len);
    }

    /**
     * \brief Updates this Ascon-Hash256 object with the contents of a
     * NUL-terminated C string.
     *
     * \param str Points to the C string to absorb.
     *
     * If \a str is NULL, then this function is equivalent to absorbing the
     * empty string into the state.
     */
    inline void update(const char *str)
    {
        if (str) {
            ::ascon_hash256_update
                (&m_state, reinterpret_cast<const unsigned char *>(str),
                 ::strlen(str));
        }
    }

    /**
     * \brief Updates this Ascon-Hash256 object with the contents of a byte array.
     *
     * \param data Reference to the byte array to absorb.
     */
    inline void update(const ascon::byte_array& data)
    {
        ::ascon_hash256_update(&m_state, data.data(), data.size());
    }

    /**
     * \brief Finalizes this Ascon-Hash256 object and returns the digest.
     *
     * The application must call reset() to perform another hashing process.
     */
    inline void finalize(unsigned char digest[ASCON_HASH256_SIZE])
    {
        ::ascon_hash256_finalize(&m_state, digest);
    }

    /**
     * \brief Finalizes this Ascon-Hash256 object and returns the digest
     * as a byte array.
     *
     * \return A byte array containing the finalized digest.
     */
    inline ascon::byte_array finalize()
    {
        ascon::byte_array vec(ASCON_HASH256_SIZE);
        ::ascon_hash256_finalize(&m_state, vec.data());
        return vec;
    }

    /**
     * \brief Computes the Ascon-Hash256 digest of a block of input data.
     *
     * \param result Points to the buffer to receive the digest.
     * \param data Points to the input data to be hashed.
     * \param len Length of the input data to be hashed.
     */
    static inline void digest
        (unsigned char result[ASCON_HASH256_SIZE],
         const unsigned char *data, size_t len)
    {
        ::ascon_hash256(result, data, len);
    }

    /**
     * \brief Gets a reference to the C version of the Ascon-Hash256 state.
     *
     * \return A reference to the state.
     */
    inline ::ascon_hash256_state_t *state() { return &m_state; }

    /**
     * \brief Gets a constant reference to the C version of the
     * Ascon-Hash256 state.
     *
     * \return A constant reference to the state.
     */
    inline const ::ascon_hash256_state_t *state() const { return &m_state; }

#if !defined(ARDUINO) && !defined(ASCON_NO_STL)

    /**
     * \brief Updates this Ascon-Hash256 object with the contents of a
     * standard C++ string.
     *
     * \param str Reference to the string to absorb.
     */
    inline void update(const std::string& str)
    {
        ::ascon_hash256_update
            (&m_state, reinterpret_cast<const unsigned char *>(str.data()),
             str.size());
    }

#elif defined(ARDUINO)

    /**
     * \brief Updates this Ascon-Hash256 object with the contents of an
     * Arduino string.
     *
     * \param str Reference to the string to absorb.
     */
    inline void update(const String& str)
    {
        ::ascon_hash256_update
            (&m_state, reinterpret_cast<const unsigned char *>(str.c_str()),
             str.length());
    }

#endif /* ARDUINO */

private:
    ::ascon_hash256_state_t m_state; /**< Internal hash state */
};

} /* namespace ascon */

#endif /* __cplusplus */

#endif
