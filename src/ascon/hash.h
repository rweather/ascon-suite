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
 * \brief ASCON-HASH and ASCON-HASHA hash algorithms.
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#include <ascon/xof.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State information for the ASCON-HASH incremental mode.
 */
typedef struct
{
    ascon_xof_state_t xof;  /**< Internal ASCON-XOF state */

} ascon_hash_state_t;

/**
 * \brief State information for the ASCON-HASHA incremental mode.
 */
typedef struct
{
    ascon_xofa_state_t xof; /**< Internal ASCON-XOFA state */

} ascon_hasha_state_t;

/**
 * \brief Hashes a block of input data with ASCON-HASH.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ASCON_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \sa ascon_hash_init(), ascon_hash_absorb(), ascon_hash_squeeze()
 */
void ascon_hash(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an ASCON-HASH hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ascon_hash_update(), ascon_hash_finalize(), ascon_hash()
 */
void ascon_hash_init(ascon_hash_state_t *state);

/**
 * \brief Re-initializes the state for an ASCON-HASH hashing operation.
 *
 * \param state Hash state to be re-initialized.
 *
 * This function is equivalent to calling ascon_hash_free() and then
 * ascon_hash_init() to restart the hashing process.
 *
 * \sa ascon_hash_init()
 */
void ascon_hash_reinit(ascon_hash_state_t *state);

/**
 * \brief Frees the ASCON-HASH state and destroys any sensitive material.
 *
 * \param state Hash state to be freed.
 */
void ascon_hash_free(ascon_hash_state_t *state);

/**
 * \brief Updates an ASCON-HASH state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hash_init(), ascon_hash_finalize()
 */
void ascon_hash_update
    (ascon_hash_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from an ASCON-HASH hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa ascon_hash_init(), ascon_hash_update()
 */
void ascon_hash_finalize(ascon_hash_state_t *state, unsigned char *out);

/**
 * \brief Clones a copy of an ASCON-HASH state.
 *
 * \param dest Destination hash state to copy into.
 * \param src Source hash state to copy from.
 *
 * The destination will be initialized by this operation, so it must
 * not previously have been initialized or it has already been freed.
 * The source must be already initialized.
 */
void ascon_hash_copy
    (ascon_hash_state_t *dest, const ascon_hash_state_t *src);

/**
 * \brief Hashes a block of input data with ASCON-HASHA.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ASCON_HASHA_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \sa ascon_hasha_init(), ascon_hasha_absorb(), ascon_hasha_squeeze()
 */
void ascon_hasha(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an ASCON-HASHA hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ascon_hasha_update(), ascon_hasha_finalize(), ascon_hasha()
 */
void ascon_hasha_init(ascon_hasha_state_t *state);

/**
 * \brief Re-initializes the state for an ASCON-HASHA hashing operation.
 *
 * \param state Hash state to be re-initialized.
 *
 * This function is equivalent to calling ascon_hasha_free() and then
 * ascon_hasha_init() to restart the hashing process.
 *
 * \sa ascon_hasha_init()
 */
void ascon_hasha_reinit(ascon_hasha_state_t *state);

/**
 * \brief Frees the ASCON-HASHA state and destroys any sensitive material.
 *
 * \param state Hash state to be freed.
 */
void ascon_hasha_free(ascon_hasha_state_t *state);

/**
 * \brief Updates an ASCON-HASHA state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ascon_hasha_init(), ascon_hasha_finalize()
 */
void ascon_hasha_update
    (ascon_hasha_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from an ASCON-HASHA hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa ascon_hasha_init(), ascon_hasha_update()
 */
void ascon_hasha_finalize(ascon_hasha_state_t *state, unsigned char *out);

/**
 * \brief Clones a copy of an ASCON-HASHA state.
 *
 * \param dest Destination hash state to copy into.
 * \param src Source hash state to copy from.
 *
 * The destination will be initialized by this operation, so it must
 * not previously have been initialized or it has already been freed.
 * The source must be already initialized.
 */
void ascon_hasha_copy
    (ascon_hasha_state_t *dest, const ascon_hasha_state_t *src);

#ifdef __cplusplus
} /* extern "C" */

namespace ascon
{

/**
 * \brief ASCON-HASH digest algorithm.
 */
class hash
{
public:
    /**
     * \brief Constructs a new ASCON-HASH object.
     */
    inline hash()
    {
        ::ascon_hash_init(&m_state);
    }

    /**
     * \brief Constructs a copy of another ASCON-HASH object.
     *
     * \param other The other ASCON-HASH digest object.
     */
    inline hash(const ascon::hash &other)
    {
        ::ascon_hash_copy(&m_state, &other.m_state);
    }

    /**
     * \brief Destroys this ASCON-HASH object.
     */
    inline ~hash()
    {
        ::ascon_hash_free(&m_state);
    }

    /**
     * \brief Copies the state of another ASCON-HASH object into this one.
     *
     * \param other The other object to copy.
     *
     * \return A reference to this ASCON-HASH object.
     */
    inline hash &operator=(const ascon::hash &other)
    {
        if (this != &other) {
            ::ascon_hash_free(&m_state);
            ::ascon_hash_copy(&m_state, &other.m_state);
        }
        return *this;
    }

    /**
     * \brief Resets this ASCON-HASH object back to its initial state.
     */
    inline void reset()
    {
        ::ascon_hash_reinit(&m_state);
    }

    /**
     * \brief Updates this ASCON-HASH object with new input data.
     *
     * \param data Points to the input data to be absorbed into the state.
     * \param len Length of the input data to be absorbed into the state.
     */
    inline void update(const unsigned char *data, size_t len)
    {
        ::ascon_hash_update(&m_state, data, len);
    }

    /**
     * \brief Updates this ASCON-HASH object with the contents of a
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
            ::ascon_hash_update
                (&m_state, reinterpret_cast<const unsigned char *>(str),
                 ::strlen(str));
        }
    }

    /**
     * \brief Updates this ASCON-HASH object with the contents of a byte array.
     *
     * \param data Reference to the byte array to absorb.
     */
    inline void update(const ascon::byte_array& data)
    {
        ::ascon_hash_update(&m_state, data.data(), data.size());
    }

    /**
     * \brief Finalizes this ASCON-HASH object and returns the digest.
     *
     * The application must call reset() to perform another hashing process.
     */
    inline void finalize(unsigned char digest[ASCON_HASH_SIZE])
    {
        ::ascon_hash_finalize(&m_state, digest);
    }

    /**
     * \brief Finalizes this ASCON-HASH object and returns the digest
     * as a byte array.
     *
     * \return A byte array containing the finalized digest.
     */
    inline ascon::byte_array finalize()
    {
        ascon::byte_array vec(ASCON_HASH_SIZE);
        ::ascon_hash_finalize(&m_state, vec.data());
        return vec;
    }

    /**
     * \brief Computes the ASCON-HASH digest of a block of input data.
     *
     * \param result Points to the buffer to receive the digest.
     * \param data Points to the input data to be hashed.
     * \param len Length of the input data to be hashed.
     */
    static inline void digest
        (unsigned char result[ASCON_HASH_SIZE],
         const unsigned char *data, size_t len)
    {
        ::ascon_hash(result, data, len);
    }

    /**
     * \brief Gets a reference to the C version of the ASCON-HASH state.
     *
     * \return A reference to the state.
     */
    inline ::ascon_hash_state_t *state() { return &m_state; }

    /**
     * \brief Gets a constant reference to the C version of the
     * ASCON-HASH state.
     *
     * \return A constant reference to the state.
     */
    inline const ::ascon_hash_state_t *state() const { return &m_state; }

#if !defined(ARDUINO) && !defined(ASCON_NO_STL)

    /**
     * \brief Updates this ASCON-HASH object with the contents of a
     * standard C++ string.
     *
     * \param str Reference to the string to absorb.
     */
    inline void update(const std::string& str)
    {
        ::ascon_hash_update
            (&m_state, reinterpret_cast<const unsigned char *>(str.data()),
             str.size());
    }

#elif defined(ARDUINO)

    /**
     * \brief Updates this ASCON-HASH object with the contents of an
     * Arduino string.
     *
     * \param str Reference to the string to absorb.
     */
    inline void update(const String& str)
    {
        ::ascon_hash_update
            (&m_state, reinterpret_cast<const unsigned char *>(str.c_str()),
             str.length());
    }

#endif /* ARDUINO */

private:
    ::ascon_hash_state_t m_state; /**< Internal hash state */
};

/**
 * \brief ASCON-HASHA digest algorithm.
 */
class hasha
{
public:
    /**
     * \brief Constructs a new ASCON-HASHA object.
     */
    inline hasha()
    {
        ::ascon_hasha_init(&m_state);
    }

    /**
     * \brief Constructs a copy of another ASCON-HASHA object.
     *
     * \param other The other ASCON-HASHA digest object.
     */
    inline hasha(const ascon::hasha &other)
    {
        ::ascon_hasha_copy(&m_state, &other.m_state);
    }

    /**
     * \brief Destroys this ASCON-HASHA object.
     */
    inline ~hasha()
    {
        ::ascon_hasha_free(&m_state);
    }

    /**
     * \brief Copies the state of another ASCON-HASHA object into this one.
     *
     * \param other The other object to copy.
     *
     * \return A reference to this ASCON-HASHA object.
     */
    inline hasha &operator=(const ascon::hasha &other)
    {
        if (this != &other) {
            ::ascon_hasha_free(&m_state);
            ::ascon_hasha_copy(&m_state, &other.m_state);
        }
        return *this;
    }

    /**
     * \brief Resets this ASCON-HASHA object back to its initial state.
     */
    inline void reset()
    {
        ::ascon_hasha_reinit(&m_state);
    }

    /**
     * \brief Updates this ASCON-HASHA object with new input data.
     *
     * \param data Points to the input data to be absorbed into the state.
     * \param len Length of the input data to be absorbed into the state.
     */
    inline void update(const unsigned char *data, size_t len)
    {
        ::ascon_hasha_update(&m_state, data, len);
    }

    /**
     * \brief Updates this ASCON-HASHA object with the contents of a
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
            ::ascon_hasha_update
                (&m_state, reinterpret_cast<const unsigned char *>(str),
                 ::strlen(str));
        }
    }

    /**
     * \brief Updates this ASCON-HASHA object with the contents of a byte array.
     *
     * \param data Reference to the byte array to absorb.
     */
    inline void update(const ascon::byte_array& data)
    {
        ::ascon_hasha_update(&m_state, data.data(), data.size());
    }

    /**
     * \brief Finalizes this ASCON-HASHA object and returns the digest.
     *
     * The application must call reset() to perform another hashing process.
     */
    inline void finalize(unsigned char digest[ASCON_HASHA_SIZE])
    {
        ::ascon_hasha_finalize(&m_state, digest);
    }

    /**
     * \brief Finalizes this ASCON-HASHA object and returns the digest
     * as a byte array.
     *
     * \return A byte array containing the finalized digest.
     */
    inline ascon::byte_array finalize()
    {
        ascon::byte_array vec(ASCON_HASHA_SIZE);
        ::ascon_hasha_finalize(&m_state, vec.data());
        return vec;
    }

    /**
     * \brief Computes the ASCON-HASHA digest of a block of input data.
     *
     * \param result Points to the buffer to receive the digest.
     * \param data Points to the input data to be hashed.
     * \param len Length of the input data to be hashed.
     */
    static inline void digest
        (unsigned char result[ASCON_HASH_SIZE],
         const unsigned char *data, size_t len)
    {
        ::ascon_hasha(result, data, len);
    }

    /**
     * \brief Gets a reference to the C version of the ASCON-HASHA state.
     *
     * \return A reference to the state.
     */
    inline ::ascon_hasha_state_t *state() { return &m_state; }

    /**
     * \brief Gets a constant reference to the C version of the
     * ASCON-HASHA state.
     *
     * \return A constant reference to the state.
     */
    inline const ::ascon_hasha_state_t *state() const { return &m_state; }

#if !defined(ARDUINO) && !defined(ASCON_NO_STL)

    /**
     * \brief Updates this ASCON-HASHA object with the contents of a
     * standard C++ string.
     *
     * \param str Reference to the string to absorb.
     */
    inline void update(const std::string& str)
    {
        ::ascon_hasha_update
            (&m_state, reinterpret_cast<const unsigned char *>(str.data()),
             str.size());
    }

#elif defined(ARDUINO)

    /**
     * \brief Updates this ASCON-HASHA object with the contents of an
     * Arduino string.
     *
     * \param str Reference to the string to absorb.
     */
    inline void update(const String& str)
    {
        ::ascon_hasha_update
            (&m_state, reinterpret_cast<const unsigned char *>(str.c_str()),
             str.length());
    }

#endif /* ARDUINO */

private:
    ::ascon_hasha_state_t m_state; /**< Internal hash state */
};

} /* namespace ascon */

#endif /* __cplusplus */

#endif
