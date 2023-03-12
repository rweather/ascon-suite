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

#ifndef ASCON_XOF_H
#define ASCON_XOF_H

/**
 * \file xof.h
 * \brief ASCON-XOF and ASCON-XOFA extensible output functions (XOF's).
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#include <ascon/permutation.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash output for ASCON-HASH and the default hash
 * output size for ASCON-XOF.
 */
#define ASCON_HASH_SIZE 32

/**
 * \brief Size of the hash output for ASCON-HASHA and the default hash
 * output size for ASCON-XOFA.
 */
#define ASCON_HASHA_SIZE ASCON_HASH_SIZE

/**
 * \brief Rate of absorbing and squeezing data for ASCON-XOF,
 * ASCON-XOFA, ASCON-HASH, and ASCON-HASHA.
 */
#define ASCON_XOF_RATE 8

/**
 * \brief State information for ASCON-XOF incremental mode.
 */
typedef struct
{
    ascon_state_t state;    /**< Current hash state */
    unsigned char count;    /**< Number of bytes in the current block */
    unsigned char mode;     /**< Hash mode: 0 for absorb, 1 for squeeze */

} ascon_xof_state_t;

/**
 * \brief State information for ASCON-XOFA incremental mode.
 */
typedef struct
{
    ascon_state_t state;    /**< Current hash state */
    unsigned char count;    /**< Number of bytes in the current block */
    unsigned char mode;     /**< Hash mode: 0 for absorb, 1 for squeeze */

} ascon_xofa_state_t;

/**
 * \brief Hashes a block of input data with ASCON-XOF and generates a
 * fixed-length 32 byte output.
 *
 * \param out Buffer to receive the hash output which must be at least
 * 32 bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * Use ascon_xof_squeeze() instead if you need variable-length XOF ouutput.
 *
 * \sa ascon_xof_init(), ascon_xof_absorb(), ascon_xof_squeeze()
 */
void ascon_xof(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an ASCON-XOF hashing operation.
 *
 * \param state XOF state to be initialized.
 *
 * \sa ascon_xof_absorb(), ascon_xof_squeeze(), ascon_xof()
 */
void ascon_xof_init(ascon_xof_state_t *state);

/**
 * \brief Initializes the state for an incremental ASCON-XOF operation,
 * with a fixed output length.
 *
 * \param state XOF state to be initialized.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * In the ASCON standard, the output length is encoded as a bit counter
 * in a 32-bit word.  If \a outlen is greater than 536870911, it will be
 * replaced with zero to indicate arbitary-length output instead.
 *
 * \sa ascon_xof_init()
 */
void ascon_xof_init_fixed(ascon_xof_state_t *state, size_t outlen);

/**
 * \brief Initializes the state for an incremental ASCON-XOF operation,
 * with a named function, customization string, and output length.
 *
 * \param state XOF state to be initialized.
 * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
 * empty for no function name.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * In the ASCON standard, the output length is encoded as a bit counter
 * in a 32-bit word.  If \a outlen is greater than 536870911, it will be
 * replaced with zero to indicate arbitary-length output instead.
 *
 * This version of initialization is intended for building higher-level
 * functions like KMAC on top of ASCON-XOF.  The function name provides
 * domain separation between different functions.  The customization string
 * provides domain separation between different users of the same function.
 *
 * \sa ascon_xof_init()
 */
void ascon_xof_init_custom
    (ascon_xof_state_t *state, const char *function_name,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Re-initializes the state for an ASCON-XOF hashing operation.
 *
 * \param state XOF state to be re-initialized.
 *
 * This function is equivalent to calling ascon_xof_free() and then
 * ascon_xof_init() to restart the hashing process.
 *
 * \sa ascon_xof_init()
 */
void ascon_xof_reinit(ascon_xof_state_t *state);

/**
 * \brief Re-initializes the state for an incremental ASCON-XOF operation,
 * with a fixed output length.
 *
 * \param state XOF state to be re-initialized.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * This function is equivalent to calling ascon_xof_free() and then
 * ascon_xof_init_fixed() to restart the hashing process.
 *
 * \sa ascon_xof_init_fixed()
 */
void ascon_xof_reinit_fixed(ascon_xof_state_t *state, size_t outlen);

/**
 * \brief Re-nitializes the state for an incremental ASCON-XOF operation,
 * with a named function, customization string, and output length.
 *
 * \param state XOF state to be initialized.
 * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
 * empty for no function name.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * \sa ascon_xof_init_custom()
 */
void ascon_xof_reinit_custom
    (ascon_xof_state_t *state, const char *function_name,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Frees the ASCON-XOF state and destroys any sensitive material.
 *
 * \param state XOF state to be freed.
 */
void ascon_xof_free(ascon_xof_state_t *state);

/**
 * \brief Absorbs more input data into an ASCON-XOF state.
 *
 * \param state XOF state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_xof_init(), ascon_xof_squeeze()
 */
void ascon_xof_absorb
    (ascon_xof_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Squeezes output data from an ASCON-XOF state.
 *
 * \param state XOF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa ascon_xof_init(), ascon_xof_update()
 */
void ascon_xof_squeeze
    (ascon_xof_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Absorbs enough zeroes into an ASCON-XOF state to pad the
 * input to the next multiple of the block rate.
 *
 * \param state XOF state to pad.  Does nothing if the \a state is
 * already aligned on a multiple of the block rate.
 *
 * This function can avoid unnecessary XOR-with-zero operations
 * to save some time when padding is required.
 */
void ascon_xof_pad(ascon_xof_state_t *state);

/**
 * \brief Clones a copy of an ASCON-XOF state.
 *
 * \param dest Destination XOF state to copy into.
 * \param src Source XOF state to copy from.
 *
 * The destination will be initialized by this operation, so it must
 * not previously have been initialized or it has already been freed.
 * The source must be already initialized.
 */
void ascon_xof_copy(ascon_xof_state_t *dest, const ascon_xof_state_t *src);

/**
 * \brief Hashes a block of input data with ASCON-XOFA and generates a
 * fixed-length 32 byte output.
 *
 * \param out Buffer to receive the hash output which must be at least
 * 32 bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * Use ascon_xofa_squeeze() instead if you need variable-length XOF ouutput.
 *
 * \sa ascon_xofa_init(), ascon_xofa_absorb(), ascon_xofa_squeeze()
 */
void ascon_xofa(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an ASCON-XOFA hashing operation.
 *
 * \param state XOF state to be initialized.
 *
 * \sa ascon_xofa_absorb(), ascon_xofa_squeeze(), ascon_xofa()
 */
void ascon_xofa_init(ascon_xofa_state_t *state);

/**
 * \brief Initializes the state for an incremental ASCON-XOFA operation,
 * with a fixed output length.
 *
 * \param state XOF state to be initialized.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * In the ASCON standard, the output length is encoded as a bit counter
 * in a 32-bit word.  If \a outlen is greater than 536870911, it will be
 * replaced with zero to indicate arbitary-length output instead.
 *
 * \sa ascon_xofa_init()
 */
void ascon_xofa_init_fixed(ascon_xofa_state_t *state, size_t outlen);

/**
 * \brief Initializes the state for an incremental ASCON-XOFA operation,
 * with a named function, customization string, and output length.
 *
 * \param state XOF state to be initialized.
 * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
 * empty for no function name.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * In the ASCON standard, the output length is encoded as a bit counter
 * in a 32-bit word.  If \a outlen is greater than 536870911, it will be
 * replaced with zero to indicate arbitary-length output instead.
 *
 * This version of initialization is intended for building higher-level
 * functions like KMAC on top of ASCON-XOF.  The function name provides
 * domain separation between different functions.  The customization string
 * provides domain separation between different users of the same function.
 *
 * \sa ascon_xofa_init()
 */
void ascon_xofa_init_custom
    (ascon_xofa_state_t *state, const char *function_name,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Re-initializes the state for an ASCON-XOFA hashing operation.
 *
 * \param state XOF state to be re-initialized.
 *
 * This function is equivalent to calling ascon_xofa_free() and then
 * ascon_xofa_init() to restart the hashing process.
 *
 * \sa ascon_xof_init()
 */
void ascon_xofa_reinit(ascon_xofa_state_t *state);

/**
 * \brief Re-initializes the state for an incremental ASCON-XOFA operation,
 * with a fixed output length.
 *
 * \param state XOF state to be re-initialized.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * This function is equivalent to calling ascon_xofa_free() and then
 * ascon_xofa_init_fixed() to restart the hashing process.
 *
 * \sa ascon_xof_init_fixed()
 */
void ascon_xofa_reinit_fixed(ascon_xofa_state_t *state, size_t outlen);

/**
 * \brief Re-nitializes the state for an incremental ASCON-XOFA operation,
 * with a named function, customization string, and output length.
 *
 * \param state XOF state to be initialized.
 * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
 * empty for no function name.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 * \param outlen The desired output length in bytes, or 0 for arbitrary-length.
 *
 * \sa ascon_xofa_init_custom()
 */
void ascon_xofa_reinit_custom
    (ascon_xofa_state_t *state, const char *function_name,
     const unsigned char *custom, size_t customlen, size_t outlen);

/**
 * \brief Frees the ASCON-XOFA state and destroys any sensitive material.
 *
 * \param state XOF state to be freed.
 */
void ascon_xofa_free(ascon_xofa_state_t *state);

/**
 * \brief Absorbs more input data into an ASCON-XOFA state.
 *
 * \param state XOF state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_xofa_init(), ascon_xofa_squeeze()
 */
void ascon_xofa_absorb
    (ascon_xofa_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Squeezes output data from an ASCON-XOFA state.
 *
 * \param state XOF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa ascon_xofa_init(), ascon_xofa_update()
 */
void ascon_xofa_squeeze
    (ascon_xofa_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Absorbs enough zeroes into an ASCON-XOFA state to pad the
 * input to the next multiple of the block rate.
 *
 * \param state XOF state to pad.  Does nothing if the \a state is
 * already aligned on a multiple of the block rate.
 *
 * This function can avoid unnecessary XOR-with-zero operations
 * to save some time when padding is required.
 */
void ascon_xofa_pad(ascon_xofa_state_t *state);

/**
 * \brief Clones a copy of an ASCON-XOFA state.
 *
 * \param dest Destination XOF state to copy into.
 * \param src Source XOF state to copy from.
 *
 * The destination will be initialized by this operation, so it must
 * not previously have been initialized or it has already been freed.
 * The source must be already initialized.
 */
void ascon_xofa_copy(ascon_xofa_state_t *dest, const ascon_xofa_state_t *src);

#ifdef __cplusplus
} /* extern "C" */

#include <ascon/utility.h>

namespace ascon
{

/**
 * \brief ASCON-XOF with a specific output length.
 *
 * This template takes the desired output length in bytes as a parameter.
 * For example, the following produces a result identical to the
 * ascon::hash class:
 *
 * \code
 * ascon::xof_with_output_length<32> hash;
 * unsigned char output[32];
 *
 * hash.absorb("Hello, World!");
 * hash.squeeze(output, sizeof(output));
 * \endcode
 *
 * The output length should be set to zero for arbitrary-length output.
 * The ascon::xof type provides a convenient alias for this use case:
 *
 * \code
 * ascon::xof x;
 * unsigned char output2[64];
 *
 * x.absorb("Hello, World!");
 * x.squeeze(output2, sizeof(output2));
 * \endcode
 */
template<size_t outlen>
class xof_with_output_length
{
public:
    /**
     * \brief Constucts a new ASCON-XOF object.
     *
     * After construction, the new object is ready to accept input
     * data with absorb().
     */
    inline xof_with_output_length()
    {
        if (outlen == 0)
            ::ascon_xof_init(&m_state);
        else
            ::ascon_xof_init_fixed(&m_state, outlen);
    }

    /**
     * \brief Constructs a copy of another ASCON-XOF object.
     *
     * \param other The other object to copy, which must have the same
     * output length as this class.
     */
    inline xof_with_output_length
        (const ascon::xof_with_output_length<outlen> &other)
    {
        ::ascon_xof_copy(&m_state, &other.m_state);
    }

    /**
     * \brief Constructs a new ASCON-XOF object with a named function and
     * customization string.
     *
     * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
     * empty for no function name.
     * \param custom Points to the customization string.
     * \param customlen Number of bytes in the customization string.
     */
    inline explicit xof_with_output_length
        (const char *function_name, const unsigned char *custom = 0,
         size_t customlen = 0)
    {
        ::ascon_xof_init_custom
            (&m_state, function_name, custom, customlen, outlen);
    }

    /**
     * \brief Constructs a new ASCON-XOF object with a named function and
     * customization string.
     *
     * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
     * empty for no function name.
     * \param custom The customization string.
     */
    inline xof_with_output_length
        (const char *function_name, const ascon::byte_array &custom)
    {
        ::ascon_xof_init_custom
            (&m_state, function_name, custom.data(), custom.size(), outlen);
    }

    /**
     * \brief Destroys this ASCON-XOF object.
     */
    inline ~xof_with_output_length()
    {
        ::ascon_xof_free(&m_state);
    }

    /**
     * \brief Copies the state of another ASCON-XOF object into this one.
     *
     * \param other The other object to copy, which must have the same
     * output length as this class.
     *
     * \return A reference to this ASCON-XOF object.
     */
    inline xof_with_output_length<outlen> &operator=
        (const ascon::xof_with_output_length<outlen> &other)
    {
        if (this != &other) {
            ::ascon_xof_free(&m_state);
            ::ascon_xof_copy(&m_state, &other.m_state);
        }
        return *this;
    }

    /**
     * \brief Resets this ASCON-XOF object back to the initial state.
     */
    inline void reset()
    {
        if (outlen == 0)
            ::ascon_xof_reinit(&m_state);
        else
            ::ascon_xof_reinit_fixed(&m_state, outlen);
    }

    /**
     * \brief Absorbs more input data into this ASCON-XOF object.
     *
     * \param data Points to the input data to be absorbed into the state.
     * \param len Length of the input data to be absorbed into the state.
     */
    inline void absorb(const unsigned char *data, size_t len)
    {
        ::ascon_xof_absorb(&m_state, data, len);
    }

    /**
     * \brief Absorbs the contents of a NUL-terminated C string into
     * this ASCON-XOF object.
     *
     * \param str Points to the C string to absorb.
     *
     * If \a str is NULL, then this function is equivalent to absorbing the
     * empty string into the state.
     */
    inline void absorb(const char *str)
    {
        if (str) {
            ::ascon_xof_absorb
                (&m_state, reinterpret_cast<const unsigned char *>(str),
                 ::strlen(str));
        }
    }

    /**
     * \brief Absorbs the contents of a byte array into this ASCON-XOF object.
     *
     * \param data Reference to the byte array to absorb.
     */
    inline void absorb(const ascon::byte_array& data)
    {
        ::ascon_xof_absorb(&m_state, data.data(), data.size());
    }

    /**
     * \brief Squeezes output data from this ASCON-XOF object.
     *
     * \param data Points to the output buffer to receive the squeezed data.
     * \param len Number of bytes of data to squeeze out of the state.
     */
    inline void squeeze(unsigned char *data, size_t len)
    {
        ::ascon_xof_squeeze(&m_state, data, len);
    }

    /**
     * \brief Squeezes data out of this ASCON-XOF object as a byte array.
     *
     * \param len The number of bytes to squeeze out.
     *
     * \return A byte array containing the squeezed data.
     */
    ascon::byte_array squeeze(size_t len)
    {
        ascon::byte_array vec(len);
        ::ascon_xof_squeeze(&m_state, vec.data(), len);
        return vec;
    }

    /**
     * \brief Absorbs enough zeroes into this ASCON-XOF object to pad the
     * input to the next multiple of the block rate.
     *
     * Does nothing if the state is already aligned on a multiple of
     * the block rate.
     *
     * This function can avoid unnecessary XOR-with-zero operations
     * to save some time when padding is required.
     */
    inline void pad()
    {
        ::ascon_xof_pad(&m_state);
    }

    /**
     * \brief Gets a reference to the C version of the ASCON-XOF state.
     *
     * \return A reference to the state.
     */
    inline ::ascon_xof_state_t *state() { return &m_state; }

    /**
     * \brief Gets a constant reference to the C version of the ASCON-XOF state.
     *
     * \return A constant reference to the state.
     */
    inline const ::ascon_xof_state_t *state() const { return &m_state; }

#if !defined(ARDUINO) && !defined(ASCON_NO_STL)

    /**
     * \brief Absorbs the contents of a standard C++ string into
     * this ASCON-XOF object.
     *
     * \param str Reference to the string to absorb.
     */
    inline void absorb(const std::string& str)
    {
        ::ascon_xof_absorb
            (&m_state, reinterpret_cast<const unsigned char *>(str.data()),
             str.size());
    }

#elif defined(ARDUINO)

    /**
     * \brief Absorbs the contents of an Arduino string object into
     * this ASCON-XOF object.
     *
     * \param str Reference to the string to absorb.
     */
    inline void absorb(const String& str)
    {
        ::ascon_xof_absorb
            (&m_state, reinterpret_cast<const unsigned char *>(str.c_str()),
             str.length());
    }

#endif /* ARDUINO */

private:
    ::ascon_xof_state_t m_state; /**< Internal XOF state */
};

/**
 * \brief ASCON-XOFA with a specific output length.
 *
 * This template takes the desired output length in bytes as a parameter.
 * For example, the following produces a result identical to the
 * ascon::hasha class:
 *
 * \code
 * ascon::xofa_with_output_length<32> hash;
 * unsigned char output[32];
 *
 * hash.absorb("Hello, World!");
 * hash.squeeze(output, sizeof(output));
 * \endcode
 *
 * The output length should be set to zero for arbitrary-length output.
 * The ascon::xofa type provides a convenient alias for this use case:
 *
 * \code
 * ascon::xofa x;
 * unsigned char output2[64];
 *
 * x.absorb("Hello, World!");
 * x.squeeze(output2, sizeof(output2));
 * \endcode
 */
template<size_t outlen>
class xofa_with_output_length
{
public:
    /**
     * \brief Constucts a new ASCON-XOFA object.
     *
     * After construction, the new object is ready to accept input
     * data with absorb().
     */
    inline xofa_with_output_length()
    {
        if (outlen == 0)
            ::ascon_xofa_init(&m_state);
        else
            ::ascon_xofa_init_fixed(&m_state, outlen);
    }

    /**
     * \brief Constructs a copy of another ASCON-XOFA object.
     *
     * \param other The other object to copy, which must have the same
     * output length as this class.
     */
    inline xofa_with_output_length
        (const ascon::xofa_with_output_length<outlen> &other)
    {
        ::ascon_xofa_copy(&m_state, &other.m_state);
    }

    /**
     * \brief Constructs a new ASCON-XOFA object with a named function and
     * customization string.
     *
     * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
     * empty for no function name.
     * \param custom Points to the customization string.
     * \param customlen Number of bytes in the customization string.
     */
    inline explicit xofa_with_output_length
        (const char *function_name, const unsigned char *custom = 0,
         size_t customlen = 0)
    {
        ::ascon_xofa_init_custom
            (&m_state, function_name, custom, customlen, outlen);
    }

    /**
     * \brief Constructs a new ASCON-XOFA object with a named function and
     * customization string.
     *
     * \param function_name Name of the function; e.g. "KMAC".  May be NULL or
     * empty for no function name.
     * \param custom The customization string.
     */
    inline xofa_with_output_length
        (const char *function_name, const ascon::byte_array &custom)
    {
        ::ascon_xofa_init_custom
            (&m_state, function_name, custom.data(), custom.size(), outlen);
    }

    /**
     * \brief Destroys this ASCON-XOFA object.
     */
    inline ~xofa_with_output_length()
    {
        ::ascon_xofa_free(&m_state);
    }

    /**
     * \brief Copies the state of another ASCON-XOFA object into this one.
     *
     * \param other The other object to copy, which must have the same
     * output length as this class.
     *
     * \return A reference to this ASCON-XOFA object.
     */
    inline xofa_with_output_length<outlen> &operator=
        (const ascon::xofa_with_output_length<outlen> &other)
    {
        if (this != &other) {
            ::ascon_xofa_free(&m_state);
            ::ascon_xofa_copy(&m_state, &other.m_state);
        }
        return *this;
    }

    /**
     * \brief Resets this ASCON-XOFA object back to the initial state.
     */
    inline void reset()
    {
        if (outlen == 0)
            ::ascon_xofa_reinit(&m_state);
        else
            ::ascon_xofa_reinit_fixed(&m_state, outlen);
    }

    /**
     * \brief Absorbs more input data into this ASCON-XOFA object.
     *
     * \param data Points to the input data to be absorbed into the state.
     * \param len Length of the input data to be absorbed into the state.
     */
    inline void absorb(const unsigned char *data, size_t len)
    {
        ::ascon_xofa_absorb(&m_state, data, len);
    }

    /**
     * \brief Absorbs the contents of a NUL-terminated C string into
     * this ASCON-XOFA object.
     *
     * \param str Points to the C string to absorb.
     *
     * If \a str is NULL, then this function is equivalent to absorbing the
     * empty string into the state.
     */
    inline void absorb(const char *str)
    {
        if (str)
            ::ascon_xofa_absorb(&m_state, str, ::strlen(str));
    }

    /**
     * \brief Absorbs the contents of a byte array into this ASCON-XOFA object.
     *
     * \param data Reference to the byte array to absorb.
     */
    inline void absorb(const ascon::byte_array& data)
    {
        ::ascon_xofa_absorb(&m_state, data.data(), data.size());
    }

    /**
     * \brief Squeezes output data from this ASCON-XOFA object.
     *
     * \param data Points to the output buffer to receive the squeezed data.
     * \param len Number of bytes of data to squeeze out of the state.
     */
    inline void squeeze(unsigned char *data, size_t len)
    {
        ::ascon_xofa_squeeze(&m_state, data, len);
    }

    /**
     * \brief Squeezes data out of this ASCON-XOFA object as a byte array.
     *
     * \param len The number of bytes to squeeze out.
     *
     * \return A byte array containing the squeezed data.
     */
    inline ascon::byte_array squeeze(size_t len)
    {
        ascon::byte_array vec(len);
        ::ascon_xofa_squeeze(&m_state, vec.data(), len);
        return vec;
    }

    /**
     * \brief Absorbs enough zeroes into this ASCON-XOFA object to pad the
     * input to the next multiple of the block rate.
     *
     * Does nothing if the state is already aligned on a multiple of
     * the block rate.
     *
     * This function can avoid unnecessary XOR-with-zero operations
     * to save some time when padding is required.
     */
    inline void pad()
    {
        ::ascon_xofa_pad(&m_state);
    }

    /**
     * \brief Gets a reference to the C version of the ASCON-XOFA state.
     *
     * \return A reference to the state.
     */
    inline ::ascon_xofa_state_t *state() { return &m_state; }

    /**
     * \brief Gets a constant reference to the C version of the ASCON-XOFA state.
     *
     * \return A constant reference to the state.
     */
    inline const ::ascon_xofa_state_t *state() const { return &m_state; }

#if !defined(ARDUINO) && !defined(ASCON_NO_STL)

    /**
     * \brief Absorbs the contents of a standard C++ string into
     * this ASCON-XOFA object.
     *
     * \param str Reference to the string to absorb.
     */
    inline void absorb(const std::string& str)
    {
        ::ascon_xofa_absorb(&m_state, str.data(), str.size());
    }

#elif defined(ARDUINO)

    /**
     * \brief Absorbs the contents of an Arduino string object into
     * this ASCON-XOFA object.
     *
     * \param str Reference to the string to absorb.
     */
    inline void absorb(const String& str)
    {
        ::ascon_xofa_absorb(&m_state, str.c_str(), str.length());
    }

#endif /* ARDUINO */

private:
    ::ascon_xofa_state_t m_state; /**< Internal XOF state */
};

/**
 * \brief ASCON-XOF object with arbitrary-length output.
 *
 * The following example runs ASCON-XOF over an input string and then
 * squeezes 64 bytes of output:
 *
 * \code
 * ascon::xof x;
 * unsigned char output2[64];
 *
 * x.absorb("Hello, World!");
 * x.squeeze(output2, sizeof(output2));
 * \endcode
 */
typedef xof_with_output_length<0> xof;

/**
 * \brief ASCON-XOFA object with arbitrary-length output.
 *
 * The following example runs ASCON-XOFA over an input string and then
 * squeezes 64 bytes of output:
 *
 * \code
 * ascon::xofa x;
 * unsigned char output2[64];
 *
 * x.absorb("Hello, World!");
 * x.squeeze(output2, sizeof(output2));
 * \endcode
 */
typedef xofa_with_output_length<0> xofa;

} /* namespace ascon */

#endif /* __cplusplus */

#endif
