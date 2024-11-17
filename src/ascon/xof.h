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
 * \brief Ascon-XOF128 and Ascon-CXOF128 extensible output functions (XOF's).
 *
 * References: https://ascon.iaik.tugraz.at/
 */

#include <ascon/permutation.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Rate of absorbing and squeezing data for Ascon-XOF128 and
 * Ascon-CXOF128.
 */
#define ASCON_XOF128_RATE 8

/**
 * \brief State information for the Ascon-XOF128 incremental mode.
 */
typedef struct
{
    ascon_state_t state;    /**< Current hash state */
    unsigned char count;    /**< Number of bytes in the current block */
    unsigned char mode;     /**< Hash mode: 0 for absorb, 1 for squeeze */

} ascon_xof128_state_t;

/**
 * \brief State information for the Ascon-CXOF128 incremental mode.
 */
typedef ascon_xof128_state_t ascon_cxof128_state_t;

/**
 * \brief Hashes a block of input data with Ascon-XOF128 and generates a
 * fixed-length 32 byte output.
 *
 * \param out Buffer to receive the hash output which must be at least
 * 32 bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * Use ascon_xof128_squeeze() instead if you need variable-length XOF ouutput.
 *
 * \sa ascon_xof128_init(), ascon_xof128_absorb(), ascon_xof128_squeeze()
 */
void ascon_xof128(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an Ascon-XOF128 hashing operation.
 *
 * \param state XOF state to be initialized.
 *
 * \sa ascon_xof128_absorb(), ascon_xof128_squeeze(), ascon_xof128()
 */
void ascon_xof128_init(ascon_xof128_state_t *state);

/**
 * \brief Initializes the state for an incremental Ascon-CXOF128 operation,
 * with a customization string.
 *
 * \param state XOF state to be initialized.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_xof128_init()
 */
void ascon_cxof128_init
    (ascon_xof128_state_t *state, const unsigned char *custom,
     size_t customlen);

/**
 * \brief Initializes the state for an incremental Ascon-CXOF128 operation,
 * with a named function and a customization string.
 *
 * \param state XOF state to be initialized.
 * \param name Points to the NUL-terminated function name.  If NULL or the
 * empty string, the function name will not be used.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_cxof128_init()
 */
void ascon_cxof128_init_named
    (ascon_xof128_state_t *state, const char *name,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Re-initializes the state for an Ascon-XOF128 hashing operation.
 *
 * \param state XOF state to be re-initialized.
 *
 * This function is equivalent to calling ascon_xof128_free() and then
 * ascon_xof128_init() to restart the hashing process.
 *
 * \sa ascon_xof128_init()
 */
void ascon_xof128_reinit(ascon_xof128_state_t *state);

/**
 * \brief Re-nitializes the state for an incremental Ascon-CXOF128 operation,
 * with a customization string.
 *
 * \param state XOF state to be initialized.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_cxof128_init()
 */
void ascon_cxof128_reinit
    (ascon_xof128_state_t *state, const unsigned char *custom,
     size_t customlen);

/**
 * \brief Re-nitializes the state for an incremental Ascon-CXOF128 operation,
 * with a named function as the customization string.
 *
 * \param state XOF state to be initialized.
 * \param name Points to the NUL-terminated function name.  If NULL or the
 * empty string, the function name will not be used.
 * \param custom Points to the customization string.
 * \param customlen Number of bytes in the customization string.
 *
 * \sa ascon_cxof128_init_named()
 */
void ascon_cxof128_reinit_named
    (ascon_xof128_state_t *state, const char *name,
     const unsigned char *custom, size_t customlen);

/**
 * \brief Frees the Ascon-XOF128 state and destroys any sensitive material.
 *
 * \param state XOF state to be freed.
 */
void ascon_xof128_free(ascon_xof128_state_t *state);

/**
 * \brief Absorbs more input data into an Ascon-XOF128 state.
 *
 * \param state XOF state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_xof128_init(), ascon_xof128_squeeze()
 */
void ascon_xof128_absorb
    (ascon_xof128_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Squeezes output data from an Ascon-XOF128 state.
 *
 * \param state XOF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa ascon_xof128_init(), ascon_xof128_update()
 */
void ascon_xof128_squeeze
    (ascon_xof128_state_t *state, unsigned char *out, size_t outlen);

/**
 * \brief Pads the current rate block with a 1 bit followed by 0 bits
 * until the next rate block boundary is reached.
 *
 * \param state XOF state to pad.
 */
void ascon_xof128_pad(ascon_xof128_state_t *state);

/**
 * \brief Absorbs enough zeroes into an Ascon-XOF128 state to pad the
 * input to the next multiple of the block rate.
 *
 * \param state XOF state to pad.  Does nothing if the \a state is
 * already aligned on a multiple of the block rate.
 *
 * This function can avoid unnecessary XOR-with-zero operations
 * to save some time when padding is required.
 */
void ascon_xof128_zero_pad(ascon_xof128_state_t *state);

/**
 * \brief Clones a copy of an Ascon-XOF128 state.
 *
 * \param dest Destination XOF state to copy into.
 * \param src Source XOF state to copy from.
 *
 * The destination will be initialized by this operation, so it must
 * not previously have been initialized or it has already been freed.
 * The source must be already initialized.
 */
void ascon_xof128_copy
    (ascon_xof128_state_t *dest, const ascon_xof128_state_t *src);

#ifdef __cplusplus
} /* extern "C" */

#include <ascon/utility.h>

namespace ascon
{

/**
 * \brief Ascon-XOF128 extendable output function.
 *
 * The following is an example of hashing a string followed by extracting
 * 64 bytes of output:
 *
 * \code
 * ascon::xof128 x;
 * unsigned char output2[64];
 *
 * x.absorb("Hello, World!");
 * x.squeeze(output2, sizeof(output2));
 * \endcode
 */
class xof128
{
public:
    /**
     * \brief Constucts a new Ascon-XOF128 object.
     *
     * After construction, the new object is ready to accept input
     * data with absorb().
     */
    inline xof128()
    {
        ::ascon_xof128_init(&m_state);
    }

    /**
     * \brief Constructs a copy of another Ascon-XOF128 object.
     *
     * \param other The other object to copy.
     */
    inline xof128(const ascon::xof128 &other)
    {
        ::ascon_xof128_copy(&m_state, &other.m_state);
    }

    /**
     * \brief Constructs a new Ascon-XOF128 object with a customization
     * string in Ascon-CXOF128 mode.
     *
     * \param custom Points to the customization string.
     * \param customlen Number of bytes in the customization string.
     */
    inline xof128(const unsigned char *custom, size_t customlen)
    {
        ::ascon_cxof128_init(&m_state, custom, customlen);
    }

    /**
     * \brief Constructs a new Ascon-XOF128 object with a customization
     * string in Ascon-CXOF128 mode.
     *
     * \param custom The customization string.
     */
    inline explicit xof128(const ascon::byte_array &custom)
    {
        ::ascon_cxof128_init(&m_state, custom.data(), custom.size());
    }

    /**
     * \brief Destroys this Ascon-XOF128 object.
     */
    inline ~xof128()
    {
        ::ascon_xof128_free(&m_state);
    }

    /**
     * \brief Copies the state of another Ascon-XOF128 object into this one.
     *
     * \param other The other object to copy, which must have the same
     * output length as this class.
     *
     * \return A reference to this Ascon-XOF128 object.
     */
    inline xof128 &operator=(const ascon::xof128 &other)
    {
        if (this != &other) {
            ::ascon_xof128_free(&m_state);
            ::ascon_xof128_copy(&m_state, &other.m_state);
        }
        return *this;
    }

    /**
     * \brief Resets this Ascon-XOF128 object back to the initial state.
     */
    inline void reset()
    {
        ::ascon_xof128_reinit(&m_state);
    }

    /**
     * \brief Absorbs more input data into this Ascon-XOF128 object.
     *
     * \param data Points to the input data to be absorbed into the state.
     * \param len Length of the input data to be absorbed into the state.
     */
    inline void absorb(const unsigned char *data, size_t len)
    {
        ::ascon_xof128_absorb(&m_state, data, len);
    }

    /**
     * \brief Absorbs the contents of a NUL-terminated C string into
     * this Ascon-XOF128 object.
     *
     * \param str Points to the C string to absorb.
     *
     * If \a str is NULL, then this function is equivalent to absorbing the
     * empty string into the state.
     */
    inline void absorb(const char *str)
    {
        if (str) {
            ::ascon_xof128_absorb
                (&m_state, reinterpret_cast<const unsigned char *>(str),
                 ::strlen(str));
        }
    }

    /**
     * \brief Absorbs the contents of a byte array into this Ascon-XOF128 object.
     *
     * \param data Reference to the byte array to absorb.
     */
    inline void absorb(const ascon::byte_array& data)
    {
        ::ascon_xof128_absorb(&m_state, data.data(), data.size());
    }

    /**
     * \brief Squeezes output data from this Ascon-XOF128 object.
     *
     * \param data Points to the output buffer to receive the squeezed data.
     * \param len Number of bytes of data to squeeze out of the state.
     */
    inline void squeeze(unsigned char *data, size_t len)
    {
        ::ascon_xof128_squeeze(&m_state, data, len);
    }

    /**
     * \brief Squeezes data out of this Ascon-XOF128 object as a byte array.
     *
     * \param len The number of bytes to squeeze out.
     *
     * \return A byte array containing the squeezed data.
     */
    ascon::byte_array squeeze(size_t len)
    {
        ascon::byte_array vec(len);
        ::ascon_xof128_squeeze(&m_state, vec.data(), len);
        return vec;
    }

    /**
     * \brief Pads the current rate block with a 1 bit followed by 0 bits
     * until the next rate block boundary is reached.
     */
    inline void pad()
    {
        ::ascon_xof128_pad(&m_state);
    }

    /**
     * \brief Absorbs enough zeroes into this Ascon-XOF128 object to pad the
     * input to the next multiple of the block rate.
     *
     * Does nothing if the state is already aligned on a multiple of
     * the block rate.
     *
     * This function can avoid unnecessary XOR-with-zero operations
     * to save some time when padding is required.
     */
    inline void zero_pad()
    {
        ::ascon_xof128_zero_pad(&m_state);
    }

    /**
     * \brief Gets a reference to the C version of the Ascon-XOF128 state.
     *
     * \return A reference to the state.
     */
    inline ::ascon_xof128_state_t *state() { return &m_state; }

    /**
     * \brief Gets a constant reference to the C version of the
     * Ascon-XOF128 state.
     *
     * \return A constant reference to the state.
     */
    inline const ::ascon_xof128_state_t *state() const { return &m_state; }

#if !defined(ARDUINO) && !defined(ASCON_NO_STL)

    /**
     * \brief Absorbs the contents of a standard C++ string into
     * this Ascon-XOF128 object.
     *
     * \param str Reference to the string to absorb.
     */
    inline void absorb(const std::string& str)
    {
        ::ascon_xof128_absorb
            (&m_state, reinterpret_cast<const unsigned char *>(str.data()),
             str.size());
    }

#elif defined(ARDUINO)

    /**
     * \brief Absorbs the contents of an Arduino string object into
     * this Ascon-XOF128 object.
     *
     * \param str Reference to the string to absorb.
     */
    inline void absorb(const String& str)
    {
        ::ascon_xof128_absorb
            (&m_state, reinterpret_cast<const unsigned char *>(str.c_str()),
             str.length());
    }

#endif /* ARDUINO */

private:
    ::ascon_xof128_state_t m_state; /**< Internal XOF state */
};

} /* namespace ascon */

#endif /* __cplusplus */

#endif
