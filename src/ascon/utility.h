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

#ifndef ASCON_UTILITY_H
#define ASCON_UTILITY_H

/**
 * \file utility.h
 * \brief System utilities of use to applications that use ASCON.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Cleans a buffer that contains sensitive material.
 *
 * \param buf Points to the buffer to clear.
 * \param size Size of the buffer to clear in bytes.
 */
void ascon_clean(void *buf, unsigned size);

/**
 * \brief Converts an array of bytes into a hexadecimal string.
 *
 * \param out Points to the buffer to receive the output string.
 * \param outlen Maximum number of characters in the \a out buffer,
 * which should be at least \a inlen * 2 + 1 in length.
 * \param in Points to the input byte array to convert into hexadecimal.
 * \param inlen Number of bytes to be converted.
 * \param upper_case Use uppercase hexadecimal letters if non-zero;
 * or use lowercase hexadecimal letters if zero.
 *
 * \return The number of characters written to \a out, excluding the
 * terminating NUL.  Returns -1 if there is something wrong with
 * the parameters such as \a outlen not being large enough.
 *
 * The result \a out buffer will be NUL-terminated except when the
 * function returns -1.
 */
int ascon_bytes_to_hex
    (char *out, size_t outlen, const unsigned char *in, size_t inlen,
     int upper_case);

/**
 * \brief Converts a hexadecimal string into an array of bytes.
 *
 * \param out Points to the buffer to receive the output bytes.
 * \param outlen Maximum number of bytes in the output buffer.
 * \param in Points to the input hexadecimal string to convert.
 * \param inlen Number of characters in the input string to convert.
 *
 * \return The number of bytes written to \a out.  Returns -1 if there
 * is something wrong with the parameters such as \a outlen not being
 * large enough or invalid characters in the input string.
 *
 * Both uppercase and lowercase hexadecimal characters are recognized.
 * Whitespace characters are ignored.  All other characters are invalid.
 */
int ascon_bytes_from_hex
    (unsigned char *out, size_t outlen, const char *in, size_t inlen);

#ifdef __cplusplus
}

#if defined(ARDUINO)
#define ASCON_NO_STL 1
#endif

#if !defined(ASCON_NO_STL) || defined(ASCON_SUITE_DOC)

#include <vector>
#include <string.h>

namespace ascon
{

    /**
     * \brief C++ type for an array of bytes.
     *
     * On systems with the Standard Template Library (STL), this is
     * identical to std::vector<unsigned char>.
     *
     * On other systems like Arduino, this is replaced with a minimal
     * implementation with a subset of the std::vector API.
     */
    typedef std::vector<unsigned char> byte_array;
}

#else /* ASCON_NO_STL */

#include <string.h>

namespace ascon
{

class byte_array
{
public:
    inline byte_array() : p(0) {}

    inline byte_array(const byte_array &other)
        : p(other.p)
    {
        if (p)
            ++(p->ref);
    }

    explicit byte_array(size_t size, unsigned char value = 0);

    inline ~byte_array()
    {
        if (p && (--(p->ref)) == 0)
            delete p;
    }

    inline byte_array &operator=(const byte_array &other)
    {
        if (p != other.p) {
            if (other.p)
                ++(other.p->ref);
            if (p && (--(p->ref)) == 0)
                delete p;
            p = other.p;
        }
        return *this;
    }

    unsigned char &operator[](size_t pos);
    const unsigned char &operator[](size_t pos) const;

    inline size_t size() const { return p ? p->size : 0; }
    inline size_t capacity() const { return p ? p->capacity : 0; }
    inline bool empty() const { return !p || p->size == 0; }

    inline unsigned char *data()
    {
        if (p) {
            if (p->ref > 1)
                detach();
            return p->data;
        } else {
            return 0;
        }
    }
    inline const unsigned char *data() const { return p ? p->data : 0; }

    void reserve(size_t size);
    void resize(size_t size);

    inline void clear()
    {
        if (p && (--(p->ref)) == 0)
            delete p;
        p = 0;
    }

    void push_back(unsigned char value);
    void pop_back();

    inline bool operator==(const byte_array &other) const
    {
        return cmp(other) == 0;
    }
    inline bool operator!=(const byte_array &other) const
    {
        return cmp(other) != 0;
    }
    inline bool operator<(const byte_array &other) const
    {
        return cmp(other) < 0;
    }
    inline bool operator<=(const byte_array &other) const
    {
        return cmp(other) <= 0;
    }
    inline bool operator>(const byte_array &other) const
    {
        return cmp(other) > 0;
    }
    inline bool operator>=(const byte_array &other) const
    {
        return cmp(other) >= 0;
    }

    typedef unsigned char *iterator;
    typedef const unsigned char *const_iterator;

    inline iterator begin() { return data(); }
    inline iterator end() { return data() + size(); }
    inline const_iterator begin() const { return data(); }
    inline const_iterator end() const { return data() + size(); }
    inline const_iterator cbegin() const { return data(); }
    inline const_iterator cend() const { return data() + size(); }

private:
    struct byte_array_private
    {
        size_t ref;
        size_t size;
        size_t capacity;
        unsigned char *data;

        inline byte_array_private(size_t reserve)
            : ref(1)
            , size(0)
            , capacity(reserve)
            , data(new unsigned char [reserve])
        {
        }
        inline ~byte_array_private() { delete[] data; }
    };

    mutable byte_array_private *p;

    void detach(size_t capacity = 0) const;
    int cmp(const byte_array &other) const;
};

} /* namespace ascon */

#endif /* ASCON_NO_STL */

#if !defined(ARDUINO) || defined(ASCON_SUITE_DOC)

#include <string>

namespace ascon
{

/**
 * \brief Converts a hexadecimal string into a byte array.
 *
 * \param str Points to the input string to convert.
 * \param len Number of characters in the input string to convert.
 *
 * \return The byte array version of \a str.  Returns an empty byte
 * array if the input is invalid.
 */
static inline byte_array bytes_from_hex(const char *str, size_t len)
{
    byte_array vec(len / 2);
    int result = ::ascon_bytes_from_hex(vec.data(), vec.size(), str, len);
    if (result != -1)
        return vec;
    else
        return byte_array();
}

/**
 * \brief Converts a hexadecimal string into a byte array.
 *
 * \param str Points to the NUL-terminated input string to convert.
 *
 * \return The byte array version of \a str.  Returns an empty byte
 * array if the input is invalid.
 */
static inline byte_array bytes_from_hex(const char *str)
{
    return bytes_from_hex(str, str ? ::strlen(str) : 0);
}

/**
 * \brief Converts a C array of bytes into a C++ array.
 *
 * \param data Points to the data to convert.
 * \param len Number of bytes of data.
 *
 * \return A C++ byte array containing the data.
 */
static inline byte_array bytes_from_data(const unsigned char *data, size_t len)
{
    byte_array result(len);
    ::memcpy(result.data(), data, len);
    return result;
}

#if !defined(ASCON_NO_STL) || defined(ASCON_SUITE_DOC)

/**
 * \brief Converts an array of bytes into a hexadecimal string.
 *
 * \param in Points to the input byte array to convert into hexadecimal.
 * \param inlen Number of bytes to be converted.
 * \param upper_case Use uppercase hexadecimal letters if true;
 * or use lowercase hexadecimal letters if false.
 *
 * \return The hexadecimal string version of \a in.
 */
static inline std::string bytes_to_hex
    (const unsigned char *in, size_t len, bool upper_case = false)
{
    char out[len * 2U + 1U];
    ::ascon_bytes_to_hex
        (out, sizeof(out), in, len, upper_case ? 1 : 0);
    return std::string(out);
}

/**
 * \brief Converts a byte array into a hexadecimal string.
 *
 * \param in The byte array to be converted.
 * \param upper_case Use uppercase hexadecimal letters if true;
 * or use lowercase hexadecimal letters if false.
 *
 * \return The hexadecimal string version of \a in.
 */
static inline std::string bytes_to_hex
    (const byte_array &in, bool upper_case = false)
{
    size_t len = in.size();
    char out[len * 2U + 1U];
    ::ascon_bytes_to_hex
        (out, sizeof(out), in.data(), len, upper_case ? 1 : 0);
    return std::string(out);
}

/**
 * \brief Converts a hexadecimal string into a byte array.
 *
 * \param str The input string to convert.
 *
 * \return The byte array version of \a str.  Returns an empty byte
 * array if the input is invalid.
 */
static inline byte_array bytes_from_hex(const std::string &str)
{
    return bytes_from_hex(str.data(), str.size());
}

#endif /* !ASCON_NO_STL */

} /* namespace ascon */

#elif defined(ARDUINO)

#include <WString.h>

namespace ascon
{

static inline String bytes_to_hex
    (const unsigned char *in, size_t len, bool upper_case = false)
{
    char out[len * 2U + 1U];
    ::ascon_bytes_to_hex
        (out, sizeof(out), in, len, upper_case ? 1 : 0);
    return String(out);
}

static inline String bytes_to_hex
    (const byte_array &in, bool upper_case = false)
{
    size_t len = in.size();
    char out[len * 2U + 1U];
    ::ascon_bytes_to_hex
        (out, sizeof(out), in.data(), len, upper_case ? 1 : 0);
    return String(out);
}

static inline byte_array bytes_from_hex(const char *str, size_t len)
{
    byte_array vec(len / 2);
    int result = ::ascon_bytes_from_hex(vec.data(), vec.size(), str, len);
    if (result != -1)
        return vec;
    else
        return byte_array();
}

static inline byte_array bytes_from_hex(const char *str)
{
    return bytes_from_hex(str, str ? ::strlen(str) : 0);
}

static inline byte_array bytes_from_hex(const String &str)
{
    return bytes_from_hex(str.c_str(), str.length());
}

static inline byte_array bytes_from_data(const unsigned char *data, size_t len)
{
    byte_array result(len);
    ::memcpy(result.data(), data, len);
    return result;
}

} /* namespace ascon */

#endif /* ARDUINO */

#endif /* _cplusplus */

#endif
