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

#endif /* _cplusplus */

#endif
