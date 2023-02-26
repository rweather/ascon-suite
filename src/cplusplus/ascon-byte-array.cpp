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

#include <ascon/utility.h>

#if defined(ASCON_NO_STL)

#include <string.h>

namespace ascon
{

// Rounds a capacity value up to the next multiple of the allocation block size.
#define CAPACITY(x) (((x) + 15U) & ~((size_t)15U))

byte_array::byte_array(size_t size, unsigned char value)
    : p(new byte_array_private(size ? CAPACITY(size) : CAPACITY(1)))
{
    p->size = size;
    ::memset(p->data, value, size);
}

unsigned char &byte_array::operator[](size_t pos)
{
    detach();
    return p->data[pos];
}

const unsigned char &byte_array::operator[](size_t pos) const
{
    detach();
    return p->data[pos];
}

void byte_array::reserve(size_t size)
{
    if (!p || size > p->capacity)
        detach(size);
}

void byte_array::resize(size_t size)
{
    reserve(size);
    if (p->size < size)
        ::memset(p->data + p->size, 0, size - p->size);
    p->size = size;
}

void byte_array::push_back(unsigned char value)
{
    if (!p)
        detach();
    else if (p->size >= p->capacity || p->ref > 1)
        detach(p->size + 1);
    p->data[(p->size)++] = value;
}

void byte_array::pop_back()
{
    if (p && p->size > 0) {
        detach();
        --(p->size);
    }
}

void byte_array::detach(size_t capacity) const
{
    // Determine the capacity to use in the detached copy.
    if (p && p->size > capacity)
        capacity = p->size;
    if (!capacity)
        capacity = 1;
    capacity = CAPACITY(capacity);

    // Create a new private object to hold the detached copy.
    byte_array_private *np = new byte_array_private(capacity);
    if (p) {
        np->size = p->size;
        ::memcpy(np->data, p->data, p->size);
    }

    // Dereference the existing object and replace with the new one.
    if (p && (--(p->ref)) == 0)
        delete p;
    p = np;
}

int byte_array::cmp(const byte_array &other) const
{
    if (p == other.p) {
        return 0;
    } else if (!p) {
        return other.p->size > 0 ? 1 : 0;
    } else if (!other.p) {
        return p->size > 0 ? -1 : 0;
    } else {
        size_t size = p->size;
        if (size > other.p->size)
            size = other.p->size;
        int result = ::memcmp(p->data, other.p->data, size);
        if (result != 0)
            return result;
        else if (size < p->size)
            return 1;
        else if (size < other.p->size)
            return -1;
        else
            return 0;
    }
}

} // namespace ascon

#endif // ASCON_NO_STL
