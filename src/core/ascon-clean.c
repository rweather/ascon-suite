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

#define __STDC_WANT_LIB_EXT1__ 1 /* Detect if the C library has memset_s */
#include <ascon/utility.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_STRINGS_H)
#include <strings.h>
#endif
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <wincrypt.h>
#endif

void ascon_clean(void *buf, unsigned size)
{
    /* The safest way to do this is using SecureZeroMemory(), memset_s(), or
     * explicit_bzero() so that the compiler will not optimise away the
     * call to memset() by accident.  If that doesn't work, then we fall
     * back to using volatile pointers which usually works to trick the
     * compiler, but may not. */
#if defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(buf, size);
#elif defined(__STDC_LIB_EXT1__) || defined(HAVE_MEMSET_S)
    memset_s(buf, (rsize_t)size, 0, (rsize_t)size);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(buf, size);
#else
    volatile unsigned char *d = (volatile unsigned char *)buf;
    while (size > 0) {
        *d++ = 0;
        --size;
    }
#endif
}
