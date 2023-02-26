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

int ascon_bytes_to_hex
    (char *out, size_t outlen, const unsigned char *in, size_t inlen,
     int upper_case)
{
    static char const hex_lower[] = "0123456789abcdef";
    static char const hex_upper[] = "0123456789ABCDEF";
    const char *hex_chars = upper_case ? hex_upper : hex_lower;
    size_t posn = 0;
    if (outlen < (inlen * 2U + 1U)) {
        if (outlen > 0)
            out[0] = '\0'; /* For safety in case the caller uses the string */
        return -1;
    }
    while (inlen > 0) {
        unsigned char ch = *in++;
        out[posn++] = hex_chars[(ch >> 4) & 0x0F];
        out[posn++] = hex_chars[ch & 0x0F];
        --inlen;
    }
    out[posn] = '\0';
    return (int)posn;
}

int ascon_bytes_from_hex
    (unsigned char *out, size_t outlen, const char *in, size_t inlen)
{
    size_t posn = 0;
    int value = 0;
    int nibble = 0;
    int digit = 0;
    while (inlen > 0) {
        char ch = *in++;
        --inlen;
        if (ch >= '0' && ch <= '9') {
            digit = ch - '0';
        } else if (ch >= 'a' && ch <= 'f') {
            digit = ch - 'a' + 10;
        } else if (ch >= 'A' && ch <= 'F') {
            digit = ch - 'A' + 10;
        } else if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' ||
                   ch == '\f' || ch == '\v') {
            continue;
        } else {
            return -1;
        }
        if (nibble) {
            if (posn >= outlen) {
                return -1;
            }
            out[posn++] = value | digit;
            nibble = 0;
        } else {
            value = digit << 4;
            nibble = 1;
        }
    }
    if (nibble) {
        return -1;
    }
    return (int)posn;
}
