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

#include "aead-metadata.h"
#include <ascon/hash.h>
#include <ascon/xof.h>

extern "C"
{

static unsigned method = 0;

void ascon_hash_cpp(unsigned char *out, const unsigned char *in, size_t inlen)
{
    // Test several methods for computing the digest.
    switch ((method++) % 3) {
    case 0:
        // All-in-one digest.
        ascon::hash::digest(out, in, inlen);
        break;

    case 1: {
        // Use the class to compute the digest.
        ascon::hash hash;
        hash.update(in, inlen);
        hash.finalize(out);
        break; }

    case 2: {
        // All-in-one digest using byte arrays.
        ascon::byte_array input(inlen);
        ascon::byte_array output;
        ascon::hash hash;
        ::memcpy(input.data(), in, inlen);
        hash.update(input);
        output = hash.finalize();
        ::memcpy(out, output.data(), ASCON_HASH_SIZE);
        break; }
    }
}

void ascon_hash_init_cpp(void *state)
{
    *(reinterpret_cast<ascon::hash **>(state)) = new ascon::hash();
}

void ascon_hash_free_cpp(void *state)
{
    delete *(reinterpret_cast<ascon::hash **>(state));
}

void ascon_hash_update_cpp
    (void *state, const unsigned char *in, size_t inlen)
{
    (*(reinterpret_cast<ascon::hash **>(state)))->update(in, inlen);
}

void ascon_hash_finalize_cpp(void *state, unsigned char *out)
{
    (*(reinterpret_cast<ascon::hash **>(state)))->finalize(out);
}

void ascon_hasha_cpp(unsigned char *out, const unsigned char *in, size_t inlen)
{
    // Test several methods for computing the digest.
    switch ((method++) % 3) {
    case 0:
        // All-in-one digest.
        ascon::hasha::digest(out, in, inlen);
        break;

    case 1: {
        // Use the class to compute the digest.
        ascon::hasha hash;
        hash.update(in, inlen);
        hash.finalize(out);
        break; }

    case 2: {
        // All-in-one digest using byte arrays.
        ascon::byte_array input(inlen);
        ascon::byte_array output;
        ascon::hasha hash;
        ::memcpy(input.data(), in, inlen);
        hash.update(input);
        output = hash.finalize();
        ::memcpy(out, output.data(), ASCON_HASH_SIZE);
        break; }
    }
}

void ascon_hasha_init_cpp(void *state)
{
    *(reinterpret_cast<ascon::hasha **>(state)) = new ascon::hasha();
}

void ascon_hasha_free_cpp(void *state)
{
    delete *(reinterpret_cast<ascon::hasha **>(state));
}

void ascon_hasha_update_cpp
    (void *state, const unsigned char *in, size_t inlen)
{
    (*(reinterpret_cast<ascon::hasha **>(state)))->update(in, inlen);
}

void ascon_hasha_finalize_cpp(void *state, unsigned char *out)
{
    (*(reinterpret_cast<ascon::hasha **>(state)))->finalize(out);
}

void ascon_xof_cpp(unsigned char *out, const unsigned char *in, size_t inlen)
{
    // Test several methods for computing the digest.
    switch ((method++) % 2) {
    case 0: {
        // Use the class to compute the digest.
        ascon::xof xof;
        xof.absorb(in, inlen);
        xof.squeeze(out, ASCON_HASH_SIZE);
        break; }

    case 1: {
        // All-in-one digest using byte arrays.
        ascon::byte_array input(inlen);
        ascon::byte_array output;
        ascon::xof xof;
        ::memcpy(input.data(), in, inlen);
        xof.absorb(input);
        output = xof.squeeze(ASCON_HASH_SIZE);
        ::memcpy(out, output.data(), ASCON_HASH_SIZE);
        break; }
    }
}

void ascon_xof_init_cpp(void *state)
{
    *(reinterpret_cast<ascon::xof **>(state)) = new ascon::xof();
}

void ascon_xof_free_cpp(void *state)
{
    delete *(reinterpret_cast<ascon::xof **>(state));
}

void ascon_xof_absorb_cpp(void *state, const unsigned char *in, size_t inlen)
{
    (*(reinterpret_cast<ascon::xof **>(state)))->absorb(in, inlen);
}

void ascon_xof_squeeze_cpp(void *state, unsigned char *out, size_t outlen)
{
    (*(reinterpret_cast<ascon::xof **>(state)))->squeeze(out, outlen);
}

void ascon_xofa_cpp(unsigned char *out, const unsigned char *in, size_t inlen)
{
    // Test several methods for computing the digest.
    switch ((method++) % 2) {
    case 0: {
        // Use the class to compute the digest.
        ascon::xofa xof;
        xof.absorb(in, inlen);
        xof.squeeze(out, ASCON_HASH_SIZE);
        break; }

    case 1: {
        // All-in-one digest using byte arrays.
        ascon::byte_array input(inlen);
        ascon::byte_array output;
        ascon::xofa xof;
        ::memcpy(input.data(), in, inlen);
        xof.absorb(input);
        output = xof.squeeze(ASCON_HASH_SIZE);
        ::memcpy(out, output.data(), ASCON_HASH_SIZE);
        break; }
    }
}

void ascon_xofa_init_cpp(void *state)
{
    *(reinterpret_cast<ascon::xofa **>(state)) = new ascon::xofa();
}

void ascon_xofa_free_cpp(void *state)
{
    delete *(reinterpret_cast<ascon::xofa **>(state));
}

void ascon_xofa_absorb_cpp(void *state, const unsigned char *in, size_t inlen)
{
    (*(reinterpret_cast<ascon::xofa **>(state)))->absorb(in, inlen);
}

void ascon_xofa_squeeze_cpp(void *state, unsigned char *out, size_t outlen)
{
    (*(reinterpret_cast<ascon::xofa **>(state)))->squeeze(out, outlen);
}

} // extern "C"
