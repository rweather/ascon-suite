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
#include <ascon/aead.h>
#include <ascon/aead-masked.h>
#include <ascon/isap.h>
#include <ascon/siv.h>
#include <ascon/hash.h>
#include <ascon/xof.h>

extern "C"
{

static unsigned method = 0;

static void ascon_aead_encrypt_cpp
    (ascon::aead *cipher, unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::byte_array in, out;

    // Set up to encrypt.
    cipher->set_key(k, cipher->key_size());
    cipher->set_nonce(npub, cipher->nonce_size());
    *clen = mlen + cipher->tag_size();

    // Use various methods from the ascon::aead class to do the encryption.
    switch ((method++) % 2) {
    case 0:
        cipher->encrypt(c, m, mlen, ad, adlen);
        break;
    default:
        in = ascon::bytes_from_data(m, mlen);
        if (adlen > 0)
            cipher->encrypt(out, in, ascon::bytes_from_data(ad, adlen));
        else
            cipher->encrypt(out, in);
        *clen = out.size();
        ::memcpy(c, out.data(), out.size());
        break;
    }

    // A second encryption should produce a different outcome because the
    // nonce has been incremented.  Fail it returns the same output.
    in = ascon::bytes_from_data(m, mlen);
    cipher->encrypt(out, in, ascon::bytes_from_data(ad, adlen));
    if (out.size() != *clen || ::memcmp(out.data(), c, *clen) == 0) {
        // Force the calling test to fail.
        ::memset(c, 0xAA, *clen);
    }
}

static int ascon_aead_decrypt_cpp
    (ascon::aead *cipher, unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::byte_array in, out;
    int result;

    // Set up to decrypt.
    cipher->set_key(k, cipher->key_size());
    cipher->set_nonce(npub, cipher->nonce_size());

    // Use various methods from the ascon::aead class to do the decryption.
    switch ((method++) % 2) {
    case 0:
        result = cipher->decrypt(m, c, clen, ad, adlen);
        break;
    default:
        in = ascon::bytes_from_data(c, clen);
        bool ok;
        if (adlen > 0)
            ok = cipher->decrypt(out, in, ascon::bytes_from_data(ad, adlen));
        else
            ok = cipher->decrypt(out, in);
        if (ok) {
            ::memcpy(m, out.data(), out.size());
            result = out.size();
        } else {
            if (clen >= 16)
                ::memset(m, 0, clen - 16);
            result = -1;
        }
        break;
    }

    // A second decryption should fail because the nonce has been incremented.
    if (result >= 0) {
        in = ascon::bytes_from_data(c, clen);
        if (cipher->decrypt(out, in, ascon::bytes_from_data(ad, adlen))) {
            // Decryption succeeded with a new nonce when it should have failed!
            ::memset(m, 0xAA, result);
            return -1;
        }
    }

    // Return the result.
    if (result >= 0) {
        *mlen = (size_t)result;
        return 0;
    }
    return result;
}

void ascon128_aead_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128 cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128_aead_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128 cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon128a_aead_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128a cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128a_aead_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128a cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon80pq_aead_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead80pq cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon80pq_aead_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead80pq cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon128_masked_aead_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128_masked cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128_masked_aead_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128_masked cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon128a_masked_aead_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128a_masked cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128a_masked_aead_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead128a_masked cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon80pq_masked_aead_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead80pq_masked cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon80pq_masked_aead_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::aead80pq_masked cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon128_isap_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::isap128 cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128_isap_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::isap128 cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon128a_isap_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::isap128a cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128a_isap_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::isap128a cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon80pq_isap_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::isap80pq cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon80pq_isap_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::isap80pq cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon128_siv_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::siv128 cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128_siv_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::siv128 cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon128a_siv_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::siv128a cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon128a_siv_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::siv128a cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

void ascon80pq_siv_encrypt_cpp
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::siv80pq cipher;
    ascon_aead_encrypt_cpp(&cipher, c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon80pq_siv_decrypt_cpp
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon::siv80pq cipher;
    return ascon_aead_decrypt_cpp
        (&cipher, m, mlen, c, clen, ad, adlen, npub, k);
}

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
