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

#include <ascon/aead-masked.h>

namespace ascon
{

static unsigned char const zero_key[ASCON80PQ_KEY_SIZE] = {0};

aead_masked::~aead_masked()
{
}

aead128_masked::aead128_masked()
{
    ::memset(&m_key, 0, sizeof(m_key));
    ::memset(m_nonce, 0, sizeof(m_nonce));
}

aead128_masked::aead128_masked(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::ascon_masked_key_128_init(&m_key, key);
    else
        ::ascon_masked_key_128_init(&m_key, zero_key);
    ::memset(m_nonce, 0, ASCON128_NONCE_SIZE);
}

aead128_masked::~aead128_masked()
{
    ::ascon_masked_key_128_free(&m_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

size_t aead128_masked::key_size() const
{
    return ASCON128_KEY_SIZE;
}

size_t aead128_masked::tag_size() const
{
    return ASCON128_TAG_SIZE;
}

size_t aead128_masked::nonce_size() const
{
    return ASCON128_NONCE_SIZE;
}

bool aead128_masked::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON128_KEY_SIZE && key) {
        ::ascon_masked_key_128_init(&m_key, key);
        return true;
    } else if (len == 0) {
        ::ascon_masked_key_128_init(&m_key, zero_key);
        return true;
    } else {
        return false;
    }
}

void aead128_masked::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON128_NONCE_SIZE) {
        ::memcpy(m_nonce, nonce, ASCON128_NONCE_SIZE);
    } else {
        ::memset(m_nonce, 0, ASCON128_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_nonce + ASCON128_NONCE_SIZE - len, nonce, len);
    }
}

void aead128_masked::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_nonce, n);
}

void aead128_masked::clear()
{
    ::ascon_masked_key_128_free(&m_key);
    ::ascon_clean(&m_nonce, sizeof(m_nonce));
}

void aead128_masked::randomize_key()
{
    ::ascon_masked_key_128_randomize(&m_key);
}

int aead128_masked::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128_masked_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_nonce, &m_key);
    ::ascon_aead_increment_nonce(m_nonce);
    return (int)clen;
}

int aead128_masked::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128_masked_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_nonce, &m_key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

aead128a_masked::aead128a_masked()
{
    ::memset(&m_key, 0, sizeof(m_key));
    ::memset(m_nonce, 0, sizeof(m_nonce));
}

aead128a_masked::aead128a_masked(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::ascon_masked_key_128_init(&m_key, key);
    else
        ::ascon_masked_key_128_init(&m_key, zero_key);
    ::memset(m_nonce, 0, ASCON128_NONCE_SIZE);
}

aead128a_masked::~aead128a_masked()
{
    ::ascon_masked_key_128_free(&m_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

size_t aead128a_masked::key_size() const
{
    return ASCON128_KEY_SIZE;
}

size_t aead128a_masked::tag_size() const
{
    return ASCON128_TAG_SIZE;
}

size_t aead128a_masked::nonce_size() const
{
    return ASCON128_NONCE_SIZE;
}

bool aead128a_masked::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON128_KEY_SIZE && key) {
        ::ascon_masked_key_128_init(&m_key, key);
        return true;
    } else if (len == 0) {
        ::ascon_masked_key_128_init(&m_key, zero_key);
        return true;
    } else {
        return false;
    }
}

void aead128a_masked::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON128_NONCE_SIZE) {
        ::memcpy(m_nonce, nonce, ASCON128_NONCE_SIZE);
    } else {
        ::memset(m_nonce, 0, ASCON128_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_nonce + ASCON128_NONCE_SIZE - len, nonce, len);
    }
}

void aead128a_masked::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_nonce, n);
}

void aead128a_masked::clear()
{
    ::ascon_masked_key_128_free(&m_key);
    ::ascon_clean(&m_nonce, sizeof(m_nonce));
}

void aead128a_masked::randomize_key()
{
    ::ascon_masked_key_128_randomize(&m_key);
}

int aead128a_masked::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128a_masked_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_nonce, &m_key);
    ::ascon_aead_increment_nonce(m_nonce);
    return (int)clen;
}

int aead128a_masked::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128a_masked_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_nonce, &m_key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

aead80pq_masked::aead80pq_masked()
{
    ::memset(&m_key, 0, sizeof(m_key));
    ::memset(m_nonce, 0, sizeof(m_nonce));
}

aead80pq_masked::aead80pq_masked(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::ascon_masked_key_160_init(&m_key, key);
    else
        ::ascon_masked_key_160_init(&m_key, zero_key);
    ::memset(m_nonce, 0, ASCON80PQ_NONCE_SIZE);
}

aead80pq_masked::~aead80pq_masked()
{
    ::ascon_masked_key_160_free(&m_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

size_t aead80pq_masked::key_size() const
{
    return ASCON80PQ_KEY_SIZE;
}

size_t aead80pq_masked::tag_size() const
{
    return ASCON80PQ_TAG_SIZE;
}

size_t aead80pq_masked::nonce_size() const
{
    return ASCON80PQ_NONCE_SIZE;
}

bool aead80pq_masked::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON80PQ_KEY_SIZE && key) {
        ::ascon_masked_key_160_init(&m_key, key);
        return true;
    } else if (len == 0) {
        ::ascon_masked_key_160_init(&m_key, zero_key);
        return true;
    } else {
        return false;
    }
}

void aead80pq_masked::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON80PQ_NONCE_SIZE) {
        ::memcpy(m_nonce, nonce, ASCON80PQ_NONCE_SIZE);
    } else {
        ::memset(m_nonce, 0, ASCON80PQ_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_nonce + ASCON80PQ_NONCE_SIZE - len, nonce, len);
    }
}

void aead80pq_masked::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_nonce, n);
}

void aead80pq_masked::clear()
{
    ::ascon_masked_key_160_free(&m_key);
    ::ascon_clean(&m_nonce, sizeof(m_nonce));
}

void aead80pq_masked::randomize_key()
{
    ::ascon_masked_key_160_randomize(&m_key);
}

int aead80pq_masked::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon80pq_masked_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_nonce, &m_key);
    ::ascon_aead_increment_nonce(m_nonce);
    return (int)clen;
}

int aead80pq_masked::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon80pq_masked_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_nonce, &m_key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

} // namespace ascon
