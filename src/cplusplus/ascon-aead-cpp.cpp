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

#include <ascon/aead.h>

namespace ascon
{

aead::~aead()
{
}

void aead::encrypt(ascon::byte_array &c, const ascon::byte_array &m)
{
    size_t len = m.size();
    c.resize(len + tag_size());
    do_encrypt(c.data(), m.data(), len, 0, 0);
}

void aead::encrypt
    (ascon::byte_array &c, const ascon::byte_array &m,
     const ascon::byte_array &ad)
{
    size_t len = m.size();
    c.resize(len + tag_size());
    do_encrypt(c.data(), m.data(), len, ad.data(), ad.size());
}

bool aead::decrypt(ascon::byte_array &m, const ascon::byte_array &c)
{
    size_t len = c.size();
    size_t tlen = tag_size();
    if (len < tlen) {
        m.resize(0);
        return false;
    }
    m.resize(len - tlen);
    if (do_decrypt(m.data(), c.data(), len, 0, 0) < 0) {
        m.resize(0);
        return false;
    }
    return true;
}

bool aead::decrypt
    (ascon::byte_array &m, const ascon::byte_array &c,
     const ascon::byte_array &ad)
{
    size_t len = c.size();
    size_t tlen = tag_size();
    if (len < tlen) {
        m.resize(0);
        return false;
    }
    m.resize(len - tlen);
    if (do_decrypt(m.data(), c.data(), len, ad.data(), ad.size()) < 0) {
        m.resize(0);
        return false;
    }
    return true;
}

aead128::aead128()
{
    ::memset(&m_state, 0, sizeof(m_state));
}

aead128::aead128(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::memcpy(&m_state.key, key, ASCON128_KEY_SIZE);
    else
        ::memset(&m_state.key, 0, ASCON128_KEY_SIZE);
    ::memset(&m_state.nonce, 0, ASCON128_NONCE_SIZE);
}

aead128::~aead128()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

size_t aead128::key_size() const
{
    return ASCON128_KEY_SIZE;
}

size_t aead128::tag_size() const
{
    return ASCON128_TAG_SIZE;
}

size_t aead128::nonce_size() const
{
    return ASCON128_NONCE_SIZE;
}

bool aead128::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON128_KEY_SIZE && key) {
        ::memcpy(m_state.key, key, ASCON128_KEY_SIZE);
        return true;
    } else if (len == 0) {
        ::memset(m_state.key, 0, ASCON128_KEY_SIZE);
        return true;
    } else {
        return false;
    }
}

void aead128::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON128_NONCE_SIZE) {
        ::memcpy(m_state.nonce, nonce, ASCON128_NONCE_SIZE);
    } else {
        ::memset(m_state.nonce, 0, ASCON128_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_state.nonce + ASCON128_NONCE_SIZE - len, nonce, len);
    }
}

void aead128::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_state.nonce, n);
}

void aead128::clear()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

int aead128::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_state.nonce, m_state.key);
    ::ascon_aead_increment_nonce(m_state.nonce);
    return (int)clen;
}

int aead128::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_state.nonce, m_state.key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_state.nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

aead128a::aead128a()
{
    ::memset(&m_state, 0, sizeof(m_state));
}

aead128a::aead128a(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::memcpy(&m_state.key, key, ASCON128_KEY_SIZE);
    else
        ::memset(&m_state.key, 0, ASCON128_KEY_SIZE);
    ::memset(&m_state.nonce, 0, ASCON128_NONCE_SIZE);
}

aead128a::~aead128a()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

size_t aead128a::key_size() const
{
    return ASCON128_KEY_SIZE;
}

size_t aead128a::tag_size() const
{
    return ASCON128_TAG_SIZE;
}

size_t aead128a::nonce_size() const
{
    return ASCON128_NONCE_SIZE;
}

bool aead128a::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON128_KEY_SIZE && key) {
        ::memcpy(m_state.key, key, ASCON128_KEY_SIZE);
        return true;
    } else if (len == 0) {
        ::memset(m_state.key, 0, ASCON128_KEY_SIZE);
        return true;
    } else {
        return false;
    }
}

void aead128a::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON128_NONCE_SIZE) {
        ::memcpy(m_state.nonce, nonce, ASCON128_NONCE_SIZE);
    } else {
        ::memset(m_state.nonce, 0, ASCON128_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_state.nonce + ASCON128_NONCE_SIZE - len, nonce, len);
    }
}

void aead128a::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_state.nonce, n);
}

void aead128a::clear()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

int aead128a::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128a_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_state.nonce, m_state.key);
    ::ascon_aead_increment_nonce(m_state.nonce);
    return (int)clen;
}

int aead128a::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128a_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_state.nonce, m_state.key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_state.nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

aead80pq::aead80pq()
{
    ::memset(&m_state, 0, sizeof(m_state));
}

aead80pq::aead80pq(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::memcpy(&m_state.key, key, ASCON128_KEY_SIZE);
    else
        ::memset(&m_state.key, 0, ASCON128_KEY_SIZE);
    ::memset(&m_state.nonce, 0, ASCON128_NONCE_SIZE);
}

aead80pq::~aead80pq()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

size_t aead80pq::key_size() const
{
    return ASCON80PQ_KEY_SIZE;
}

size_t aead80pq::tag_size() const
{
    return ASCON80PQ_TAG_SIZE;
}

size_t aead80pq::nonce_size() const
{
    return ASCON80PQ_NONCE_SIZE;
}

bool aead80pq::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON80PQ_KEY_SIZE && key) {
        ::memcpy(m_state.key, key, ASCON80PQ_KEY_SIZE);
        return true;
    } else if (len == 0) {
        ::memset(m_state.key, 0, ASCON80PQ_KEY_SIZE);
        return true;
    } else {
        return false;
    }
}

void aead80pq::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON80PQ_NONCE_SIZE) {
        ::memcpy(m_state.nonce, nonce, ASCON80PQ_NONCE_SIZE);
    } else {
        ::memset(m_state.nonce, 0, ASCON80PQ_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_state.nonce + ASCON80PQ_NONCE_SIZE - len, nonce, len);
    }
}

void aead80pq::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_state.nonce, n);
}

void aead80pq::clear()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

int aead80pq::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon80pq_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_state.nonce, m_state.key);
    ::ascon_aead_increment_nonce(m_state.nonce);
    return (int)clen;
}

int aead80pq::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon80pq_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_state.nonce, m_state.key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_state.nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

} // namespace ascon
