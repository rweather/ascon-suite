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

#include <ascon/siv.h>

namespace ascon
{

siv128::siv128()
{
    ::memset(&m_state, 0, sizeof(m_state));
}

siv128::siv128(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::memcpy(&m_state.key, key, ASCON128_KEY_SIZE);
    else
        ::memset(&m_state.key, 0, ASCON128_KEY_SIZE);
    ::memset(&m_state.nonce, 0, ASCON128_NONCE_SIZE);
}

siv128::~siv128()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

size_t siv128::key_size() const
{
    return ASCON128_KEY_SIZE;
}

size_t siv128::tag_size() const
{
    return ASCON128_TAG_SIZE;
}

size_t siv128::nonce_size() const
{
    return ASCON128_NONCE_SIZE;
}

bool siv128::set_key(const unsigned char *key, size_t len)
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

void siv128::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON128_NONCE_SIZE) {
        ::memcpy(m_state.nonce, nonce, ASCON128_NONCE_SIZE);
    } else {
        ::memset(m_state.nonce, 0, ASCON128_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_state.nonce + ASCON128_NONCE_SIZE - len, nonce, len);
    }
}

void siv128::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_state.nonce, n);
}

void siv128::clear()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

int siv128::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128_siv_encrypt
        (c, &clen, m, len, ad, adlen, m_state.nonce, m_state.key);
    ::ascon_aead_increment_nonce(m_state.nonce);
    return (int)clen;
}

int siv128::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128_siv_decrypt
        (m, &mlen, c, len, ad, adlen, m_state.nonce, m_state.key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_state.nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

siv128a::siv128a()
{
    ::memset(&m_state, 0, sizeof(m_state));
}

siv128a::siv128a(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::memcpy(&m_state.key, key, ASCON128_KEY_SIZE);
    else
        ::memset(&m_state.key, 0, ASCON128_KEY_SIZE);
    ::memset(&m_state.nonce, 0, ASCON128_NONCE_SIZE);
}

siv128a::~siv128a()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

size_t siv128a::key_size() const
{
    return ASCON128_KEY_SIZE;
}

size_t siv128a::tag_size() const
{
    return ASCON128_TAG_SIZE;
}

size_t siv128a::nonce_size() const
{
    return ASCON128_NONCE_SIZE;
}

bool siv128a::set_key(const unsigned char *key, size_t len)
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

void siv128a::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON128_NONCE_SIZE) {
        ::memcpy(m_state.nonce, nonce, ASCON128_NONCE_SIZE);
    } else {
        ::memset(m_state.nonce, 0, ASCON128_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_state.nonce + ASCON128_NONCE_SIZE - len, nonce, len);
    }
}

void siv128a::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_state.nonce, n);
}

void siv128a::clear()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

int siv128a::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128a_siv_encrypt
        (c, &clen, m, len, ad, adlen, m_state.nonce, m_state.key);
    ::ascon_aead_increment_nonce(m_state.nonce);
    return (int)clen;
}

int siv128a::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128a_siv_decrypt
        (m, &mlen, c, len, ad, adlen, m_state.nonce, m_state.key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_state.nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

siv80pq::siv80pq()
{
    ::memset(&m_state, 0, sizeof(m_state));
}

siv80pq::siv80pq(const unsigned char key[ASCON128_KEY_SIZE])
{
    if (key)
        ::memcpy(&m_state.key, key, ASCON128_KEY_SIZE);
    else
        ::memset(&m_state.key, 0, ASCON128_KEY_SIZE);
    ::memset(&m_state.nonce, 0, ASCON128_NONCE_SIZE);
}

siv80pq::~siv80pq()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

size_t siv80pq::key_size() const
{
    return ASCON80PQ_KEY_SIZE;
}

size_t siv80pq::tag_size() const
{
    return ASCON80PQ_TAG_SIZE;
}

size_t siv80pq::nonce_size() const
{
    return ASCON80PQ_NONCE_SIZE;
}

bool siv80pq::set_key(const unsigned char *key, size_t len)
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

void siv80pq::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON80PQ_NONCE_SIZE) {
        ::memcpy(m_state.nonce, nonce, ASCON80PQ_NONCE_SIZE);
    } else {
        ::memset(m_state.nonce, 0, ASCON80PQ_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_state.nonce + ASCON80PQ_NONCE_SIZE - len, nonce, len);
    }
}

void siv80pq::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_state.nonce, n);
}

void siv80pq::clear()
{
    ::ascon_clean(&m_state, sizeof(m_state));
}

int siv80pq::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon80pq_siv_encrypt
        (c, &clen, m, len, ad, adlen, m_state.nonce, m_state.key);
    ::ascon_aead_increment_nonce(m_state.nonce);
    return (int)clen;
}

int siv80pq::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon80pq_siv_decrypt
        (m, &mlen, c, len, ad, adlen, m_state.nonce, m_state.key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_state.nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

} // namespace ascon
