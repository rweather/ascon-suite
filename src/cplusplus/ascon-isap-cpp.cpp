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

#include <ascon/isap.h>

namespace ascon
{

static unsigned char const zero_key[ASCON80PQ_ISAP_KEY_SIZE] = {0};

isap128::isap128()
{
    ::ascon128_isap_aead_init(&m_key, zero_key);
    ::memset(m_nonce, 0, sizeof(m_nonce));
}

isap128::isap128(const unsigned char *key, size_t len)
{
    if (len == ASCON128_ISAP_KEY_SIZE)
        ::ascon128_isap_aead_init(&m_key, key);
    else if (len == ASCON_ISAP_SAVED_KEY_SIZE)
        ::ascon128_isap_aead_load_key(&m_key, key);
    else
        ::ascon128_isap_aead_init(&m_key, zero_key);
    ::memset(m_nonce, 0, ASCON_ISAP_NONCE_SIZE);
}

isap128::~isap128()
{
    ::ascon128_isap_aead_free(&m_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

void isap128::save_key(unsigned char key[ASCON_ISAP_SAVED_KEY_SIZE])
{
    ::ascon128_isap_aead_save_key(&m_key, key);
}

size_t isap128::key_size() const
{
    return ASCON128_ISAP_KEY_SIZE;
}

size_t isap128::tag_size() const
{
    return ASCON_ISAP_TAG_SIZE;
}

size_t isap128::nonce_size() const
{
    return ASCON_ISAP_NONCE_SIZE;
}

bool isap128::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON128_ISAP_KEY_SIZE && key) {
        ::ascon128_isap_aead_free(&m_key);
        ::ascon128_isap_aead_init(&m_key, key);
        return true;
    } else if (len == ASCON_ISAP_SAVED_KEY_SIZE && key) {
        ::ascon128_isap_aead_free(&m_key);
        ::ascon128_isap_aead_load_key(&m_key, key);
        return true;
    } else if (len == 0) {
        ::ascon128_isap_aead_free(&m_key);
        ::ascon128_isap_aead_init(&m_key, key);
        return true;
    } else {
        return false;
    }
}

void isap128::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON_ISAP_NONCE_SIZE) {
        ::memcpy(m_nonce, nonce, ASCON_ISAP_NONCE_SIZE);
    } else {
        ::memset(m_nonce, 0, ASCON_ISAP_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_nonce + ASCON_ISAP_NONCE_SIZE - len, nonce, len);
    }
}

void isap128::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_nonce, n);
}

void isap128::clear()
{
    ::ascon128_isap_aead_free(&m_key);
    ::ascon128_isap_aead_init(&m_key, zero_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

int isap128::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128_isap_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_nonce, &m_key);
    ::ascon_aead_increment_nonce(m_nonce);
    return (int)clen;
}

int isap128::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128_isap_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_nonce, &m_key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

isap128a::isap128a()
{
    ::ascon128a_isap_aead_init(&m_key, zero_key);
    ::memset(m_nonce, 0, sizeof(m_nonce));
}

isap128a::isap128a(const unsigned char *key, size_t len)
{
    if (len == ASCON128_ISAP_KEY_SIZE)
        ::ascon128a_isap_aead_init(&m_key, key);
    else if (len == ASCON_ISAP_SAVED_KEY_SIZE)
        ::ascon128a_isap_aead_load_key(&m_key, key);
    else
        ::ascon128a_isap_aead_init(&m_key, zero_key);
    ::memset(m_nonce, 0, ASCON_ISAP_NONCE_SIZE);
}

isap128a::~isap128a()
{
    ::ascon128a_isap_aead_free(&m_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

void isap128a::save_key(unsigned char key[ASCON_ISAP_SAVED_KEY_SIZE])
{
    ::ascon128a_isap_aead_save_key(&m_key, key);
}

size_t isap128a::key_size() const
{
    return ASCON128_ISAP_KEY_SIZE;
}

size_t isap128a::tag_size() const
{
    return ASCON_ISAP_TAG_SIZE;
}

size_t isap128a::nonce_size() const
{
    return ASCON_ISAP_NONCE_SIZE;
}

bool isap128a::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON128_ISAP_KEY_SIZE && key) {
        ::ascon128a_isap_aead_free(&m_key);
        ::ascon128a_isap_aead_init(&m_key, key);
        return true;
    } else if (len == ASCON_ISAP_SAVED_KEY_SIZE && key) {
        ::ascon128a_isap_aead_free(&m_key);
        ::ascon128a_isap_aead_load_key(&m_key, key);
        return true;
    } else if (len == 0) {
        ::ascon128a_isap_aead_free(&m_key);
        ::ascon128a_isap_aead_init(&m_key, key);
        return true;
    } else {
        return false;
    }
}

void isap128a::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON_ISAP_NONCE_SIZE) {
        ::memcpy(m_nonce, nonce, ASCON_ISAP_NONCE_SIZE);
    } else {
        ::memset(m_nonce, 0, ASCON_ISAP_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_nonce + ASCON_ISAP_NONCE_SIZE - len, nonce, len);
    }
}

void isap128a::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_nonce, n);
}

void isap128a::clear()
{
    ::ascon128a_isap_aead_free(&m_key);
    ::ascon128a_isap_aead_init(&m_key, zero_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

int isap128a::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon128a_isap_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_nonce, &m_key);
    ::ascon_aead_increment_nonce(m_nonce);
    return (int)clen;
}

int isap128a::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon128a_isap_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_nonce, &m_key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

isap80pq::isap80pq()
{
    ::ascon80pq_isap_aead_init(&m_key, zero_key);
    ::memset(m_nonce, 0, sizeof(m_nonce));
}

isap80pq::isap80pq(const unsigned char *key, size_t len)
{
    if (len == ASCON80PQ_ISAP_KEY_SIZE)
        ::ascon80pq_isap_aead_init(&m_key, key);
    else if (len == ASCON_ISAP_SAVED_KEY_SIZE)
        ::ascon80pq_isap_aead_load_key(&m_key, key);
    else
        ::ascon80pq_isap_aead_init(&m_key, zero_key);
    ::memset(m_nonce, 0, ASCON_ISAP_NONCE_SIZE);
}

isap80pq::~isap80pq()
{
    ::ascon80pq_isap_aead_free(&m_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

void isap80pq::save_key(unsigned char key[ASCON_ISAP_SAVED_KEY_SIZE])
{
    ::ascon80pq_isap_aead_save_key(&m_key, key);
}

size_t isap80pq::key_size() const
{
    return ASCON80PQ_ISAP_KEY_SIZE;
}

size_t isap80pq::tag_size() const
{
    return ASCON_ISAP_TAG_SIZE;
}

size_t isap80pq::nonce_size() const
{
    return ASCON_ISAP_NONCE_SIZE;
}

bool isap80pq::set_key(const unsigned char *key, size_t len)
{
    if (len == ASCON80PQ_ISAP_KEY_SIZE && key) {
        ::ascon80pq_isap_aead_free(&m_key);
        ::ascon80pq_isap_aead_init(&m_key, key);
        return true;
    } else if (len == ASCON_ISAP_SAVED_KEY_SIZE && key) {
        ::ascon80pq_isap_aead_free(&m_key);
        ::ascon80pq_isap_aead_load_key(&m_key, key);
        return true;
    } else if (len == 0) {
        ::ascon80pq_isap_aead_free(&m_key);
        ::ascon80pq_isap_aead_init(&m_key, key);
        return true;
    } else {
        return false;
    }
}

void isap80pq::set_nonce(const unsigned char *nonce, size_t len)
{
    if (len >= ASCON_ISAP_NONCE_SIZE) {
        ::memcpy(m_nonce, nonce, ASCON_ISAP_NONCE_SIZE);
    } else {
        ::memset(m_nonce, 0, ASCON_ISAP_NONCE_SIZE - len);
        if (len > 0)
            ::memcpy(m_nonce + ASCON_ISAP_NONCE_SIZE - len, nonce, len);
    }
}

void isap80pq::set_counter(uint64_t n)
{
    ::ascon_aead_set_counter(m_nonce, n);
}

void isap80pq::clear()
{
    ::ascon80pq_isap_aead_free(&m_key);
    ::ascon80pq_isap_aead_init(&m_key, zero_key);
    ::ascon_clean(m_nonce, sizeof(m_nonce));
}

int isap80pq::do_encrypt
    (unsigned char *c, const unsigned char *m, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t clen = 0;
    ::ascon80pq_isap_aead_encrypt
        (c, &clen, m, len, ad, adlen, m_nonce, &m_key);
    ::ascon_aead_increment_nonce(m_nonce);
    return (int)clen;
}

int isap80pq::do_decrypt
    (unsigned char *m, const unsigned char *c, size_t len,
     const unsigned char *ad, size_t adlen)
{
    size_t mlen = 0;
    int result = ::ascon80pq_isap_aead_decrypt
        (m, &mlen, c, len, ad, adlen, m_nonce, &m_key);
    if (result >= 0) {
        ::ascon_aead_increment_nonce(m_nonce);
        return (int)mlen;
    } else {
        return -1;
    }
}

} // namespace ascon
