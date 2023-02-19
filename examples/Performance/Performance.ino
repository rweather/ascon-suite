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

// This sketch runs performance tests on the ASCON primitives.

#include <ASCON.h>

#if defined(ESP8266)
extern "C" void system_soft_wdt_feed(void);
#define crypto_feed_watchdog() system_soft_wdt_feed()
#else
#define crypto_feed_watchdog() do { ; } while (0)
#endif

typedef void (*aead_cipher_encrypt_t)
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);
typedef int (*aead_cipher_decrypt_t)
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);
typedef void (*aead_cipher_pk_init_t)
    (unsigned char *pk, const unsigned char *k);
typedef void (*aead_cipher_pk_free_t)(unsigned char *pk);
typedef void (*aead_hash_t)
    (unsigned char *out, const unsigned char *in, size_t inlen);

#if defined(__AVR__)
#define DEFAULT_PERF_LOOPS 200
#define DEFAULT_PERF_LOOPS_16 200
#define DEFAULT_PERF_HASH_LOOPS 100
#elif defined(ESP8266)
#define DEFAULT_PERF_LOOPS 1000
#define DEFAULT_PERF_LOOPS_16 3000
#define DEFAULT_PERF_HASH_LOOPS 300
#else
#define DEFAULT_PERF_LOOPS 1000
#define DEFAULT_PERF_LOOPS_16 3000
#define DEFAULT_PERF_HASH_LOOPS 1000
#endif

static int PERF_LOOPS = DEFAULT_PERF_LOOPS;
static int PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16;
static int PERF_HASH_LOOPS = DEFAULT_PERF_HASH_LOOPS;
static bool PERF_MASKING = false;

#define MAX_DATA_SIZE 128
#define MAX_TAG_SIZE 32

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];

void perfCipherEncrypt128
    (aead_cipher_encrypt_t encrypt,
     unsigned key_size,
     aead_cipher_pk_init_t init_key,
     aead_cipher_pk_free_t free_key)
{
    const unsigned char *k = key;
    unsigned char pk[key_size + 8];
    unsigned long start;
    unsigned long elapsed;
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt 128 byte packets ... ");

    if (init_key) {
        init_key(pk, key);
        k = pk;
    }

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        encrypt(ciphertext, &len, plaintext, 128, 0, 0, nonce, k);
    }
    elapsed = micros() - start;

    if (free_key)
        free_key(pk);

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt128
    (aead_cipher_encrypt_t encrypt,
     aead_cipher_decrypt_t decrypt,
     unsigned key_size,
     aead_cipher_pk_init_t init_key,
     aead_cipher_pk_free_t free_key)
{
    const unsigned char *k = key;
    unsigned char pk[key_size + 8];
    unsigned long start;
    unsigned long elapsed;
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    encrypt(ciphertext, &clen, plaintext, 128, 0, 0, nonce, k);

    Serial.print("   decrypt 128 byte packets ... ");

    if (init_key) {
        init_key(pk, key);
        k = pk;
    }

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        decrypt(plaintext, &plen, ciphertext, clen, 0, 0, nonce, k);
    }
    elapsed = micros() - start;

    if (free_key)
        free_key(pk);

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherEncrypt16
    (aead_cipher_encrypt_t encrypt,
     unsigned key_size,
     aead_cipher_pk_init_t init_key,
     aead_cipher_pk_free_t free_key)
{
    const unsigned char *k = key;
    unsigned char pk[key_size + 8];
    unsigned long start;
    unsigned long elapsed;
    size_t len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt  16 byte packets ... ");

    if (init_key) {
        init_key(pk, key);
        k = pk;
    }

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        encrypt(ciphertext, &len, plaintext, 16, 0, 0, nonce, k);
    }
    elapsed = micros() - start;

    if (free_key)
        free_key(pk);

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt16
    (aead_cipher_encrypt_t encrypt,
     aead_cipher_decrypt_t decrypt,
     unsigned key_size,
     aead_cipher_pk_init_t init_key,
     aead_cipher_pk_free_t free_key)
{
    const unsigned char *k = key;
    unsigned char pk[key_size + 8];
    unsigned long start;
    unsigned long elapsed;
    size_t clen;
    size_t plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    encrypt(ciphertext, &clen, plaintext, 16, 0, 0, nonce, k);

    Serial.print("   decrypt  16 byte packets ... ");

    if (init_key) {
        init_key(pk, key);
        k = pk;
    }

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        decrypt(plaintext, &plen, ciphertext, clen, 0, 0, nonce, k);
    }
    elapsed = micros() - start;

    if (free_key)
        free_key(pk);

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

bool equal_hex(const char *expected, const unsigned char *actual, unsigned len)
{
    int ch, value;
    while (len > 0) {
        if (expected[0] == '\0' || expected[1] == '\0')
            return false;
        ch = *expected++;
        if (ch >= '0' && ch <= '9')
            value = (ch - '0') * 16;
        else if (ch >= 'A' && ch <= 'F')
            value = (ch - 'A' + 10) * 16;
        else if (ch >= 'a' && ch <= 'f')
            value = (ch - 'a' + 10) * 16;
        else
            return false;
        ch = *expected++;
        if (ch >= '0' && ch <= '9')
            value += (ch - '0');
        else if (ch >= 'A' && ch <= 'F')
            value += (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f')
            value += (ch - 'a' + 10);
        else
            return false;
        if (actual[0] != value)
            return false;
        ++actual;
        --len;
    }
    return len == 0;
}

void perfCipherSanityCheck
    (aead_cipher_encrypt_t encrypt, unsigned key_size,
     aead_cipher_pk_init_t init_key, aead_cipher_pk_free_t free_key,
     const char *sanity_vec)
{
    const unsigned char *k = key;
    unsigned char pk[key_size + 8];
    unsigned count;
    size_t clen;

    Serial.print("   sanity check ... ");

    if (init_key) {
        init_key(pk, key);
        k = pk;
    }

    for (count = 0; count < 23; ++count)
        plaintext[count] = (unsigned char)count;
    for (count = 0; count < 11; ++count)
        plaintext[32 + count] = (unsigned char)count;

    encrypt(ciphertext, &clen, plaintext, 23, plaintext + 32, 11, nonce, k);

    if (free_key)
        free_key(pk);

    if (equal_hex(sanity_vec, ciphertext, clen))
        Serial.println("ok");
    else
        Serial.println("FAILED");
}

void perfCipher(const char *name, aead_cipher_encrypt_t encrypt,
                aead_cipher_decrypt_t decrypt, const char *sanity_vec)
{
    crypto_feed_watchdog();
    Serial.print(name);
    Serial.print(':');
    Serial.println();

    perfCipherSanityCheck(encrypt, 0, 0, 0, sanity_vec);
    perfCipherEncrypt128(encrypt, 0, 0, 0);
    perfCipherDecrypt128(encrypt, decrypt, 0, 0, 0);
    perfCipherEncrypt16(encrypt, 0, 0, 0);
    perfCipherDecrypt16(encrypt, decrypt, 0, 0, 0);

    Serial.println();
}

void perfCipherPK(const char *name, unsigned key_size,
                  aead_cipher_encrypt_t encrypt,
                  aead_cipher_decrypt_t decrypt,
                  aead_cipher_pk_init_t init_key,
                  aead_cipher_pk_free_t free_key,
                  const char *sanity_vec)
{
    crypto_feed_watchdog();
    Serial.print(name);
    Serial.print(':');
    Serial.println();

    perfCipherSanityCheck(encrypt, key_size, init_key, free_key, sanity_vec);
    perfCipherEncrypt128(encrypt, key_size, init_key, free_key);
    perfCipherDecrypt128(encrypt, decrypt, key_size, init_key, free_key);
    perfCipherEncrypt16(encrypt, key_size, init_key, free_key);
    perfCipherDecrypt16(encrypt, decrypt, key_size, init_key, free_key);

    Serial.println();
}

// Reduce the maximum hash buffer size on Uno because there isn't enough RAM.
#if defined(ARDUINO_AVR_UNO)
#define HASH_BUFSIZ 512
#else
#define HASH_BUFSIZ 1024
#endif

static unsigned char hash_buffer[HASH_BUFSIZ];

void perfHash_N(aead_hash_t hash_func, int size)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count, loops;

    for (count = 0; count < size; ++count)
        hash_buffer[count] = (unsigned char)count;

    Serial.print("   hash ");
    if (size < 1000) {
        if (size < 100)
            Serial.print("  ");
        else
            Serial.print(" ");
    }
    Serial.print(size);
    Serial.print(" bytes ... ");

    // Adjust the number of loops to do more loops on smaller sizes.
    if (size < HASH_BUFSIZ)
        loops = PERF_HASH_LOOPS * 4;
    else
        loops = PERF_HASH_LOOPS;

    start = micros();
    for (count = 0; count < loops; ++count) {
        hash_func(ciphertext, hash_buffer, size);
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (((double)size) * loops));
    Serial.print("us per byte, ");
    Serial.print((1000000.0 * size * loops) / elapsed);
    Serial.println(" bytes per second");
}

void perfHash(const char *name, aead_hash_t hash_func)
{
    crypto_feed_watchdog();
    Serial.print(name);
    Serial.print(':');
    Serial.println();

    perfHash_N(hash_func, HASH_BUFSIZ);
    perfHash_N(hash_func, 128);
    perfHash_N(hash_func, 16);

    Serial.println();
}

void setup()
{
    Serial.begin(9600);
    Serial.println();

    // The test vectors are for doing a quick sanity check that the
    // algorithm appears to be working correctly.  The test vector is:
    //      Key = 0001020304...    (up to the key length)
    //      Nonce = 0001020304...  (up to the nonce length)
    //      PT = 000102030405060708090A0B0C0D0E0F10111213141516  (size = 23)
    //      AD = 000102030405060708090A                          (size = 11)
    // Usually this is "Count = 771" in the standard NIST KAT vectors.
    perfCipher("ASCON-128", ascon128_aead_encrypt, ascon128_aead_decrypt,
               "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC");
    perfCipher("ASCON-128a", ascon128a_aead_encrypt, ascon128a_aead_decrypt,
               "C52E4E39F5EF9F8461912AED7ABBA1B8EB8AD7ACD54637D193C5371279753F2177BFC76E5FC300");
    perfCipher("ASCON-80pq", ascon80pq_aead_encrypt, ascon80pq_aead_decrypt,
               "368D3F1F3BA75BA929D4A5327E8DE42A55383F238CCC04F75BF026EF5BE70D67741B339B908B04");

    perfCipher("ASCON-128-SIV", ascon128_siv_encrypt, ascon128_siv_decrypt,
               "800A4B5581E640EDC9B3CFB1311BB5FADF412013FD9658820534BA25D617235573AEBEEE3EC415");
    perfCipher("ASCON-128a-SIV", ascon128a_siv_encrypt, ascon128a_siv_decrypt,
               "5D20209930C3DF4FAED4472BA266FAC0E9A465F40BF209849DA61D2A40710289A13266D4DE563B");
    perfCipher("ASCON-80pq-SIV", ascon80pq_siv_encrypt, ascon80pq_siv_decrypt,
               "4B567E83664C14BF9384C858AF5A6D96B95761DDD95E6F400B7A7432BB9F6D09D95E10D82CEAF4");

    perfHash("ASCON-HASH", ascon_hash);
    perfHash("ASCON-HASHA", ascon_hasha);
    perfHash("ASCON-XOF", ascon_xof);
    perfHash("ASCON-XOFA", ascon_xofa);

    perfCipherPK("ASCON-128-masked", sizeof(ascon_masked_key_128_t),
                 (aead_cipher_encrypt_t)ascon128_masked_aead_encrypt,
                 (aead_cipher_decrypt_t)ascon128_masked_aead_decrypt,
                 (aead_cipher_pk_init_t)ascon_masked_key_128_init,
                 (aead_cipher_pk_free_t)ascon_masked_key_128_free,
                 "76807B6448896CE58842CB4AED6C41041D6DEC3B3A0DD69901F988A337A7239C411A18313622FC");
    perfCipherPK("ASCON-128a-masked", sizeof(ascon_masked_key_128_t),
                 (aead_cipher_encrypt_t)ascon128a_masked_aead_encrypt,
                 (aead_cipher_decrypt_t)ascon128a_masked_aead_decrypt,
                 (aead_cipher_pk_init_t)ascon_masked_key_128_init,
                 (aead_cipher_pk_free_t)ascon_masked_key_128_free,
                 "C52E4E39F5EF9F8461912AED7ABBA1B8EB8AD7ACD54637D193C5371279753F2177BFC76E5FC300");
    perfCipherPK("ASCON-80pq-masked", sizeof(ascon_masked_key_160_t),
                 (aead_cipher_encrypt_t)ascon80pq_masked_aead_encrypt,
                 (aead_cipher_decrypt_t)ascon80pq_masked_aead_decrypt,
                 (aead_cipher_pk_init_t)ascon_masked_key_160_init,
                 (aead_cipher_pk_free_t)ascon_masked_key_160_free,
                 "368D3F1F3BA75BA929D4A5327E8DE42A55383F238CCC04F75BF026EF5BE70D67741B339B908B04");
}

void loop()
{
}
