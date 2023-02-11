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

/* We expect a number of macros to be defined before this file
 * is included to configure the underlying ISAP variant.
 *
 * ISAP_ALG_NAME        Name of the ISAP algorithm; e.g. isap_keccak_128
 * ISAP_KEY_STATE       Type for the pre-computed key state
 * ISAP_KEY_SIZE        Size of the key in bytes.
 * ISAP_NONCE_SIZE      Size of the nonce in bytes.
 * ISAP_TAG_SIZE        Size of the authentication tag in bytes.
 * ISAP_STATE_SIZE      Size of the permutation state in bytes.
 * ISAP_RATE            Number of bytes in the rate for hashing and encryption.
 * ISAP_sH              Number of rounds for hashing.
 * ISAP_sE              Number of rounds for encryption.
 * ISAP_sB              Number of rounds for key bit absorption.
 * ISAP_sK              Number of rounds for keying.
 */
#if defined(ISAP_ALG_NAME)

#define ISAP_CONCAT_INNER(name,suffix) name##suffix
#define ISAP_CONCAT(name,suffix) ISAP_CONCAT_INNER(name,suffix)

#if defined(ASCON_BACKEND_DIRECT_XOR)

#define ISAP_ADD_BIT(state, value, bit) \
    do { \
        (state)->B[0] ^= ((value) << (bit)) & 0x80; \
    } while (0)

#elif defined(ASCON_BACKEND_SLICED32)

#define ISAP_ADD_BIT(state, value, bit) \
    do { \
        (state)->W[1] ^= (((uint32_t)(value)) << (24 + (bit))) & 0x80000000U; \
    } while (0)

#elif defined(ASCON_BACKEND_SLICED64)

#define ISAP_ADD_BIT(state, value, bit) \
    do { \
        (state)->S[0] ^= (((uint64_t)(value)) << (56 + (bit))) & 0x8000000000000000ULL; \
    } while (0)

#else

#define ISAP_ADD_BIT(state, value, bit) \
    do { \
        uint8_t absorb = (uint8_t)(((value) << (bit)) & 0x80); \
        ascon_add_bytes((state), &absorb, 0, 1); \
    } while (0)

#endif

/* IV string for initialising the associated data */
static unsigned char const ISAP_CONCAT(ISAP_ALG_NAME,_IV_A)
        [ISAP_STATE_SIZE - ISAP_NONCE_SIZE] = {
    0x01, ISAP_KEY_SIZE * 8, ISAP_RATE * 8, 1,
    ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK
};

/* IV string for authenticating associated data */
static unsigned char const ISAP_CONCAT(ISAP_ALG_NAME,_IV_KA)
        [ISAP_STATE_SIZE - ISAP_KEY_SIZE] = {
    0x02, ISAP_KEY_SIZE * 8, ISAP_RATE * 8, 1,
    ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK
};

/* IV string for encrypting payload data */
static unsigned char const ISAP_CONCAT(ISAP_ALG_NAME,_IV_KE)
        [ISAP_STATE_SIZE - ISAP_KEY_SIZE] = {
    0x03, ISAP_KEY_SIZE * 8, ISAP_RATE * 8, 1,
    ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK
};

/**
 * \brief Re-keys the ISAP permutation state.
 *
 * \param state The permutation state to be re-keyed.
 * \param pk Points to the pre-computed key information.
 * \param data Points to the data to be absorbed to perform the re-keying.
 * \param data_len Length of the data to be absorbed.
 *
 * The output key will be left in the leading bytes of \a state.
 */
static void ISAP_CONCAT(ISAP_ALG_NAME,_rekey)
    (ascon_state_t *state, const ascon_state_t *pk,
     const unsigned char *data, unsigned data_len)
{
    unsigned bit, num_bits;

    /* Initialize the state with the key and IV from "pk" */
    ascon_copy(state, pk);

    /* Absorb all of the bits of the data buffer one by one */
    num_bits = data_len * 8 - 1;
    for (bit = 0; bit < num_bits; ++bit) {
        ISAP_ADD_BIT(state, data[bit / 8], bit % 8);
        ascon_permute(state, 12 - ISAP_sB);
    }
    ISAP_ADD_BIT(state, data[bit / 8], bit % 8);
    ascon_permute(state, 12 - ISAP_sK);
}

/**
 * \brief Encrypts (or decrypts) a message payload with ISAP.
 *
 * \param state ISAP permutation state.
 * \param pk Points to the pre-computed key information.
 * \param npub Points to the 128-bit nonce for the ISAP cipher.
 * \param c Buffer to receive the output ciphertext.
 * \param m Buffer to receive the input plaintext.
 * \param mlen Length of the input plaintext.
 */
static void ISAP_CONCAT(ISAP_ALG_NAME,_encrypt)
    (ascon_state_t *state, const ISAP_KEY_STATE *pk, const unsigned char *npub,
     unsigned char *c, const unsigned char *m, size_t mlen)
{
    /* Set up the re-keyed encryption key and nonce in the state */
    ISAP_CONCAT(ISAP_ALG_NAME,_rekey)
        (state, &(pk->ke), npub, ISAP_NONCE_SIZE);
    ascon_overwrite_bytes
        (state, npub, ISAP_STATE_SIZE - ISAP_NONCE_SIZE, ISAP_NONCE_SIZE);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= ISAP_RATE) {
        ascon_permute(state, 12 - ISAP_sE);
        ascon_extract_and_add_bytes(state, m, c, 0, ISAP_RATE);
        c += ISAP_RATE;
        m += ISAP_RATE;
        mlen -= ISAP_RATE;
    }
    if (mlen > 0) {
        ascon_permute(state, 12 - ISAP_sE);
        ascon_extract_and_add_bytes(state, m, c, 0, (unsigned)mlen);
    }
}

/**
 * \brief Authenticates the associated data and ciphertext using ISAP.
 *
 * \param state ISAP permutation state.
 * \param pk Points to the pre-computed key information.
 * \param npub Points to the 128-bit nonce for the ISAP cipher.
 * \param ad Buffer containing the associated data.
 * \param adlen Length of the associated data.
 * \param c Buffer containing the ciphertext.
 * \param clen Length of the ciphertext.
 */
static void ISAP_CONCAT(ISAP_ALG_NAME,_mac)
    (ascon_state_t *state, const ISAP_KEY_STATE *pk,
     const unsigned char *npub,
     const unsigned char *ad, size_t adlen,
     const unsigned char *c, size_t clen,
     unsigned char *tag)
{
    unsigned char preserve[ISAP_STATE_SIZE - ISAP_KEY_SIZE];
#if ISAP_KEY_SIZE != ISAP_TAG_SIZE
    unsigned char k[ISAP_KEY_SIZE];
#endif
    unsigned temp;

    /* Absorb the associated data */
    ascon_overwrite_bytes(state, npub, 0, ISAP_NONCE_SIZE);
    ascon_overwrite_bytes
        (state, ISAP_CONCAT(ISAP_ALG_NAME,_IV_A), ISAP_NONCE_SIZE,
         sizeof(ISAP_CONCAT(ISAP_ALG_NAME,_IV_A)));
    ascon_permute(state, 12 - ISAP_sH);
    while (adlen >= ISAP_RATE) {
        ascon_add_bytes(state, ad, 0, ISAP_RATE);
        ascon_permute(state, 12 - ISAP_sH);
        ad += ISAP_RATE;
        adlen -= ISAP_RATE;
    }
    temp = (unsigned)adlen;
    if (temp)
        ascon_add_bytes(state, ad, 0, temp);
    ascon_pad(state, temp);
    ascon_permute(state, 12 - ISAP_sH);
    ascon_separator(state);

    /* Absorb the ciphertext */
    while (clen >= ISAP_RATE) {
        ascon_add_bytes(state, c, 0, ISAP_RATE);
        ascon_permute(state, 12 - ISAP_sH);
        c += ISAP_RATE;
        clen -= ISAP_RATE;
    }
    temp = (unsigned)clen;
    if (temp)
        ascon_add_bytes(state, c, 0, temp);
    ascon_pad(state, temp);
    ascon_permute(state, 12 - ISAP_sH);

    /* Re-key the state and generate the authentication tag */
#if ISAP_KEY_SIZE == ISAP_TAG_SIZE
    ascon_extract_bytes(state, tag, 0, ISAP_TAG_SIZE);
    ascon_extract_bytes(state, preserve, ISAP_KEY_SIZE, sizeof(preserve));
    ISAP_CONCAT(ISAP_ALG_NAME,_rekey)
        (state, &(pk->ka), tag, ISAP_TAG_SIZE);
#else
    ascon_extract_bytes(state, k, 0, ISAP_KEY_SIZE);
    ascon_extract_bytes(state, preserve, ISAP_KEY_SIZE, sizeof(preserve));
    ISAP_CONCAT(ISAP_ALG_NAME,_rekey)
        (state, &(pk->ka), k, ISAP_KEY_SIZE);
#endif
    ascon_overwrite_bytes(state, preserve, ISAP_KEY_SIZE, sizeof(preserve));
    ascon_permute(state, 12 - ISAP_sH);
    ascon_extract_bytes(state, tag, 0, ISAP_TAG_SIZE);
    ascon_clean(preserve, sizeof(preserve));
#if ISAP_KEY_SIZE != ISAP_TAG_SIZE
    ascon_clean(k, sizeof(k));
#endif
}

void ISAP_CONCAT(ISAP_ALG_NAME,_aead_init)
    (ISAP_KEY_STATE *pk, const unsigned char *k)
{
    /* Expand the encryption key */
    ascon_init(&(pk->ke));
    ascon_overwrite_bytes(&(pk->ke), k, 0, ISAP_KEY_SIZE);
    ascon_overwrite_bytes
        (&(pk->ke), ISAP_CONCAT(ISAP_ALG_NAME,_IV_KE), ISAP_KEY_SIZE,
         sizeof(ISAP_CONCAT(ISAP_ALG_NAME,_IV_KE)));
    ascon_permute(&(pk->ke), 12 - ISAP_sK);
    ascon_release(&(pk->ke));

    /* Expand the authentication key */
    ascon_init(&(pk->ka));
    ascon_overwrite_bytes(&(pk->ka), k, 0, ISAP_KEY_SIZE);
    ascon_overwrite_bytes
        (&(pk->ka), ISAP_CONCAT(ISAP_ALG_NAME,_IV_KA), ISAP_KEY_SIZE,
         sizeof(ISAP_CONCAT(ISAP_ALG_NAME,_IV_KA)));
    ascon_permute(&(pk->ka), 12 - ISAP_sK);
    ascon_release(&(pk->ka));
}

void ISAP_CONCAT(ISAP_ALG_NAME,_aead_load_key)
    (ISAP_KEY_STATE *pk,
     const unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE])
{
    /* Load the ke and ka values directly into the permutation states */
    ascon_init(&(pk->ke));
    ascon_overwrite_bytes(&(pk->ke), k, 0, ISAP_STATE_SIZE);
    ascon_release(&(pk->ke));
    ascon_init(&(pk->ka));
    ascon_overwrite_bytes(&(pk->ka), k + ISAP_STATE_SIZE, 0, ISAP_STATE_SIZE);
    ascon_release(&(pk->ka));
}

void ISAP_CONCAT(ISAP_ALG_NAME,_aead_save_key)
    (ISAP_KEY_STATE *pk,
     unsigned char k[ASCON_ISAP_SAVED_KEY_SIZE])
{
    /* Extract the ASCON state for ke and ka into the buffer */
    ascon_acquire(&(pk->ke));
    ascon_extract_bytes(&(pk->ke), k, 0, ISAP_STATE_SIZE);
    ascon_release(&(pk->ke));
    ascon_acquire(&(pk->ka));
    ascon_extract_bytes(&(pk->ka), k + ISAP_STATE_SIZE, 0, ISAP_STATE_SIZE);
    ascon_release(&(pk->ka));
}

void ISAP_CONCAT(ISAP_ALG_NAME,_aead_free)(ISAP_KEY_STATE *pk)
{
    if (pk) {
        ascon_acquire(&(pk->ke));
        ascon_free(&(pk->ke));
        ascon_acquire(&(pk->ka));
        ascon_free(&(pk->ka));
    }
}

void ISAP_CONCAT(ISAP_ALG_NAME,_aead_encrypt)
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ISAP_KEY_STATE *pk)
{
    ascon_state_t state;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ISAP_TAG_SIZE;

    /* Encrypt the plaintext to produce the ciphertext */
    ascon_init(&state);
    ISAP_CONCAT(ISAP_ALG_NAME,_encrypt)(&state, pk, npub, c, m, mlen);

    /* Authenticate the associated data and ciphertext to generate the tag */
    ISAP_CONCAT(ISAP_ALG_NAME,_mac)
        (&state, pk, npub, ad, adlen, c, mlen, c + mlen);
    ascon_free(&state);
}

int ISAP_CONCAT(ISAP_ALG_NAME,_aead_decrypt)
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const ISAP_KEY_STATE *pk)
{
    ascon_state_t state;
    unsigned char tag[ISAP_TAG_SIZE];
    int result;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ISAP_TAG_SIZE)
        return -1;
    *mlen = clen - ISAP_TAG_SIZE;

    /* Authenticate the associated data and ciphertext to generate the tag */
    ascon_init(&state);
    ISAP_CONCAT(ISAP_ALG_NAME,_mac)
        (&state, pk, npub, ad, adlen, c, *mlen, tag);

    /* Decrypt the ciphertext to produce the plaintext */
    ISAP_CONCAT(ISAP_ALG_NAME,_encrypt)(&state, pk, npub, m, c, *mlen);

    /* Check the authentication tag */
    result = ascon_aead_check_tag(m, *mlen, tag, c + *mlen, ISAP_TAG_SIZE);
    ascon_clean(tag, sizeof(tag));
    ascon_free(&state);
    return result;
}

#endif /* ISAP_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the ISAP algorithm */
#undef ISAP_ALG_NAME
#undef ISAP_KEY_STATE
#undef ISAP_KEY_SIZE
#undef ISAP_NONCE_SIZE
#undef ISAP_TAG_SIZE
#undef ISAP_RATE
#undef ISAP_sH
#undef ISAP_sE
#undef ISAP_sB
#undef ISAP_sK
#undef ISAP_STATE_SIZE
#undef ISAP_CONCAT_INNER
#undef ISAP_CONCAT
#undef ISAP_ADD_BIT
