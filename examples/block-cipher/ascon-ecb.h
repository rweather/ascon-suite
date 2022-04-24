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

#ifndef ASCON_ECB_H
#define ASCON_ECB_H

/**
 * \file ascon-ecb.h
 * \brief ASCON permutation operated as a tweakable block cipher in ECB mode.
 *
 * See \ref blockcipher "Building a block cipher with the ASCON permutation"
 * for further details.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for ASCON-ECB.
 */
#define ASCON_ECB_KEY_SIZE 16

/**
 * \brief Size of the tweak for ASCON-ECB.
 */
#define ASCON_ECB_TWEAK_SIZE 12

/**
 * \brief Size of the round constant for ASCON-ECB.
 */
#define ASCON_ECB_RC_SIZE 4

/**
 * \brief Size of the block for ASCON-ECB.
 */
#define ASCON_ECB_BLOCK_SIZE 16

/**
 * \brief Number of rounds for ASCON-ECB, between 4 and 64.
 */
#define ASCON_ECB_ROUNDS 10

/**
 * \brief Key schedule for ASCON-ECB.
 */
typedef struct
{
    /** Expanded keys for all of the rounds */
    unsigned char k[ASCON_ECB_ROUNDS][ASCON_ECB_KEY_SIZE];

} ascon_ecb_key_schedule_t;

/**
 * \brief Initializes a key schedule for ASCON-ECB.
 *
 * \param ks Points to the key schedule to be initialized.
 * \param k Points to the 16 bytes of the key.
 */
void ascon_ecb_init(ascon_ecb_key_schedule_t *ks, const unsigned char *k);

/**
 * \brief Frees an ASCON-ECB key schedule and destroys any sensitve material.
 *
 * \param ks Points to the key schedule to free.
 */
void ascon_ecb_free(ascon_ecb_key_schedule_t *ks);

/**
 * \brief Encrypts a block with ASCON-ECB.
 *
 * \param ks Points to the key schedule for ASCON-ECB.
 * \param tweak Points to the 12 bytes of the tweak.  May be NULL to use an
 * all-zereos tweak value.
 * \param c Points to the 16 byte buffer to receive the output ciphertest.
 * \param m Points to the 16 byte buffer that contains the input plaintext.
 */
void ascon_ecb_encrypt
    (ascon_ecb_key_schedule_t *ks, const unsigned char *tweak,
     unsigned char *c, const unsigned char *m);

/**
 * \brief Decrypts a block with ASCON-ECB.
 *
 * \param ks Points to the key schedule for ASCON-ECB.
 * \param tweak Points to the 12 bytes of the tweak.  May be NULL to use an
 * all-zereos tweak value.
 * \param m Points to the 16 byte buffer to receive the output plaintext.
 * \param c Points to the 16 byte buffer that contains the input ciphertext.
 */
void ascon_ecb_decrypt
    (ascon_ecb_key_schedule_t *ks, const unsigned char *tweak,
     unsigned char *m, const unsigned char *c);

#ifdef __cplusplus
}
#endif

#endif
