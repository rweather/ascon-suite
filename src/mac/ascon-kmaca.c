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

#include <ascon/kmac.h>
#include <ascon/utility.h>
#include <string.h>

/**
 * \brief Intializes a ASCON-KMACA context with the prefix pre-computed.
 *
 * \param state Points to the KMAC state to initialize.
 */
static void ascon_kmaca_init_precomputed(ascon_kmac_state_t *state)
{
    static unsigned char const kmac_iv[40] = {
        0xcd, 0xec, 0xd0, 0x06, 0x9c, 0xdd, 0x34, 0x6d,
        0x85, 0x05, 0x91, 0xbd, 0x8b, 0xec, 0x55, 0xce,
        0x7e, 0x37, 0xb5, 0x5f, 0xd2, 0xed, 0x0f, 0x93,
        0x3a, 0xbf, 0xa5, 0x65, 0x20, 0xf6, 0x27, 0xf9,
        0x3b, 0xdc, 0xaa, 0x5c, 0x4b, 0x50, 0x7b, 0x82
    };
    ascon_init(&(state->state));
    ascon_overwrite_bytes(&(state->state), kmac_iv, 0, sizeof(kmac_iv));
    ascon_release(&(state->state));
    state->count = 0;
    state->mode = 0;
}

/* The actual implementation is in the "ascon-kmac-common.h" file */

/* ASCON-XOFA */
#define KMAC_ALG_NAME ascon_kmaca
#define KMAC_SIZE ASCON_KMAC_SIZE
#define KMAC_STATE ascon_kmac_state_t
#define KMAC_RATE ASCON_XOF_RATE
#define KMAC_XOF_INIT ascon_xofa_init
#define KMAC_XOF_PREINIT ascon_kmaca_init_precomputed
#define KMAC_XOF_FREE ascon_xofa_free
#define KMAC_XOF_ABSORB ascon_xofa_absorb
#define KMAC_XOF_SQUEEZE ascon_xofa_squeeze
#define KMAC_XOF_PAD ascon_xofa_pad
#define KMAC_XOF_IS_ABSORBING(state) ((state)->mode == 0)
#include "mac/ascon-kmac-common.h"
