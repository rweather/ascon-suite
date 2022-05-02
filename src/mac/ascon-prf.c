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

#include <ascon/prf.h>
#include <ascon/utility.h>
#include "core/ascon-util-snp.h"
#include "aead/ascon-aead-common.h"

/**
 * \brief Rate of absorption for input blocks.
 */
#define ASCON_PRF_RATE_IN 32

/**
 * \brief Rate of squeezing for output blocks.
 */
#define ASCON_PRF_RATE_OUT 16

void ascon_prf
    (unsigned char *out, size_t outlen,
     const unsigned char *in, size_t inlen,
     const unsigned char *key)
{
    ascon_prf_state_t state;
    ascon_prf_fixed_init(&state, key, 0);
    ascon_prf_absorb(&state, in, inlen);
    ascon_prf_squeeze(&state, out, outlen);
    ascon_prf_free(&state);
}

void ascon_prf_fixed
    (unsigned char *out, size_t outlen,
     const unsigned char *in, size_t inlen,
     const unsigned char *key)
{
    ascon_prf_state_t state;
    ascon_prf_fixed_init(&state, key, outlen);
    ascon_prf_absorb(&state, in, inlen);
    ascon_prf_squeeze(&state, out, outlen);
    ascon_prf_free(&state);
}

int ascon_prf_short
    (unsigned char *out, size_t outlen,
     const unsigned char *in, size_t inlen,
     const unsigned char *key)
{
    ascon_state_t state;
    unsigned char iv[8] = {0x80, 0x00, 0x4c, 0x80, 0x00, 0x00, 0x00, 0x00};
    if (inlen > ASCON_PRF_SHORT_MAX_INPUT_SIZE)
        return -1;
    if (outlen > ASCON_PRF_SHORT_MAX_OUTPUT_SIZE)
        return -1;
    iv[1] = (unsigned char)(inlen * 8U);
    ascon_init(&state);
    ascon_overwrite_bytes(&state, iv, 0, 8);
    ascon_overwrite_bytes(&state, key, 8, ASCON_PRF_SHORT_KEY_SIZE);
    ascon_overwrite_bytes(&state, in, 24, inlen);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, key, 24);
    ascon_squeeze_partial(&state, out, 24, outlen);
    ascon_free(&state);
    return 0;
}

void ascon_mac
    (unsigned char *tag,
     const unsigned char *in, size_t inlen,
     const unsigned char *key)
{
    ascon_prf_state_t state;
    ascon_prf_fixed_init(&state, key, ASCON_MAC_TAG_SIZE);
    ascon_prf_absorb(&state, in, inlen);
    ascon_prf_squeeze(&state, tag, ASCON_MAC_TAG_SIZE);
    ascon_prf_free(&state);
}

int ascon_mac_verify
    (const unsigned char *tag,
     const unsigned char *in, size_t inlen,
     const unsigned char *key)
{
    unsigned char tag2[ASCON_MAC_TAG_SIZE];
    int result;
    ascon_mac(tag2, in, inlen, key);
    result = ascon_aead_check_tag(0, 0, tag, tag2, sizeof(tag2));
    ascon_clean(tag2, sizeof(tag2));
    return result;
}

void ascon_prf_init(ascon_prf_state_t *state, const unsigned char *key)
{
    ascon_prf_fixed_init(state, key, 0);
}

void ascon_prf_fixed_init
    (ascon_prf_state_t *state, const unsigned char *key, size_t outlen)
{
    unsigned char iv[8] = {0x80, 0x80, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x00};
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    if (outlen >= (((size_t)1) << 29))
        outlen = 0; /* Too large, so switch to arbitrary-length output */
#endif
    be_store_word32(iv + 4, (uint32_t)(outlen * 8U));
    ascon_init(&(state->state));
    ascon_overwrite_bytes(&(state->state), iv, 0, 8);
    ascon_overwrite_bytes(&(state->state), key, 8, ASCON_PRF_KEY_SIZE);
    ascon_permute(&(state->state), 0);
    ascon_release(&(state->state));
    state->count = 0;
    state->mode = 0;
}

void ascon_prf_reinit(ascon_prf_state_t *state, const unsigned char *key)
{
    ascon_prf_free(state);
    ascon_prf_fixed_init(state, key, 0);
}

void ascon_prf_fixed_reinit
    (ascon_prf_state_t *state, const unsigned char *key, size_t outlen)
{
    ascon_prf_free(state);
    ascon_prf_fixed_init(state, key, outlen);
}

void ascon_prf_free(ascon_prf_state_t *state)
{
    if (state) {
        ascon_acquire(&(state->state));
        ascon_free(&(state->state));
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_prf_absorb
    (ascon_prf_state_t *state, const unsigned char *in, size_t inlen)
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    ascon_acquire(&(state->state));

    /* If we were squeezing output, then go back to the absorb phase */
    if (state->mode) {
        state->mode = 0;
        state->count = 0;
        ascon_permute(&(state->state), 0);
    }

    /* Handle the partial left-over block from last time */
    if (state->count) {
        temp = ASCON_PRF_RATE_IN - state->count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            ascon_absorb_partial(&(state->state), in, state->count, temp);
            state->count += temp;
            ascon_release(&(state->state));
            return;
        }
        ascon_absorb_partial(&(state->state), in, state->count, temp);
        state->count = 0;
        in += temp;
        inlen -= temp;
        ascon_permute(&(state->state), 0);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ASCON_PRF_RATE_IN) {
        ascon_absorb_16(&(state->state), in, 0);
        ascon_absorb_16(&(state->state), in + 16, 16);
        in += ASCON_PRF_RATE_IN;
        inlen -= ASCON_PRF_RATE_IN;
        ascon_permute(&(state->state), 0);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    if (temp > 0)
        ascon_absorb_partial(&(state->state), in, 0, temp);
    state->count = temp;

    /* Release access to the shared hardware */
    ascon_release(&(state->state));
}

void ascon_prf_squeeze
    (ascon_prf_state_t *state, unsigned char *out, size_t outlen)
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    ascon_acquire(&(state->state));

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->mode) {
        ascon_pad(&(state->state), state->count);
        ascon_separator(&(state->state));
        state->count = 0;
        state->mode = 1;
    }

    /* Handle left-over partial blocks from last time */
    if (state->count) {
        temp = ASCON_PRF_RATE_OUT - state->count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            ascon_squeeze_partial(&(state->state), out, state->count, temp);
            state->count += temp;
            ascon_release(&(state->state));
            return;
        }
        ascon_squeeze_partial(&(state->state), out, state->count, temp);
        out += temp;
        outlen -= temp;
        state->count = 0;
    }

    /* Handle full blocks */
    while (outlen >= ASCON_PRF_RATE_OUT) {
        ascon_permute(&(state->state), 0);
        ascon_squeeze_16(&(state->state), out, 0);
        out += ASCON_PRF_RATE_OUT;
        outlen -= ASCON_PRF_RATE_OUT;
    }

    /* Handle the left-over block */
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_permute(&(state->state), 0);
        ascon_squeeze_partial(&(state->state), out, 0, temp);
        state->count = temp;
    }

    /* Release access to the shared hardware */
    ascon_release(&(state->state));
}
