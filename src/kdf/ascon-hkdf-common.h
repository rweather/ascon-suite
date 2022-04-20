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

/*
 * The contents of this header file expand out to the full implementation of
 * HKDF for a specific underlying hash algorithm.  We expect a number of
 * macros to be defined before this file is included to configure the
 * underlying HKDF variant:
 *
 * HKDF_ALG_NAME        Name of the HKDF algorithm; e.g. ascon_hkdf
 * HKDF_STATE           Type for the HKDF state; e.g. ascon_khdf_state_t
 * HKDF_HMAC_SIZE       Size of the output for the HMAC algorithm.
 * HKDF_HMAC_STATE      Type for the HMAC state; e.g. ascon_hmac_state_t
 * HKDF_HMAC_INIT       Name of the HMAC initialization function.
 * HKDF_HMAC_UPDATE     Name of the HMAC update function.
 * HKDF_HMAC_FINALIZE   Name of the HMAC finalization function.
 */
#if defined(HKDF_ALG_NAME)

#define HKDF_CONCAT_INNER(name,suffix) name##suffix
#define HKDF_CONCAT(name,suffix) HKDF_CONCAT_INNER(name,suffix)

int HKDF_ALG_NAME
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen)
{
    HKDF_STATE state;
    if (outlen > (size_t)(HKDF_HMAC_SIZE * 255))
        return -1;
    HKDF_CONCAT(HKDF_ALG_NAME,_extract)(&state, key, keylen, salt, saltlen);
    HKDF_CONCAT(HKDF_ALG_NAME,_expand)(&state, info, infolen, out, outlen);
    ascon_clean(&state, sizeof(state));
    return 0;
}

void HKDF_CONCAT(HKDF_ALG_NAME,_extract)
    (HKDF_STATE *state,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen)
{
    HKDF_HMAC_STATE hmac;
    HKDF_HMAC_INIT(&hmac, salt, saltlen);
    HKDF_HMAC_UPDATE(&hmac, key, keylen);
    HKDF_HMAC_FINALIZE(&hmac, salt, saltlen, state->prk);
    state->counter = 1;
    state->posn = HKDF_HMAC_SIZE;
    ascon_clean(&hmac, sizeof(hmac));
}

int HKDF_CONCAT(HKDF_ALG_NAME,_expand)
    (HKDF_STATE *state,
     const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen)
{
    HKDF_HMAC_STATE hmac;
    size_t len;

    /* Deal with left-over data from the last output block */
    len = HKDF_HMAC_SIZE - state->posn;
    if (len > outlen)
        len = outlen;
    memcpy(out, state->out + state->posn, len);
    out += len;
    outlen -= len;
    state->posn += len;

    /* Squeeze out the data one block at a time */
    while (outlen > 0) {
        /* Have we squeezed out too many blocks already? */
        if (state->counter == 0) {
            memset(out, 0, outlen); /* Zero the rest of the output data */
            ascon_clean(&hmac, sizeof(hmac));
            return -1;
        }

        /* Squeeze out the next block of data */
        HKDF_HMAC_INIT(&hmac, state->prk, sizeof(state->prk));
        if (state->counter != 1)
            HKDF_HMAC_UPDATE(&hmac, state->out, sizeof(state->out));
        HKDF_HMAC_UPDATE(&hmac, info, infolen);
        HKDF_HMAC_UPDATE(&hmac, &(state->counter), 1);
        HKDF_HMAC_FINALIZE(&hmac, state->prk, sizeof(state->prk), state->out);
        ++(state->counter);

        /* Copy the data to the output buffer */
        len = HKDF_HMAC_SIZE;
        if (len > outlen)
            len = outlen;
        memcpy(out, state->out, len);
        state->posn = len;
        out += len;
        outlen -= len;
    }
    ascon_clean(&hmac, sizeof(hmac));
    return 0;
}

void HKDF_CONCAT(HKDF_ALG_NAME,_free)(HKDF_STATE *state)
{
    ascon_clean(state, sizeof(HKDF_STATE));
}

#endif /* HKDF_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the HKDF algorithm */
#undef HKDF_ALG_NAME
#undef HKDF_STATE
#undef HKDF_HMAC_SIZE
#undef HKDF_HMAC_STATE
#undef HKDF_HMAC_INIT
#undef HKDF_HMAC_UPDATE
#undef HKDF_HMAC_FINALIZE
