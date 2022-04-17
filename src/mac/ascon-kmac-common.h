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
 * KMAC for a specific underlying XOF algorithm.  We expect a number of
 * macros to be defined before this file is included to configure the
 * underlying KMAC variant:
 *
 * KMAC_ALG_NAME        Name of the KMAC algorithm; e.g. ascon_hmac
 * KMAC_SIZE            Size of the default KMAC output.
 * KMAC_STATE           Type for the KMAC state; e.g. ascon_hmac_state_t
 * KMAC_RATE            Rate for the underlying permutation for padding.
 * KMAC_XOF_INIT        Name of the XOF initialization function.
 * KMAC_XOF_PREINIT     Name of the XOF precomputed initialization function.
 * KMAC_XOF_FREE        Name of the XOF state free function.
 * KMAC_XOF_ABSORB      Name of the XOF absorb function.
 * KMAC_XOF_SQUEEZE     Name of the XOF squeeze function.
 * KMAC_XOF_PAD         Name of the XOF function to zero-pad to a
 *                      multiple of the rate block size.
 * KMAC_XOF_IS_ABSORBING(state) Checks to see if the underlying XOF state
 *                      is still in absorbing mode.
 */
#if defined(KMAC_ALG_NAME)

#define KMAC_CONCAT_INNER(name,suffix) name##suffix
#define KMAC_CONCAT(name,suffix) KMAC_CONCAT_INNER(name,suffix)

void KMAC_ALG_NAME
    (const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen,
     const unsigned char *custom, size_t customlen,
     unsigned char *out, size_t outlen)
{
    KMAC_STATE state;
    KMAC_CONCAT(KMAC_ALG_NAME,_init)(&state, key, keylen, custom, customlen);
    KMAC_XOF_ABSORB(&(state.xof), in, inlen);
    KMAC_CONCAT(KMAC_ALG_NAME,_set_output_length)(&state, outlen);
    KMAC_XOF_SQUEEZE(&(state.xof), out, outlen);
    KMAC_CONCAT(KMAC_ALG_NAME,_free)(&state);
}

/**
 * \brief Encodes a string bit length according to NIST SP 800-185.
 *
 * \param buf Buffer to receive the encoded length.
 * \param value Length in bytes to be encoded.
 *
 * \return The number of bytes that were written to \a buf.
 */
static size_t KMAC_CONCAT(KMAC_ALG_NAME,_encode_length)
    (unsigned char buf[sizeof(size_t) + 1], size_t value)
{
    uint64_t val = value * 8ULL;
    if (value) {
        uint64_t temp = val;
        size_t size = 0;
        size_t posn;
        while (temp != 0) {
            ++size;
            temp >>= 8;
        }
        buf[0] = (unsigned char)size;
        for (posn = 1; posn <= size; ++posn)
            buf[posn] = (unsigned char)(val >> ((size - posn) * 8));
        return size + 1;
    } else {
        buf[0] = 0x01;
        buf[1] = 0x00;
        return 2;
    }
}

void KMAC_CONCAT(KMAC_ALG_NAME,_init)
    (KMAC_STATE *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen)
{
    unsigned char buf[sizeof(uint64_t) + 1];
    size_t len;

    /* Rate declaration as a prefix-encoded length value, followed by the
     * function name, which is the length-prefixed string "KMAC" */
    static unsigned char const kmac_prefix[] = {
        0x01, KMAC_RATE
#if !defined(KMAC_XOF_PREINIT)
        , 0x01, 0x20, 0x4B, 0x4D, 0x41, 0x43
#endif
    };

    /* Initialize the XOF state and absorb the prefix.  If we have a
     * precompute function, then use it to shortcut the process. */
#if defined(KMAC_XOF_PREINIT)
    KMAC_XOF_PREINIT(&(state->xof));
#else
    KMAC_XOF_INIT(&(state->xof));
    KMAC_XOF_ABSORB(&(state->xof), kmac_prefix, sizeof(kmac_prefix));
#endif

    /* Absorb the customization string and pad */
    len = KMAC_CONCAT(KMAC_ALG_NAME,_encode_length)(buf, customlen);
    KMAC_XOF_ABSORB(&(state->xof), buf, len);
    KMAC_XOF_ABSORB(&(state->xof), custom, customlen);
    KMAC_XOF_PAD(&(state->xof));

    /* Absorb the key and pad */
    KMAC_XOF_ABSORB(&(state->xof), kmac_prefix, 2); /* Just the rate prefix */
    len = KMAC_CONCAT(KMAC_ALG_NAME,_encode_length)(buf, keylen);
    KMAC_XOF_ABSORB(&(state->xof), buf, len);
    KMAC_XOF_ABSORB(&(state->xof), key, keylen);
    KMAC_XOF_PAD(&(state->xof));
}

void KMAC_CONCAT(KMAC_ALG_NAME,_reinit)
    (KMAC_STATE *state, const unsigned char *key, size_t keylen,
     const unsigned char *custom, size_t customlen)
{
    KMAC_CONCAT(KMAC_ALG_NAME,_free)(state);
    KMAC_CONCAT(KMAC_ALG_NAME,_init)(state, key, keylen, custom, customlen);
}

void KMAC_CONCAT(KMAC_ALG_NAME,_free)(KMAC_STATE *state)
{
    if (state)
        KMAC_XOF_FREE(&(state->xof));
}

void KMAC_CONCAT(KMAC_ALG_NAME,_absorb)
    (KMAC_STATE *state, const unsigned char *in, size_t inlen)
{
    KMAC_XOF_ABSORB(&(state->xof), in, inlen);
}

/**
 * \brief Encodes a string bit length according to NIST SP 800-185
 * using the right-encoded form.
 *
 * \param state Points to the XOF state to absorb the length into.
 * \param outlen Desired output length in bytes.
 */
static void KMAC_CONCAT(KMAC_ALG_NAME,_encode_output_length)
    (KMAC_STATE *state, size_t outlen)
{
    /* Similar to encode_length() but the length prefix is now a suffix */
    unsigned char buf[sizeof(uint64_t) + 1];
    size_t len = KMAC_CONCAT(KMAC_ALG_NAME,_encode_length)(buf, outlen);
    KMAC_XOF_ABSORB(&(state->xof), buf + 1, len - 1);
    KMAC_XOF_ABSORB(&(state->xof), buf, 1);
}

void KMAC_CONCAT(KMAC_ALG_NAME,_set_output_length)
    (KMAC_STATE *state, size_t outlen)
{
    if (KMAC_XOF_IS_ABSORBING(&(state->xof))) {
        /* Encode the desired output length and absorb it into the input */
        KMAC_CONCAT(KMAC_ALG_NAME,_encode_output_length)(state, outlen);

        /* Switch the underlying XOF state into squeezing mode */
        KMAC_XOF_SQUEEZE(&(state->xof), 0, 0);
    }
}

void KMAC_CONCAT(KMAC_ALG_NAME,_squeeze)
    (KMAC_STATE *state, unsigned char *out, size_t outlen)
{
    if (KMAC_XOF_IS_ABSORBING(&(state->xof))) {
        /* We are still in the absorb phase, so set the desired
         * output length to arbitrary */
        KMAC_CONCAT(KMAC_ALG_NAME,_encode_output_length)(state, 0);
    }
    KMAC_XOF_SQUEEZE(&(state->xof), out, outlen);
}

void KMAC_CONCAT(KMAC_ALG_NAME,_finalize)
    (KMAC_STATE *state, unsigned char out[KMAC_SIZE])
{
    if (KMAC_XOF_IS_ABSORBING(&(state->xof))) {
        /* We are still in the absorb phase, so set the desired
         * output length now */
        KMAC_CONCAT(KMAC_ALG_NAME,_encode_output_length)(state, KMAC_SIZE);
    }
    KMAC_XOF_SQUEEZE(&(state->xof), out, KMAC_SIZE);
}

#endif /* KMAC_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the KMAC algorithm */
#undef KMAC_ALG_NAME
#undef KMAC_SIZE
#undef KMAC_STATE
#undef KMAC_RATE
#undef KMAC_XOF_INIT
#undef KMAC_XOF_PREINIT
#undef KMAC_XOF_ABSORB
#undef KMAC_XOF_SQUEEZE
#undef KMAC_XOF_PAD
#undef KMAC_XOF_IS_ABSORBING
#undef KMAC_CONCAT_INNER
#undef KMAC_CONCAT
