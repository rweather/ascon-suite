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

#ifndef ASCON_MASKED_CONFIG_H
#define ASCON_MASKED_CONFIG_H

/**
 * \file ascon-masked-config.h
 * \brief Configures the number of shares to use for masked AEAD modes.
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \def ASCON_MASKED_MAX_SHARES
 * \brief Maximum number of shares to use in the library.
 *
 * This will clamp ASCON_MASKED_KEY_SHARES and ASCON_MASKED_DATA_SHARES.
 */

/**
 * \def ASCON_MASKED_KEY_SHARES
 * \brief Number of shares to use for key material, between 2 and 4
 * with the default being 4.
 */

/**
 * \def ASCON_MASKED_DATA_SHARES
 * \brief Number of shares to use for plaintext data and associated data,
 * between 1 and ASCON_MASKED_KEY_SHARES.  Default is 2.
 */

/* Set the defaults if not selected in the build configuration */
#ifndef ASCON_MASKED_MAX_SHARES
#define ASCON_MASKED_MAX_SHARES 4
#endif
#ifndef ASCON_MASKED_KEY_SHARES
#define ASCON_MASKED_KEY_SHARES 4
#endif
#ifndef ASCON_MASKED_DATA_SHARES
#define ASCON_MASKED_DATA_SHARES 2
#endif

/* AVR is limited to no more than 3 shares at present */
#if defined(__AVR__) && ASCON_MASKED_MAX_SHARES > 3
#undef ASCON_MASKED_MAX_SHARES
#define ASCON_MASKED_MAX_SHARES 3
#endif

/* Check that the values are in the correct range */
#if ASCON_MASKED_KEY_SHARES < 2 || ASCON_MASKED_KEY_SHARES > 4
#error "ASCON_MASKED_KEY_SHARES must be between 2 and 4"
#endif
#if ASCON_MASKED_DATA_SHARES < 1 || ASCON_MASKED_DATA_SHARES > ASCON_MASKED_KEY_SHARES
#error "ASCON_MASKED_DATA_SHARES must be between 1 and ASCON_MASKED_KEY_SHARES"
#endif

/* Clamp the number of key and data shares to no more than
 * ASCON_MASKED_MAX_SHARES */
#if ASCON_MASKED_KEY_SHARES > ASCON_MASKED_MAX_SHARES
#undef ASCON_MASKED_KEY_SHARES
#define ASCON_MASKED_KEY_SHARES ASCON_MASKED_MAX_SHARES
#endif
#if ASCON_MASKED_DATA_SHARES > ASCON_MASKED_MAX_SHARES
#undef ASCON_MASKED_DATA_SHARES
#define ASCON_MASKED_DATA_SHARES ASCON_MASKED_MAX_SHARES
#endif

#ifdef __cplusplus
}
#endif

#endif
