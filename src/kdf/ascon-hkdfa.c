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

#include <ascon/hkdf.h>
#include <ascon/hmac.h>
#include <ascon/utility.h>
#include "core/ascon-util.h"
#include <string.h>

/* The actual implementation is in the "ascon-hkdf-common.h" file */

/* ASCON-HKDFA */
#define HKDF_ALG_NAME ascon_hkdfa
#define HKDF_STATE ascon_hkdfa_state_t
#define HKDF_HMAC_SIZE ASCON_HMACA_SIZE
#define HKDF_HMAC_STATE ascon_hmaca_state_t
#define HKDF_HMAC_INIT ascon_hmaca_init
#define HKDF_HMAC_UPDATE ascon_hmaca_update
#define HKDF_HMAC_FINALIZE ascon_hmaca_finalize
#include "kdf/ascon-hkdf-common.h"
