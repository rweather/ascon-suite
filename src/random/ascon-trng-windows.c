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

#include "ascon-trng.h"
#include "core/ascon-select-backend.h"
#include <string.h>

#if defined(ASCON_TRNG_WINDOWS)

#include <windows.h>
#include <wincrypt.h>

/* Microsoft documentation recommends using RtlGenRandom() rather
 * than CryptGenRandom() as it is more efficient than creating a
 * cryptography service provider.  But it is harder to access as
 * there is no import library.  Fix this later to dynamically load
 * "Advapi32.dll" and resolve the entry point for RtlGenRandom(). */

int ascon_trng_generate(unsigned char *out, size_t outlen)
{
    HCRYPTPROV provider = 0;
    int ok = 0;
    if (CryptAcquireContextW
            (&provider, 0, 0, PROV_RSA_FULL,
             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        if (CryptGenRandom(provider, outlen, out))
            ok = 1;
        CryptReleaseContext(provider, 0);
    }
    if (!ok) {
        /* Could not open the provider or it didn't work; this is a problem! */
        memset(out, 0, outlen);
    }
    return ok;
}

#endif /* ASCON_TRNG_WINDOWS */
