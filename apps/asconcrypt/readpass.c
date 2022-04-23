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

#include "readpass.h"
#include <ascon/utility.h>
#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#if defined(HAVE_GETPASS)
#include <unistd.h>
#endif
#include <string.h>

int read_password(const char *prompt, char *password, size_t len)
{
#if defined(HAVE_GETPASS)
    char *pwd = getpass(prompt);
    size_t plen, plen2;
    if (!pwd)
        return 0;
    plen = strlen(pwd);
    if (plen >= len)
        plen2 = len - 1;
    else
        plen2 = plen;
    memcpy(password, pwd, plen2);
    password[plen2] = '\0';
    ascon_clean(pwd, plen);
    return 1;
#else
    (void)prompt;
    (void)password;
    (void)len;
    return 0;
#endif
}
