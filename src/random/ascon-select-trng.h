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

#ifndef ASCON_SELECT_TRNG_H
#define ASCON_SELECT_TRNG_H

#if defined(_WIN32) || defined(__WIN32__) || defined(_WIN64) || \
    defined(__CYGWIN__) || defined(__CYGWIN32__)

/* Use the Windows CryptGenRandom() function */
#define ASCON_TRNG_WINDOWS 1
#define ASCON_TRNG_MIXER 1

#elif defined(__linux__) || defined(__APPLE__) || defined(__MACH__) || \
      defined(__FreeBSD__) || defined(__unix__) || defined(__ANDROID__) || \
      defined(__OpenBSD__)

/* Unix-like system with access to a /dev/urandom or /dev/random device */
#define ASCON_TRNG_DEV_RANDOM 1
#define ASCON_TRNG_MIXER 1

#elif defined(USE_HAL_DRIVER)

/* STM32 platform with HAL libraries.  Detecting the TRNG is complicated. */
#include "ascon-trng-stm32.h"

#elif defined(__arm__) && defined(__SAM3X8E__) && defined(ARDUINO)

/* TRNG on the Arduino Due */
#define ASCON_TRNG_DUE 1

#elif defined(ESP8266) || defined(ESP32)

/* TRNG on ESP8266 and ESP32 modules */
#define ASCON_TRNG_ESP 1

#else

/* No idea how to generate random numbers on this device yet */
#define ASCON_TRNG_NONE 1
#define ASCON_TRNG_MIXER 1

#endif

#endif
