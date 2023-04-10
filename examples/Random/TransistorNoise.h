/*
 * Copyright (C) 2015 Southern Storm Software, Pty Ltd.
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

#ifndef TRANSISTORNOISE_H
#define TRANSISTORNOISE_H

#include <stdint.h>
#include <ascon/random.h>

class TransistorNoise
{
public:
    explicit TransistorNoise(uint8_t pin);
    ~TransistorNoise();

    bool calibrating() const;

    void stir(ascon_random_state_t *prng);

    bool haveCredits(size_t size);

private:
    int threshold;
    uint8_t _pin;
    uint8_t prevBit;
    uint8_t posn;
    uint8_t bitNum;
    uint8_t calState;
    uint8_t buffer[32];
    int minValue;
    int maxValue;
    int count;
    int ones;
    size_t credits;

    void restart();
};

#endif
