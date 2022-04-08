/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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

#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>

/**
 * \brief Type for the tick counter that is used for performance timing.
 */
typedef uint64_t perf_timer_t;

/**
 * \brief Initializes the timing system.
 *
 * \return Non-zero if the timing system was initialized, zero if there
 * is no usable cycle counter or high resolution timer on this system.
 * The code may need to be modified in that case.
 */
int perf_timer_init(void);

/**
 * \brief Gets the cycle counter value, or the closest analogue we can find.
 *
 * \return The timer value.
 *
 * This function should complete quickly to avoid the overhead of the
 * cycle measurement from dominating the measurements.
 */
perf_timer_t perf_timer_get_time(void);

/**
 * \brief Gets the number of ticks per second for the timer.
 *
 * \return The number of ticks per second for the values that are
 * returned by perf_timer_get_time().
 *
 * If this function returns zero, then we don't know how to measure
 * performance on this platform.  The code needs to be modified.
 */
perf_timer_t perf_timer_ticks_per_second(void);

#endif
