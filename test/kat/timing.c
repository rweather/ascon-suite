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

#include "timing.h"
#include <time.h>

/* Timers that we currently know about */
#define PERF_TIMER_UNKNOWN 0
#define PERF_TIMER_CLOCK_GETTIME 1

/*
 * Detect the timer implementation to use.
 *
 * We prefer to use the high-resolution CLOCK_THREAD_CPUTIME_ID or
 * CLOCK_PROCESS_CPUTIME_ID timers because the kernel will take care of
 * factoring out the time spent in other processes for us.  It will
 * also handle thread migration between CPU's in SMP systems.
 */
#if defined(CLOCK_THREAD_CPUTIME_ID)
    #define PERF_TIMER PERF_TIMER_CLOCK_GETTIME
    #define PERF_TIMER_NAME CLOCK_THREAD_CPUTIME_ID
#elif defined(CLOCK_PROCESS_CPUTIME_ID)
    #define PERF_TIMER PERF_TIMER_CLOCK_GETTIME
    #define PERF_TIMER_NAME CLOCK_PROCESS_CPUTIME_ID
#elif defined(CLOCK_MONOTONIC_RAW)
    #define PERF_TIMER PERF_TIMER_CLOCK_GETTIME
    #define PERF_TIMER_NAME CLOCK_MONOTONIC_RAW
#elif defined(CLOCK_MONOTONIC)
    #define PERF_TIMER PERF_TIMER_CLOCK_GETTIME
    #define PERF_TIMER_NAME CLOCK_MONOTONIC
#else
    #define PERF_TIMER PERF_TIMER_UNKNOWN
#endif

int perf_timer_init(void)
{
#if PERF_TIMER == PERF_TIMER_CLOCK_GETTIME
    return 1;
#else
    return 0;
#endif
}

perf_timer_t perf_timer_get_time(void)
{
#if PERF_TIMER == PERF_TIMER_CLOCK_GETTIME
    struct timespec tv;
    clock_gettime(PERF_TIMER_NAME, &tv);
    return tv.tv_sec * 1000000000LL + tv.tv_nsec;
#else
    return 0;
#endif
}

perf_timer_t perf_timer_ticks_per_second(void)
{
#if PERF_TIMER == PERF_TIMER_CLOCK_GETTIME
    return 1000000000ULL;
#else
    return 0;
#endif
}
