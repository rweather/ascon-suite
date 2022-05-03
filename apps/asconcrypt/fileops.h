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

/* File operations that try to avoid using stdio so as not to leave
 * sensitive data lying around in libc stdio buffers.  This may need
 * to be modified for non-POSIX systems. */

#ifndef FILEOPS_H
#define FILEOPS_H

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#include <stdio.h>
#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#define USE_WINDOWS_FDS 1
#define USE_POSIX_FDS 1
#elif defined(HAVE_OPEN) && defined(HAVE_UNISTD_H) && defined(HAVE_FCNTL_H)
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#define USE_POSIX_FDS 1
#endif

typedef struct
{
#if defined(USE_POSIX_FDS)
    int fd;
#else
    FILE *file;
#endif
    const char *filename;
} SAFEFILE;

int safe_file_open_read(SAFEFILE *file, const char *filename);
int safe_file_open_write(SAFEFILE *file, const char *filename);
void safe_file_close(SAFEFILE *file);
int safe_file_read(SAFEFILE *file, void *data, size_t len);
int safe_file_write(SAFEFILE *file, const void *data, size_t len);
void safe_file_delete(SAFEFILE *file);

#endif /* FILEOPS_H */
