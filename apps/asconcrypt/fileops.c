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

#include "fileops.h"
#include <string.h>

#if defined(USE_WINDOWS_FDS)
/* Windows gives POSIX functions "_" names, which is annoying */
#undef open
#undef close
#undef read
#undef write
#undef unlink
#define open _open
#define close _close
#define read _read
#define write _write
#define unlink _unlink
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif
#ifndef O_WRONLY
#define O_WRONLY _O_WRONLY
#endif
#ifndef O_CREAT
#define O_CREAT _O_CREAT
#endif
#ifndef O_TRUNC
#define O_TRUNC _O_TRUNC
#endif
#ifndef S_IWUSR
#define S_IWUSR _S_IWRITE
#endif
#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#endif
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif
#if defined(S_IWUSR) && defined(S_IRUSR)
#define WRITE_PERMISSIONS (S_IWUSR | S_IRUSR)
#else
#define WRITE_PERMISSIONS 0600
#endif

int safe_file_open_read(SAFEFILE *file, const char *filename)
{
#if defined(USE_POSIX_FDS)
    if (!strcmp(filename, "-")) {
        file->fd = 0;
    } else if ((file->fd = open(filename, O_RDONLY | O_BINARY)) < 0) {
        perror(filename);
        return 0;
    }
    file->filename = filename;
    return 1;
#else
    if (!strcmp(filename, "-")) {
        file->file = stdin;
    } else if ((file->file = fopen(filename, "rb")) == NULL) {
        perror(filename);
        return 0;
    }
    file->filename = filename;
    return 1;
#endif
}

int safe_file_open_write(SAFEFILE *file, const char *filename)
{
#if defined(USE_POSIX_FDS)
    if (!strcmp(filename, "-")) {
        file->fd = 1;
    } else if ((file->fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, WRITE_PERMISSIONS)) < 0) {
        perror(filename);
        return 0;
    }
    file->filename = filename;
    return 1;
#else
    if (!strcmp(filename, "-")) {
        file->file = stdout;
    } else if ((file->file = fopen(filename, "wb")) == NULL) {
        perror(filename);
        return 0;
    }
    file->filename = filename;
    return 1;
#endif
}

void safe_file_close(SAFEFILE *file)
{
#if defined(USE_POSIX_FDS)
    if (file->fd >= 2)
        close(file->fd);
    file->fd = -1;
#else
    if (file->filename && strcmp(file->filename, "-") != 0)
        fclose(file->file);
    file->file = NULL;
#endif
}

int safe_file_read(SAFEFILE *file, void *data, size_t len)
{
#if defined(USE_POSIX_FDS)
    unsigned char *d = (unsigned char *)data;
    int result = 0;
    int temp;
    for (;;) {
        temp = read(file->fd, d, len);
        if (temp < 0) {
            /* Handle signal interruptions and non-blocking I/O */
            if (errno == EINTR || errno == EAGAIN)
                continue;
            perror(file->filename);
            return -1;
        } else if (temp == 0) {
            break;
        } else {
            result += temp;
            d += temp;
            len -= temp;
        }
    }
    return result;
#else
    int result = fread(data, 1, len, file->file);
    if (result < 0)
        perror(file->filename);
    return result;
#endif
}

int safe_file_write(SAFEFILE *file, const void *data, size_t len)
{
#if defined(USE_POSIX_FDS)
    const unsigned char *d = (const unsigned char *)data;
    int result = 0;
    int temp;
    for (;;) {
        temp = write(file->fd, d, len);
        if (temp < 0) {
            /* Handle signal interruptions and non-blocking I/O */
            if (errno == EINTR || errno == EAGAIN)
                continue;
            perror(file->filename);
            return -1;
        } else if (temp == 0) {
            break;
        } else {
            result += temp;
            d += temp;
            len -= temp;
        }
    }
    return result;
#else
    int result = fwrite(data, 1, len, file->file);
    if (result < 0)
        perror(file->filename);
    return result;
#endif
}

void safe_file_delete(SAFEFILE *file)
{
    safe_file_close(file);
#if defined(USE_POSIX_FDS)
    if (strcmp(file->filename, "-") != 0)
        unlink(file->filename);
#else
    #warning "don't know how to delete files on this platform"
#endif
}
