/*
 * Copyright (C) 2023 Southern Storm Software, Pty Ltd.
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

#ifndef ASCON_STORAGE_H
#define ASCON_STORAGE_H

#include <stddef.h>

/**
 * \file storage.h
 * \brief Functions for accessing non-volatile storage.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Information about how to access non-volatile storage.
 */
typedef struct ascon_storage_s ascon_storage_t;

/**
 * \brief Information about how to access non-volatile storage.
 */
struct ascon_storage_s
{
    /** Size of a page in non-volatile storage, which is the minimum
     *  writable unit.  The minimum readable unit is assumed to be 1. */
    size_t page_size;

    /** Size of an erase block in non-volatile storage, which is the
     *  minimum erasable unit.  Set to zero if the storage does not
     *  need to be erased before it is written; e.g. EEPROM. */
    size_t erase_size;

    /** Address within non-volatile storage of where the data begins. */
    size_t address;

    /** Size of the non-voltage storage area.  This must be a multiple of
     *  page_size and erase_size. */
    size_t size;

    /** Non-zero if partial writes are allowed without erasing first.
     *  Used with flash memory that supports converting 1 bits to 0 bits,
     *  while leaving existing 0 bits as-is. */
    int partial_writes;

    /**
     * \brief Reads data from non-volatile storage.
     *
     * \param storage Points to the non-volatile storage information block.
     * \param offset Offset into the non-volatile storage to read from.
     * \param data Points to the buffer to receive the read data.
     * \param size Number of bytes to read from the non-volatile storage.
     *
     * \return The number of bytes that were read, or -1 on error.
     */
    int (*read)(const ascon_storage_t *storage, size_t offset,
                unsigned char *data, size_t size);

    /**
     * \brief Writes data to non-volatile storage.
     *
     * \param storage Points to the non-volatile storage information block.
     * \param offset Offset into the non-volatile storage to write to,
     * which must be a multiple of page_size.
     * \param data Points to the buffer containing the bytes to write.
     * \param size Number of bytes to write to non-volatile storage.
     * \param erase Non-zero to erase before writing, or zero if the
     * memory should be already assumed to be erased.
     *
     * \return The number of bytes that were written, or -1 on error.
     *
     * If \a data is NULL and \a erase is non-zero, then the region
     * defined by \a offset and \a size will be erased with nothing
     * written over the top.
     */
    int (*write)(const ascon_storage_t *storage, size_t offset,
                 const unsigned char *data, size_t size, int erase);
};

#ifdef __cplusplus
}
#endif

#endif
