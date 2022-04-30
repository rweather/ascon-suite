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

#include "x86_common.h"
#include <stdio.h>

int target_word_size = 64;

void function_header(const char *name)
{
    if (target_word_size == 32 && !X86_64_PLATFORM) {
        printf("\n\t.p2align 4,,15\n");
        printf("#if defined(__CYGWIN32__) || defined(_WIN32)\n");
        printf("\t.globl\t_%s\n", name);
        printf("\t.def\t_%s;\t.scl\t2;\t.type\t32;\t.endef\n", name);
        printf("_%s:\n", name);
        printf("#else\n");
        printf("\t.globl\t%s\n", name);
        printf("\t.type\t%s, @function\n", name);
        printf("%s:\n", name);
        printf("#endif\n");
    } else {
        printf("\t.p2align 4,,15\n");
        printf("\t.globl\t%s\n", name);
        printf("\t.type\t%s, @function\n", name);
        printf("%s:\n", name);
        printf("\t.cfi_startproc\n");
    }
}

void function_footer(const char *name)
{
    if (target_word_size == 32 && !X86_64_PLATFORM) {
        printf("\tret\n");
        printf("#if !(defined(__CYGWIN32__) || defined(_WIN32))\n");
        printf("\t.size\t%s, .-%s\n", name, name);
        printf("#endif\n");
    } else {
        printf("\tret\n");
        printf("\t.cfi_endproc\n");
        printf("\t.size\t%s, .-%s\n", name, name);
    }
}

void binop(const char *name, const char *reg1, const char *reg2)
{
#if INTEL_SYNTAX
    printf("%s%s, %s\n", name, reg1, reg2);
#else
    printf("%s%s, %s\n", name, reg2, reg1);
#endif
}

void unop(const char *name, const char *reg)
{
    printf("%s%s\n", name, reg);
}

void ror(const char *dest, int shift)
{
#if INTEL_SYNTAX
    if (target_word_size == 32)
        printf(INSNL(ror) "%s, %d\n", dest, shift);
    else
        printf(INSNQ(ror) "%s, %d\n", dest, shift);
#else
    if (target_word_size == 32)
        printf(INSNL(ror) "$%d, %s\n", shift, dest);
    else
        printf(INSNQ(ror) "$%d, %s\n", shift, dest);
#endif
}

void load(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (target_word_size == 32) {
        if (offset != 0)
            printf(INSNL(mov) "%s, [%s + %d]\n", reg, ptr, offset);
        else
            printf(INSNL(mov) "%s, [%s]\n", reg, ptr);
    } else {
        if (offset != 0)
            printf(INSNQ(mov) "%s, [%s + %d]\n", reg, ptr, offset);
        else
            printf(INSNQ(mov) "%s, [%s]\n", reg, ptr);
    }
#else
    if (target_word_size == 32) {
        if (offset != 0)
            printf(INSNL(mov) "%d(%s), %s\n", offset, ptr, reg);
        else
            printf(INSNL(mov) "(%s), %s\n", ptr, reg);
    } else {
        if (offset != 0)
            printf(INSNQ(mov) "%d(%s), %s\n", offset, ptr, reg);
        else
            printf(INSNQ(mov) "(%s), %s\n", ptr, reg);
    }
#endif
}

void store(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (target_word_size == 32) {
        if (offset != 0)
            printf(INSNL(mov) "[%s + %d], %s\n", ptr, offset, reg);
        else
            printf(INSNL(mov) "[%s], %s\n", ptr, reg);
    } else {
        if (offset != 0)
            printf(INSNQ(mov) "[%s + %d], %s\n", ptr, offset, reg);
        else
            printf(INSNQ(mov) "[%s], %s\n", ptr, reg);
    }
#else
    if (target_word_size == 32) {
        if (offset != 0)
            printf(INSNL(mov) "%s, %d(%s)\n", reg, offset, ptr);
        else
            printf(INSNL(mov) "%s, (%s)\n", reg, ptr);
    } else {
        if (offset != 0)
            printf(INSNQ(mov) "%s, %d(%s)\n", reg, offset, ptr);
        else
            printf(INSNQ(mov) "%s, (%s)\n", reg, ptr);
    }
#endif
}

void xor_rc(const char *reg, int rc)
{
#if INTEL_SYNTAX
    if (target_word_size == 32)
        printf(INSNL(xor) "%s, %d\n", reg, rc);
    else
        printf(INSNQ(xor) "%s, %d\n", reg, rc);
#else
    if (target_word_size == 32)
        printf(INSNL(xor) "$%d, %s\n", rc, reg);
    else
        printf(INSNQ(xor) "$%d, %s\n", rc, reg);
#endif
}

void clear_reg(const char *reg)
{
#if INTEL_SYNTAX
    if (target_word_size == 32)
        printf(INSNL(mov) "%s, 0\n", reg);
    else
        printf(INSNQ(mov) "%s, 0\n", reg);
#else
    if (target_word_size == 32)
        printf(INSNL(mov) "$0, %s\n", reg);
    else
        printf(INSNQ(mov) "$0, %s\n", reg);
#endif
}
