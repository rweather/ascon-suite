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
#include <string.h>
#include <stdlib.h>

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

void binop(const char *name, reg_t reg1, reg_t reg2)
{
#if INTEL_SYNTAX
    printf("\t%s\t%s, %s\n", name, get_real(&reg1), get_real(&reg2));
#else
    if (target_word_size == 32)
        printf("\t%sl\t%s, %s\n", name, get_real(&reg2), get_real(&reg1));
    else
        printf("\t%sq\t%s, %s\n", name, get_real(&reg2), get_real(&reg1));
#endif
}

void unop(const char *name, reg_t reg)
{
#if INTEL_SYNTAX
    printf("\t%s\t%s\n", name, get_real(&reg));
#else
    if (target_word_size == 32)
        printf("\t%sl\t%s\n", name, get_real(&reg));
    else
        printf("\t%sq\t%s\n", name, get_real(&reg));
#endif
}

void ror(reg_t dest, int shift)
{
#if INTEL_SYNTAX
    printf("\tror\t%s, %d\n", get_real(&dest), shift);
#else
    if (target_word_size == 32)
        printf("\trorl\t$%d, %s\n", shift, get_real(&dest));
    else
        printf("\trorq\t$%d, %s\n", shift, get_real(&dest));
#endif
}

void load(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (offset != 0)
        printf("\tmov\t%s, [%s + %d]\n", reg, ptr, offset);
    else
        printf("\tmov\t%s, [%s]\n", reg, ptr);
#else
    if (target_word_size == 32) {
        if (offset != 0)
            printf("\tmovl\t%d(%s), %s\n", offset, ptr, reg);
        else
            printf("\tmovl\t(%s), %s\n", ptr, reg);
    } else {
        if (offset != 0)
            printf("\tmovq\t%d(%s), %s\n", offset, ptr, reg);
        else
            printf("\tmovq\t(%s), %s\n", ptr, reg);
    }
#endif
}

void store(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (offset != 0)
        printf("\tmov\t[%s + %d], %s\n", ptr, offset, reg);
    else
        printf("\tmov\t[%s], %s\n", ptr, reg);
#else
    if (target_word_size == 32) {
        if (offset != 0)
            printf("\tmovl\t%s, %d(%s)\n", reg, offset, ptr);
        else
            printf("\tmovl\t%s, (%s)\n", reg, ptr);
    } else {
        if (offset != 0)
            printf("\tmovq\t%s, %d(%s)\n", reg, offset, ptr);
        else
            printf("\tmovq\t%s, (%s)\n", reg, ptr);
    }
#endif
}

void xor_rc(reg_t reg, int rc)
{
#if INTEL_SYNTAX
    printf("\txor\t%s, %d\n", get_real(&reg), rc);
#else
    if (target_word_size == 32)
        printf("\txorl\t$%d, %s\n", rc, get_real(&reg));
    else
        printf("\txorq\t$%d, %s\n", rc, get_real(&reg));
#endif
}

void clear_reg(const char *reg)
{
#if INTEL_SYNTAX
    printf("\tmov\t%s, 0\n", reg);
#else
    if (target_word_size == 32)
        printf("\tmovl\t$0, %s\n", reg);
    else
        printf("\tmovq\t$0, %s\n", reg);
#endif
}

void push(const char *reg)
{
#if INTEL_SYNTAX
    printf("\tpush\t%s\n", reg);
#else
    if (target_word_size == 32 && !X86_64_PLATFORM)
        printf("\tpushl\t%s\n", reg);
    else
        printf("\tpushq\t%s\n", reg);
#endif
}

void pop(const char *reg)
{
#if INTEL_SYNTAX
    printf("\tpop\t%s\n", reg);
#else
    if (target_word_size == 32 && !X86_64_PLATFORM)
        printf("\tpopl\t%s\n", reg);
    else
        printf("\tpopq\t%s\n", reg);
#endif
}

void move_direct(const char *dest, const char *src)
{
#if INTEL_SYNTAX
    printf("\tmov\t%s, %s\n", dest, src);
#else
    if (target_word_size == 32 && !X86_64_PLATFORM)
        printf("\tmovl\t%s, %s\n", src, dest);
    else
        printf("\tmovq\t%s, %s\n", src, dest);
#endif
}
