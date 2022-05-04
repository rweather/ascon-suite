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

/* Instruction flags */
#define INSN_HAS_IMM        0x0001
#define INSN_SUFFIX_LONG    0x0002
#define INSN_SUFFIX_QUAD    0x0004
#define INSN_LOAD           0x0008
#define INSN_STORE          0x0010

/* Information about an instruction in the pipeline */
typedef struct
{
    const char *opcode;     /* Base opcode such as "mov", "xor", "not", etc */
    int flags;              /* Flags that modify the instruction */
    const char *dest;       /* Destination register */
    const char *src1;       /* Source register 1 */
    const char *src2;       /* Source register 2 or NULL */
    int imm;                /* Immediate or shift count */
    int reschedule;         /* Offset to reschedule by during codegen */

} insn_t;

/* Maximum number of instructions before a forced pipeline flush */
#define MAX_INSNS 5000

/* Instruction list that is pending for the next pipeline flush */
static insn_t insns[MAX_INSNS];
static int num_insns = 0;

static void add_insn(const insn_t *insn)
{
    if (num_insns >= MAX_INSNS)
        flush_pipeline();
    insns[num_insns++] = *insn;
}

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
        printf("#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)\n");
        printf("\t.globl\t%s\n", name);
        printf("\t.def\t%s;\t.scl\t3;\t.type\t32;\t.endef\n", name);
        printf("\t.seh_proc\t%s\n", name);
        printf("%s:\n", name);
        printf("#else\n");
        printf("\t.globl\t%s\n", name);
        printf("\t.type\t%s, @function\n", name);
        printf("%s:\n", name);
        printf("\t.cfi_startproc\n");
        printf("#endif\n");
    }
}

void function_footer(const char *name)
{
    flush_pipeline();
    if (target_word_size == 32 && !X86_64_PLATFORM) {
        printf("\tret\n");
        printf("#if !(defined(__CYGWIN32__) || defined(_WIN32))\n");
        printf("\t.size\t%s, .-%s\n", name, name);
        printf("#endif\n");
    } else {
        printf("\tret\n");
        printf("#if defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)\n");
        printf("\t.seh_endproc\n");
        printf("#else\n");
        printf("\t.cfi_endproc\n");
        printf("\t.size\t%s, .-%s\n", name, name);
        printf("#endif\n");
    }
}

void binop(const char *name, reg_t *reg1, reg_t *reg2)
{
    live(reg1);
    live(reg2);
    insn_t insn = {
        .opcode = name,
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32) ? INSN_SUFFIX_LONG
                                          : INSN_SUFFIX_QUAD,
#endif
        .dest = get_real(reg1),
        .src1 = get_real(reg1),
        .src2 = get_real(reg2)
    };
    add_insn(&insn);
    dirty(reg1);
}

void unop(const char *name, reg_t *reg)
{
    live(reg);
    insn_t insn = {
        .opcode = name,
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32) ? INSN_SUFFIX_LONG
                                          : INSN_SUFFIX_QUAD,
#endif
        .dest = get_real(reg),
        .src1 = get_real(reg)
    };
    add_insn(&insn);
    dirty(reg);
}

void ror(reg_t *dest, int shift)
{
    live(dest);
    insn_t insn = {
        .opcode = "ror",
#if INTEL_SYNTAX
        .flags = INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32) ? (INSN_SUFFIX_LONG | INSN_HAS_IMM)
                                          : (INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = get_real(dest),
        .src1 = get_real(dest),
        .imm = shift
    };
    add_insn(&insn);
    dirty(dest);
}

void load_machine(const char *reg, const char *ptr, int offset)
{
    insn_t insn = {
        .opcode = "mov",
#if INTEL_SYNTAX
        .flags = INSN_LOAD | INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32)
                    ? (INSN_LOAD | INSN_SUFFIX_LONG | INSN_HAS_IMM)
                    : (INSN_LOAD | INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = reg,
        .src1 = ptr,
        .imm = offset
    };
    add_insn(&insn);
}

void load(reg_t *reg, const char *ptr, int offset)
{
    load_machine(get_real(reg), ptr, offset);
    clean(reg);
}

void store_machine(const char *reg, const char *ptr, int offset)
{
    insn_t insn = {
        .opcode = "mov",
#if INTEL_SYNTAX
        .flags = INSN_STORE | INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32)
                    ? (INSN_STORE | INSN_SUFFIX_LONG | INSN_HAS_IMM)
                    : (INSN_STORE | INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = ptr,
        .src1 = reg,
        .imm = offset
    };
    add_insn(&insn);
}

void store(reg_t *reg, const char *ptr, int offset)
{
    store_machine(get_real(reg), ptr, offset);
    clean(reg);
}

void xor_rc(reg_t *reg, int rc)
{
    live(reg);
    insn_t insn = {
        .opcode = "xor",
#if INTEL_SYNTAX
        .flags = INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32) ? (INSN_SUFFIX_LONG | INSN_HAS_IMM)
                                          : (INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = get_real(reg),
        .src1 = get_real(reg),
        .imm = rc
    };
    add_insn(&insn);
    dirty(reg);
}

void xor_direct(reg_t *reg1, const char *reg2)
{
    live(reg1);
    insn_t insn = {
        .opcode = "xor",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32) ? INSN_SUFFIX_LONG
                                          : INSN_SUFFIX_QUAD,
#endif
        .dest = get_real(reg1),
        .src1 = get_real(reg1),
        .src2 = reg2
    };
    add_insn(&insn);
    dirty(reg1);
}

void move(reg_t *dest, reg_t *src)
{
    if (dest->is_temp)
        acquire(dest);
    else
        live_noload(dest);
    live(src);
    insn_t insn = {
        .opcode = "mov",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32) ? INSN_SUFFIX_LONG
                                          : INSN_SUFFIX_QUAD,
#endif
        .dest = get_real(dest),
        .src1 = get_real(src),
        .src2 = get_real(src)
    };
    add_insn(&insn);
    dirty(dest);
}

void clear_reg(const char *reg)
{
    insn_t insn = {
        .opcode = "mov",
#if INTEL_SYNTAX
        .flags = INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32) ? (INSN_SUFFIX_LONG | INSN_HAS_IMM)
                                          : (INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = reg,
        .src1 = reg,
        .imm = 0
    };
    add_insn(&insn);
}

void push(const char *reg)
{
    insn_t insn = {
        .opcode = "push",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32 && !X86_64_PLATFORM)
                        ? INSN_SUFFIX_LONG : INSN_SUFFIX_QUAD,
#endif
        .dest = reg,
        .src1 = reg,
        .imm = 0
    };
    add_insn(&insn);
}

void pop(const char *reg)
{
    insn_t insn = {
        .opcode = "pop",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32 && !X86_64_PLATFORM)
                        ? INSN_SUFFIX_LONG : INSN_SUFFIX_QUAD,
#endif
        .dest = reg,
        .src1 = reg,
        .imm = 0
    };
    add_insn(&insn);
}

void move_direct(const char *dest, const char *src)
{
    insn_t insn = {
        .opcode = "mov",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32 && !X86_64_PLATFORM)
                        ? INSN_SUFFIX_LONG : INSN_SUFFIX_QUAD,
#endif
        .dest = dest,
        .src1 = src,
        .src2 = src
    };
    add_insn(&insn);
}

void reschedule(int offset)
{
    if (num_insns > 0)
        insns[num_insns - 1].reschedule = offset;
}

static void flush_load(const insn_t *insn)
{
#if INTEL_SYNTAX
    if (insn->imm != 0)
        printf("%s, [%s + %d]\n", insn->dest, insn->src1, insn->imm);
    else
        printf("%s, [%s]\n", insn->dest, insn->src1);
#else
    if (insn->imm != 0)
        printf("%d(%s), %s\n", insn->imm, insn->src1, insn->dest);
    else
        printf("(%s), %s\n", insn->src1, insn->dest);
#endif
}

static void flush_store(const insn_t *insn)
{
#if INTEL_SYNTAX
    if (insn->imm != 0)
        printf("[%s + %d], %s\n", insn->dest, insn->imm, insn->src1);
    else
        printf("[%s], %s\n", insn->dest, insn->src1);
#else
    if (insn->imm != 0)
        printf("%s, %d(%s)\n", insn->src1, insn->imm, insn->dest);
    else
        printf("%s, (%s)\n", insn->src1, insn->dest);
#endif
}

static void flush_immediate(const insn_t *insn)
{
#if INTEL_SYNTAX
    printf("%s, %d\n", insn->dest, insn->imm);
#else
    printf("$%d, %s\n", insn->imm, insn->dest);
#endif
}

static void flush_binary(const insn_t *insn)
{
#if INTEL_SYNTAX
    printf("%s, %s\n", insn->dest, insn->src2);
#else
    printf("%s, %s\n", insn->src2, insn->dest);
#endif
}

static void flush_unary(const insn_t *insn)
{
    printf("%s\n", insn->dest);
}

void flush_pipeline(void)
{
    int index, offset;

    /* Apply re-schedule requests to the final code */
    for (index = 0; index < num_insns; ++index) {
        insn_t insn = insns[index];
        offset = insn.reschedule;
        if (offset != 0) {
            insn.reschedule = 0;
            if (offset > 0 && (index + offset) < num_insns) {
                memmove(&(insns[index]), &(insns[index + 1]),
                        offset * sizeof(insn_t));
                insns[index + offset] = insn;
            } else if (offset < 0 && (index + offset) >= 0) {
                memmove(&(insns[index + offset + 1]),
                        &(insns[index + offset]),
                        offset * sizeof(insn_t));
                insns[index + offset] = insn;
            }
        }
    }

    /* Write out all of the instructions */
    for (index = 0; index < num_insns; ++index) {
        const insn_t *insn = &(insns[index]);
        printf("\t%s%s\t", insn->opcode,
               ((insn->flags & INSN_SUFFIX_LONG) ? "l" :
                    ((insn->flags & INSN_SUFFIX_QUAD) ? "q" : "")));
        if (insn->flags & INSN_LOAD)
            flush_load(insn);
        else if (insn->flags & INSN_STORE)
            flush_store(insn);
        else if (insn->flags & INSN_HAS_IMM)
            flush_immediate(insn);
        else if (insn->src2)
            flush_binary(insn);
        else
            flush_unary(insn);
    }

    /* Instruction list is now empty */
    num_insns = 0;
}
