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
#define INSN_SUFFIX_WORD    0x0008
#define INSN_SUFFIX_BYTE    0x0010
#define INSN_LOAD           0x0020
#define INSN_STORE          0x0040

/* Information about an instruction in the pipeline */
typedef struct
{
    const char *opcode;     /* Base opcode such as "mov", "xor", "not", etc */
    int flags;              /* Flags that modify the instruction */
    const char *dest;       /* Destination register */
    const char *src1;       /* Source register 1 */
    const char *src2;       /* Source register 2 or NULL */
    long long imm;          /* Immediate or shift count */
    int reschedule;         /* Offset to reschedule by during codegen */

} insn_t;

/* Maximum number of instructions before a forced pipeline flush */
#define MAX_INSNS 5000

/* Instruction list that is pending for the next pipeline flush */
static insn_t insns[MAX_INSNS];
static int num_insns = 0;

/* Next label number to allocate */
static int next_label = 100;

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
        printf("#if defined(__APPLE__)\n");
        printf("\t.p2align 4, 0x90\n");
        printf("\t.globl\t_%s\n", name);
        printf("_%s:\n", name);
        printf("\t.cfi_startproc\n");
        printf("#elif defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)\n");
        printf("\t.p2align 4,,15\n");
        printf("\t.globl\t%s\n", name);
        printf("\t.def\t%s;\t.scl\t3;\t.type\t32;\t.endef\n", name);
        printf("\t.seh_proc\t%s\n", name);
        printf("%s:\n", name);
        printf("#else\n");
        printf("\t.p2align 4,,15\n");
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
        printf("#if defined(__APPLE__)\n");
        printf("\tretq\n");
        printf("\t.cfi_endproc\n");
        printf("#elif defined(__CYGWIN__) || defined(_WIN32) || defined(_WIN64)\n");
        printf("\tret\n");
        printf("\t.seh_endproc\n");
        printf("#else\n");
        printf("\tret\n");
        printf("\t.cfi_endproc\n");
        printf("\t.size\t%s, .-%s\n", name, name);
        printf("#endif\n");
    }
}

static const char *map_register_to_smaller(const char *reg, int size)
{
    static const char * const map[] = {
        REG_RAX, REG_EAX, REG_AX, REG_AL,
        REG_RBX, REG_EBX, REG_BX, REG_BL,
        REG_RCX, REG_ECX, REG_CX, REG_CL,
        REG_RDX, REG_EDX, REG_DX, REG_DL,
        REG_RSI, REG_ESI, 0,      0,
        REG_RDI, REG_EDI, 0,      0,
        REG_RBP, REG_EBP, 0,      0,
        0
    };
    int index = 0;
    while (map[index] != 0) {
        if (!strcmp(reg, map[index])) {
            const char *mapping;
            if (size == 2)
                mapping = map[index + 2];
            else if (size == 1)
                mapping = map[index + 3];
            else
                mapping = map[index + 1];
            if (!mapping)
                break;
            return mapping;
        }
        index += 4;
    }
    fprintf(stderr, "map_register_to_smaller: cannot map %s to a smaller size\n", reg);
    exit(1);
    return reg;
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

void ror_reg(reg_t *dest, reg_t *shift)
{
    live(dest);
    live(shift);
    insn_t insn = {
        .opcode = "ror",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32) ? INSN_SUFFIX_LONG : INSN_SUFFIX_QUAD,
#endif
        .dest = get_real(dest),
        .src1 = get_real(dest),
        .src2 = map_register_to_smaller(get_real(shift), 1)
    };
    add_insn(&insn);
    dirty(dest);
}

void shl(reg_t *dest, int shift)
{
    live(dest);
    insn_t insn = {
        .opcode = "shl",
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

void shl_reg(reg_t *dest, reg_t *shift)
{
    live(dest);
    live(shift);
    insn_t insn = {
        .opcode = "shl",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32) ? INSN_SUFFIX_LONG : INSN_SUFFIX_QUAD,
#endif
        .dest = get_real(dest),
        .src1 = get_real(dest),
        .src2 = map_register_to_smaller(get_real(shift), 1)
    };
    add_insn(&insn);
    dirty(dest);
}

void shr(reg_t *dest, int shift)
{
    live(dest);
    insn_t insn = {
        .opcode = "shr",
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

void shr_reg(reg_t *dest, reg_t *shift)
{
    live(dest);
    live(shift);
    insn_t insn = {
        .opcode = "shr",
#if INTEL_SYNTAX
        .flags = 0,
#else
        .flags = (target_word_size == 32) ? INSN_SUFFIX_LONG : INSN_SUFFIX_QUAD,
#endif
        .dest = get_real(dest),
        .src1 = get_real(dest),
        .src2 = map_register_to_smaller(get_real(shift), 1)
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

void load_and_xor(reg_t *reg, const char *ptr, int offset)
{
    insn_t insn = {
        .opcode = "xor",
#if INTEL_SYNTAX
        .flags = INSN_LOAD | INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32)
                    ? (INSN_LOAD | INSN_SUFFIX_LONG | INSN_HAS_IMM)
                    : (INSN_LOAD | INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = get_real(reg),
        .src1 = ptr,
        .imm = offset
    };
    add_insn(&insn);
    dirty(reg);
}

void load_smaller(reg_t *reg, const char *ptr, int offset, int size)
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
        .dest = get_real(reg),
        .src1 = ptr,
        .imm = offset
    };
#if !INTEL_SYNTAX
    insn.flags &= ~INSN_SUFFIX_QUAD;
    insn.flags |= INSN_SUFFIX_LONG;
#endif
    if (target_word_size == 64) {
        insn.dest = map_register_to_smaller(insn.dest, 4);
    }
    if (size == 2) {
        insn.opcode = "movzw";
    } else if (size == 1) {
        insn.opcode = "movzb";
    }
    add_insn(&insn);
    dirty(reg);
}

void load_smaller_plus_reg
    (reg_t *reg, const char *ptr, const char *ptrplus, int size)
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
        .dest = get_real(reg),
        .src1 = ptr,
        .src2 = ptrplus
    };
#if !INTEL_SYNTAX
    insn.flags &= ~INSN_SUFFIX_QUAD;
    insn.flags |= INSN_SUFFIX_LONG;
#endif
    if (target_word_size == 64) {
        insn.dest = map_register_to_smaller(insn.dest, 4);
    }
    if (size == 2) {
        insn.opcode = "movzw";
    } else if (size == 1) {
        insn.opcode = "movzb";
    }
    add_insn(&insn);
    dirty(reg);
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

void store_smaller(reg_t *reg, const char *ptr, int offset, int size)
{
    insn_t insn = {
        .opcode = "mov",
#if INTEL_SYNTAX
        .flags = INSN_STORE | INSN_HAS_IMM,
#else
        .flags = (size == 1)
                    ? (INSN_STORE | INSN_SUFFIX_BYTE | INSN_HAS_IMM)
                    :
                ((size == 2)
                    ? (INSN_STORE | INSN_SUFFIX_WORD | INSN_HAS_IMM)
                    : (INSN_STORE | INSN_SUFFIX_LONG | INSN_HAS_IMM)),
#endif
        .dest = ptr,
        .src1 = map_register_to_smaller(get_real(reg), size),
        .imm = offset
    };
    add_insn(&insn);
}

void xor_and_store(reg_t *reg, const char *ptr, int offset)
{
    insn_t insn = {
        .opcode = "xor",
#if INTEL_SYNTAX
        .flags = INSN_STORE | INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32)
                    ? (INSN_STORE | INSN_SUFFIX_LONG | INSN_HAS_IMM)
                    : (INSN_STORE | INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = ptr,
        .src1 = get_real(reg),
        .imm = offset
    };
    add_insn(&insn);
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

void move_imm(reg_t *dest, long long value)
{
    if (dest->is_temp)
        acquire(dest);
    else
        live_noload(dest);
    insn_t insn = {
        .opcode = "mov",
#if INTEL_SYNTAX
        .flags = INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32) ?
                    (INSN_SUFFIX_LONG | INSN_HAS_IMM) :
                    (INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = get_real(dest),
        .src1 = get_real(dest),
        .imm = value
    };
    add_insn(&insn);
    dirty(dest);
}

void add_imm(reg_t *reg, int value)
{
    if (reg->is_temp)
        acquire(reg);
    else
        live_noload(reg);
    insn_t insn = {
        .opcode = (value < 0 ? "sub" : "add"),
#if INTEL_SYNTAX
        .flags = INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32) ?
                    (INSN_SUFFIX_LONG | INSN_HAS_IMM) :
                    (INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = get_real(reg),
        .src1 = get_real(reg),
        .imm = (value < 0 ? (-value) : value)
    };
    add_insn(&insn);
    dirty(reg);
}

int compare_imm(const char *condition, int label, reg_t *reg, int value)
{
    if (reg->is_temp)
        acquire(reg);
    else
        live_noload(reg);
    insn_t insn = {
        .opcode = "cmp",
#if INTEL_SYNTAX
        .flags = INSN_HAS_IMM,
#else
        .flags = (target_word_size == 32) ?
                    (INSN_SUFFIX_LONG | INSN_HAS_IMM) :
                    (INSN_SUFFIX_QUAD | INSN_HAS_IMM),
#endif
        .dest = get_real(reg),
        .src1 = get_real(reg),
        .imm = value
    };
    add_insn(&insn);
    return branch(condition, label);
}

int branch(const char *condition, int label)
{
    flush_pipeline();
    if (label < 0)
        label = next_label++;
    printf("\t%s\t.L%d\n", condition, label);
    return label;
}

int set_label(int label)
{
    flush_pipeline();
    if (label < 0)
        label = next_label++;
    printf(".L%d:\n", label);
    return label;
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
    if (insn->src2 != 0)
        printf("%s, [%s + %s]\n", insn->dest, insn->src1, insn->src2);
    else if (insn->imm != 0)
        printf("%s, [%s + %lld]\n", insn->dest, insn->src1, insn->imm);
    else
        printf("%s, [%s]\n", insn->dest, insn->src1);
#else
    if (insn->src2 != 0)
        printf("(%s,%s), %s\n", insn->src1, insn->src2, insn->dest);
    else if (insn->imm != 0)
        printf("%lld(%s), %s\n", insn->imm, insn->src1, insn->dest);
    else
        printf("(%s), %s\n", insn->src1, insn->dest);
#endif
}

static void flush_store(const insn_t *insn)
{
#if INTEL_SYNTAX
    if (insn->imm != 0)
        printf("[%s + %lld], %s\n", insn->dest, insn->imm, insn->src1);
    else
        printf("[%s], %s\n", insn->dest, insn->src1);
#else
    if (insn->imm != 0)
        printf("%s, %lld(%s)\n", insn->src1, insn->imm, insn->dest);
    else
        printf("%s, (%s)\n", insn->src1, insn->dest);
#endif
}

static void flush_immediate(const insn_t *insn)
{
#if INTEL_SYNTAX
    printf("%s, %lld\n", insn->dest, insn->imm);
#else
    printf("$%lld, %s\n", insn->imm, insn->dest);
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
                    ((insn->flags & INSN_SUFFIX_QUAD) ? "q" :
                        ((insn->flags & INSN_SUFFIX_WORD) ? "w" :
                            ((insn->flags & INSN_SUFFIX_BYTE) ? "b" : "")))));
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

static void util_function_setup_i386
    (util_frame_t *frame, int num_args, int word_arg, int trng_bytes)
{
    /* TODO */
    (void)frame;
    (void)num_args;
    (void)word_arg;
    (void)trng_bytes;
}

/*
 * %rdi, %rsi, %rdx, %rcx, %r8, %r9 hold the function parameters.
 * %rax holds the 64-bit return value on exit if necessary.
 *
 * %rax, %rcx, %rdx, %rdi, %rsi, %r8, %r9, %r10, %r11 can be used
 * as scratch registers without saving.
 *
 * %rbx, %rbp, %r12, %r13, %r14, %r15 must be callee-saved.
 */
static void util_function_setup_x86_64
    (util_frame_t *frame, int num_args, int word_arg, int trng_bytes)
{
    static char * const arg_regs[] = {
        REG_RDI, REG_RSI, REG_RDX, REG_RCX, REG_R8, REG_R9, NULL
    };
    static char * const callee_regs[] = {
        REG_RBX, REG_RBP, REG_R12, REG_R13, REG_R14, REG_R15, NULL
    };
    int used_count = 0;
    int frame_size = 0;
    int callee_index = 0;
    int save_index = 0;
    int posn;
    char *name;
    const char *state_reg = NULL;
    char *trng_reg = NULL;

    /* Initialize the frame structure */
    memset(frame, 0, sizeof(util_frame_t));

    /* Add all scratch registers to the register list */
    frame->reg_list[used_count++] = REG_RAX;
    frame->reg_list[used_count++] = REG_RCX;
    frame->reg_list[used_count++] = REG_RDX;
    frame->reg_list[used_count++] = REG_R8;
    frame->reg_list[used_count++] = REG_R9;
    frame->reg_list[used_count++] = REG_RDI;
    frame->reg_list[used_count++] = REG_RSI;

    /* If we need to allocate from the TRNG, then the main arguments
     * need to be moved into callee-saved registers.  We will also need
     * some callee-saved registers to hold the TRNG results if multiple
     * calls are needed to obtain all necessary bytes. */
    if (trng_bytes > 0) {
        for (posn = 0; posn < num_args; ++posn) {
            name = callee_regs[callee_index++];
            if (!name) {
                fprintf(stderr, "not enough callee-saved registers\n");
                exit(1);
            }
            frame->reg_list[used_count++] = name;
            if (posn == word_arg)
                state_reg = name;
            frame_size += 8;
        }
        if (trng_bytes > 8) {
            /* Need to also save the TRNG pointer between calls */
            name = callee_regs[callee_index++];
            if (!name) {
                fprintf(stderr, "not enough callee-saved registers\n");
                exit(1);
            }
            frame->reg_list[used_count++] = name;
            trng_reg = name;
            frame_size += 8;
        }
        for (posn = 0; posn < ((trng_bytes + 7) / 8) - 1; ++posn) {
            name = callee_regs[callee_index++];
            if (!name) {
                fprintf(stderr, "not enough callee-saved registers\n");
                exit(1);
            }
            frame->reg_list[used_count++] = name;
            frame_size += 8;
        }
    } else if (word_arg >= 0) {
        state_reg = arg_regs[word_arg];
        trng_reg = NULL;
    } else {
        state_reg = REG_RDX; /* Not used, but needs to be something */
        trng_reg = NULL;
    }
    frame->reg_list[used_count] = NULL;

    /* Round up the frame size to a multiple of 16.  Note: The return
     * address for the function is already using 8 bytes, so we need to
     * ensure that the local frame size is odd. */
    if ((frame_size % 8) == 0)
        frame_size += 8;
    frame->frame_size = 0;

    /* Initialize the register allocator */
    start_allocator(frame->reg_list, state_reg, REG_RSP);
    frame->state_reg = state_reg;

    /* Set up the logical registers that will contain the arguments */
    callee_index = 0;
    frame_size = 0;
    if (trng_bytes > 0) {
        for (posn = 0; posn < num_args; ++posn) {
            name = callee_regs[callee_index++];
            push(name);
            frame->arg[posn] = alloc_named_register(name);
            frame->save_regs[save_index++] = name;
            frame_size += 8;
        }
    } else {
        for (posn = 0; posn < num_args; ++posn) {
            name = arg_regs[posn];
            frame->arg[posn] = alloc_named_register(name);
        }
    }

    /* Save the TRNG pointer if we need to make multiple calls */
    if (trng_reg) {
        ++callee_index;
        frame->save_regs[save_index++] = trng_reg;
        push(trng_reg);
        frame_size += 8;
    }

    /* Set up the logical registers that will contain saved TRNG bytes */
    for (posn = 0; posn < ((trng_bytes + 7) / 8) - 1; ++posn) {
        name = callee_regs[callee_index++];
        push(name);
        frame->save_regs[save_index++] = name;
        frame->random[posn] = alloc_named_register(name);
        frame_size += 8;
    }
    if (trng_bytes > 0) {
        /* The last TRNG word can be left in the function return register */
        posn = (trng_bytes + 7) / 8 - 1;
        frame->random[posn] = alloc_named_register(REG_RAX);
    }
    frame->num_save_regs = save_index;

    /* Do we need to align the stack? */
    if (frame_size < frame->frame_size)
        push(REG_RAX);

    /* Move the arguments and TRNG pointer into callee-saved registers */
    if (trng_bytes > 0) {
        for (posn = 0; posn < num_args; ++posn) {
            move_direct(frame->arg[posn]->real_reg, arg_regs[posn]);
        }
    }
    if (trng_reg) {
        move_direct(trng_reg, arg_regs[num_args]);
    }

    /* Make as many TRNG calls as necessary to collect the random bytes */
    for (posn = 0; posn < trng_bytes; posn += 8) {
        if (posn == 0)
            move_direct(REG_RDI, arg_regs[num_args]);
        else
            move_direct(REG_RDI, trng_reg);
        flush_pipeline();
        printf("\tcall\ttrng_generate_64\n");
        if (posn < (trng_bytes - 8))
            move_direct(frame->random[posn / 8]->real_reg, REG_RAX);
    }

    /* Flush all instructions so far */
    flush_pipeline();
}

void util_function_setup
    (util_frame_t *frame, int num_args, int word_arg, int trng_bytes)
{
    if (target_word_size == 32)
        util_function_setup_i386(frame, num_args, word_arg, trng_bytes);
    else
        util_function_setup_x86_64(frame, num_args, word_arg, trng_bytes);
}

static void util_function_teardown_i386(util_frame_t *frame)
{
    /* TODO */
}

static void util_function_teardown_x86_64(util_frame_t *frame)
{
    int posn;
    if (frame->frame_size > (frame->num_save_regs * 8))
        pop(REG_EDX); /* Discard the alignment word */
    for (posn = frame->num_save_regs - 1; posn >= 0; --posn)
        pop(frame->save_regs[posn]);
    flush_pipeline();
}

void util_function_teardown(util_frame_t *frame)
{
    if (target_word_size == 32)
        util_function_teardown_i386(frame);
    else
        util_function_teardown_x86_64(frame);
}
