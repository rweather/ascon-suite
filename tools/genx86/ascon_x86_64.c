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

/*
 * This program is used to generate the assembly code version of the
 * ASCON permutation for x86-64 microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"

/* Should we output Intel syntax (1) or AT&T syntax (0)? */
#define INTEL_SYNTAX 1

/* Determine the register names to use */
#if INTEL_SYNTAX
#define REG_RAX "rax"
#define REG_RBX "rbx"
#define REG_RCX "rcx"
#define REG_RDX "rdx"
#define REG_RDI "rdi"
#define REG_RSI "rsi"
#define REG_RBP "rbp"
#define REG_RSP "rsp"
#define REG_R8  "r8"
#define REG_R9  "r9"
#define REG_R10 "r10"
#define REG_R11 "r11"
#define REG_R12 "r12"
#define REG_R13 "r13"
#define REG_R14 "r14"
#define REG_R15 "r15"
#else
#define REG_RAX "%rax"
#define REG_RBX "%rbx"
#define REG_RCX "%rcx"
#define REG_RDX "%rdx"
#define REG_RDI "%rdi"
#define REG_RSI "%rsi"
#define REG_RBP "%rbp"
#define REG_RSP "%rsp"
#define REG_R8  "%r8"
#define REG_R9  "%r9"
#define REG_R10 "%r10"
#define REG_R11 "%r11"
#define REG_R12 "%r12"
#define REG_R13 "%r13"
#define REG_R14 "%r14"
#define REG_R15 "%r15"
#endif

/* Instruction that operates on a quad word register */
#if INTEL_SYNTAX
#define INSNQ(name) "\t" #name "\t"
#else
#define INSNQ(name) "\t" #name "q\t"
#endif

static void function_header(const char *name)
{
    printf("\t.p2align 4,,15\n");
    printf("\t.globl\t%s\n", name);
    printf("\t.type\t%s, @function\n", name);
    printf("%s:\n", name);
    printf("\t.cfi_startproc\n");
}

static void function_footer(const char *name)
{
    printf("\tret\n");
    printf("\t.cfi_endproc\n");
    printf("\t.size\t%s, .-%s\n", name, name);
}

/* List of all registers that we can work with */
typedef struct
{
    const char *x0;
    const char *x1;
    const char *x2;
    const char *x3;
    const char *x4;
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;
    const char *t4;
    const char *t5;

} reg_names;

/* Generates a binary operator */
static void binop(const char *name, const char *reg1, const char *reg2)
{
#if INTEL_SYNTAX
    printf("%s%s, %s\n", name, reg1, reg2);
#else
    printf("%s%s, %s\n", name, reg2, reg1);
#endif
}

/* Generates a unary operator */
static void unop(const char *name, const char *reg)
{
    printf("%s%s\n", name, reg);
}

/* Generates a rotate-right of a register */
static void ror(const char *dest, int shift)
{
#if INTEL_SYNTAX
    printf(INSNQ(ror) "%s, %d\n", dest, shift);
#else
    printf(INSNQ(ror) "$%d, %s\n", shift, dest);
#endif
}

/* Loads a register from a memory location */
static void load(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (offset != 0)
        printf(INSNQ(mov) "%s, [%s + %d]\n", reg, ptr, offset);
    else
        printf(INSNQ(mov) "%s, [%s]\n", reg, ptr);
#else
    if (offset != 0)
        printf(INSNQ(mov) "%d(%s), %s\n", offset, ptr, reg);
    else
        printf(INSNQ(mov) "(%s), %s\n", ptr, reg);
#endif
}

/* Stores a register to a memory location */
static void store(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (offset != 0)
        printf(INSNQ(mov) "[%s + %d], %s\n", ptr, offset, reg);
    else
        printf(INSNQ(mov) "[%s], %s\n", ptr, reg);
#else
    if (offset != 0)
        printf(INSNQ(mov) "%s, %d(%s)\n", reg, offset, ptr);
    else
        printf(INSNQ(mov) "%s, (%s)\n", reg, ptr);
#endif
}

/* Applies the S-box to five 64-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    /* x0 ^= x4;   x4 ^= x3;   x2 ^= x1; */
    binop(INSNQ(xor), regs->x0, regs->x4);
    binop(INSNQ(xor), regs->x4, regs->x3);
    binop(INSNQ(xor), regs->x2, regs->x1);

    /* t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4; */
    binop(INSNQ(mov), regs->t0, regs->x0);
    binop(INSNQ(mov), regs->t1, regs->x1);
    binop(INSNQ(mov), regs->t2, regs->x2);
    binop(INSNQ(mov), regs->t3, regs->x3);
    binop(INSNQ(mov), regs->t4, regs->x4);
    unop(INSNQ(not), regs->t0);
    unop(INSNQ(not), regs->t1);
    unop(INSNQ(not), regs->t2);
    unop(INSNQ(not), regs->t3);
    unop(INSNQ(not), regs->t4);

    /* t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0; */
    binop(INSNQ(and), regs->t0, regs->x1);
    binop(INSNQ(and), regs->t1, regs->x2);
    binop(INSNQ(and), regs->t2, regs->x3);
    binop(INSNQ(and), regs->t3, regs->x4);
    binop(INSNQ(and), regs->t4, regs->x0);

    /* x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0; */
    binop(INSNQ(xor), regs->x0, regs->t1);
    binop(INSNQ(xor), regs->x1, regs->t2);
    binop(INSNQ(xor), regs->x2, regs->t3);
    binop(INSNQ(xor), regs->x3, regs->t4);
    binop(INSNQ(xor), regs->x4, regs->t0);

    /* x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2; */
    binop(INSNQ(xor), regs->x1, regs->x0);
    binop(INSNQ(xor), regs->x0, regs->x4);
    binop(INSNQ(xor), regs->x3, regs->x2);
#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    unop(INSNQ(not), regs->x2);
#endif
}

/* Generate the code for a single ASCON round */
static void gen_round(const reg_names *regs, int round)
{
    int rc;

    /* Apply the round constant to x2, and also NOT x2 in the process */
    rc = ~(((0x0F - round) << 4) | round);
#if INTEL_SYNTAX
    printf(INSNQ(xor) "%s, %d\n", regs->x2, rc);
#else
    printf(INSNQ(xor) "$%d, %s\n", rc, regs->x2);
#endif

    /* Apply the S-box to the words of the state */
    gen_sbox(regs);

    /* Linear diffusion layer */
    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    binop(INSNQ(mov), regs->t0, regs->x0);
    binop(INSNQ(mov), regs->t1, regs->x0);
    binop(INSNQ(mov), regs->t2, regs->x1);
    binop(INSNQ(mov), regs->t3, regs->x1);
    binop(INSNQ(mov), regs->t4, regs->x2);
    binop(INSNQ(mov), regs->t5, regs->x2);
    ror(regs->t0, 19);
    ror(regs->t1, 28);
    ror(regs->t2, 61);
    ror(regs->t3, 39);
    ror(regs->t4, 1);
    ror(regs->t5, 6);
    binop(INSNQ(xor), regs->x0, regs->t0);
    binop(INSNQ(xor), regs->x0, regs->t1);
    binop(INSNQ(xor), regs->x1, regs->t2);
    binop(INSNQ(xor), regs->x1, regs->t3);
    binop(INSNQ(xor), regs->x2, regs->t4);
    binop(INSNQ(xor), regs->x2, regs->t5);
    binop(INSNQ(mov), regs->t0, regs->x3);
    binop(INSNQ(mov), regs->t1, regs->x3);
    binop(INSNQ(mov), regs->t2, regs->x4);
    binop(INSNQ(mov), regs->t3, regs->x4);
    ror(regs->t0, 10);
    ror(regs->t1, 17);
    ror(regs->t2, 7);
    ror(regs->t3, 41);
    binop(INSNQ(xor), regs->x3, regs->t0);
    binop(INSNQ(xor), regs->x3, regs->t1);
    binop(INSNQ(xor), regs->x4, regs->t2);
    binop(INSNQ(xor), regs->x4, regs->t3);
}

/* Generate the body of the ASCON permutation function */
static void gen_permute(void)
{
    /*
     * %rdi holds the pointer to the ASCON state on entry and exit.
     *
     * %rsi is the "first round" parameter on entry, which will normally be
     * one of the values 0, 4, or 6.
     *
     * %rax, %rcx, %rdx, %rdi, %rsi, %r8, %r9, %r10, %r11 can be used
     * as scratch registers without saving.
     *
     * %rbx, %rbp, %r12, %r13, %r14, %r15 must be callee-saved.
     */
    const char *state = REG_RDI;
    const char *first_round = REG_RSI;
    reg_names regs;
    int round;
    regs.x0 = REG_RAX;
    regs.x1 = REG_RCX;
    regs.x2 = REG_RDX;
    regs.x3 = REG_R8;
    regs.x4 = REG_R9;
    regs.t0 = REG_RBX;
    regs.t1 = REG_RSI;
    regs.t2 = REG_R10;
    regs.t3 = REG_R11;
    regs.t4 = REG_R12;
    regs.t5 = REG_R13;

    /* Push callee-saved registers on the stack */
    unop(INSNQ(push), REG_RBX);
    unop(INSNQ(push), REG_R12);
    unop(INSNQ(push), REG_R13);

    /* Load all words of the state into registers */
    load(regs.x0, state, 0);
    load(regs.x1, state, 8);
    load(regs.x2, state, 16);
    load(regs.x3, state, 24);
    load(regs.x4, state, 32);

    /* Invert x2 before entry to the rounds */
    unop(INSNQ(not), regs.x2);

    /* Switch on the "first round" parameter and jump ahead */
#if INTEL_SYNTAX
    printf(INSNQ(cmp) "%s, 12\n", first_round);
    printf("\tjge\t.L13\n");
    printf(INSNQ(lea) "%s, [rip + .L14]\n", regs.t0);
    printf(INSNQ(movsxd) "%s, [%s + %s*4]\n", regs.t1, regs.t0, first_round);
    printf(INSNQ(add) "%s, %s\n", regs.t1, regs.t0);
    printf("\tjmp\t%s\n", regs.t1);
#else
    printf(INSNQ(cmp) "$12, %s\n", first_round);
    printf("\tjge\t.L13\n");
    printf(INSNQ(lea) ".L14(%%rip), %s\n", regs.t0);
    printf(INSNQ(movsl) "(%s,%s,4), %s\n", regs.t0, first_round, regs.t1);
    printf(INSNQ(add) "%s, %s\n", regs.t0, regs.t1);
    printf("\tjmp\t*%s\n", regs.t1);
#endif
    printf(".L13:\n");
    printf("\tjmp\t.L12\n");
    printf("\t.section\t.rodata\n");
    printf("\t.align\t4\n");
    printf("\t.L14:\n");
    for (round = 0; round < 12; ++round) {
        printf("\t.long\t.L%d-.L14\n", round);
    }
    printf("\t.text\n");
    printf("\t.p2align\t4,,10\n");
    printf("\t.p2align\t3\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round(&regs, round);
    }

    /* Store the words back to the state and exit */
    printf(".L12:\n");
    unop(INSNQ(not), regs.x2);
    store(regs.x0, state, 0);
    store(regs.x1, state, 8);
    store(regs.x2, state, 16);
    store(regs.x3, state, 24);
    store(regs.x4, state, 32);
    unop(INSNQ(pop), REG_R13);
    unop(INSNQ(pop), REG_R12);
    unop(INSNQ(pop), REG_RBX);
}

/* Output the function to convert to or from sliced form,
 * which is as simple as byte-reversing the 64-bit words */
static void gen_to_or_from_sliced(void)
{
    const char *state = REG_RDI;
    const char *x0 = REG_RAX;
    const char *x1 = REG_RCX;
    const char *x2 = REG_RDX;
    const char *x3 = REG_RSI;
    const char *x4 = REG_R8;
    load(x0, state, 0);
    load(x1, state, 8);
    load(x2, state, 16);
    load(x3, state, 24);
    load(x4, state, 32);
    unop(INSNQ(bswap), x0);
    unop(INSNQ(bswap), x1);
    unop(INSNQ(bswap), x2);
    unop(INSNQ(bswap), x3);
    unop(INSNQ(bswap), x4);
    store(x0, state, 0);
    store(x1, state, 8);
    store(x2, state, 16);
    store(x3, state, 24);
    store(x4, state, 32);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
    printf("#if defined(ASCON_BACKEND_X86_64)\n");
    fputs(copyright_message, stdout);
#if INTEL_SYNTAX
    printf("\t.intel_syntax noprefix\n");
#endif
    printf("\t.text\n");

    /* Output the permutation function */
    function_header("ascon_permute");
    gen_permute();
    function_footer("ascon_permute");

    /* Output the function to convert to sliced form */
    function_header("ascon_from_regular");
    gen_to_or_from_sliced();
    function_footer("ascon_from_regular");

    /* Output the function to convert from sliced form */
    function_header("ascon_to_regular");
    gen_to_or_from_sliced();
    function_footer("ascon_to_regular");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
