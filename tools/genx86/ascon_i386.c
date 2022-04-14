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
 * ASCON permutation for 32-bit i386 and higher microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"

/* Should we output Intel syntax (1) or AT&T syntax (0)? */
#define INTEL_SYNTAX 0

/* Special hack for testing the i386 backend on x86-64 platforms if 1 */
#define X86_64_PLATFORM 0

/* Determine the register names to use */
#if INTEL_SYNTAX
#define REG_EAX "eax"
#define REG_EBX "ebx"
#define REG_ECX "ecx"
#define REG_EDX "edx"
#define REG_EDI "edi"
#define REG_ESI "esi"
#define REG_EBP "ebp"
#if X86_64_PLATFORM
#define REG_ESP "rsp"
#else
#define REG_ESP "esp"
#endif
#define REG_RAX "rax"
#define REG_RBX "rbx"
#define REG_RDI "rdi"
#define REG_RSI "rsi"
#define REG_RBP "rbp"
#define REG_R8  "r8"
#else
#define REG_EAX "%eax"
#define REG_EBX "%ebx"
#define REG_ECX "%ecx"
#define REG_EDX "%edx"
#define REG_EDI "%edi"
#define REG_ESI "%esi"
#define REG_EBP "%ebp"
#if X86_64_PLATFORM
#define REG_ESP "%rsp"
#else
#define REG_ESP "%esp"
#endif
#define REG_RAX "%rax"
#define REG_RBX "%rbx"
#define REG_RDI "%rdi"
#define REG_RSI "%rsi"
#define REG_RBP "%rbp"
#define REG_R8  "%r8"
#endif

/* Instructions that operate on long and quad word registers */
#if INTEL_SYNTAX
#define INSNL(name) "\t" #name "\t"
#define INSNQ(name) "\t" #name "\t"
#else
#define INSNL(name) "\t" #name "l\t"
#define INSNQ(name) "\t" #name "q\t"
#endif

/* Offsets of words in the bit-sliced state */
#define X0_E 0
#define X0_O 4
#define X1_E 8
#define X1_O 12
#define X2_E 16
#define X2_O 20
#define X3_E 24
#define X3_O 28
#define X4_E 32
#define X4_O 36

static void function_header(const char *name)
{
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
}

static void function_footer(const char *name)
{
    printf("\tret\n");
    printf("#if !(defined(__CYGWIN32__) || defined(_WIN32))\n");
    printf("\t.size\t%s, .-%s\n", name, name);
    printf("#endif\n");
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

/* Generates a shift operation on a register */
static void shiftop(const char *name, const char *dest, int shift)
{
#if INTEL_SYNTAX
    printf("%s%s, %d\n", name, dest, shift);
#else
    printf("%s$%d, %s\n", name, shift, dest);
#endif
}

/* Generates a rotate-right of a register */
static void ror(const char *dest, int shift)
{
    shiftop(INSNL(ror), dest, shift);
}

/* AND's a register with an immediate mask value */
static void andimm(const char *reg, int mask)
{
#if INTEL_SYNTAX
    printf(INSNL(and) "%s, %d\n", reg, mask);
#else
    printf(INSNL(and) "$%d, %s\n", mask, reg);
#endif
}

/* Loads a register from a memory location */
static void load(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (offset != 0)
        printf(INSNL(mov) "%s, [%s + %d]\n", reg, ptr, offset);
    else
        printf(INSNL(mov) "%s, [%s]\n", reg, ptr);
#else
    if (offset != 0)
        printf(INSNL(mov) "%d(%s), %s\n", offset, ptr, reg);
    else
        printf(INSNL(mov) "(%s), %s\n", ptr, reg);
#endif
}

/* Stores a register to a memory location */
static void store(const char *reg, const char *ptr, int offset)
{
#if INTEL_SYNTAX
    if (offset != 0)
        printf(INSNL(mov) "[%s + %d], %s\n", ptr, offset, reg);
    else
        printf(INSNL(mov) "[%s], %s\n", ptr, reg);
#else
    if (offset != 0)
        printf(INSNL(mov) "%s, %d(%s)\n", reg, offset, ptr);
    else
        printf(INSNL(mov) "%s, (%s)\n", reg, ptr);
#endif
}


/* Applies the S-box to five 32-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    /* x0 ^= x4;   x4 ^= x3;   x2 ^= x1; */
    binop(INSNL(xor), regs->x0, regs->x4);
    binop(INSNL(xor), regs->x4, regs->x3);
    binop(INSNL(xor), regs->x2, regs->x1);

    /* We are low on registers, so we save t0/t1 on the stack until later */
    /* t1 = x0; */
    /* t0 = (~x0) & x1; */
    store(regs->x0, REG_ESP, 44);
    binop(INSNL(mov), regs->t0, regs->x0);
    unop(INSNL(not), regs->t0);
    binop(INSNL(and), regs->t0, regs->x1);
    store(regs->t0, REG_ESP, 40);

    /* x0 ^= (~x1) & x2; */
    /* x1 ^= (~x2) & x3; */
    binop(INSNL(mov), regs->t1, regs->x1);
    binop(INSNL(mov), regs->t0, regs->x2);
    unop(INSNL(not), regs->t1);
    unop(INSNL(not), regs->t0);
    binop(INSNL(and), regs->t1, regs->x2);
    binop(INSNL(and), regs->t0, regs->x3);
    binop(INSNL(xor), regs->x0, regs->t1);
    binop(INSNL(xor), regs->x1, regs->t0);

    /* x3 ^= (~x4) & t1; */
    binop(INSNL(mov), regs->t0, regs->x4);
    load(regs->t1, REG_ESP, 44);
    unop(INSNL(not), regs->t0);
    binop(INSNL(and), regs->t0, regs->t1);
    binop(INSNL(xor), regs->x3, regs->t0);

    /* x2 ^= (~x3) & x4; */
    binop(INSNL(mov), regs->t1, regs->x3);
    unop(INSNL(not), regs->t1);
    binop(INSNL(and), regs->t1, regs->x4);
    binop(INSNL(xor), regs->x2, regs->t1);

    /* x4 ^= t0; */
    load(regs->t0, REG_ESP, 40);
    binop(INSNL(xor), regs->x4, regs->t0);

    /* x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2; */
    binop(INSNL(xor), regs->x1, regs->x0);
    binop(INSNL(xor), regs->x0, regs->x4);
    binop(INSNL(xor), regs->x3, regs->x2);
#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    unop(INSNL(not), regs->x2);
#endif
}

/* Generate the code for a single sliced ASCON round */
static void gen_round_sliced(const reg_names *regs, int round)
{
    /* Round constants for all rounds */
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };
    const char *t2;

    /* Apply the inverted version of the round constant to x2_e */
#if INTEL_SYNTAX
    printf(INSNL(xor) "%s, %d\n", regs->x2, ~((int)RC[round * 2]));
#else
    printf(INSNL(xor) "$%d, %s\n", ~((int)RC[round * 2]), regs->x2);
#endif

    /* Apply the S-box to the even half of the state */
    gen_sbox(regs);

    /* Store the even half to the stack and load the odd half into registers */
    store(regs->x0, REG_ESP, X0_E);
    store(regs->x1, REG_ESP, X1_E);
    store(regs->x2, REG_ESP, X2_E);
    store(regs->x3, REG_ESP, X3_E);
    store(regs->x4, REG_ESP, X4_E);
    load(regs->x0, REG_ESP, X0_O);
    load(regs->x1, REG_ESP, X1_O);
    load(regs->x2, REG_ESP, X2_O);
    load(regs->x3, REG_ESP, X3_O);
    load(regs->x4, REG_ESP, X4_O);

    /* Apply the inverted version of the round constant to x2_o */
#if INTEL_SYNTAX
    printf(INSNL(xor) "%s, %d\n", regs->x2, ~((int)RC[round * 2 + 1]));
#else
    printf(INSNL(xor) "$%d, %s\n", ~((int)RC[round * 2 + 1]), regs->x2);
#endif

    /* Apply the S-box to the odd half of the state */
    gen_sbox(regs);

    /* Linear diffusion layer.  At the end of this, the even words
     * will be back in registers and the odd words back on the stack. */

    /* We are very low on registers, but need 3 temporaries to do
     * the work below.  Move x4 to the stack so that we can use it
     * as an extra temporary.  Then later do the same with x0 when
     * it is time to operate on x4 for real. */
    store(regs->x4, REG_ESP, 40);
    t2 = regs->x4;

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    // t0 = x0_e ^ rightRotate4(x0_o);
    // t1 = x0_o ^ rightRotate5(x0_e);
    // x0_e ^= rightRotate9(t1);
    // x0_o ^= rightRotate10(t0);
    load(t2, REG_ESP, X0_E);
    binop(INSNL(mov), regs->t0, regs->x0);
    binop(INSNL(mov), regs->t1, t2);
    ror(regs->t0, 4);
    ror(regs->t1, 5);
    binop(INSNL(xor), regs->t0, t2);
    binop(INSNL(xor), regs->t1, regs->x0);
    ror(regs->t0, 10);
    ror(regs->t1, 9);
    binop(INSNL(xor), regs->t0, regs->x0);
    binop(INSNL(xor), t2, regs->t1);
    store(regs->t0, REG_ESP, X0_O);
    binop(INSNL(mov), regs->x0, t2);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
    load(t2, REG_ESP, X1_E);
    binop(INSNL(mov), regs->t1, regs->x1);
    binop(INSNL(mov), regs->t0, t2);
    ror(regs->t1, 11);
    ror(regs->t0, 11);
    binop(INSNL(xor), regs->t1, regs->x1);
    binop(INSNL(xor), regs->t0, t2);
    ror(regs->t1, 19);
    ror(regs->t0, 20);
    binop(INSNL(xor), t2, regs->t1);
    binop(INSNL(xor), regs->t0, regs->x1);
    binop(INSNL(mov), regs->x1, t2);
    store(regs->t0, REG_ESP, X1_O);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
    load(t2, REG_ESP, X2_E);
    binop(INSNL(mov), regs->t0, regs->x2);
    binop(INSNL(mov), regs->t1, t2);
    ror(regs->t0, 2);
    ror(regs->t1, 3);
    binop(INSNL(xor), regs->t0, t2);
    binop(INSNL(xor), regs->t1, regs->x2);
    ror(regs->t0, 1);
    binop(INSNL(xor), t2, regs->t1);
    binop(INSNL(xor), regs->t0, regs->x2);
    binop(INSNL(mov), regs->x2, t2);
    store(regs->t0, REG_ESP, X2_O);

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
    load(t2, REG_ESP, X3_E);
    binop(INSNL(mov), regs->t0, regs->x3);
    binop(INSNL(mov), regs->t1, t2);
    ror(regs->t0, 3);
    ror(regs->t1, 4);
    binop(INSNL(xor), regs->t0, t2);
    binop(INSNL(xor), regs->t1, regs->x3);
    ror(regs->t0, 5);
    ror(regs->t1, 5);
    binop(INSNL(xor), t2, regs->t0);
    binop(INSNL(xor), regs->t1, regs->x3);
    binop(INSNL(mov), regs->x3, t2);
    store(regs->t1, REG_ESP, X3_O);

    /* Reclaim x4 and use x0 as the new third temporary */
    load(regs->x4, REG_ESP, 40);
    store(regs->x0, REG_ESP, 40);
    t2 = regs->x0;

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    // t0 = x4_e ^ rightRotate17(x4_e);
    // t1 = x4_o ^ rightRotate17(x4_o);
    // x4_e ^= rightRotate3(t1);
    // x4_o ^= rightRotate4(t0);
    load(t2, REG_ESP, X4_E);
    binop(INSNL(mov), regs->t1, regs->x4);
    binop(INSNL(mov), regs->t0, t2);
    ror(regs->t1, 17);
    ror(regs->t0, 17);
    binop(INSNL(xor), regs->t1, regs->x4);
    binop(INSNL(xor), regs->t0, t2);
    ror(regs->t1, 3);
    ror(regs->t0, 4);
    binop(INSNL(xor), t2, regs->t1);
    binop(INSNL(xor), regs->t0, regs->x4);
    binop(INSNL(mov), regs->x4, t2);
    store(regs->t0, REG_ESP, X4_O);

    /* Reclaim x0 */
    load(regs->x0, REG_ESP, 40);
}

/* Generate the body of the 32-bit sliced ASCON permutation function */
static void gen_permute(void)
{
    /*
     * The "state" and "first_round" arguments are on the stack on entry.
     *
     * eax, ecx, and edx can be used as scratch registers.
     *
     * ebx, esi, edi, and ebp must be callee-saved.
     */
    reg_names regs;
    const char *state;
    const char *first_round;
    int round;
    regs.x0 = REG_EBX;
    regs.x1 = REG_ECX;
    regs.x2 = REG_EDX;
    regs.x3 = REG_ESI;
    regs.x4 = REG_EDI;
    regs.t0 = REG_EAX;
    regs.t1 = REG_EBP;

    /* Set up the stack frame, and load the arguments into eax and ebp */
#if X86_64_PLATFORM
    unop(INSNQ(push), REG_RBP);
    unop(INSNQ(push), REG_RBX);
#if INTEL_SYNTAX
    printf(INSNQ(sub) "%s, 48\n", REG_ESP);
#else
    printf(INSNQ(sub) "$48, %s\n", REG_ESP);
#endif
    binop(INSNQ(mov), REG_RAX, REG_RDI);
    binop(INSNQ(mov), REG_RBP, REG_RSI);
    binop(INSNQ(mov), REG_R8, REG_RDI); /* Save in r8 for the later store */
    state = REG_RAX;
    first_round = REG_EBP;
#else
    unop(INSNL(push), REG_EBP);
    unop(INSNL(push), REG_EBX);
    unop(INSNL(push), REG_ESI);
    unop(INSNL(push), REG_EDI);
#if INTEL_SYNTAX
    printf(INSNL(sub) "%s, 48\n", REG_ESP);
#else
    printf(INSNL(sub) "$48, %s\n", REG_ESP);
#endif
    load(regs.t0, REG_ESP, 48 + 16 + 4);
    load(regs.t1, REG_ESP, 48 + 16 + 8);
    state = regs.t0;
    first_round = regs.t1;
#endif

    /* Shift the state to the stack so that we can offset via SP.
     * We keep the even words in registers between rounds and store
     * the odd words in the stack.  The even slots on the stack
     * will be filled later when we need to swap even and odd. */
    load(regs.x0, state, X0_O);
    load(regs.x1, state, X1_O);
    load(regs.x2, state, X2_O);
    load(regs.x3, state, X3_O);
    load(regs.x4, state, X4_O);
    unop(INSNL(not), regs.x2); /* Invert x2_o before the first round */
    store(regs.x0, REG_ESP, X0_O);
    store(regs.x1, REG_ESP, X1_O);
    store(regs.x2, REG_ESP, X2_O);
    store(regs.x3, REG_ESP, X3_O);
    store(regs.x4, REG_ESP, X4_O);
    load(regs.x0, state, X0_E);
    load(regs.x1, state, X1_E);
    load(regs.x2, state, X2_E);
    load(regs.x3, state, X3_E);
    load(regs.x4, state, X4_E);
    unop(INSNL(not), regs.x2); /* Invert x2_e before the first round */

    /* Switch on the "first round" parameter and jump ahead */
#if INTEL_SYNTAX
    printf(INSNL(cmp) "%s, 12\n", first_round);
    printf("\tjge\t.L13\n");
#if X86_64_PLATFORM
    printf(INSNQ(mov) "%s, [%s * 8 + .L14]\n", REG_RAX, REG_RBP);
#else
    printf(INSNL(mov) "%s, [%s * 4 + .L14]\n", regs.t0, first_round);
#endif
    printf("\tjmp\t%s\n", state);
#else /* !INTEL_SYNTAX */
    printf(INSNL(cmp) "$12, %s\n", first_round);
    printf("\tjge\t.L13\n");
#if X86_64_PLATFORM
    printf(INSNQ(mov) ".L14(,%s,8), %s\n", REG_RBP, REG_RAX);
#else
    printf(INSNL(mov) ".L14(,%s,4), %s\n", first_round, regs.t0);
#endif
    printf("\tjmp\t*%s\n", state);
#endif /* !INTEL_SYNTAX */
    printf(".L13:\n");
    printf("\tjmp\t.L12\n");
    printf("\t.section\t.rodata\n");
    printf("\t.align\t4\n");
    printf("\t.L14:\n");
    for (round = 0; round < 12; ++round) {
#if X86_64_PLATFORM
        printf("\t.quad\t.L%d\n", round);
#else
        printf("\t.long\t.L%d\n", round);
#endif
    }
    printf("\t.text\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round_sliced(&regs, round);
    }

    /* Store the words back to the state */
    printf(".L12:\n");
#if X86_64_PLATFORM
    binop(INSNQ(mov), REG_RAX, REG_R8);
#else
    load(regs.t0, REG_ESP, 48 + 16 + 4);
#endif
    unop(INSNL(not), regs.x2); /* Invert x2_e after the last round */
    store(regs.x0, state, X0_E);
    store(regs.x1, state, X1_E);
    store(regs.x2, state, X2_E);
    store(regs.x3, state, X3_E);
    store(regs.x4, state, X4_E);
    load(regs.x0, REG_ESP, X0_O);
    load(regs.x1, REG_ESP, X1_O);
    load(regs.x2, REG_ESP, X2_O);
    load(regs.x3, REG_ESP, X3_O);
    load(regs.x4, REG_ESP, X4_O);
    unop(INSNL(not), regs.x2); /* Invert x2_o after the last round */
    store(regs.x0, state, X0_O);
    store(regs.x1, state, X1_O);
    store(regs.x2, state, X2_O);
    store(regs.x3, state, X3_O);
    store(regs.x4, state, X4_O);

    /* Pop the stack frame */
#if X86_64_PLATFORM
#if INTEL_SYNTAX
    printf(INSNQ(add) "%s, 48\n", REG_ESP);
#else
    printf(INSNQ(add) "$48, %s\n", REG_ESP);
#endif
    unop(INSNQ(pop), REG_RBX);
    unop(INSNQ(pop), REG_RBP);
#else
#if INTEL_SYNTAX
    printf(INSNL(add) "%s, 48\n", REG_ESP);
#else
    printf(INSNL(add) "$48, %s\n", REG_ESP);
#endif
    unop(INSNL(pop), REG_EDI);
    unop(INSNL(pop), REG_ESI);
    unop(INSNL(pop), REG_EBX);
    unop(INSNL(pop), REG_EBP);
#endif
}

/* Do two bit_permute_step() operations in parallel to improve scheduling */
static void bit_permute_step_two
    (const char *y1, const char *y2, const char *t1,
     const char *t2, unsigned long mask, int shift)
{
    /* t = ((y >> (shift)) ^ y) & (mask);
     * y = (y ^ t) ^ (t << (shift)); */
    binop(INSNL(mov), t1, y1);
    binop(INSNL(mov), t2, y2);
    shiftop(INSNL(shr), t1, shift);
    shiftop(INSNL(shr), t2, shift);
    binop(INSNL(xor), t1, y1);
    binop(INSNL(xor), t2, y2);
    andimm(t1, (int)mask);
    andimm(t2, (int)mask);
    binop(INSNL(xor), y1, t1);
    binop(INSNL(xor), y2, t2);
    shiftop(INSNL(shl), t1, shift);
    shiftop(INSNL(shl), t2, shift);
    binop(INSNL(xor), y1, t1);
    binop(INSNL(xor), y2, t2);
}

/* Output the function to convert to sliced form */
static void gen_to_sliced(void)
{
    /*
     * The "state" argument is on the stack on entry.
     *
     * eax, ecx, and edx can be used as scratch registers.
     *
     * ebx, esi, edi, and ebp must be callee-saved.
     */
#if X86_64_PLATFORM
    const char *state = REG_RAX;
    const char *high = REG_ECX;
    const char *low = REG_EDX;
    const char *temp1 = REG_EDI;
    const char *temp2 = REG_ESI;
#else
    const char *state = REG_EAX;
    const char *high = REG_ECX;
    const char *low = REG_EDX;
    const char *temp1 = REG_EDI;
    const char *temp2 = REG_ESI;
#endif
    int loop;

    /* Set up the stack frame, and load the state pointer into eax */
#if X86_64_PLATFORM
    binop(INSNQ(mov), REG_RAX, REG_RDI);
#else
    unop(INSNL(push), REG_EDI);
    unop(INSNL(push), REG_ESI);
    load(state, REG_ESP, 12);
#endif

    /* Process 5 rounds for each of the 8-byte words of the state */
    for (loop = 0; loop < 5; ++loop) {
        /* load high and low from the state */
        load(high, state, loop * 8);
        load(low, state, loop * 8 + 4);

        /* ascon_separate(high) and ascon_separate(low) */
        bit_permute_step_two(high, low, temp1, temp2, 0x22222222, 1);
        bit_permute_step_two(high, low, temp1, temp2, 0x0c0c0c0c, 2);
        bit_permute_step_two(high, low, temp1, temp2, 0x000f000f, 12);
        bit_permute_step_two(high, low, temp1, temp2, 0x000000ff, 24);

        /* rearrange and store back */
        // state->W[index] = (high << 16) | (low & 0x0000FFFFU);
        // state->W[index + 1] = (high & 0xFFFF0000U) | (low >> 16);
        binop(INSNL(mov), temp1, high);
        binop(INSNL(mov), temp2, low);
        shiftop(INSNL(shl), temp1, 16);
        andimm(temp2, 0xFFFF);
        binop(INSNL(or), temp2, temp1);
        andimm(high, (int)0xFFFF0000U);
        shiftop(INSNL(shr), low, 16);
        binop(INSNL(or), low, high);
        store(temp2, state, loop * 8);
        store(low, state, loop * 8 + 4);
    }

    /* Pop the stack frame and return */
#if !X86_64_PLATFORM
    unop(INSNL(pop), REG_ESI);
    unop(INSNL(pop), REG_EDI);
#endif
}

/* Output the function to convert from sliced form */
static void gen_from_sliced(void)
{
    /*
     * The "state" argument is on the stack on entry.
     *
     * eax, ecx, and edx can be used as scratch registers.
     *
     * ebx, esi, edi, and ebp must be callee-saved.
     */
#if X86_64_PLATFORM
    const char *state = REG_RAX;
    const char *high = REG_ECX;
    const char *low = REG_EDX;
    const char *temp1 = REG_EDI;
    const char *temp2 = REG_ESI;
#else
    const char *state = REG_EAX;
    const char *high = REG_ECX;
    const char *low = REG_EDX;
    const char *temp1 = REG_EDI;
    const char *temp2 = REG_ESI;
#endif
    int loop;

    /* Set up the stack frame, and load the state pointer into eax */
#if X86_64_PLATFORM
    binop(INSNQ(mov), REG_RAX, REG_RDI);
#else
    unop(INSNL(push), REG_EDI);
    unop(INSNL(push), REG_ESI);
    load(state, REG_ESP, 12);
#endif

    /* Process 5 rounds for each of the 8-byte words of the state */
    for (loop = 0; loop < 5; ++loop) {
        /* load and rearrange the half words */
        // high = (state->W[index] >> 16) | (state->W[index + 1] & 0xFFFF0000U);
        // low  = (state->W[index] & 0x0000FFFFU) | (state->W[index + 1] << 16);
        load(low, state, loop * 8);
        load(high, state, loop * 8 + 4);
        binop(INSNL(mov), temp1, low);
        binop(INSNL(mov), temp2, high);
        shiftop(INSNL(shr), temp1, 16);
        shiftop(INSNL(shl), temp2, 16);
        andimm(low, 0xFFFF);
        andimm(high, (int)0xFFFF0000U);
        binop(INSNL(or), low, temp2);
        binop(INSNL(or), high, temp1);

        /* ascon_combine(high) and ascon_combine(low) */
        bit_permute_step_two(high, low, temp1, temp2, 0x0000aaaa, 15);
        bit_permute_step_two(high, low, temp1, temp2, 0x0000cccc, 14);
        bit_permute_step_two(high, low, temp1, temp2, 0x0000f0f0, 12);
        bit_permute_step_two(high, low, temp1, temp2, 0x000000ff, 24);
        store(high, state, loop * 8);
        store(low, state, loop * 8 + 4);
    }

    /* Pop the stack frame and return */
#if !X86_64_PLATFORM
    unop(INSNL(pop), REG_ESI);
    unop(INSNL(pop), REG_EDI);
#endif
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
    printf("#if defined(ASCON_BACKEND_I386)\n");
    fputs(copyright_message, stdout);
#if INTEL_SYNTAX
    printf("\t.intel_syntax noprefix\n");
#endif
    printf("\t.text\n");

    /* Output the sliced version of the permutation function */
    function_header("ascon_permute");
    gen_permute();
    function_footer("ascon_permute");

    /* Output the function to convert to sliced form */
    function_header("ascon_from_regular");
    gen_to_sliced();
    function_footer("ascon_from_regular");

    /* Output the function to convert from sliced form */
    function_header("ascon_to_regular");
    gen_from_sliced();
    function_footer("ascon_to_regular");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
