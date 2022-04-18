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
 * ASCON permutation for 32-bit RISC-V microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"

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

/* Define to 1 to run the resulting code on a RV64I platform for testing */
#define RV64I_PLATFORM 0

/* Name of an instruction, optionally modified for hosting on RV64I */
#if RV64I_PLATFORM
#define INSN(name)  "\t" #name "\t"
#define INSNW(name) "\t" #name "w\t"
#else
#define INSN(name)  "\t" #name "\t"
#define INSNW(name) "\t" #name "\t"
#endif

static void function_header(const char *name)
{
    printf("\n\t.align\t1\n");
    printf("\t.globl\t%s\n", name);
    printf("\t.type\t%s, @function\n", name);
    printf("%s:\n", name);
}

static void function_footer(const char *name)
{
    printf("\tret\n");
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
    const char *x0_e;
    const char *x1_e;
    const char *x2_e;
    const char *x3_e;
    const char *x4_e;
    const char *x0_o;
    const char *x1_o;
    const char *x2_o;
    const char *x3_o;
    const char *x4_o;
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;
    const char *t4;

} reg_names;

/* Generates a binary operator */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    printf("%s%s, %s, %s\n", name, reg1, reg1, reg2);
}

/* Generates a binary operator with a different destination */
static void binop2
    (const char *name, const char *dest, const char *reg1, const char *reg2)
{
    printf("%s%s, %s, %s\n", name, dest, reg1, reg2);
}

/* Generates a unary operator */
static void unop(const char *name, const char *reg1, const char *reg2)
{
    printf("%s%s, %s\n", name, reg1, reg2);
}

/* Applies the S-box to five 32-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    /* x0 ^= x4;   x4 ^= x3;   x2 ^= x1; */
    binop(INSN(xor), regs->x0, regs->x4);
    binop(INSN(xor), regs->x2, regs->x1);
    binop(INSN(xor), regs->x4, regs->x3);

    /* t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4; */
    unop(INSN(not), regs->t0, regs->x0);
    unop(INSN(not), regs->t1, regs->x1);
    unop(INSN(not), regs->t2, regs->x2);
    unop(INSN(not), regs->t3, regs->x3);
    unop(INSN(not), regs->t4, regs->x4);

    /* t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0; */
    binop(INSN(and), regs->t0, regs->x1);
    binop(INSN(and), regs->t1, regs->x2);
    binop(INSN(and), regs->t2, regs->x3);
    binop(INSN(and), regs->t3, regs->x4);
    binop(INSN(and), regs->t4, regs->x0);

    /* x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0; */
    binop(INSN(xor), regs->x0, regs->t1);
    binop(INSN(xor), regs->x1, regs->t2);
    binop(INSN(xor), regs->x2, regs->t3);
    binop(INSN(xor), regs->x3, regs->t4);
    binop(INSN(xor), regs->x4, regs->t0);

    /* x1 ^= x0;   x0 ^= x4;   x3 ^= x2; */
    binop(INSN(xor), regs->x1, regs->x0);
    binop(INSN(xor), regs->x3, regs->x2);
    binop(INSN(xor), regs->x0, regs->x4);

#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    unop(INSN(not), regs->x2, regs->x2);        /* x2 = ~x2; */
#endif
}

/* Applies the S-box to the even words of the state */
static void gen_sbox_even(const reg_names *regs)
{
    reg_names regs2 = *regs;
    regs2.x0 = regs2.x0_e;
    regs2.x1 = regs2.x1_e;
    regs2.x2 = regs2.x2_e;
    regs2.x3 = regs2.x3_e;
    regs2.x4 = regs2.x4_e;
    gen_sbox(&regs2);
}

/* Applies the S-box to the odd words of the state */
static void gen_sbox_odd(const reg_names *regs)
{
    reg_names regs2 = *regs;
    regs2.x0 = regs2.x0_o;
    regs2.x1 = regs2.x1_o;
    regs2.x2 = regs2.x2_o;
    regs2.x3 = regs2.x3_o;
    regs2.x4 = regs2.x4_o;
    gen_sbox(&regs2);
}

/* Generate the code for a single ASCON round */
static void gen_round(const reg_names *regs, int round)
{
    /* Sliced round constants for all rounds */
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };
    const char *even;

    /* Apply the round constant to x2_e, and also NOT it in the process */
    printf(INSN(xori) "%s, %s, %d\n", regs->x2_e, regs->x2_e,
           ~((int)(RC[round * 2])));

    /* Apply the S-box to the even words of the state */
    gen_sbox_even(regs);

#ifdef RV32E
    /* Store the even half to the state and load the odd half into registers */
    printf("\tsw\t%s, (a0)\n", regs->x0_e);
    printf("\tsw\t%s, %d(a0)\n", regs->x1_e, X1_E);
    printf("\tsw\t%s, %d(a0)\n", regs->x2_e, X2_E);
    printf("\tsw\t%s, %d(a0)\n", regs->x3_e, X3_E);
    printf("\tsw\t%s, %d(a0)\n", regs->x4_e, X4_E);
    printf("\tlw\t%s, %d(a0)\n", regs->x0_o, X0_O);
    printf("\tlw\t%s, %d(a0)\n", regs->x1_o, X1_O);
    printf("\tlw\t%s, %d(a0)\n", regs->x2_o, X2_O);
    printf("\tlw\t%s, %d(a0)\n", regs->x3_o, X3_O);
    printf("\tlw\t%s, %d(a0)\n", regs->x4_o, X4_O);
#endif

    /* Apply the round constant to x2_o, and also NOT it in the process */
    printf(INSN(xori) "%s, %s, %d\n", regs->x2_o, regs->x2_o,
           ~((int)(RC[round * 2 + 1])));

    /* Apply the S-box to the odd words of the state */
    gen_sbox_odd(regs);

    /* Linear diffusion layer */

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    // t0 = x0_e ^ rightRotate4(x0_o);
    // t1 = x0_o ^ rightRotate5(x0_e);
    // x0_e ^= rightRotate9(t1);
    // x0_o ^= rightRotate10(t0);
#ifdef RV32E
    even = regs->t4;
    printf("\tlw\t%s, (a0)\n", even);
#else
    even = regs->x0_e;
#endif
    printf(INSNW(srli) "%s, %s, %d\n", regs->t0, regs->x0_o, 4);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t1, even, 5);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t2, regs->x0_o, 32 - 4);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t3, even, 32 - 5);
    binop(INSN(xor), regs->t0, even);
    binop(INSN(xor), regs->t1, regs->x0_o);
    binop(INSN(xor), regs->t0, regs->t2);
    binop(INSN(xor), regs->t1, regs->t3);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t2, regs->t0, 10);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t3, regs->t1, 9);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t0, regs->t0, 32 - 10);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t1, regs->t1, 32 - 9);
#ifdef RV32E
    binop(INSN(xor), regs->t2, regs->x0_o);
    binop2(INSN(xor), regs->x0_e, even, regs->t3);
    binop(INSN(xor), regs->t2, regs->t0);
    binop(INSN(xor), regs->x0_e, regs->t1);
    printf("\tsw\t%s, %d(a0)\n", regs->t2, X0_O);
#else
    binop(INSN(xor), regs->x0_o, regs->t2);
    binop2(INSN(xor), regs->x0_e, even, regs->t3);
    binop(INSN(xor), regs->x0_o, regs->t0);
    binop(INSN(xor), regs->x0_e, regs->t1);
#endif

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
#ifdef RV32E
    even = regs->t4;
    printf("\tlw\t%s, %d(a0)\n", even, X1_E);
#else
    even = regs->x1_e;
#endif
    printf(INSNW(srli) "%s, %s, %d\n", regs->t1, regs->x1_o, 11);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t0, even, 11);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t3, regs->x1_o, 32 - 11);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t2, even, 32 - 11);
    binop(INSN(xor), regs->t0, even);
    binop(INSN(xor), regs->t1, regs->x1_o);
    binop(INSN(xor), regs->t0, regs->t2);
    binop(INSN(xor), regs->t1, regs->t3);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t2, regs->t0, 20);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t3, regs->t1, 19);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t0, regs->t0, 32 - 20);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t1, regs->t1, 32 - 19);
#ifdef RV32E
    binop(INSN(xor), regs->t2, regs->x1_o);
    binop2(INSN(xor), regs->x1_e, even, regs->t3);
    binop(INSN(xor), regs->t2, regs->t0);
    binop(INSN(xor), regs->x1_e, regs->t1);
    printf("\tsw\t%s, %d(a0)\n", regs->t2, X1_O);
#else
    binop(INSN(xor), regs->x1_o, regs->t2);
    binop2(INSN(xor), regs->x1_e, even, regs->t3);
    binop(INSN(xor), regs->x1_o, regs->t0);
    binop(INSN(xor), regs->x1_e, regs->t1);
#endif

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
#ifdef RV32E
    even = regs->t4;
    printf("\tlw\t%s, %d(a0)\n", even, X2_E);
#else
    even = regs->x2_e;
#endif
    printf(INSNW(srli) "%s, %s, %d\n", regs->t0, regs->x2_o, 2);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t1, even, 3);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t2, regs->x2_o, 32 - 2);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t3, even, 32 - 3);
    binop(INSN(xor), regs->t0, even);
    binop(INSN(xor), regs->t1, regs->x2_o);
    binop(INSN(xor), regs->t0, regs->t2);
    binop(INSN(xor), regs->t1, regs->t3);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t2, regs->t0, 1);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t0, regs->t0, 32 - 1);
#ifdef RV32E
    binop(INSN(xor), regs->t2, regs->x2_o);
    binop2(INSN(xor), regs->x2_e, even, regs->t1);
    binop(INSN(xor), regs->t2, regs->t0);
    printf("\tsw\t%s, %d(a0)\n", regs->t2, X2_O);
#else
    binop(INSN(xor), regs->x2_o, regs->t2);
    binop2(INSN(xor), regs->x2_e, even, regs->t1);
    binop(INSN(xor), regs->x2_o, regs->t0);
#endif

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
#ifdef RV32E
    even = regs->t4;
    printf("\tlw\t%s, %d(a0)\n", even, X3_E);
#else
    even = regs->x3_e;
#endif
    printf(INSNW(srli) "%s, %s, %d\n", regs->t0, regs->x3_o, 3);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t1, even, 4);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t2, regs->x3_o, 32 - 3);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t3, even, 32 - 4);
    binop(INSN(xor), regs->t0, even);
    binop(INSN(xor), regs->t1, regs->x3_o);
    binop(INSN(xor), regs->t0, regs->t2);
    binop(INSN(xor), regs->t1, regs->t3);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t2, regs->t0, 5);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t3, regs->t1, 5);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t0, regs->t0, 32 - 5);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t1, regs->t1, 32 - 5);
#ifdef RV32E
    binop(INSN(xor), regs->t3, regs->x3_o);
    binop2(INSN(xor), regs->x3_e, even, regs->t2);
    binop(INSN(xor), regs->t3, regs->t1);
    binop(INSN(xor), regs->x3_e, regs->t0);
    printf("\tsw\t%s, %d(a0)\n", regs->t3, X3_O);
#else
    binop(INSN(xor), regs->x3_o, regs->t3);
    binop2(INSN(xor), regs->x3_e, even, regs->t2);
    binop(INSN(xor), regs->x3_o, regs->t1);
    binop(INSN(xor), regs->x3_e, regs->t0);
#endif

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    // t0 = x4_e ^ rightRotate17(x4_e);
    // t1 = x4_o ^ rightRotate17(x4_o);
    // x4_e ^= rightRotate3(t1);
    // x4_o ^= rightRotate4(t0);
#ifdef RV32E
    even = regs->t4;
    printf("\tlw\t%s, %d(a0)\n", even, X4_E);
#else
    even = regs->x4_e;
#endif
    printf(INSNW(srli) "%s, %s, %d\n", regs->t1, regs->x4_o, 17);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t0, even, 17);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t3, regs->x4_o, 32 - 17);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t2, even, 32 - 17);
    binop(INSN(xor), regs->t0, even);
    binop(INSN(xor), regs->t1, regs->x4_o);
    binop(INSN(xor), regs->t0, regs->t2);
    binop(INSN(xor), regs->t1, regs->t3);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t2, regs->t0, 4);
    printf(INSNW(srli) "%s, %s, %d\n", regs->t3, regs->t1, 3);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t0, regs->t0, 32 - 4);
    printf(INSNW(slli) "%s, %s, %d\n", regs->t1, regs->t1, 32 - 3);
#ifdef RV32E
    binop(INSN(xor), regs->t2, regs->x4_o);
    binop2(INSN(xor), regs->x4_e, even, regs->t3);
    binop(INSN(xor), regs->t2, regs->t0);
    binop(INSN(xor), regs->x4_e, regs->t1);
    printf("\tsw\t%s, %d(a0)\n", regs->t2, X4_O);
#else
    binop(INSN(xor), regs->x4_o, regs->t2);
    binop2(INSN(xor), regs->x4_e, even, regs->t3);
    binop(INSN(xor), regs->x4_o, regs->t0);
    binop(INSN(xor), regs->x4_e, regs->t1);
#endif
}

/* Generate the body of the ASCON permutation function */
static void gen_permute(void)
{
    /*
     * x0/zero is hard-wired to zero.
     *
     * a0-a7 contain arguments and can be used as scratch registers.
     * t0-t6 can be used as scratch registers.
     *
     * s0/fp is the frame pointer.
     * ra is the link register.
     * t0 can be used as an alternative link register.
     * s1-s11 are callee-saved.
     */
    const char *first_round = "a1";
    reg_names regs = { .x0 = 0 };
    int round;
#ifdef RV32E
    regs.x0 = "a2";
    regs.x1 = "a3";
    regs.x2 = "a4";
    regs.x3 = "a5";
    regs.x4 = "t0";
    regs.t0 = "t1";
    regs.t1 = "t2";
    regs.t2 = "a1";
    regs.t3 = "s1";
    regs.t4 = "fp";
    regs.x0_e = regs.x0_o = regs.x0;
    regs.x1_e = regs.x1_o = regs.x1;
    regs.x2_e = regs.x2_o = regs.x2;
    regs.x3_e = regs.x3_o = regs.x3;
    regs.x4_e = regs.x4_o = regs.x4;
#else
    regs.x0_e = "a2";
    regs.x1_e = "a3";
    regs.x2_e = "a4";
    regs.x3_e = "a5";
    regs.x4_e = "a6";
    regs.x0_o = "a7";
    regs.x1_o = "t0";
    regs.x2_o = "t4";
    regs.x3_o = "t5";
    regs.x4_o = "t6";
    regs.x0 = regs.x0_e;
    regs.x1 = regs.x1_e;
    regs.x2 = regs.x2_e;
    regs.x3 = regs.x3_e;
    regs.x4 = regs.x4_e;
    regs.t0 = "t1";
    regs.t1 = "t2";
    regs.t2 = "t3";
    regs.t3 = "a1";
    regs.t4 = "s1";
#endif

    /* Create the stack frame and load all words into registers.
     * For RV32E we are very low on registers so we keep the even
     * words in registers between rounds and the odd words in
     * the original state structure.  The halves are swapped at
     * various points in the process. */
#ifdef RV32E
    /* ABI documentation suggests to align the stack on a 16 byte boundary */
    printf("\taddi\tsp, sp, -16\n");
    printf("\tlw\t%s, (a0)\n", regs.x0);
    printf("\tlw\t%s, %d(a0)\n", regs.x1, X1_E);
    printf("\tlw\t%s, %d(a0)\n", regs.x2, X2_E);
    printf("\tlw\t%s, %d(a0)\n", regs.t0, X2_O);
    printf("\tlw\t%s, %d(a0)\n", regs.x3, X3_E);
    printf("\tlw\t%s, %d(a0)\n", regs.x4, X4_E);
    unop(INSN(not), regs.x2, regs.x2);
    unop(INSN(not), regs.t0, regs.t0);

    /* Save s1 and fp on the stack for later */
#if RV64I_PLATFORM
    printf("\tsd\ts1, (sp)\n");
    printf("\tsd\tfp, 8(sp)\n");
#else
    printf("\tsw\ts1, (sp)\n");
    printf("\tsw\tfp, 4(sp)\n");
#endif

    /* Put the NOT'ed version of x2_o back into the state */
    printf("\tsw\t%s, %d(a0)\n", regs.t0, X2_O);
#else
    printf("\taddi\tsp, sp, -16\n");
#if RV64I_PLATFORM
    printf("\tsd\ts1, (sp)\n");
#else
    printf("\tsw\ts1, (sp)\n");
#endif
    printf("\tlw\t%s, (a0)\n", regs.x0_e);
    printf("\tlw\t%s, %d(a0)\n", regs.x0_o, X0_O);
    printf("\tlw\t%s, %d(a0)\n", regs.x1_e, X1_E);
    printf("\tlw\t%s, %d(a0)\n", regs.x1_o, X1_O);
    printf("\tlw\t%s, %d(a0)\n", regs.x2_e, X2_E);
    printf("\tlw\t%s, %d(a0)\n", regs.x2_o, X2_O);
    printf("\tlw\t%s, %d(a0)\n", regs.x3_e, X3_E);
    printf("\tlw\t%s, %d(a0)\n", regs.x3_o, X3_O);
    printf("\tlw\t%s, %d(a0)\n", regs.x4_e, X4_E);
    printf("\tlw\t%s, %d(a0)\n", regs.x4_o, X4_O);
    unop(INSN(not), regs.x2_e, regs.x2_e);
    unop(INSN(not), regs.x2_o, regs.x2_o);
#endif

    /* Determine which round is first and jump ahead.  Most of the time,
     * we will be seeing "first round" set to 6, 0, or 4 so we handle
     * those cases first.  But we can do any number of rounds.   If the
     * "first round" value is 12 or higher, then we will do nothing. */
    printf("\tli\t%s, 6\n", regs.t0);
    printf("\tbeq\t%s, %s, .L6\n", first_round, regs.t0);
    printf("\tbeq\t%s, x0, .L0\n", first_round);
    printf("\tli\t%s, 4\n", regs.t0);
    printf("\tbeq\t%s, %s, .L4\n", first_round, regs.t0);
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        printf("\tli\t%s, %d\n", regs.t0, round);
        printf("\tbeq\t%s, %s, .L%d\n", first_round, regs.t0, round);
    }
    printf("\tj\t.L12\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round(&regs, round);
    }

    /* Store the words back to the state and exit */
    printf(".L12:\n");
#ifdef RV32E
    unop(INSN(not), regs.x2, regs.x2);
    printf("\tlw\t%s, %d(a0)\n", regs.t0, X2_O);
    printf("\tsw\t%s, (a0)\n", regs.x0);
    printf("\tsw\t%s, %d(a0)\n", regs.x1, X1_E);
    printf("\tsw\t%s, %d(a0)\n", regs.x2, X2_E);
    unop(INSN(not), regs.t0, regs.t0);
    printf("\tsw\t%s, %d(a0)\n", regs.x3, X3_E);
    printf("\tsw\t%s, %d(a0)\n", regs.x4, X4_E);
    printf("\tsw\t%s, %d(a0)\n", regs.t0, X2_O);

    /* Pop the stack frame */
#if RV64I_PLATFORM
    printf("\tld\ts1, (sp)\n");
    printf("\tld\tfp, 8(sp)\n");
    printf("\taddi\tsp, sp, 16\n");
#else
    printf("\tlw\ts1, (sp)\n");
    printf("\tlw\tfp, 4(sp)\n");
    printf("\taddi\tsp, sp, 16\n");
#endif
#else /* RV32I */
    unop(INSN(not), regs.x2_e, regs.x2_e);
    unop(INSN(not), regs.x2_o, regs.x2_o);
    printf("\tsw\t%s, (a0)\n", regs.x0_e);
    printf("\tsw\t%s, %d(a0)\n", regs.x0_o, X0_O);
    printf("\tsw\t%s, %d(a0)\n", regs.x1_e, X1_E);
    printf("\tsw\t%s, %d(a0)\n", regs.x1_o, X1_O);
    printf("\tsw\t%s, %d(a0)\n", regs.x2_e, X2_E);
    printf("\tsw\t%s, %d(a0)\n", regs.x2_o, X2_O);
    printf("\tsw\t%s, %d(a0)\n", regs.x3_e, X3_E);
    printf("\tsw\t%s, %d(a0)\n", regs.x3_o, X3_O);
    printf("\tsw\t%s, %d(a0)\n", regs.x4_e, X4_E);
    printf("\tsw\t%s, %d(a0)\n", regs.x4_o, X4_O);

    /* Pop the stack frame */
#if RV64I_PLATFORM
    printf("\tld\ts1, (sp)\n");
    printf("\taddi\tsp, sp, 16\n");
#else
    printf("\tlw\ts1, (sp)\n");
    printf("\taddi\tsp, sp, 16\n");
#endif
#endif /* RV32I */
}

/* Output the function to free sensitive material in registers */
static void gen_backend_free(void)
{
    /* Clear all the scratch registers that we used in ascon_permute() */
    printf("\tli\ta1, 0\n");
    printf("\tli\ta2, 0\n");
    printf("\tli\ta3, 0\n");
    printf("\tli\ta4, 0\n");
    printf("\tli\ta5, 0\n");
#ifndef RV32E
    printf("\tli\ta6, 0\n");
    printf("\tli\ta7, 0\n");
#endif
    printf("\tli\tt0, 0\n");
    printf("\tli\tt1, 0\n");
    printf("\tli\tt2, 0\n");
#ifndef RV32E
    printf("\tli\tt3, 0\n");
    printf("\tli\tt4, 0\n");
    printf("\tli\tt5, 0\n");
    printf("\tli\tt6, 0\n");
#endif
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
#ifdef RV32E
    printf("#if defined(ASCON_BACKEND_RISCV32E)\n");
#else
    printf("#if defined(ASCON_BACKEND_RISCV32I)\n");
#endif
    fputs(copyright_message, stdout);
    printf("#ifdef __riscv_cmodel_pic\n");
    printf("\t.option\tpic\n");
    printf("#else\n");
    printf("\t.option\tnopic\n");
    printf("#endif\n");
    printf("\t.text\n");

    /* Output the permutation function */
    function_header("ascon_permute");
    gen_permute();
    function_footer("ascon_permute");

    /* Output the function to free sensitive material in registers */
    function_header("ascon_backend_free");
    gen_backend_free();
    function_footer("ascon_backend_free");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
