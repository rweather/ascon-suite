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
 * ASCON permutation for ARM v6m microprocessors.
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

static void function_header(const char *name)
{
    printf("\n\t.align\t2\n");
    printf("\t.global\t%s\n", name);
    printf("\t.thumb\n");
    printf("\t.thumb_func\n");
    printf("\t.type\t%s, %%function\n", name);
    printf("%s:\n", name);
}

static void function_footer(const char *name)
{
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
    const char *x0_alt;
    const char *x1_alt;
    const char *x2_alt;
    const char *x3_alt;
    const char *x4_alt;
    const char *x5_alt;
    const char *t0;
    const char *t1;
    const char *t2;

} reg_names;

static int is_low_reg(const char *reg)
{
    return reg[0] == 'r' && atoi(reg + 1) < 8;
}

/* Generates a binary operator, preferring thumb instructions if possible */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    if (is_low_reg(reg1) && is_low_reg(reg2))
        printf("\t%ss\t%s, %s\n", name, reg1, reg2);
    else
        printf("\t%s\t%s, %s\n", name, reg1, reg2);
}

/* Generates a "bic" instruction: dest = src1 & ~src2 */
static void bic(const char *dest, const char *src1, const char *src2)
{
    if (!strcmp(dest, src1) && is_low_reg(src1) && is_low_reg(src2)) {
        printf("\tbics\t%s, %s\n", src1, src2);
    } else if (is_low_reg(dest) && is_low_reg(src1) && is_low_reg(src2)) {
        printf("\tmvns\t%s, %s\n", dest, src2);
        printf("\tands\t%s, %s\n", dest, src1);
    } else {
        /* Not a armv6 instruction: use this to find errors in the generator */
        printf("\tbic\t%s, %s, %s\n", dest, src1, src2);
    }
}

/* Applies the S-box to five 32-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    binop("eor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("eor", regs->x4, regs->x3);       /* x4 ^= x3; */
    binop("eor", regs->x2, regs->x1);       /* x2 ^= x1; */
    binop("mov", regs->t1, regs->x0);       /* t1 = x0; */
    bic(regs->t0, regs->x1, regs->x0);      /* t0 = (~x0) & x1; */
    bic(regs->t2, regs->x2, regs->x1);      /* x0 ^= (~x1) & x2; */
    binop("eor", regs->x0, regs->t2);
    bic(regs->t2, regs->x3, regs->x2);      /* x1 ^= (~x2) & x3; */
    binop("eor", regs->x1, regs->t2);
    bic(regs->t2, regs->t1, regs->x4);      /* x3 ^= (~x4) & t1; */
    binop("eor", regs->x3, regs->t2);
    bic(regs->t2, regs->x4, regs->x3);      /* x2 ^= (~x3) & x4; */
    binop("eor", regs->x2, regs->t2);
    binop("eor", regs->x4, regs->t0);       /* x4 ^= t0; */
    binop("eor", regs->x1, regs->x0);       /* x1 ^= x0; */
    binop("eor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("eor", regs->x3, regs->x2);       /* x3 ^= x2; */
    binop("mvn", regs->x2, regs->x2);       /* x2 = ~x2; */
}

/* Rotate a value right and shift the result into a destination register */
static void rotate
    (const char *dest, const char *src, const char *immreg, int shift)
{
    if (shift != -1)
        printf("\tmovs\t%s, #%d\n", immreg, shift);
    if (!strcmp(dest, src)) {
        printf("\trors\t%s, %s, %s\n", dest, dest, immreg);
    } else {
        printf("\tmovs\t%s, %s\n", dest, src);
        printf("\trors\t%s, %s, %s\n", dest, dest, immreg);
    }
}

/* Generate the code for a single sliced ASCON round */
static void gen_round_sliced(const reg_names *regs, int round)
{
    /* Round constants for all rounds */
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };
    const char *immreg;

    /* Apply the round constant to x2_e */
    printf("\tmovs\t%s, #%d\n", regs->t0, RC[round * 2]);
    printf("\teors\t%s, %s\n", regs->x2, regs->t0);

    /* Apply the S-box to the even half of the state */
    gen_sbox(regs);

    /* Swap the even and odd halves of the state.  The odd words that
     * were in r8..r15 move to r0..r7 and the even words that were in
     * r0..r7 move to r8..r15.  Even is offset by 1 for easier swapping. */
    binop("mov", regs->x5_alt, regs->x4);
    binop("mov", regs->x4, regs->x4_alt);
    binop("mov", regs->x4_alt, regs->x3);
    binop("mov", regs->x3, regs->x3_alt);
    binop("mov", regs->x3_alt, regs->x2);
    binop("mov", regs->x2, regs->x2_alt);
    binop("mov", regs->x2_alt, regs->x1);
    binop("mov", regs->x1, regs->x1_alt);
    binop("mov", regs->x1_alt, regs->x0);
    binop("mov", regs->x0, regs->x0_alt);

    /* Apply the round constant to x2_o */
    printf("\tmovs\t%s, #%d\n", regs->t0, RC[round * 2 + 1]);
    printf("\teors\t%s, %s\n", regs->x2, regs->t0);

    /* Apply the S-box to the odd half of the state */
    gen_sbox(regs);

    /* Linear diffusion layer.  At the end of this, the even words
     * will be back in registers and the odd words back on the stack. */

    /* We are very low on registers, but need 4 temporaries to do
     * the work below.  Move x4 to the stack so that we can use it
     * an extra temporary.  Then later do the same with x0 when it
     * is time to operate on x4 for real. */
    printf("\tstr\t%s, [sp, #4]\n", regs->x4);
    immreg = regs->x4;

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    // t0 = x0_e ^ rightRotate4(x0_o);
    // t1 = x0_o ^ rightRotate5(x0_e);
    // x0_e ^= rightRotate9(t1);
    // x0_o ^= rightRotate10(t0);
    binop("mov", regs->t2, regs->x1_alt); // x0_e
    rotate(regs->t0, regs->x0, immreg, 4);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->t2, immreg, 5);
    binop("eor", regs->t1, regs->x0);
    rotate(regs->t0, regs->t0, immreg, 10);
    binop("eor", regs->t0, regs->x0);
    binop("mov", regs->x0_alt, regs->t0);
    rotate(regs->x0, regs->t1, immreg, 9);
    binop("eor", regs->x0, regs->t2);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
    binop("mov", regs->t2, regs->x2_alt); // x1_e
    rotate(regs->t0, regs->t2, immreg, 11);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->x1, immreg, -1); // 11 but we can avoid the load.
    binop("eor", regs->t1, regs->x1);
    rotate(regs->t0, regs->t0, immreg, 20);
    binop("eor", regs->t0, regs->x1);
    binop("mov", regs->x1_alt, regs->t0);
    rotate(regs->x1, regs->t1, immreg, 19);
    binop("eor", regs->x1, regs->t2);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
    binop("mov", regs->t2, regs->x3_alt); // x2_e
    rotate(regs->t0, regs->x2, immreg, 2);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->t2, immreg, 3);
    binop("eor", regs->t1, regs->x2);
    rotate(regs->t0, regs->t0, immreg, 1);
    binop("eor", regs->t0, regs->x2);
    binop("mov", regs->x2_alt, regs->t0);
    binop("mov", regs->x2, regs->t1);
    binop("eor", regs->x2, regs->t2);

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
    binop("mov", regs->t2, regs->x4_alt); // x3_e
    rotate(regs->t0, regs->x3, immreg, 3);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->t2, immreg, 4);
    binop("eor", regs->t1, regs->x3);
    rotate(regs->t1, regs->t1, immreg, 5);
    binop("eor", regs->t1, regs->x3);
    binop("mov", regs->x3_alt, regs->t1);
    rotate(regs->x3, regs->t0, immreg, -1); // 5 but we can avoid the load.
    binop("eor", regs->x3, regs->t2);

    /* Reclaim x4 and use x0 as the new fourth temporary */
    printf("\tldr\t%s, [sp, #4]\n", regs->x4);
    printf("\tstr\t%s, [sp, #4]\n", regs->x0);
    immreg = regs->x0;

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    // t0 = x4_e ^ rightRotate17(x4_e);
    // t1 = x4_o ^ rightRotate17(x4_o);
    // x4_e ^= rightRotate3(t1);
    // x4_o ^= rightRotate4(t0);
    binop("mov", regs->t2, regs->x5_alt); // x4_e
    rotate(regs->t0, regs->t2, immreg, 17);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->x4, immreg, -1); // 17 but we can avoid the load.
    binop("eor", regs->t1, regs->x4);
    rotate(regs->t0, regs->t0, immreg, 4);
    binop("eor", regs->t0, regs->x4);
    binop("mov", regs->x4_alt, regs->t0);
    rotate(regs->x4, regs->t1, immreg, 3);
    binop("eor", regs->x4, regs->t2);

    /* Reclaim x0 */
    printf("\tldr\t%s, [sp, #4]\n", regs->x0);
}

/* Generate the body of the 32-bit sliced ASCON permutation function */
static void gen_permute(void)
{
    /*
     * r0 holds the pointer to the ASCON state on entry and exit.
     *
     * r1 is the "first round" parameter on entry, which will normally be
     * one of the values 0, 4, or 6.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs;
    int round;
    regs.x0 = "r3";
    regs.x1 = "r4";
    regs.x2 = "r5";
    regs.x3 = "r6";
    regs.x4 = "r7";
    regs.x0_alt = "r8";
    regs.x1_alt = "r9";
    regs.x2_alt = "r10";
    regs.x3_alt = "fp";
    regs.x4_alt = "ip";
    regs.x5_alt = "lr";
    regs.t0 = "r0";
    regs.t1 = "r1";
    regs.t2 = "r2";
    printf("\tpush\t{r4, r5, r6, r7, lr}\n");
    binop("mov", "r2", "r8");
    binop("mov", "r3", "r9");
    binop("mov", "r4", "r10");
    binop("mov", "r5", "fp");
    printf("\tpush\t{r2, r3, r4, r5}\n");

    /*
     * The armv6m architecture has restrictions as to which registers
     * can be used for bitwise logical and shift operands.  For the most
     * part we are limited to r0..r7 using thumb instructions only.
     *
     * So while we can keep the entire state in registers, we cannot
     * always operate on it in-place.  The solution is to store the even
     * words in r0..r7 and the odd words in r8..r15.  We then swap the
     * halves at various points in the process.  The even words return
     * to the low registers between each round.
     */
    printf("\tsub\tsp, sp, #8\n");
    printf("\tstr\tr0, [sp, #0]\n");
    printf("\tldr\t%s, [r0, #%d]\n", regs.x0, X0_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x1, X1_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x2, X2_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x3, X3_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x4, X4_O);
    binop("mov", regs.x0_alt, regs.x0);
    binop("mov", regs.x1_alt, regs.x1);
    binop("mov", regs.x2_alt, regs.x2);
    binop("mov", regs.x3_alt, regs.x3);
    binop("mov", regs.x4_alt, regs.x4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x0, X0_E);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x1, X1_E);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x2, X2_E);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x3, X3_E);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x4, X4_E);

    /* Jump ahead to the first round that is specified by "r1" */
    printf("\tcmp\tr1, #11\n");
    printf("\tbhi\t.L91\n");
    printf("\tlsls\tr1, r1, #2\n");
    printf("\tadr\tr2, .L90\n");
    printf("\tldr\tr1, [r2, r1]\n");
    printf("\tadd\tr1, r2\n");
    printf("\tmov\tpc, r1\n");
    printf("\t.align\t2\n");
    printf(".L90:\n");
    for (round = 0; round < 12; ++round) {
        printf("\t.word\t.L%d-.L90\n", round);
    }
    printf(".L91:\n");
    /* This is not really a subroutine call as we immediately discard LR.
     * We use "bl" so that we can get a long branch as "b" can't reach. */
    printf("\tbl\t.L12\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round_sliced(&regs, round);
    }

    /* Store the words back to the state and exit */
    printf(".L12:\n");
    printf("\tmovs\tr1, #0\n");
    printf("\tldr\tr0, [sp, #0]\n");
    printf("\tstr\tr1, [sp, #4]\n"); /* Clear temporary variable slot */
    printf("\tstr\t%s, [r0, #%d]\n", regs.x0, X0_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x1, X1_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x2, X2_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x3, X3_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x4, X4_E);
    binop("mov", regs.x0, regs.x0_alt);
    binop("mov", regs.x1, regs.x1_alt);
    binop("mov", regs.x2, regs.x2_alt);
    binop("mov", regs.x3, regs.x3_alt);
    binop("mov", regs.x4, regs.x4_alt);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x0, X0_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x1, X1_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x2, X2_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x3, X3_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x4, X4_O);

    /* Pop the stack frame */
    printf("\tadd\tsp, sp, #8\n");
    printf("\tpop\t{r2, r3, r4, r5}\n");
    binop("mov", "r8", "r2");
    binop("mov", "r9", "r3");
    binop("mov", "r10", "r4");
    binop("mov", "fp", "r5");
    printf("\tpop\t{r4, r5, r6, r7, pc}\n");
}

/* Output the function to free sensitive material in registers */
static void gen_backend_free(void)
{
    /* Destroy the scratch registers: r1-r3 and ip.  We don't need to
     * destroy r0 as the caller already put the state pointer into it.
     * That will destroy any previous contents of r0. */
    printf("\tmovs\tr1, #0\n");
    printf("\tmovs\tr2, #0\n");
    printf("\tmovs\tr3, #0\n");
    printf("\tmov\tip, r1\n");
    printf("\tbx\tlr\n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
    printf("#if defined(ASCON_BACKEND_ARMV6M)\n");
    fputs(copyright_message, stdout);
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the sliced version of the permutation function */
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
