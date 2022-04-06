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
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;

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

    /* Store the even half to the stack and load the odd half into registers */
    printf("\tstr\t%s, [sp, #%d]\n", regs->x0, X0_E);
    printf("\tstr\t%s, [sp, #%d]\n", regs->x1, X1_E);
    printf("\tstr\t%s, [sp, #%d]\n", regs->x2, X2_E);
    printf("\tstr\t%s, [sp, #%d]\n", regs->x3, X3_E);
    printf("\tstr\t%s, [sp, #%d]\n", regs->x4, X4_E);
    printf("\tldr\t%s, [sp, #%d]\n", regs->x0, X0_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs->x1, X1_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs->x2, X2_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs->x3, X3_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs->x4, X4_O);

    /* Apply the round constant to x2_o */
    printf("\tmovs\t%s, #%d\n", regs->t0, RC[round * 2 + 1]);
    printf("\teors\t%s, %s\n", regs->x2, regs->t0);

    /* Apply the S-box to the odd half of the state */
    gen_sbox(regs);

    /* Linear diffusion layer.  At the end of this, the even words
     * will be back in registers and the odd words back on the stack. */

    /* We are very low on registers, but need 4 temporaries to do
     * the work below.  Move x4 to a high register so that we can
     * use it as an extra temporary.  Then later do the same with
     * x0 when it is time to operate on x4 for real. */
    binop("mov", regs->t3, regs->x4);
    immreg = regs->x4;

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    // t0 = x0_e ^ rightRotate4(x0_o);
    // t1 = x0_o ^ rightRotate5(x0_e);
    // x0_e ^= rightRotate9(t1);
    // x0_o ^= rightRotate10(t0);
    printf("\tldr\t%s, [sp, #%d]\n", regs->t2, X0_E);
    rotate(regs->t0, regs->x0, immreg, 4);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->x2, immreg, 5);
    binop("eor", regs->t1, regs->t0);
    rotate(regs->t0, regs->x0, immreg, 10);
    binop("eor", regs->t0, regs->x0);
    printf("\tstr\t%s, [sp, #%d]\n", regs->t0, X0_O);
    rotate(regs->x0, regs->t1, immreg, 9);
    binop("eor", regs->x0, regs->t2);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
    printf("\tldr\t%s, [sp, #%d]\n", regs->t2, X1_E);
    rotate(regs->t0, regs->t2, immreg, 11);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->x1, immreg, -1); // 11 but we can avoid the load.
    binop("eor", regs->t1, regs->x1);
    rotate(regs->t0, regs->t0, immreg, 20);
    binop("eor", regs->t0, regs->x1);
    printf("\tstr\t%s, [sp, #%d]\n", regs->t0, X1_O);
    rotate(regs->x1, regs->t1, immreg, 19);
    binop("eor", regs->x1, regs->t2);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
    printf("\tldr\t%s, [sp, #%d]\n", regs->t2, X2_E);
    rotate(regs->t0, regs->x2, immreg, 2);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->t2, immreg, 3);
    binop("eor", regs->t1, regs->x2);
    rotate(regs->t0, regs->t0, immreg, 1);
    binop("eor", regs->t0, regs->x2);
    printf("\tstr\t%s, [sp, #%d]\n", regs->t0, X2_O);
    binop("mov", regs->x2, regs->t1);
    binop("eor", regs->x2, regs->t2);

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
    printf("\tldr\t%s, [sp, #%d]\n", regs->t2, X3_E);
    rotate(regs->t0, regs->x3, immreg, 3);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->t2, immreg, 4);
    binop("eor", regs->t1, regs->x3);
    rotate(regs->t1, regs->t1, immreg, 5);
    binop("eor", regs->t1, regs->x3);
    printf("\tstr\t%s, [sp, #%d]\n", regs->t1, X3_O);
    rotate(regs->x3, regs->t0, immreg, -1); // 5 but we can avoid the load.
    binop("eor", regs->x3, regs->t2);

    /* Reclaim x4 and use x0 as the new fourth temporary */
    binop("mov", regs->x4, regs->t3);
    binop("mov", regs->t3, regs->x0);
    immreg = regs->x0;

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    // t0 = x4_e ^ rightRotate17(x4_e);
    // t1 = x4_o ^ rightRotate17(x4_o);
    // x4_e ^= rightRotate3(t1);
    // x4_o ^= rightRotate4(t0);
    printf("\tldr\t%s, [sp, #%d]\n", regs->t2, X4_E);
    rotate(regs->t0, regs->t2, immreg, 17);
    binop("eor", regs->t0, regs->t2);
    rotate(regs->t1, regs->x4, immreg, -1); // 17 but we can avoid the load.
    binop("eor", regs->t1, regs->x4);
    rotate(regs->t0, regs->t0, immreg, 4);
    binop("eor", regs->t0, regs->x4);
    printf("\tstr\t%s, [sp, #%d]\n", regs->t0, X4_O);
    rotate(regs->x4, regs->t1, immreg, 3);
    binop("eor", regs->x4, regs->t2);

    /* Reclaim x0 */
    binop("mov", regs->x0, regs->t3);
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
    regs.t0 = "r0";
    regs.t1 = "r1";
    regs.t2 = "r2";
    regs.t3 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, lr}\n");

    /* Since we are so low on registers, we need r0 for temporaries.
     * Shift the state to the stack so that we can offset via SP.
     * We keep the even words in registers between rounds and store
     * the odd words in the stack.  The even slots on the stack
     * will be filled later when we need to swap even and odd. */
    printf("\tsub\tsp, sp, #44\n");
    printf("\tstr\tr0, [sp, #40]\n");
    printf("\tldr\t%s, [r0, #%d]\n", regs.x0, X0_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x1, X1_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x2, X2_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x3, X3_O);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x4, X4_O);
    printf("\tstr\t%s, [sp, #%d]\n", regs.x0, X0_O);
    printf("\tstr\t%s, [sp, #%d]\n", regs.x1, X1_O);
    printf("\tstr\t%s, [sp, #%d]\n", regs.x2, X2_O);
    printf("\tstr\t%s, [sp, #%d]\n", regs.x3, X3_O);
    printf("\tstr\t%s, [sp, #%d]\n", regs.x4, X4_O);
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
    printf("\tbx\tr1\n");
    printf("\t.align\t2\n");
    printf(".L90:\n");
    for (round = 0; round < 12; ++round) {
        printf("\t.word\t.L%d\n", round);
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
    printf("\tldr\tr0, [sp, #40]\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.x0, X0_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x1, X1_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x2, X2_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x3, X3_E);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x4, X4_E);
    printf("\tldr\t%s, [sp, #%d]\n", regs.x0, X0_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs.x1, X1_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs.x2, X2_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs.x3, X3_O);
    printf("\tldr\t%s, [sp, #%d]\n", regs.x4, X4_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x0, X0_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x1, X1_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x2, X2_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x3, X3_O);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x4, X4_O);
    printf("\tadd\tsp, sp, #44\n");
    printf("\tpop\t{r4, r5, r6, r7, pc}\n");
}

/* Do two bit_permute_step() operations in parallel to improve scheduling */
static void bit_permute_step_two
    (const char *y1, const char *y2, const char *t1, const char *t2,
     const char *t3, unsigned long mask, int shift)
{
    /* t = ((y >> (shift)) ^ y) & (mask);
     * y = (y ^ t) ^ (t << (shift)); */
    if ((mask & 0xFFFFFF00U) == 0U)
        printf("\tmovs\t%s, #%lu\n", t3, mask);
    else
        printf("\tldr\t%s, =const_%08lx\n", t3, mask);
    printf("\tlsrs\t%s, %s, #%d\n", t1, y1, shift);
    printf("\tlsrs\t%s, %s, #%d\n", t2, y2, shift);
    printf("\teors\t%s, %s\n", t1, y1);
    printf("\teors\t%s, %s\n", t2, y2);
    binop("and", t1, t3);
    binop("and", t2, t3);
    binop("eor", y1, t1);
    binop("eor", y2, t2);
    printf("\tlsls\t%s, %s, #%d\n", t1, t1, shift);
    printf("\tlsls\t%s, %s, #%d\n", t2, t2, shift);
    printf("\teors\t%s, %s\n", y1, t1);
    printf("\teors\t%s, %s\n", y2, t2);
}

/* Generate a constant into the text segment */
static void gen_const(unsigned long mask)
{
    printf("const_%08lx:\n", mask);
    printf("\t.word\t0x%08lx\n", mask);
}

/* Output the function to convert to sliced form */
static void gen_to_sliced(void)
{
    /*
     * r0 holds the pointer to the ASCON state to be rearranged.
     * r1, r2, and r3 can be used as scratch registers without saving.
     */
    const char *state = "r0";
    const char *high = "r1";
    const char *low = "r2";
    const char *temp1 = "r3";
    const char *temp2 = "r4";
    const char *temp3 = "r5";
    const char *loop = "r6";

    /* Top of the main loop */
    printf("\tpush\t{%s, %s, %s, lr}\n", temp2, temp3, loop);
    printf("\tmovs\t%s, #5\n", loop);
    printf(".L100:\n");

    /* load high and low from the state */
    printf("\tldr\t%s, [%s]\n", high, state);
    printf("\tldr\t%s, [%s, #4]\n", low, state);

    /* ascon_separate(high) and ascon_separate(low) */
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x22222222, 1);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0c0c0c0c, 2);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x000f000f, 12);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x000000ff, 24);

    /* rearrange and store back */
    printf("\tuxth\t%s, %s\n", temp1, low);
    printf("\tlsls\t%s, %s, #16\n", temp3, high);
    printf("\torrs\t%s, %s\n", temp1, temp3);
    printf("\tlsrs\t%s, %s, #16\n", high, high);
    printf("\tstr\t%s, [%s]\n", temp1, state);
    printf("\tlsls\t%s, %s, #16\n", temp2, high);
    printf("\tlsrs\t%s, %s, #16\n", low, low);
    printf("\torrs\t%s, %s\n", temp2, low);
    printf("\tstr\t%s, [%s, #4]\n", temp2, state);
    printf("\tadds\t%s, %s, #8\n", state, state);

    /* Bottom of the main loop */
    printf("\tsubs\t%s, %s, #1\n", loop, loop);
    printf("\tbne\t.L100\n");
    printf("\tpop\t{%s, %s, %s, pc}\n", temp2, temp3, loop);
    printf("\t.align\t2\n");
    gen_const(0x22222222);
    gen_const(0x0c0c0c0c);
    gen_const(0x000f000f);
}

/* Output the function to convert from sliced form */
static void gen_from_sliced(void)
{
    /*
     * r0 holds the pointer to the ASCON state to be rearranged.
     * r1, r2, and r3 can be used as scratch registers without saving.
     */
    const char *state = "r0";
    const char *high = "r1";
    const char *low = "r2";
    const char *temp1 = "r3";
    const char *temp2 = "r4";
    const char *temp3 = "r5";
    const char *loop = "r6";

    /* Top of the main loop */
    printf("\tpush\t{%s, %s, %s, lr}\n", temp2, temp3, loop);
    printf("\tmovs\t%s, #5\n", loop);
    printf(".L101:\n");

    /* load high and low from the state */
    printf("\tldr\t%s, [%s]\n", high, state);
    printf("\tldr\t%s, [%s, #4]\n", low, state);

    /* rearrange the half words */
    printf("\tlsrs\t%s, %s, #16\n", temp1, low);
    printf("\tlsls\t%s, %s, #16\n", temp1, temp1);
    printf("\tuxth\t%s, %s\n", temp2, high);
    printf("\tlsrs\t%s, %s, #16\n", high, high);
    printf("\torrs\t%s, %s\n", high, temp1);
    printf("\tlsls\t%s, %s, #16\n", low, low);
    printf("\torrs\t%s, %s\n", low, temp2);

    /* ascon_combine(high) and ascon_combine(low) */
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000aaaa, 15);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000cccc, 14);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000f0f0, 12);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x000000ff, 24);
    printf("\tstr\t%s, [%s]\n", high, state);
    printf("\tstr\t%s, [%s, #4]\n", low, state);
    printf("\tadds\t%s, %s, #8\n", state, state);

    /* Bottom of the main loop */
    printf("\tsubs\t%s, %s, #1\n", loop, loop);
    printf("\tbne\t.L101\n");
    printf("\tpop\t{%s, %s, %s, pc}\n", temp2, temp3, loop);
    printf("\t.align\t2\n");
    gen_const(0x0000aaaa);
    gen_const(0x0000cccc);
    gen_const(0x0000f0f0);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-permutation-select.h\"\n");
    printf("#if defined(ASCON_BACKEND_ARMV6M)\n");
    fputs(copyright_message, stdout);
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
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
