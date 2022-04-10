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
 * ASCON permutation for Xtensa microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "copyright.h"

static void function_header(const char *name)
{
    printf("\t.section .text.%s,\"ax\",@progbits\n", name);
    printf("\t.align\t4\n");
    printf("\t.literal_position\n");
    printf("\t.global\t%s\n", name);
    printf("\t.type\t%s, @function\n", name);
    printf("%s:\n", name);
}

static void function_return(void)
{
    printf("#ifdef __XTENSA_WINDOWED_ABI__\n");
    printf("\tretw.n\n");
    printf("#else\n");
    printf("\tret.n\n");
    printf("#endif\n");
}

static void function_footer(const char *name)
{
    printf("\t.size\t%s, .-%s\n", name, name);
}

/* List of all registers that we can work with */
typedef struct
{
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
    const char *x0;
    const char *x1;
    const char *x2;
    const char *x3;
    const char *x4;
    const char *t0;
    const char *t1;
    const char *t2;

} reg_names;

/* Generates a binary operator */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    if (!strcmp(name, "mov"))
        printf("\t%s\t%s, %s\n", name, reg1, reg2);
    else if (!strcmp(name, "not")) /* Pseudo-instruction for doing a NOT */
        printf("\txor\t%s, %s, %s\n", reg1, reg2, "a15"); /* a15 is -1 */
    else
        printf("\t%s\t%s, %s, %s\n", name, reg1, reg1, reg2);
}

/* Generates a "bit clear" instruction: dest = ~src1 & src2 */
static void bic(const char *dest, const char *src1, const char *src2)
{
    binop("not", dest, src1);
    binop("and", dest, src2);
}

/* Applies the S-box to five 32-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    binop("xor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("xor", regs->x4, regs->x3);       /* x4 ^= x3; */
    binop("xor", regs->x2, regs->x1);       /* x2 ^= x1; */
    binop("mov", regs->t1, regs->x0);       /* t1 = x0; */
    bic(regs->t0, regs->x0, regs->x1);      /* t0 = (~x0) & x1; */
    bic(regs->t2, regs->x1, regs->x2);      /* x0 ^= (~x1) & x2; */
    binop("xor", regs->x0, regs->t2);
    bic(regs->t2, regs->x2, regs->x3);      /* x1 ^= (~x2) & x3; */
    binop("xor", regs->x1, regs->t2);
    bic(regs->t2, regs->x4, regs->t1);      /* x3 ^= (~x4) & t1; */
    binop("xor", regs->x3, regs->t2);
    bic(regs->t2, regs->x3, regs->x4);      /* x2 ^= (~x3) & x4; */
    binop("xor", regs->x2, regs->t2);
    binop("xor", regs->x4, regs->t0);       /* x4 ^= t0; */
    binop("xor", regs->x1, regs->x0);       /* x1 ^= x0; */
    binop("xor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("xor", regs->x3, regs->x2);       /* x3 ^= x2; */

#if 0
    /* This is done as part of the round constant */
    binop("not", regs->x2, regs->x2);       /* x2 = ~x2; */
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

/* Rotates the contents of a 32-bit register right */
static void ror(const char *dest, const char *src, int shift)
{
    /* Xtensa doesn't have an explicit "ror" instruction, but it does
     * have a "shift right combined" (SRC) instruction that can do the
     * same thing by concatenating two 32-bit registers and shifting
     * them together as a group. */
    if (shift != -1)
        printf("\tssai\t%d\n", shift);
    printf("\tsrc\t%s, %s, %s\n", dest, src, src);
}

/* Generate the code for a single sliced ASCON round */
static void gen_round_sliced(const reg_names *regs, int round)
{
    /* Sliced round constants for all rounds */
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };

    /* Apply the round constants to x2_e and x2_o */
    printf("\tmovi.n\t%s, %d\n", regs->t0, (int)(~RC[round * 2]));
    printf("\tmovi.n\t%s, %d\n", regs->t1, (int)(~RC[round * 2 + 1]));
    binop("xor", regs->x2_e, regs->t0);
    binop("xor", regs->x2_o, regs->t1);

    /* Apply the S-box to the even and odd halves of the state */
    gen_sbox_even(regs);
    gen_sbox_odd(regs);

    /* Linear diffusion layer */

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    // t0 = x0_e ^ rightRotate4(x0_o);
    // t1 = x0_o ^ rightRotate5(x0_e);
    // x0_e ^= rightRotate9(t1);
    // x0_o ^= rightRotate10(t0);
    ror(regs->t0, regs->x0_o, 4);
    ror(regs->t1, regs->x0_e, 5);
    binop("xor", regs->t0, regs->x0_e);
    binop("xor", regs->t1, regs->x0_o);
    ror(regs->t0, regs->t0, 10);
    ror(regs->t1, regs->t1, 9);
    binop("xor", regs->x0_o, regs->t0);
    binop("xor", regs->x0_e, regs->t1);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
    ror(regs->t0, regs->x1_e, 11);
    ror(regs->t1, regs->x1_o, -1); /* Avoid setting SSAI to 11 again */
    binop("xor", regs->t0, regs->x1_e);
    binop("xor", regs->t1, regs->x1_o);
    ror(regs->t0, regs->t0, 20);
    ror(regs->t1, regs->t1, 19);
    binop("xor", regs->x1_o, regs->t0);
    binop("xor", regs->x1_e, regs->t1);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
    ror(regs->t0, regs->x2_o, 2);
    ror(regs->t1, regs->x2_e, 3);
    binop("xor", regs->t0, regs->x2_e);
    binop("xor", regs->t1, regs->x2_o);
    ror(regs->t0, regs->t0, 1);
    binop("xor", regs->x2_e, regs->t1);
    binop("xor", regs->x2_o, regs->t0);

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
    ror(regs->t0, regs->x3_o, 3);
    ror(regs->t1, regs->x3_e, 4);
    binop("xor", regs->t0, regs->x3_e);
    binop("xor", regs->t1, regs->x3_o);
    ror(regs->t0, regs->t0, 5);
    ror(regs->t1, regs->t1, -1); /* Avoid setting SSAI to 5 again */
    binop("xor", regs->x3_e, regs->t0);
    binop("xor", regs->x3_o, regs->t1);

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    // t0 = x4_e ^ rightRotate17(x4_e);
    // t1 = x4_o ^ rightRotate17(x4_o);
    // x4_e ^= rightRotate3(t1);
    // x4_o ^= rightRotate4(t0);
    ror(regs->t0, regs->x4_e, 17);
    ror(regs->t1, regs->x4_o, -1); /* Avoid setting SSAI to 17 again */
    binop("xor", regs->t0, regs->x4_e);
    binop("xor", regs->t1, regs->x4_o);
    ror(regs->t0, regs->t0, 4);
    ror(regs->t1, regs->t1, 3);
    binop("xor", regs->x4_o, regs->t0);
    binop("xor", regs->x4_e, regs->t1);
}

/* Generate the body of the ASCON permutation function */
static void gen_permute(void)
{
    /*
     * a0 holds the return address pointer (link register).
     * a1 holds the stack pointer.
     * a2 holds the pointer to the ASCON state on entry and exit.
     * a3 holds the "first round" parameter on entry, which will normally be
     * one of the values 0, 4, or 6.
     *
     * a2-a15 can be used freely as scratch registers without saving if the
     * Xtensa has the Windowed Register Option configured.
     *
     * a2-a11 can be used freely as scratch registers without saving if the
     * Xtensa does not have the Windowed Register Option configured.
     * a12-a15 must be callee-saved in this case.
     */
    reg_names regs;
    int round;
    regs.x0_e = "a4";
    regs.x1_e = "a5";
    regs.x2_e = "a6";
    regs.x3_e = "a7";
    regs.x4_e = "a8";
    regs.x0_o = "a9";
    regs.x1_o = "a10";
    regs.x2_o = "a11";
    regs.x3_o = "a12";
    regs.x4_o = "a13";
    regs.t0 = "a2";
    regs.t1 = "a3";
    regs.t2 = "a14";
    /* a15 is used to hold the constant -1 to invert words */

    /* Establish the stack frame.  We need to save a2 for later to
     * free it up for use as a temporary during the function.
     * Note: The instruction set reference indicates that the stack
     * pointer must be aligned on a 16-byte boundary, but ESP32 seems
     * to require multiples of 32 instead, so that's what we do. */
    printf("#ifdef __XTENSA_WINDOWED_ABI__\n");
    printf("\tentry\tsp, 32\n");
    printf("\ts32i.n\ta2, sp, 0\n");
    printf("#else\n");
    printf("\taddi\tsp, sp, -32\n");
    printf("\ts32i.n\ta2, sp, 0\n");
    printf("\ts32i.n\ta12, sp, 4\n");
    printf("\ts32i.n\ta13, sp, 8\n");
    printf("\ts32i.n\ta14, sp, 12\n");
    printf("\ts32i.n\ta15, sp, 16\n");
    printf("#endif\n");

    /* Load all words of the state into registers */
    printf("\tl32i.n\t%s, a2, %d\n", regs.x0_e, 0);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x0_o, 4);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x1_e, 8);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x1_o, 12);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x2_e, 16);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x2_o, 20);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x3_e, 24);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x3_o, 28);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x4_e, 32);
    printf("\tl32i.n\t%s, a2, %d\n", regs.x4_o, 36);

    /* We will need the value -1 a lot during the S-boxes to invert words.
     * Load it into a15 now so that it is available later. */
    printf("\tmovi.n\ta15, -1\n");

    /* Invert x2 now so we can avoid doing that during the rounds */
    printf("\txor\t%s, %s, a15\n", regs.x2_e, regs.x2_e);
    printf("\txor\t%s, %s, a15\n", regs.x2_o, regs.x2_o);

    /* Determine which round is first and jump ahead.  Most of the time,
     * we will be seeing "first round" set to 6, 0, or 4 so we handle
     * those cases first.  But we can do any number of rounds.   If the
     * "first round" value is 12 or higher, then we will do nothing. */
    printf("\tbeqi\ta3, 6, .L6\n");
    printf("\tbeqz\ta3, .L0\n");
    printf("\tbeqi\ta3, 4, .L4\n");
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        /* Note: 9 and 11 cannot be encoded as an immediate constant
         * with the "beqi" instruction, so we need a temporary */
        if (round == 9 || round == 11) {
            printf("\tmovi.n\t%s, %d\n", regs.t1, round);
            printf("\tbeq\ta3, %s, .L%d\n", regs.t1, round);
        } else {
            printf("\tbeqi\ta3, %d, .L%d\n", round, round);
        }
    }
    printf("\tj\t.L12\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round_sliced(&regs, round);
    }

    /* Store the words back to the state and exit */
    printf(".L12:\n");
    printf("\tl32i.n\ta2, sp, 0\n");
    printf("\txor\t%s, %s, a15\n", regs.x2_e, regs.x2_e);
    printf("\txor\t%s, %s, a15\n", regs.x2_o, regs.x2_o);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x0_e, 0);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x0_o, 4);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x1_e, 8);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x1_o, 12);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x2_e, 16);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x2_o, 20);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x3_e, 24);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x3_o, 28);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x4_e, 32);
    printf("\ts32i.n\t%s, a2, %d\n", regs.x4_o, 36);

    /* Pop the stack frame, which is a NOP when register windows are in use */
    printf("#ifdef __XTENSA_WINDOWED_ABI__\n");
    printf("\tretw.n\n");
    printf("#else\n");
    printf("\tl32i.n\ta12, sp, 4\n");
    printf("\tl32i.n\ta13, sp, 8\n");
    printf("\tl32i.n\ta14, sp, 12\n");
    printf("\tl32i.n\ta15, sp, 16\n");
    printf("\taddi\tsp, sp, 32\n");
    printf("\tret.n\n");
    printf("#endif\n");
}

static int num_literals = 0;

/* Load an immediate value into a register */
static void loadimm(const char *reg, int value)
{
    if (value >= -32 && value <= 95) {
        printf("\tmovi.n\t%s, %d\n", reg, value);
    } else if (value >= -2048 && value <= 2048) {
        printf("\tmovi\t%s, %d\n", reg, value);
    } else {
        ++num_literals;
        printf("\t.literal .LC%d, %d\n", num_literals, value);
        printf("\tl32r\t%s, .LC%d\n", reg, num_literals);
    }
}

/* Do two bit_permute_step() operations in parallel to improve scheduling */
static void bit_permute_step_two
    (const char *y1, const char *y2, const char *t1, const char *t2,
     const char *t3, unsigned long mask, int shift)
{
    /* t = ((y >> (shift)) ^ y) & (mask);
     * y = (y ^ t) ^ (t << (shift)); */
    loadimm(t3, (int)mask);
    printf("\tsrli\t%s, %s, %d\n", t1, y1, shift);
    printf("\tsrli\t%s, %s, %d\n", t2, y2, shift);
    binop("xor", t1, y1);
    binop("xor", t2, y2);
    binop("and", t1, t3);
    binop("and", t2, t3);
    binop("xor", y1, t1);
    binop("xor", y2, t2);
    printf("\tslli\t%s, %s, %d\n", t1, t1, shift);
    printf("\tslli\t%s, %s, %d\n", t2, t2, shift);
    binop("xor", y1, t1);
    binop("xor", y2, t2);
}

/* Output the function to convert to sliced form */
static void gen_to_sliced(void)
{
    /*
     * a2 holds the pointer to the ASCON state to be rearranged.
     *
     * a2-a11 can be used freely as scratch registers without saving.
     */
    const char *state = "a2";
    const char *high = "a3";
    const char *low = "a4";
    const char *temp1 = "a5";
    const char *temp2 = "a6";
    const char *temp3 = "a7";
    const char *temp4 = "a8";
    const char *loop = "a9";

    /* Enter the function in windowed mode.  We don't need to create a
     * stack frame for non-windowed mode because there are no registers
     * that we need to preserve from the caller */
    printf("#ifdef __XTENSA_WINDOWED_ABI__\n");
    printf("\tentry\tsp, 32\n");
    printf("#endif\n");

    /* Top of the loop */
    loadimm(temp4, (int)0xFFFF0000);
    printf("\tmovi.n\t%s, 5\n", loop);
    printf(".L100:\n");

    /* Load high and low from the state */
    printf("\tl32i.n\t%s, %s, 0\n", high, state);
    printf("\tl32i.n\t%s, %s, 4\n", low, state);

    /* ascon_separate(high) and ascon_separate(low).  We can handle both
     * little-endian and big-endian cases with different masks and shifts. */
    printf("#ifdef __XTENSA_EL__\n");
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x22222222, 1);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0c0c0c0c, 2);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x000f000f, 12);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x000000ff, 24);
    printf("#else /* __XTENSA_EB__ */\n");
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x22222222, 1);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0c0c0c0c, 2);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x00f000f0, 4);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000ff00, 8);
    printf("#endif /* __XTENSA_EB__ */\n");

    /* rearrange and store back */
    //state->W[index] = (high << 16) | (low & 0x0000FFFFU);
    //state->W[index + 1] = (high & 0xFFFF0000U) | (low >> 16);
    printf("\textui\t%s, %s, 0, 16\n", temp1, low);
    printf("\tslli\t%s, %s, 16\n", temp2, high);
    printf("\textui\t%s, %s, 16, 16\n", temp3, low);
    printf("\tor\t%s, %s, %s\n", temp1, temp1, temp2);
    printf("\tand\t%s, %s, %s\n", high, high, temp4);
    printf("\ts32i.n\t%s, %s, 0\n", temp1, state);
    printf("\tor\t%s, %s, %s\n", high, high, temp3);
    printf("\ts32i.n\t%s, %s, 4\n", high, state);

    /* Bottom of the loop */
    printf("\taddi\t%s, %s, -1\n", loop, loop);
    printf("\taddi\t%s, %s, 8\n", state, state);
    printf("\tbnez\t%s, .L100\n", loop);
}

/* Output the function to convert from sliced form */
static void gen_from_sliced(void)
{
    /*
     * a2 holds the pointer to the ASCON state to be rearranged.
     *
     * a2-a11 can be used freely as scratch registers without saving.
     */
    const char *state = "a2";
    const char *high = "a3";
    const char *low = "a4";
    const char *temp1 = "a5";
    const char *temp2 = "a6";
    const char *temp3 = "a7";
    const char *temp4 = "a8";
    const char *loop = "a9";

    /* Enter the function in windowed mode.  We don't need to create a
     * stack frame for non-windowed mode because there are no registers
     * that we need to preserve from the caller */
    printf("#ifdef __XTENSA_WINDOWED_ABI__\n");
    printf("\tentry\tsp, 32\n");
    printf("#endif\n");

    /* Top of the loop */
    loadimm(temp4, (int)0xFFFF0000);
    printf("\tmovi.n\t%s, 5\n", loop);
    printf(".L101:\n");

    /* Load even and odd words from the state */
    printf("\tl32i.n\t%s, %s, 0\n", temp1, state);
    printf("\tl32i.n\t%s, %s, 4\n", temp2, state);

    /* rearrange the half words */
    // high = (state->W[index] >> 16) | (state->W[index + 1] & 0xFFFF0000U);
    // low  = (state->W[index] & 0x0000FFFFU) | (state->W[index + 1] << 16);
    printf("\textui\t%s, %s, 16, 16\n", high, temp1);
    printf("\tand\t%s, %s, %s\n", temp3, temp2, temp4);
    printf("\textui\t%s, %s, 0, 16\n", low, temp1);
    printf("\tor\t%s, %s, %s\n", high, high, temp3);
    printf("\tslli\t%s, %s, 16\n", temp2, temp2);
    printf("\tor\t%s, %s, %s\n", low, low, temp2);

    /* ascon_combine(high) and ascon_combine(low).  We can handle both
     * little-endian and big-endian cases with different masks and shifts. */
    printf("#ifdef __XTENSA_EL__\n");
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000aaaa, 15);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000cccc, 14);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000f0f0, 12);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x000000ff, 24);
    printf("#else /* __XTENSA_EB__ */\n");
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000aaaa, 15);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000cccc, 14);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000f0f0, 12);
    bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000ff00, 8);
    printf("#endif /* __XTENSA_EB__ */\n");
    printf("\ts32i.n\t%s, %s, 0\n", high, state);
    printf("\ts32i.n\t%s, %s, 4\n", low, state);

    /* Bottom of the loop */
    printf("\taddi\t%s, %s, -1\n", loop, loop);
    printf("\taddi\t%s, %s, 8\n", state, state);
    printf("\tbnez\t%s, .L101\n", loop);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
    printf("#if defined(ASCON_BACKEND_XTENSA)\n");
    fputs(copyright_message, stdout);

    /* Output the permutation function */
    function_header("ascon_permute");
    gen_permute();
    function_footer("ascon_permute");
    printf("\n");

    /* Output the function to convert to sliced form */
    function_header("ascon_from_regular");
    gen_to_sliced();
    function_return();
    function_footer("ascon_from_regular");
    printf("\n");

    /* Output the function to convert from sliced form */
    function_header("ascon_to_regular");
    gen_from_sliced();
    function_return();
    function_footer("ascon_to_regular");
    printf("\n");

    /* Output the file footer */
    printf("#endif\n");
    return 0;
}
