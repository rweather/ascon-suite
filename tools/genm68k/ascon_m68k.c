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
 * ASCON permutation for m68k or ColdFire microprocessors.
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
    printf("\t.globl\t%s\n", name);
    printf("\t.type\t%s, @function\n", name);
    printf("%s:\n", name);
}

static void function_footer(const char *name)
{
    printf("\trts\n");
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
    const char *x0_alt;
    const char *x1_alt;
    const char *x2_alt;
    const char *x3_alt;
    const char *x4_alt;
    const char *x5_alt;

} reg_names;

/* Generates a binary operator */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    printf("\t%s.l\t%s, %s\n", name, reg2, reg1);
}

/* Generates a register move operation */
static void mov(const char *reg1, const char *reg2)
{
    if (!strncmp(reg1, "%a", 2))
        printf("\tmovea.l\t%s, %s\n", reg2, reg1);
    else
        printf("\tmove.l\t%s, %s\n", reg2, reg1);
}

/* Generates a "bic" instruction: dest = ~src1 & src2 */
static void bic(const char *dest, const char *src1, const char *src2)
{
    printf("\tmove.l\t%s, %s\n", src1, dest);
    printf("\tnot.l\t%s\n", dest);
    printf("\tand.l\t%s, %s\n", src2, dest);
}

/* Rotates the contents of a register right */
static void ror
    (const char *reg, int shift, const char *temp1, const char *temp2)
{
    /* ColdFire does not have the "ror" and "rol" instructions, so we
     * need to perform the rotation using shift operations.  Other m68k
     * microprocessors do have "ror" and "rol" which simplifies things. */
    int left = 32 - shift;
    if (shift == 16) {
        /* A rotation of 16 is a simple swap of the 16-bit halves */
        printf("\tswap.w\t%s\n", reg);
        return;
    }
    printf("#ifdef __mcoldfire__\n");
    /* result = (reg >> shift) | (reg << (32 - shift)) */
    printf("\tmove.l\t%s, %s\n", reg, temp1);
    if (left <= 8) {
        printf("\tlsl.l\t#%d, %s\n", left, temp1);
    } else {
        printf("\tmoveq.l\t#%d, %s\n", left, temp2);
        printf("\tlsl.l\t%s, %s\n", temp2, temp1);
    }
    if (shift <= 8) {
        printf("\tlsr.l\t#%d, %s\n", shift, reg);
    } else {
        printf("\tmoveq.l\t#%d, %s\n", shift, temp2);
        printf("\tlsr.l\t%s, %s\n", temp2, reg);
    }
    printf("\tor.l\t%s, %s\n", temp1, reg);
    printf("#else\n");
    if (shift <= 8) {
        printf("\tror.l\t#%d, %s\n", shift, reg);
    } else if (left <= 8) {
        printf("\trol.l\t#%d, %s\n", left, reg);
    } else {
        printf("\tmoveq.l\t#%d, %s\n", shift, temp1);
        printf("\tror.l\t%s, %s\n", temp1, reg);
    }
    printf("#endif\n");
}

/* Applies the S-box to five 32-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    binop("eor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("eor", regs->x4, regs->x3);       /* x4 ^= x3; */
    binop("eor", regs->x2, regs->x1);       /* x2 ^= x1; */
    mov(regs->t1, regs->x0);                /* t1 = x0; */
    bic(regs->t0, regs->x0, regs->x1);      /* t0 = (~x0) & x1; */
    bic(regs->t2, regs->x1, regs->x2);      /* x0 ^= (~x1) & x2; */
    binop("eor", regs->x0, regs->t2);
    bic(regs->t2, regs->x2, regs->x3);      /* x1 ^= (~x2) & x3; */
    binop("eor", regs->x1, regs->t2);
    bic(regs->t2, regs->x4, regs->t1);      /* x3 ^= (~x4) & t1; */
    binop("eor", regs->x3, regs->t2);
    bic(regs->t2, regs->x3, regs->x4);      /* x2 ^= (~x3) & x4; */
    binop("eor", regs->x2, regs->t2);
    binop("eor", regs->x4, regs->t0);       /* x4 ^= t0; */
    binop("eor", regs->x1, regs->x0);       /* x1 ^= x0; */
    binop("eor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("eor", regs->x3, regs->x2);       /* x3 ^= x2; */

#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    printf("\tnot.l\t%s\n", regs->x2);
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
    const char *temp1;
    const char *temp2;

    /* Apply the round constant to x2_e */
    printf("\teori.l\t#%d, %s\n", ~((int)RC[round * 2]), regs->x2);

    /* Apply the S-box to the even half of the state */
    gen_sbox(regs);

    /* Swap the even and odd halves of the state.  The odd words that
     * were in a0..a4 move to d0..d4 and the even words that were in
     * d0..d4 move to a1..a5.  Even is offset by 1 for easier swapping. */
    mov(regs->x5_alt, regs->x4);
    mov(regs->x4, regs->x4_alt);
    mov(regs->x4_alt, regs->x3);
    mov(regs->x3, regs->x3_alt);
    mov(regs->x3_alt, regs->x2);
    mov(regs->x2, regs->x2_alt);
    mov(regs->x2_alt, regs->x1);
    mov(regs->x1, regs->x1_alt);
    mov(regs->x1_alt, regs->x0);
    mov(regs->x0, regs->x0_alt);

    /* Apply the round constant to x2_o */
    printf("\teori.l\t#%d, %s\n", ~((int)RC[round * 2 + 1]), regs->x2);

    /* Apply the S-box to the odd half of the state */
    gen_sbox(regs);

    /* Linear diffusion layer.  At the end of this, the even words will be
     * back in data registers and the odd words will be in address registers. */

    /* We are very low on data registers, and need 1 or 2 temporaries
     * to perform the rotations below.  Move x3 and x4 to the stack so
     * that we can use them as temporaries.  Then later do the same
     * with x0 and x1 when we need to operate with x3 and x4. */
    printf("\tmove.l\t%s, -44(%%fp)\n", regs->x3);
    printf("#ifdef __mcoldfire__\n");
    printf("\tmove.l\t%s, -48(%%fp)\n", regs->x4);
    printf("#endif\n");
    temp1 = regs->x3;
    temp2 = regs->x4;

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    // t0 = x0_e ^ rightRotate4(x0_o);
    // t1 = x0_o ^ rightRotate5(x0_e);
    // x0_e ^= rightRotate9(t1);
    // x0_o ^= rightRotate10(t0);
    mov(regs->t2, regs->x1_alt); // x0_e
    mov(regs->t0, regs->x0);
    mov(regs->t1, regs->t2);
    ror(regs->t0, 4, temp1, temp2);
    ror(regs->t1, 5, temp1, temp2);
    binop("eor", regs->t0, regs->t2);
    binop("eor", regs->t1, regs->x0);
    ror(regs->t0, 10, temp1, temp2);
    ror(regs->t1, 9, temp1, temp2);
    binop("eor", regs->t0, regs->x0);
    binop("eor", regs->t1, regs->t2);
    mov(regs->x0_alt, regs->t0);
    mov(regs->x0, regs->t1);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
    mov(regs->t2, regs->x2_alt); // x1_e
    mov(regs->t1, regs->x1);
    mov(regs->t0, regs->t2);
    ror(regs->t1, 11, temp1, temp2);
    ror(regs->t0, 11, temp1, temp2);
    binop("eor", regs->t1, regs->x1);
    binop("eor", regs->t0, regs->t2);
    ror(regs->t1, 19, temp1, temp2);
    ror(regs->t0, 20, temp1, temp2);
    binop("eor", regs->t1, regs->t2);
    binop("eor", regs->t0, regs->x1);
    mov(regs->x1_alt, regs->t0);
    mov(regs->x1, regs->t1);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
    mov(regs->t2, regs->x3_alt); // x2_e
    mov(regs->t0, regs->x0);
    mov(regs->t1, regs->t2);
    ror(regs->t0, 2, temp1, temp2);
    ror(regs->t1, 3, temp1, temp2);
    binop("eor", regs->t0, regs->t2);
    binop("eor", regs->t1, regs->x2);
    ror(regs->t0, 1, temp1, temp2);
    binop("eor", regs->t0, regs->x2);
    binop("eor", regs->t1, regs->t2);
    mov(regs->x2_alt, regs->t0);
    mov(regs->x2, regs->t1);

    /* Reclaim x3 and x4 and use x0 and x1 as the new temporaries */
    printf("#ifdef __mcoldfire__\n");
    printf("\tmove.l\t-44(%%fp), %s\n", regs->x3);
    printf("\tmove.l\t-48(%%fp), %s\n", regs->x4);
    printf("\tmove.l\t%s, -44(%%fp)\n", regs->x0);
    printf("\tmove.l\t%s, -48(%%fp)\n", regs->x1);
    printf("#else\n");
    printf("\tmove.l\t-44(%%fp), %s\n", regs->x3);
    printf("\tmove.l\t%s, -44(%%fp)\n", regs->x0);
    printf("#endif\n");
    temp1 = regs->x0;
    temp2 = regs->x1;

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
    mov(regs->t2, regs->x4_alt); // x3_e
    mov(regs->t0, regs->x3);
    mov(regs->t1, regs->t2);
    ror(regs->t0, 3, temp1, temp2);
    ror(regs->t1, 4, temp1, temp2);
    binop("eor", regs->t0, regs->t2);
    binop("eor", regs->t1, regs->x3);
    ror(regs->t0, 5, temp1, temp2);
    ror(regs->t1, 5, temp1, temp2);
    binop("eor", regs->t0, regs->t2);
    binop("eor", regs->t1, regs->x3);
    mov(regs->x3, regs->t0);
    mov(regs->x3_alt, regs->t1);

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    // t0 = x4_e ^ rightRotate17(x4_e);
    // t1 = x4_o ^ rightRotate17(x4_o);
    // x4_e ^= rightRotate3(t1);
    // x4_o ^= rightRotate4(t0);
    mov(regs->t2, regs->x5_alt); // x4_e
    mov(regs->t1, regs->x4);
    mov(regs->t0, regs->t2);
    ror(regs->t1, 17, temp1, temp2);
    ror(regs->t0, 17, temp1, temp2);
    binop("eor", regs->t1, regs->x4);
    binop("eor", regs->t0, regs->t2);
    ror(regs->t1, 3, temp1, temp2);
    ror(regs->t0, 4, temp1, temp2);
    binop("eor", regs->t1, regs->t2);
    binop("eor", regs->t0, regs->x4);
    mov(regs->x4_alt, regs->t0);
    mov(regs->x4, regs->t1);

    /* Reclaim x0 and x1 for the next round */
    printf("\tmove.l\t-44(%%fp), %s\n", regs->x0);
    printf("#ifdef __mcoldfire__\n");
    printf("\tmove.l\t-48(%%fp), %s\n", regs->x1);
    printf("#endif\n");
}

/* Generate the body of the 32-bit sliced ASCON permutation function */
static void gen_permute(void)
{
    /*
     * Arguments are passed on the stack.
     *
     * d0, d1, a0, and a1 can be used as scratch registers
     *
     * d2 .. d7 and a2 .. a5 must be callee-saved
     *
     * a6 is the frame pointer and a7 is the stack pointer
     */
    const char *state = "%a5";
    reg_names regs;
    int round;
    regs.x0 = "%d0";
    regs.x1 = "%d1";
    regs.x2 = "%d2";
    regs.x3 = "%d3";
    regs.x4 = "%d4";
    regs.t0 = "%d5";
    regs.t1 = "%d6";
    regs.t2 = "%d7";
    regs.x0_alt = "%a0";
    regs.x1_alt = "%a1";
    regs.x2_alt = "%a2";
    regs.x3_alt = "%a3";
    regs.x4_alt = "%a4";
    regs.x5_alt = "%a5";

    /* Set up the stack frame */
    printf("\tlink.w\t%%fp, #-48\n");
    printf("\tmove.l\t%%d2, -4(%%fp)\n");
    printf("\tmove.l\t%%d3, -8(%%fp)\n");
    printf("\tmove.l\t%%d4, -12(%%fp)\n");
    printf("\tmove.l\t%%d5, -16(%%fp)\n");
    printf("\tmove.l\t%%d6, -20(%%fp)\n");
    printf("\tmove.l\t%%d7, -24(%%fp)\n");
    printf("\tmove.l\t%%a2, -28(%%fp)\n");
    printf("\tmove.l\t%%a3, -32(%%fp)\n");
    printf("\tmove.l\t%%a4, -36(%%fp)\n");
    printf("\tmove.l\t%%a5, -40(%%fp)\n");

    /*
     * The m68k architecture has restrictions as to which registers
     * can be used for bitwise logical and shift operands.  We need
     * to restrict ourselves to data registers for the most part.
     *
     * So while we can keep the entire state in registers, we cannot
     * always operate on it in-place.  The solution is to store the even
     * words in data registers and the odd words in address registers.
     * We then swap the halves at various points in the process.
     * The even words return to the data registers between each round.
     *
     * We also invert x2_e and x2_o before the first round.
     */
    printf("\tmovea.l\t8(%%fp), %s\n", state);
    printf("\tmove.l\t(%s), %s\n", state, regs.x0);
    printf("\tmove.l\t%d(%s), %s\n", X1_E, state, regs.x1);
    printf("\tmove.l\t%d(%s), %s\n", X2_E, state, regs.x2);
    printf("\tmove.l\t%d(%s), %s\n", X3_E, state, regs.x3);
    printf("\tmove.l\t%d(%s), %s\n", X4_E, state, regs.x4);
    printf("\tnot.l\t%s\n", regs.x2);
    printf("\tmovea.l\t%d(%s), %s\n", X0_O, state, regs.x0_alt);
    printf("\tmovea.l\t%d(%s), %s\n", X1_O, state, regs.x1_alt);
    printf("\tmove.l\t%d(%s), %s\n", X2_O, state, regs.t0);
    printf("\tmovea.l\t%d(%s), %s\n", X3_O, state, regs.x3_alt);
    printf("\tnot.l\t%s\n", regs.t0);
    printf("\tmovea.l\t%d(%s), %s\n", X4_O, state, regs.x4_alt);
    printf("\tmovea.l\t%s, %s\n", regs.t0, regs.x2_alt);

    /* Determine which round is first and jump ahead.  Most of the time,
     * we will be seeing "first round" set to 6, 0, or 4 so we handle
     * those cases first.  But we can do any number of rounds.   If the
     * "first round" value is 12 or higher, then we will do nothing. */
    printf("\tmove.l\t12(%%fp), %s\n", regs.t2);
    printf("\tcmpi.l\t#6, %s\n", regs.t2);
    printf("\tjbeq\t.L6\n");
    printf("\tcmpi.l\t#0, %s\n", regs.t2);
    printf("\tjbeq\t.L0\n");
    printf("\tcmpi.l\t#4, %s\n", regs.t2);
    printf("\tjbeq\t.L4\n");
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        printf("\tcmpi.l\t#%d, %s\n", round, regs.t2);
        printf("\tjbeq\t.L%d\n", round);
    }
    printf("\tjmp\t.L12\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round_sliced(&regs, round);
    }

    /* Save the results back to the state after a final invert of x2_e/x2_o  */
    printf(".L12:\n");
    printf("\tmovea.l\t8(%%fp), %s\n", state);
    printf("\tnot.l\t%s\n", regs.x2);
    printf("\tmove.l\t%s, (%s)\n", regs.x0, state);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x1, X1_E, state);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x2, X2_E, state);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x3, X3_E, state);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x4, X4_E, state);
    printf("\tmove.l\t%s, %s\n", regs.x2_alt, regs.t0);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x0_alt, X0_O, state);
    printf("\tnot.l\t%s\n", regs.t0);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x1_alt, X1_O, state);
    printf("\tmove.l\t%s, %d(%s)\n", regs.t0, X2_O, state);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x3_alt, X3_O, state);
    printf("\tmove.l\t%s, %d(%s)\n", regs.x4_alt, X4_O, state);

    /* Destroy temporaries on the stack that were holding sensitive material */
    printf("\tmove.l\t%s, -44(%%fp)\n", state);
    printf("#ifdef __mcoldfire__\n");
    printf("\tmove.l\t%s, -48(%%fp)\n", state);
    printf("#endif\n");

    /* Pop the stack frame */
    printf("\tmove.l\t-4(%%fp), %%d2\n");
    printf("\tmove.l\t-8(%%fp), %%d3\n");
    printf("\tmove.l\t-12(%%fp), %%d4\n");
    printf("\tmove.l\t-16(%%fp), %%d5\n");
    printf("\tmove.l\t-20(%%fp), %%d6\n");
    printf("\tmove.l\t-24(%%fp), %%d7\n");
    printf("\tmovea.l\t-28(%%fp), %%a2\n");
    printf("\tmovea.l\t-32(%%fp), %%a3\n");
    printf("\tmovea.l\t-36(%%fp), %%a4\n");
    printf("\tmovea.l\t-40(%%fp), %%a5\n");
    printf("\tunlk\t%%fp\n");
}

/* Output the function to free sensitive material in registers */
static void gen_backend_free(void)
{
    /* Destroy the scratch registers: d0, d1, a0, and a1 */
    printf("\tmoveq.l\t#0, %%d0\n");
    printf("\tmoveq.l\t#0, %%d1\n");
    mov("%a0", "%d0");
    mov("%a1", "%d1");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
    printf("#if defined(ASCON_BACKEND_M68K)\n");
    fputs(copyright_message, stdout);
    printf("#NO_APP\n");
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
