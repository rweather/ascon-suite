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
 * ASCON permutation for 64-bit RISC-V microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"

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
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;
    const char *t4;
    const char *t5;
    const char *t6;
    const char *t7;

} reg_names;

/* Generates a binary operator */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    if (!strcmp(name, "mv"))
        printf("\t%s\t%s, %s\n", name, reg1, reg2);
    else
        printf("\t%s\t%s, %s, %s\n", name, reg1, reg1, reg2);
}

/* Generates a unary operator */
static void unop(const char *name, const char *reg1, const char *reg2)
{
    printf("\t%s\t%s, %s\n", name, reg1, reg2);
}

/* Applies the S-box to five 64-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    /* x0 ^= x4;   x4 ^= x3;   x2 ^= x1; */
    binop("xor", regs->x0, regs->x4);
    binop("xor", regs->x2, regs->x1);
    binop("xor", regs->x4, regs->x3);

    /* t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4; */
    unop("not", regs->t0, regs->x0);
    unop("not", regs->t1, regs->x1);
    unop("not", regs->t2, regs->x2);
    unop("not", regs->t3, regs->x3);
    unop("not", regs->t4, regs->x4);

    /* t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0; */
    binop("and", regs->t0, regs->x1);
    binop("and", regs->t1, regs->x2);
    binop("and", regs->t2, regs->x3);
    binop("and", regs->t3, regs->x4);
    binop("and", regs->t4, regs->x0);

    /* x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0; */
    binop("xor", regs->x0, regs->t1);
    binop("xor", regs->x1, regs->t2);
    binop("xor", regs->x2, regs->t3);
    binop("xor", regs->x3, regs->t4);
    binop("xor", regs->x4, regs->t0);

    /* x1 ^= x0;   x0 ^= x4;   x3 ^= x2; */
    binop("xor", regs->x1, regs->x0);
    binop("xor", regs->x3, regs->x2);
    binop("xor", regs->x0, regs->x4);

#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    unop("not", regs->x2, regs->x2);            /* x2 = ~x2; */
#endif
}

/* Generate the code for a single ASCON round */
static void gen_round(const reg_names *regs, int round)
{
    /* Apply the round constant to x2, and also NOT x2 in the process */
    printf("\txori\t%s, %s, %d\n", regs->x2, regs->x2,
           ~((int)(((0x0F - round) << 4) | round)));

    /* Apply the S-box to the words of the state */
    gen_sbox(regs);

    /* Linear diffusion layer */
    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    printf("\tsrli\t%s, %s, %d\n", regs->t0, regs->x0, 19);
    printf("\tslli\t%s, %s, %d\n", regs->t1, regs->x0, 64 - 19);
    printf("\tsrli\t%s, %s, %d\n", regs->t2, regs->x0, 28);
    printf("\tslli\t%s, %s, %d\n", regs->t3, regs->x0, 64 - 28);
    printf("\tsrli\t%s, %s, %d\n", regs->t4, regs->x1, 61);
    printf("\tslli\t%s, %s, %d\n", regs->t5, regs->x1, 64 - 61);
    printf("\tsrli\t%s, %s, %d\n", regs->t6, regs->x1, 39);
    printf("\tslli\t%s, %s, %d\n", regs->t7, regs->x1, 64 - 39);
    printf("\tor\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
    printf("\tor\t%s, %s, %s\n", regs->t2, regs->t2, regs->t3);
    printf("\tor\t%s, %s, %s\n", regs->t4, regs->t4, regs->t5);
    printf("\tor\t%s, %s, %s\n", regs->t6, regs->t6, regs->t7);
    printf("\txor\t%s, %s, %s\n", regs->x0, regs->x0, regs->t0);
    printf("\txor\t%s, %s, %s\n", regs->x1, regs->x1, regs->t4);
    printf("\txor\t%s, %s, %s\n", regs->x0, regs->x0, regs->t2);
    printf("\txor\t%s, %s, %s\n", regs->x1, regs->x1, regs->t6);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    printf("\tsrli\t%s, %s, %d\n", regs->t0, regs->x2, 1);
    printf("\tslli\t%s, %s, %d\n", regs->t1, regs->x2, 64 - 1);
    printf("\tsrli\t%s, %s, %d\n", regs->t2, regs->x2, 6);
    printf("\tslli\t%s, %s, %d\n", regs->t3, regs->x2, 64 - 6);
    printf("\tsrli\t%s, %s, %d\n", regs->t4, regs->x3, 10);
    printf("\tslli\t%s, %s, %d\n", regs->t5, regs->x3, 64 - 10);
    printf("\tsrli\t%s, %s, %d\n", regs->t6, regs->x3, 17);
    printf("\tslli\t%s, %s, %d\n", regs->t7, regs->x3, 64 - 17);
    printf("\tor\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
    printf("\tor\t%s, %s, %s\n", regs->t2, regs->t2, regs->t3);
    printf("\tor\t%s, %s, %s\n", regs->t4, regs->t4, regs->t5);
    printf("\tor\t%s, %s, %s\n", regs->t6, regs->t6, regs->t7);
    printf("\txor\t%s, %s, %s\n", regs->x2, regs->x2, regs->t0);
    printf("\txor\t%s, %s, %s\n", regs->x3, regs->x3, regs->t4);
    printf("\txor\t%s, %s, %s\n", regs->x2, regs->x2, regs->t2);
    printf("\txor\t%s, %s, %s\n", regs->x3, regs->x3, regs->t6);

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    printf("\tsrli\t%s, %s, %d\n", regs->t0, regs->x4, 7);
    printf("\tslli\t%s, %s, %d\n", regs->t1, regs->x4, 64 - 7);
    printf("\tsrli\t%s, %s, %d\n", regs->t2, regs->x4, 41);
    printf("\tslli\t%s, %s, %d\n", regs->t3, regs->x4, 64 - 41);
    printf("\tor\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
    printf("\tor\t%s, %s, %s\n", regs->t2, regs->t2, regs->t3);
    printf("\txor\t%s, %s, %s\n", regs->x4, regs->x4, regs->t0);
    printf("\txor\t%s, %s, %s\n", regs->x4, regs->x4, regs->t2);
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
    reg_names regs;
    int round;
    regs.x0 = "a2";
    regs.x1 = "a3";
    regs.x2 = "a4";
    regs.x3 = "a5";
    regs.x4 = "a6";
    regs.t0 = "t1";
    regs.t1 = "t2";
    regs.t2 = "t3";
    regs.t3 = "t4";
    regs.t4 = "t5";
    regs.t5 = "t6";
    regs.t6 = "a1";
    regs.t7 = "a7";

    /* Load all words of the state into registers and invert x2 */
    printf("\tld\t%s, (a0)\n",   regs.x0);
    printf("\tld\t%s, 8(a0)\n",  regs.x1);
    printf("\tld\t%s, 16(a0)\n", regs.x2);
    printf("\tld\t%s, 24(a0)\n", regs.x3);
    printf("\tld\t%s, 32(a0)\n", regs.x4);
    printf("\tnot\t%s, %s\n", regs.x2, regs.x2);

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
    printf("\tnot\t%s, %s\n", regs.x2, regs.x2);
    printf("\tsd\t%s, (a0)\n",   regs.x0);
    printf("\tsd\t%s, 8(a0)\n",  regs.x1);
    printf("\tsd\t%s, 16(a0)\n", regs.x2);
    printf("\tsd\t%s, 24(a0)\n", regs.x3);
    printf("\tsd\t%s, 32(a0)\n", regs.x4);
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
    printf("\tli\ta6, 0\n");
    printf("\tli\ta7, 0\n");
    printf("\tli\tt1, 0\n");
    printf("\tli\tt2, 0\n");
    printf("\tli\tt3, 0\n");
    printf("\tli\tt4, 0\n");
    printf("\tli\tt5, 0\n");
    printf("\tli\tt6, 0\n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
    printf("#if defined(ASCON_BACKEND_RISCV64)\n");
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
