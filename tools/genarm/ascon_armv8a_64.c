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
 * ASCON permutation for ARMv8a microprocessors (64-bit ARM).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"

static void function_header(const char *name)
{
    printf("\n\t.align\t2\n");
    printf("\t.p2align 4,,11\n");
    printf("\t.global\t%s\n", name);
    printf("\t.type\t%s, %%function\n", name);
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
    if (!strcmp(name, "mov") || !strcmp(name, "mvn"))
        printf("\t%s\t%s, %s\n", name, reg1, reg2);
    else
        printf("\t%s\t%s, %s, %s\n", name, reg1, reg1, reg2);
}

/* Generates a "bic" instruction: dest = ~src1 & src2 */
static void bic(const char *dest, const char *src1, const char *src2)
{
    printf("\tbic\t%s, %s, %s\n", dest, src2, src1);
}

/* Applies the S-box to five 64-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    binop("eor", regs->x0, regs->x4);           /* x0 ^= x4; */
    binop("eor", regs->x4, regs->x3);           /* x4 ^= x3; */
    binop("eor", regs->x2, regs->x1);           /* x2 ^= x1; */
    binop("mov", regs->t1, regs->x0);           /* t1 = x0; */
    bic(regs->t0, regs->x0, regs->x1);          /* t0 = (~x0) & x1; */
    bic(regs->t2, regs->x1, regs->x2);          /* x0 ^= (~x1) & x2; */
    binop("eor", regs->x0, regs->t2);
    bic(regs->t3, regs->x2, regs->x3);          /* x1 ^= (~x2) & x3; */
    binop("eor", regs->x1, regs->t3);
    bic(regs->t4, regs->x4, regs->t1);          /* x3 ^= (~x4) & t1; */
    binop("eor", regs->x3, regs->t4);
    bic(regs->t5, regs->x3, regs->x4);          /* x2 ^= (~x3) & x4; */
    binop("eor", regs->x2, regs->t5);
    binop("eor", regs->x4, regs->t0);           /* x4 ^= t0; */
    binop("eor", regs->x1, regs->x0);           /* x1 ^= x0; */
    binop("eor", regs->x0, regs->x4);           /* x0 ^= x4; */
    binop("eor", regs->x3, regs->x2);           /* x3 ^= x2; */

#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    binop("mvn", regs->x2, regs->x2);           /* x2 = ~x2; */
#endif
}

/* Generate the code for a single ASCON round */
static void gen_round(const reg_names *regs, int round)
{
    /* Apply the round constant to x2, and also NOT x2 in the process */
    printf("\tldr\t%s, =0x%llx\n", regs->t5,
           ~((unsigned long long)(((0x0F - round) << 4) | round))) &
           0xFFFFFFFFFFFFFFFFULL;
    printf("\teor\t%s, %s, %s\n", regs->x2, regs->x2, regs->t5);

    /* Apply the S-box to the words of the state */
    gen_sbox(regs);

    /* Linear diffusion layer */
    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    printf("\tror\t%s, %s, #%d\n", regs->t0, regs->x0, 19);
    printf("\tror\t%s, %s, #%d\n", regs->t1, regs->x1, 61);
    printf("\tror\t%s, %s, #%d\n", regs->t2, regs->x2, 1);
    printf("\tror\t%s, %s, #%d\n", regs->t3, regs->x3, 10);
    printf("\tror\t%s, %s, #%d\n", regs->t4, regs->x4, 7);
    printf("\teor\t%s, %s, %s, ror #%d\n", regs->x0, regs->x0, regs->x0, 28);
    printf("\teor\t%s, %s, %s, ror #%d\n", regs->x1, regs->x1, regs->x1, 39);
    printf("\teor\t%s, %s, %s, ror #%d\n", regs->x2, regs->x2, regs->x2, 6);
    printf("\teor\t%s, %s, %s, ror #%d\n", regs->x3, regs->x3, regs->x3, 17);
    printf("\teor\t%s, %s, %s, ror #%d\n", regs->x4, regs->x4, regs->x4, 41);
    printf("\teor\t%s, %s, %s\n", regs->x0, regs->x0, regs->t0);
    printf("\teor\t%s, %s, %s\n", regs->x1, regs->x1, regs->t1);
    printf("\teor\t%s, %s, %s\n", regs->x2, regs->x2, regs->t2);
    printf("\teor\t%s, %s, %s\n", regs->x3, regs->x3, regs->t3);
    printf("\teor\t%s, %s, %s\n", regs->x4, regs->x4, regs->t4);
}

/* Generate the body of the ASCON permutation function */
static void gen_permute(void)
{
    /*
     * x0 holds the pointer to the ASCON state on entry and exit.
     *
     * x1 is the "first round" parameter on entry, which will normally be
     * one of the values 0, 4, or 6.
     *
     * x0-x7, x9-x15 can be used as scratch registers without saving.
     * x19-x29 must be saved by the function.  The others have special
     * assignments and can be used as well.  But we have more than
     * enough registers without worrying about needing the special ones.
     */
    reg_names regs;
    int round;
    regs.x0 = "x2";
    regs.x1 = "x3";
    regs.x2 = "x4";
    regs.x3 = "x5";
    regs.x4 = "x6";
    regs.t0 = "x1";
    regs.t1 = "x7";
    regs.t2 = "x9";
    regs.t3 = "x10";
    regs.t4 = "x11";
    regs.t5 = "x12";

    /* Load all words of the state into registers */
    printf("\tldp\t%s, %s, [x0]\n", regs.x0, regs.x1);
    printf("\tldp\t%s, %s, [x0, 16]\n", regs.x2, regs.x3);
    printf("\tldr\t%s, [x0, 32]\n", regs.x4);
    binop("mvn", regs.x2, regs.x2);

    /* Determine which round is first and jump ahead.  Most of the time,
     * we will be seeing "first round" set to 6, 0, or 4 so we handle
     * those cases first.  But we can do any number of rounds.   If the
     * "first round" value is 12 or higher, then we will do nothing. */
    printf("\tand\tw1, w1, #255\n");
    printf("\tcmp\tw1, #6\n");
    printf("\tbeq\t.L6\n");
    printf("\tcmp\tw1, #0\n");
    printf("\tbeq\t.L0\n");
    printf("\tcmp\tw1, #4\n");
    printf("\tbeq\t.L4\n");
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        printf("\tcmp\tw1, #%d\n", round);
        printf("\tbeq\t.L%d\n", round);
    }
    printf("\tb\t.L12\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round(&regs, round);
    }

    /* Store the words back to the state and exit */
    printf(".L12:\n");
    binop("mvn", regs.x2, regs.x2);
    printf("\tstp\t%s, %s, [x0]\n", regs.x0, regs.x1);
    printf("\tstp\t%s, %s, [x0, 16]\n", regs.x2, regs.x3);
    printf("\tstr\t%s, [x0, 32]\n", regs.x4);
}

/* Output the function to convert to or from sliced form,
 * which is as simple as byte-reversing the 64-bit words */
static void gen_to_or_from_sliced(void)
{
    const char *x0 = "x1";
    const char *x1 = "x2";
    const char *x2 = "x3";
    const char *x3 = "x4";
    const char *x4 = "x5";
    printf("\tldp\t%s, %s, [x0]\n", x0, x1);
    printf("\tldp\t%s, %s, [x0, 16]\n", x2, x3);
    printf("\tldr\t%s, [x0, 32]\n", x4);
    printf("\trev\t%s, %s\n", x0, x0);
    printf("\trev\t%s, %s\n", x1, x1);
    printf("\trev\t%s, %s\n", x2, x2);
    printf("\trev\t%s, %s\n", x3, x3);
    printf("\trev\t%s, %s\n", x4, x4);
    printf("\tstp\t%s, %s, [x0]\n", x0, x1);
    printf("\tstp\t%s, %s, [x0, 16]\n", x2, x3);
    printf("\tstr\t%s, [x0, 32]\n", x4);
}

/* Output the function to free sensitive material in registers */
static void gen_backend_free(void)
{
    /*
     * The ascon_permute() function stores the state and temporaries
     * in x2-x7 and x9-x12 so technically only those registers need
     * to be destroyed.
     *
     * However, functions that call ascon_permute() could have staged
     * sensitive material in other registers prior to passing them in.
     * We destroy all of the scratch registers as a precaution.
     */
    printf("\tmov\tx1, #0\n");
    printf("\tmov\tx2, #0\n");
    printf("\tmov\tx3, #0\n");
    printf("\tmov\tx4, #0\n");
    printf("\tmov\tx5, #0\n");
    printf("\tmov\tx6, #0\n");
    printf("\tmov\tx7, #0\n");
    printf("\tmov\tx9, #0\n");
    printf("\tmov\tx10, #0\n");
    printf("\tmov\tx11, #0\n");
    printf("\tmov\tx12, #0\n");
    printf("\tmov\tx13, #0\n");
    printf("\tmov\tx14, #0\n");
    printf("\tmov\tx15, #0\n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#include \"ascon-select-backend.h\"\n");
    printf("#if defined(ASCON_BACKEND_ARMV8A)\n");
    fputs(copyright_message, stdout);
    printf("\t.arch\tarmv8-a\n");
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

    /* Output the function to free sensitive material in registers */
    function_header("ascon_backend_free");
    gen_backend_free();
    function_footer("ascon_backend_free");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
