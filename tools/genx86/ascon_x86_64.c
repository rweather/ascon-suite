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
#include "x86_common.h"

/* List of all registers that we can work with */
typedef struct
{
    reg_t *x0;
    reg_t *x1;
    reg_t *x2;
    reg_t *x3;
    reg_t *x4;
    reg_t *t0;
    reg_t *t1;
    reg_t *t2;
    reg_t *t3;
    reg_t *t4;
    reg_t *t5;

} reg_names;

/* Applies the S-box to five 64-bit words of the state */
static void gen_sbox(reg_names *regs)
{
    /* x0 ^= x4;   x4 ^= x3;   x2 ^= x1; */
    binop("xor", regs->x0, regs->x4);
    binop("xor", regs->x4, regs->x3);
    reschedule(2); /* Improve scheduling of x4 ^= x3 */
    binop("xor", regs->x2, regs->x1);

    /* t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4; */
    binop("mov", regs->t0, regs->x0);
    binop("mov", regs->t1, regs->x1);
    binop("mov", regs->t2, regs->x2);
    binop("mov", regs->t3, regs->x3);
    binop("mov", regs->t4, regs->x4);
    unop("not", regs->t0);
    unop("not", regs->t1);
    unop("not", regs->t2);
    unop("not", regs->t3);
    unop("not", regs->t4);

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

    /* x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2; */
    binop("xor", regs->x1, regs->x0);
    binop("xor", regs->x0, regs->x4);
    binop("xor", regs->x3, regs->x2);
#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    unop("not", regs->x2);
#endif
}

/* Generate the code for a single ASCON round */
static void gen_round(reg_names *regs, int round)
{
    int rc;

    /* Apply the round constant to x2, and also NOT x2 in the process */
    rc = ~(((0x0F - round) << 4) | round);
    xor_rc(regs->x2, rc);

    /* Apply the S-box to the words of the state */
    gen_sbox(regs);

    /* Linear diffusion layer */
    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    binop("mov", regs->t0, regs->x0);
    binop("mov", regs->t1, regs->x0);
    binop("mov", regs->t2, regs->x1);
    binop("mov", regs->t3, regs->x1);
    binop("mov", regs->t4, regs->x2);
    binop("mov", regs->t5, regs->x2);
    ror(regs->t0, 19);
    ror(regs->t1, 28);
    ror(regs->t2, 61);
    ror(regs->t3, 39);
    ror(regs->t4, 1);
    ror(regs->t5, 6);
    binop("xor", regs->x0, regs->t0);
    binop("xor", regs->x1, regs->t2);
    binop("xor", regs->x2, regs->t4);
    binop("xor", regs->x0, regs->t1);
    binop("mov", regs->t0, regs->x3);
    binop("mov", regs->t2, regs->x4);
    binop("xor", regs->x1, regs->t3);
    binop("xor", regs->x2, regs->t5);
    binop("mov", regs->t1, regs->x3);
    binop("mov", regs->t3, regs->x4);
    ror(regs->t0, 10);
    ror(regs->t2, 7);
    ror(regs->t1, 17);
    binop("xor", regs->x3, regs->t0);
    ror(regs->t3, 41);
    binop("xor", regs->x4, regs->t2);
    binop("xor", regs->x3, regs->t1);
    binop("xor", regs->x4, regs->t3);
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
    const char *first_round = REG_RSI;
    reg_names regs;
    int round;
    char *reg_list[] = {
        REG_RAX, REG_RCX, REG_RDX, REG_R8, REG_R9, REG_RBX,
        REG_R10, REG_R11, REG_R12, REG_R13, REG_RSI, NULL
    };

    /* Start the register allocator */
    start_allocator(reg_list, REG_RDI, REG_RSP);

    /* Push callee-saved registers on the stack */
    push(REG_RBX);
    push(REG_R12);
    push(REG_R13);
    flush_pipeline();

    /* Load all words of the state into registers */
    regs.x0 = alloc_state("x0", 0);
    regs.x1 = alloc_state("x1", 8);
    regs.x2 = alloc_state("x2", 16);
    regs.x3 = alloc_state("x3", 24);
    regs.x4 = alloc_state("x4", 32);
    live(regs.x0);
    live(regs.x1);
    live(regs.x2);
    live(regs.x3);
    live(regs.x4);

    /* Allocate the registers that we need to hold temporary values */
    regs.t0 = alloc_temp("t0");
    regs.t1 = alloc_temp("t1");
    regs.t2 = alloc_temp("t2");
    regs.t3 = alloc_temp("t3");
    regs.t4 = alloc_temp("t4");
    regs.t5 = alloc_temp("t5");
    acquire(regs.t0);
    acquire(regs.t1);
    acquire(regs.t2);
    acquire(regs.t3);
    acquire(regs.t4);
    acquire(regs.t5);

    /* Invert x2 before entry to the rounds */
    unop("not", regs.x2);

    /* Switch on the "first round" parameter and jump ahead */
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNQ(cmp) "%s, 12\n", first_round);
    printf("\tjge\t.L13\n");
    printf(INSNQ(lea) "%s, [rip + .L14]\n", regs.t0->real_reg);
    printf(INSNQ(movsxd) "%s, [%s + %s*4]\n", regs.t1->real_reg, regs.t0->real_reg, first_round);
    printf(INSNQ(add) "%s, %s\n", regs.t1->real_reg, regs.t0->real_reg);
    printf("\tjmp\t%s\n", regs.t1->real_reg);
#else
    printf(INSNQ(cmp) "$12, %s\n", first_round);
    printf("\tjge\t.L13\n");
    printf(INSNQ(lea) ".L14(%%rip), %s\n", regs.t0->real_reg);
    printf(INSNQ(movsl) "(%s,%s,4), %s\n", regs.t0->real_reg, first_round, regs.t1->real_reg);
    printf(INSNQ(add) "%s, %s\n", regs.t0->real_reg, regs.t1->real_reg);
    printf("\tjmp\t*%s\n", regs.t1->real_reg);
#endif
    printf(".L13:\n");
    printf("\tjmp\t.L12\n");
    printf("\t.section\t.rodata\n");
    printf("\t.align\t4\n");
    printf(".L14:\n");
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
        flush_pipeline();
    }

    /* Store the words back to the state and exit */
    printf(".L12:\n");
    unop("not", regs.x2);
    spill(regs.x0);
    spill(regs.x1);
    spill(regs.x2);
    spill(regs.x3);
    spill(regs.x4);
    flush_pipeline();
    pop(REG_R13);
    pop(REG_R12);
    pop(REG_RBX);
    flush_pipeline();
}

/* Output the function to free sensitive material in registers */
static void gen_backend_free(void)
{
    /*
     * %rdi holds the pointer to the ASCON state on entry and exit.
     *
     * %rax, %rcx, %rdx, %rdi, %rsi, %r8, %r9, %r10, %r11 can be used
     * as scratch registers without saving.  These are the registers
     * that we need to destroy.
     *
     * %rbx, %rbp, %r12, %r13, %r14, %r15 must be callee-saved, so their
     * contents were already destroyed when ascon_permute() returned.
     */
    clear_reg(REG_RAX);
    clear_reg(REG_RCX);
    /* rdi contains the pointer to the state so it is already destroyed */
    /*clear_reg(REG_RDI);*/
    clear_reg(REG_RSI);
    clear_reg(REG_R8);
    clear_reg(REG_R9);
    clear_reg(REG_R10);
    clear_reg(REG_R11);
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

    /* Output the function to free sensitive material in registers */
    function_header("ascon_backend_free");
    gen_backend_free();
    function_footer("ascon_backend_free");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
