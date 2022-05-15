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
 * masked ASCON permutation for x86-64 microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"
#include "x86_common.h"

/* Maximum number of shares that we can support */
#define MAX_SHARES 4

/* Number of shares to generate for */
static int num_shares = 2;

/* Each share is rotated with respect to the next by this much */
#define ROT_SHARE 11
#define ROT(n) (ROT_SHARE * (n))
#define UNROT(n) (64 - ROT_SHARE * (n))

/* List of all registers that we can work with */
typedef struct
{
    reg_t *x0[MAX_SHARES];
    reg_t *x1[MAX_SHARES];
    reg_t *x2[MAX_SHARES];
    reg_t *x3[MAX_SHARES];
    reg_t *x4[MAX_SHARES];
    reg_t *t0[MAX_SHARES];
    reg_t *t1[MAX_SHARES];
    reg_t *t2, *t3, *t4;

} reg_names;

/* Toffoli gate implementation: x ^= (~y) & z */
static void and_not_xor
    (reg_names *regs, reg_t **x, reg_t **y, reg_t **z)
{
    if (num_shares == 2) {
        /* x_a ^= ((~y_a) & ascon_mask64_unrotate_share1_0(z_b)); */
        move(regs->t2, y[0]);
        move(regs->t3, z[1]);
        unop(IN_NOT, regs->t2);
        ror(regs->t3, UNROT(1));
        binop(IN_AND, regs->t3, regs->t2);
        binop(IN_XOR, x[0], regs->t3);

        /* x_a ^= ((~y_a) & z_a); */
        binop(IN_AND, regs->t2, z[0]);
        binop(IN_XOR, x[0], regs->t2);

        /* x_b ^= (y_b & z_b); */
        /* x_b ^= (y_b & ascon_mask64_rotate_share1_0(z_a)); */
        move(regs->t3, y[1]);
        move(regs->t2, z[0]);
        binop(IN_AND, regs->t3, z[1]);
        ror(regs->t2, ROT(1));
        binop(IN_XOR, x[1], regs->t3);
        binop(IN_AND, regs->t2, y[1]);
        binop(IN_XOR, x[1], regs->t2);
    } else if (num_shares == 3) {
        /* x_a ^= (~(y_a) & z_a); */
        /* x_a ^= (y_a & ascon_mask64_unrotate_share1_0(z_b)); */
        /* x_a ^= (y_a & ascon_mask64_unrotate_share2_0(z_c)); */
        acquire(regs->t4);
        move(regs->t2, y[0]);
        move(regs->t3, z[1]);
        move(regs->t4, z[2]);
        unop(IN_NOT, regs->t2);
        ror(regs->t3, UNROT(1));
        ror(regs->t4, UNROT(2));
        binop(IN_AND, regs->t2, z[0]);
        binop(IN_AND, regs->t3, y[0]);
        binop(IN_AND, regs->t4, y[0]);
        binop(IN_XOR, x[0], regs->t2);
        binop(IN_XOR, x[0], regs->t3);
        binop(IN_XOR, x[0], regs->t4);

        /* x_b ^= (y_b & ascon_mask64_rotate_share1_0(z_a)); */
        /* x_b ^= ((~y_b) & z_b); */
        /* x_b ^= (y_b & ascon_mask64_unrotate_share2_1(z_c)); */
        move(regs->t2, y[1]);
        move(regs->t3, z[0]);
        move(regs->t4, z[2]);
        unop(IN_NOT, regs->t2);
        ror(regs->t3, ROT(1));
        ror(regs->t4, UNROT(1));
        binop(IN_AND, regs->t2, z[1]);
        binop(IN_AND, regs->t3, y[1]);
        binop(IN_AND, regs->t4, y[1]);
        binop(IN_XOR, x[1], regs->t2);
        binop(IN_XOR, x[1], regs->t3);
        binop(IN_XOR, x[1], regs->t4);

        /* x_c ^= (y_c & ascon_mask64_rotate_share2_0(~z_a)); */
        /* x_c ^= (y_c & ascon_mask64_rotate_share2_1(z_b)); */
        /* x_c ^= (y_c | z_c); */
        move(regs->t2, z[0]);
        move(regs->t3, z[1]);
        move(regs->t4, z[2]);
        unop(IN_NOT, regs->t2);
        ror(regs->t2, ROT(2));
        ror(regs->t3, ROT(1));
        binop(IN_AND, regs->t2, y[2]);
        binop(IN_AND, regs->t3, y[2]);
        binop(IN_OR, regs->t4, y[2]);
        binop(IN_XOR, x[2], regs->t2);
        binop(IN_XOR, x[2], regs->t3);
        binop(IN_XOR, x[2], regs->t4);
        release(regs->t4);
    } else if (num_shares == 4) {
        /* x##_a ^= (~(y##_a) & z##_a); */
        /* x##_a ^= (ascon_mask64_unrotate_share1_0(y##_b) & z##_a); */
        /* x##_a ^= (ascon_mask64_unrotate_share2_0(y##_c) & z##_a); */
        acquire(regs->t4);
        move(regs->t2, y[0]);
        move(regs->t3, y[1]);
        move(regs->t4, y[2]);
        unop(IN_NOT, regs->t2);
        ror(regs->t3, UNROT(1));
        ror(regs->t4, UNROT(2));
        binop(IN_AND, regs->t2, z[0]);
        binop(IN_AND, regs->t3, z[0]);
        binop(IN_AND, regs->t4, z[0]);
        binop(IN_XOR, x[0], regs->t2);
        binop(IN_XOR, x[0], regs->t3);
        binop(IN_XOR, x[0], regs->t4);

        /* x##_a ^= (ascon_mask64_unrotate_share3_0(y##_d) & z##_a); */
        /* x##_b ^= (ascon_mask64_rotate_share1_0(~(y##_a)) & z##_b); */
        /* x##_b ^= (y##_b & z##_b); */
        move(regs->t2, y[3]);
        move(regs->t3, y[0]);
        move(regs->t4, y[1]);
        ror(regs->t2, UNROT(3));
        unop(IN_NOT, regs->t3);
        binop(IN_AND, regs->t2, z[0]);
        ror(regs->t3, ROT(1));
        binop(IN_AND, regs->t4, z[1]);
        binop(IN_AND, regs->t3, z[1]);
        binop(IN_XOR, x[0], regs->t2);
        binop(IN_XOR, x[1], regs->t3);
        binop(IN_XOR, x[1], regs->t4);

        /* x##_b ^= (ascon_mask64_unrotate_share2_1(y##_c) & z##_b); */
        /* x##_b ^= (ascon_mask64_unrotate_share3_1(y##_d) & z##_b); */
        /* x##_c ^= (ascon_mask64_rotate_share2_0(~(y##_a)) & z##_c); */
        move(regs->t2, y[2]);
        move(regs->t3, y[3]);
        move(regs->t4, y[0]);
        ror(regs->t2, UNROT(1));
        unop(IN_NOT, regs->t4);
        ror(regs->t3, UNROT(2));
        ror(regs->t4, ROT(2));
        binop(IN_AND, regs->t2, z[1]);
        binop(IN_AND, regs->t3, z[1]);
        binop(IN_AND, regs->t4, z[2]);
        binop(IN_XOR, x[1], regs->t2);
        binop(IN_XOR, x[1], regs->t3);
        binop(IN_XOR, x[2], regs->t4);

        /* x##_c ^= (ascon_mask64_rotate_share2_1(y##_b) & z##_c); */
        /* x##_c ^= (y##_c & z##_c); */
        /* x##_c ^= (ascon_mask64_unrotate_share3_2(y##_d) & z##_c); */
        move(regs->t2, y[1]);
        move(regs->t3, y[2]);
        move(regs->t4, y[3]);
        ror(regs->t2, ROT(1));
        ror(regs->t4, UNROT(1));
        binop(IN_AND, regs->t2, z[2]);
        binop(IN_AND, regs->t3, z[2]);
        binop(IN_AND, regs->t4, z[2]);
        binop(IN_XOR, x[2], regs->t2);
        binop(IN_XOR, x[2], regs->t3);
        binop(IN_XOR, x[2], regs->t4);

        /* x##_d ^= (ascon_mask64_rotate_share3_0(~(y##_a)) & z##_d); */
        /* x##_d ^= (ascon_mask64_rotate_share3_1(y##_b) & z##_d); */
        /* x##_d ^= (ascon_mask64_rotate_share3_2(y##_c) & z##_d); */
        move(regs->t2, y[0]);
        move(regs->t3, y[1]);
        move(regs->t4, y[2]);
        unop(IN_NOT, regs->t2);
        ror(regs->t3, ROT(2));
        ror(regs->t4, ROT(1));
        ror(regs->t2, ROT(3));
        binop(IN_AND, regs->t3, z[3]);
        binop(IN_AND, regs->t4, z[3]);
        binop(IN_AND, regs->t2, z[3]);
        binop(IN_XOR, x[3], regs->t3);
        binop(IN_XOR, x[3], regs->t4);
        binop(IN_XOR, x[3], regs->t2);

        /* x##_d ^= (y##_d & z##_d); */
        move(regs->t3, y[3]);
        binop(IN_AND, regs->t3, z[3]);
        binop(IN_XOR, x[3], regs->t3);
        release(regs->t4);
    }
}

/* Applies the S-box to five 64-bit words of the state */
static void gen_sbox(reg_names *regs)
{
    reg_t *t0_end;
    int share;

    /* Affine step at the start of the substitution layer */
    /* x0 ^= x4; x4 ^= x3; x2 ^= x1; t1 = x0; */
    for (share = 0; share < num_shares; ++share) {
        binop(IN_XOR, regs->x0[share], regs->x4[share]);
        binop(IN_XOR, regs->x4[share], regs->x3[share]);
        binop(IN_XOR, regs->x2[share], regs->x1[share]);
        acquire(regs->t1[share]);
        move(regs->t1[share], regs->x0[share]);
    }

    /* Generate a randomized zero value in t0 */
    t0_end = regs->t0[num_shares - 1];
    acquire(t0_end);
    acquire(regs->t2);
    acquire(regs->t3);
    if (num_shares == 2) {
        move(t0_end, regs->t0[0]);
        ror(t0_end, ROT_SHARE);
    } else if (num_shares == 3) {
        move(t0_end, regs->t0[0]);
        move(regs->t2, regs->t0[1]);
        ror(t0_end, ROT_SHARE * 2);
        ror(regs->t2, ROT_SHARE);
        binop(IN_XOR, t0_end, regs->t2);
    } else {
        acquire(regs->t2);
        acquire(regs->t3);
        move(t0_end, regs->t0[0]);
        move(regs->t2, regs->t0[1]);
        move(regs->t3, regs->t0[2]);
        ror(t0_end, ROT_SHARE * 3);
        ror(regs->t2, ROT_SHARE * 2);
        ror(regs->t3, ROT_SHARE);
        binop(IN_XOR, t0_end, regs->t2);
        binop(IN_XOR, t0_end, regs->t3);
    }

    /* Toffoli gates in the middle of the subsitution layer */
    and_not_xor(regs, regs->t0, regs->x0, regs->x1);    /* t0 ^= (~x0) & x1; */
    and_not_xor(regs, regs->x0, regs->x1, regs->x2);    /* x0 ^= (~x1) & x2; */
    and_not_xor(regs, regs->x1, regs->x2, regs->x3);    /* x1 ^= (~x2) & x3; */
    and_not_xor(regs, regs->x2, regs->x3, regs->x4);    /* x2 ^= (~x3) & x4; */
    and_not_xor(regs, regs->x3, regs->x4, regs->t1);    /* x3 ^= (~x4) & t1; */
    release(regs->t2);
    release(regs->t3);

    /* Release the t1 temporary shares */
    for (share = 0; share < num_shares; ++share) {
        release(regs->t1[share]);
    }

    /* Affine step at the end of the substitution layer */
    /* x4 ^= t0; x1 ^= x0; x0 ^= x4; x3 ^= x2; */
    for (share = 0; share < num_shares; ++share) {
        binop(IN_XOR, regs->x4[share], regs->t0[share]);
        binop(IN_XOR, regs->x1[share], regs->x0[share]);
        binop(IN_XOR, regs->x0[share], regs->x4[share]);
        binop(IN_XOR, regs->x3[share], regs->x2[share]);
    }

    /* Release the temporary share t0[num_shares - 1] */
    release(t0_end);
}

/* Generate code for one step of the linear layer */
static void gen_linear(reg_names *regs, reg_t *x, int shift1, int shift2)
{
    move(regs->t2, x);
    move(regs->t3, x);
    ror(regs->t2, shift1);
    ror(regs->t3, shift2);
    binop(IN_XOR, x, regs->t2);
    binop(IN_XOR, x, regs->t3);
}

/* Generate code for two steps of the linear layer to try to
 * schedule the instructions further apart */
static void gen_linear_two
    (reg_names *regs, reg_t *xa, int shift1a, int shift2a,
     reg_t *xb, int shift1b, int shift2b)
{
    move(regs->t2, xa);
    move(regs->t1[0], xb);
    move(regs->t3, xa);
    move(regs->t1[1], xb);
    ror(regs->t2, shift1a);
    ror(regs->t1[0], shift1b);
    ror(regs->t3, shift2a);
    ror(regs->t1[1], shift2b);
    binop(IN_XOR, xa, regs->t2);
    binop(IN_XOR, xb, regs->t1[0]);
    binop(IN_XOR, xa, regs->t3);
    binop(IN_XOR, xb, regs->t1[1]);
}

/* Generate the code for a single ASCON round */
static void gen_round(reg_names *regs, const char *rc)
{
    /* XOR the round constant with x2 */
    xor_direct(regs->x2[0], rc);
    reschedule(3); /* Move the rc XOR down a bit in the final code */

    /* Apply the S-box to the words of the state */
    gen_sbox(regs);

    /* Linear diffusion layer */
    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    acquire(regs->t2);
    acquire(regs->t3);
    acquire(regs->t1[0]);
    acquire(regs->t1[1]);
    if (num_shares == 2) {
        gen_linear_two(regs, regs->x0[1], 19, 28, regs->x1[1], 61, 39);
        gen_linear_two(regs, regs->x2[1],  1,  6, regs->x3[1], 10, 17);
        gen_linear_two(regs, regs->x4[1],  7, 41, regs->x0[0], 19, 28);
        gen_linear_two(regs, regs->x1[0], 61, 39, regs->x2[0],  1,  6);
        gen_linear_two(regs, regs->x3[0], 10, 17, regs->x4[0],  7, 41);
    } else if (num_shares == 3) {
        gen_linear_two(regs, regs->x0[2], 19, 28, regs->x1[2], 61, 39);
        gen_linear_two(regs, regs->x2[2],  1,  6, regs->x3[2], 10, 17);
        gen_linear_two(regs, regs->x4[2],  7, 41, regs->x0[1], 19, 28);
        gen_linear_two(regs, regs->x1[1], 61, 39, regs->x2[1],  1,  6);
        gen_linear_two(regs, regs->x3[1], 10, 17, regs->x4[1],  7, 41);
        gen_linear_two(regs, regs->x0[0], 19, 28, regs->x1[0], 61, 39);
        gen_linear_two(regs, regs->x2[0],  1,  6, regs->x3[0], 10, 17);
        gen_linear    (regs, regs->x4[0],  7, 41);
    } else {
        gen_linear_two(regs, regs->x0[3], 19, 28, regs->x1[3], 61, 39);
        gen_linear_two(regs, regs->x2[3],  1,  6, regs->x3[3], 10, 17);
        gen_linear_two(regs, regs->x4[3],  7, 41, regs->x0[2], 19, 28);
        gen_linear_two(regs, regs->x1[2], 61, 39, regs->x2[2],  1,  6);
        gen_linear_two(regs, regs->x3[2], 10, 17, regs->x4[2],  7, 41);
        gen_linear_two(regs, regs->x0[1], 19, 28, regs->x1[1], 61, 39);
        gen_linear_two(regs, regs->x2[1],  1,  6, regs->x3[1], 10, 17);
        gen_linear_two(regs, regs->x4[1],  7, 41, regs->x0[0], 19, 28);
        gen_linear_two(regs, regs->x1[0], 61, 39, regs->x2[0],  1,  6);
        gen_linear_two(regs, regs->x3[0], 10, 17, regs->x4[0],  7, 41);
    }
    release(regs->t2);
    release(regs->t3);
    release(regs->t1[0]);
    release(regs->t1[1]);
}

/* Generate the body of the ASCON permutation function */
static void gen_permute(int max_shares)
{
    /*
     * %rdi holds the pointer to the ASCON state on entry and exit.
     *
     * %rsi is the "first round" parameter on entry, which will normally be
     * one of the values 0, 4, or 6.
     *
     * %rdx is the "preserve" parameter.
     *
     * %rax, %rcx, %rdx, %rdi, %rsi, %r8, %r9, %r10, %r11 can be used
     * as scratch registers without saving.
     *
     * %rbx, %rbp, %r12, %r13, %r14, %r15 must be callee-saved.
     */
    const char *first_round = REG_RSI;
    const char *preserve = REG_RDX;
    reg_names regs;
    int share;
    char *reg_list[] = {
        /* RDI keeps the state pointer throughout the function because
         * we need the state to be able to spill to and reload from */
        REG_RAX, REG_RCX, REG_R8, REG_R9, REG_R10, REG_R11, REG_R12,
        REG_R13, REG_R14, REG_R15, REG_RBX, REG_RBP, REG_RSI, REG_RDX, NULL
    };
    char *reg_names[7][4] = {
        {"x0_a", "x0_b", "x0_c", "x0_d"},
        {"x1_a", "x1_b", "x1_c", "x1_d"},
        {"x2_a", "x2_b", "x2_c", "x2_d"},
        {"x3_a", "x3_b", "x3_c", "x3_d"},
        {"x4_a", "x4_b", "x4_c", "x4_d"},
        {"t0_a", "t0_b", "t0_c", "t0_d"},
        {"t1_a", "t1_b", "t1_c", "t1_d"},
    };

    /* Push callee-saved registers on the stack */
    push(REG_RBP);
    push(REG_RBX);
    push(REG_R12);
    push(REG_R13);
    push(REG_R14);
    push(REG_R15);
    flush_pipeline();

    /* Start the register allocator */
    start_allocator(reg_list, REG_RDI, REG_RSP);
    memset(&regs, 0, sizeof(regs));

    /* Allocate the state registers and temporaries */
    for (share = 0; share < num_shares; ++share) {
        regs.x0[share] = alloc_state
            (reg_names[0][share], 0 * max_shares * 8 + share * 8);
        regs.x1[share] = alloc_state
            (reg_names[1][share], 1 * max_shares * 8 + share * 8);
        regs.x2[share] = alloc_state
            (reg_names[2][share], 2 * max_shares * 8 + share * 8);
        regs.x3[share] = alloc_state
            (reg_names[3][share], 3 * max_shares * 8 + share * 8);
        regs.x4[share] = alloc_state
            (reg_names[4][share], 4 * max_shares * 8 + share * 8);
        regs.t0[share] = alloc_temp(reg_names[5][share]);
        regs.t1[share] = alloc_temp(reg_names[6][share]);
    }
    regs.t2 = alloc_temp("t2");
    regs.t3 = alloc_temp("t3");
    regs.t4 = alloc_temp("t4");

    /* Load the preserved words into temporaries and keep them there */
    for (share = 0; share < (num_shares - 1); ++share) {
        acquire(regs.t0[share]);
        pin(regs.t0[share]);
        load(regs.t0[share], preserve, share * 8);
    }
    push(preserve); /* Free up RDX for use as a temporary */

    /* Load the value of x2_a and keep it in a register between rounds.
     * Also invert it before the first round. */
    live(regs.x2[0]);
    pin(regs.x2[0]);
    unop(IN_NOT, regs.x2[0]);

    /*
     * Compute the round constant for the first round:
     *
     *    rc = ~(((0x0F - first_round) << 4) | first_round)
     *       = -((15 - first_round) * 16 + first_round) - 1
     *       = (first_round - 15) * 16 - first_round - 1
     */
    acquire(regs.t2);
    move_direct(regs.t2->real_reg, first_round);
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNQ(sub) "%s, 15\n", first_round);
    printf(INSNQ(shl) "%s, 4\n", first_round);
    printf(INSNQ(sub) "%s, %s\n", first_round, regs.t2->real_reg);
    printf(INSNQ(sub) "%s, 1\n", first_round);
#else
    printf(INSNQ(sub) "$15, %s\n", first_round);
    printf(INSNQ(shl) "$4, %s\n", first_round);
    printf(INSNQ(sub) "%s, %s\n", regs.t2->real_reg, first_round);
    printf(INSNQ(sub) "$1, %s\n", first_round);
#endif
    release(regs.t2);
    flush_pipeline();
    printf("\tjmp\t.L1\n");

    /* Top of the round loop */
    printf(".L0:\n");
    push(first_round); /* Free RSI up for use as a temporary */

    /* Generate the code for the round */
    gen_round(&regs, first_round);

    /* Ensure that the state is completely spilled before looping back */
    for (share = 0; share < num_shares; ++share) {
        spill(regs.x0[share]);
        spill(regs.x1[share]);
        spill(regs.x2[share]);
        spill(regs.x3[share]);
        spill(regs.x4[share]);
    }
    flush_pipeline();

    /* Bottom of the round loop */
    pop(first_round);
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNQ(add) "%s, 15\n", first_round);
    printf(".L1:\n");
    printf(INSNQ(cmp) "%s, -61\n", first_round);
#else
    printf(INSNQ(add) "$15, %s\n", first_round);
    printf(".L1:\n");
    printf(INSNQ(cmp) "$-61, %s\n", first_round);
#endif
    printf("\tjl\t.L0\n");

    /* Save the preserved randomness back to the caller-supplied buffer */
    acquire(regs.t2);
    preserve = regs.t2->real_reg;
    pop(preserve);
    for (share = 0; share < (num_shares - 1); ++share) {
        store(regs.t0[share], preserve, share * 8);
    }

    /* Store the unspilled words back to the state */
    unop(IN_NOT, regs.x2[0]);
    unpin(regs.x2[0]);
    spill(regs.x2[0]);

    /* Destroy sensitive values in registers and return */
    clear_reg(REG_RAX);
    clear_reg(REG_RCX);
    clear_reg(REG_RSI);
    clear_reg(REG_R8);
    clear_reg(REG_R9);
    clear_reg(REG_R10);
    clear_reg(REG_R11);
    flush_pipeline();
    pop(REG_R15);
    pop(REG_R14);
    pop(REG_R13);
    pop(REG_R12);
    pop(REG_RBX);
    pop(REG_RBP);
    flush_pipeline();
}

int main(int argc, char *argv[])
{
    char function_name[64];
    int share_count;
    int need_elif;

    /* Get the number of shares from the command-line */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s num-shares\n", argv[0]);
        return 1;
    }
    num_shares = atoi(argv[1]);
    if (num_shares < 2 || num_shares > MAX_SHARES) {
        fprintf(stderr, "invalid number of shares\n");
        return 1;
    }

    /* Output the file header */
    printf("#include \"ascon-masked-backend.h\"\n");
    printf("#if defined(ASCON_MASKED_X%d_BACKEND_X86_64) && ASCON_MASKED_MAX_SHARES >= %d\n", num_shares, num_shares);
    fputs(copyright_message, stdout);
#if INTEL_SYNTAX
    printf("\t.intel_syntax noprefix\n");
#endif
    printf("#if defined(__APPLE__)\n");
    printf("\t.section __TEXT,__text,regular,pure_instructions\n");
    printf("#else\n");
    printf("\t.text\n");
    printf("#endif\n");

    /* Output several versions of the permutation function depending
     * upon the value of ASCON_MASKED_MAX_SHARES because the offsets into the
     * state will change with different configurations. */
    need_elif = 0;
    for (share_count = MAX_SHARES; share_count >= num_shares; --share_count) {
        if (need_elif) {
            printf("#elif ASCON_MASKED_MAX_SHARES >= %d\n", share_count);
        } else {
            printf("#if ASCON_MASKED_MAX_SHARES >= %d\n", share_count);
            need_elif = 1;
        }
        snprintf(function_name, sizeof(function_name),
                 "ascon_x%d_permute", num_shares);
        function_header(function_name);
        gen_permute(share_count);
        function_footer(function_name);
    }
    printf("#endif\n");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
