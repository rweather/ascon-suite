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
#include "x86_common.h"

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

/* List of all registers that we can work with */
typedef struct
{
    reg_t *x0_e;
    reg_t *x1_e;
    reg_t *x2_e;
    reg_t *x3_e;
    reg_t *x4_e;
    reg_t *x0_o;
    reg_t *x1_o;
    reg_t *x2_o;
    reg_t *x3_o;
    reg_t *x4_o;
    reg_t *x0;
    reg_t *x1;
    reg_t *x2;
    reg_t *x3;
    reg_t *x4;
    reg_t *t0;
    reg_t *t1;

} reg_names;

/* Applies the S-box to five 32-bit words of the state */
static void gen_sbox(reg_names *regs)
{
    /* x0 ^= x4;   x4 ^= x3;   x2 ^= x1; */
    binop(IN_XOR, regs->x0, regs->x4);
    binop(IN_XOR, regs->x4, regs->x3);
    reschedule(2); /* Improve scheduling of x4 ^= x3 */
    binop(IN_XOR, regs->x2, regs->x1);

    /* We are low on registers, so we save t0/t1 on the stack until later */
    /* t1 = x0; */
    /* t0 = (~x0) & x1; */
    store(regs->x0, REG_ESP, 44);
    move(regs->t0, regs->x0);
    unop(IN_NOT, regs->t0);
    binop(IN_AND, regs->t0, regs->x1);
    store(regs->t0, REG_ESP, 40);

    /* x0 ^= (~x1) & x2; */
    /* x1 ^= (~x2) & x3; */
    move(regs->t1, regs->x1);
    move(regs->t0, regs->x2);
    unop(IN_NOT, regs->t1);
    unop(IN_NOT, regs->t0);
    binop(IN_AND, regs->t1, regs->x2);
    binop(IN_AND, regs->t0, regs->x3);
    binop(IN_XOR, regs->x0, regs->t1);
    binop(IN_XOR, regs->x1, regs->t0);

    /* x3 ^= (~x4) & t1; */
    move(regs->t0, regs->x4);
    load(regs->t1, REG_ESP, 44);
    unop(IN_NOT, regs->t0);
    binop(IN_AND, regs->t0, regs->t1);
    binop(IN_XOR, regs->x3, regs->t0);

    /* x2 ^= (~x3) & x4; */
    move(regs->t1, regs->x3);
    unop(IN_NOT, regs->t1);
    binop(IN_AND, regs->t1, regs->x4);
    binop(IN_XOR, regs->x2, regs->t1);

    /* x4 ^= t0; */
    load(regs->t0, REG_ESP, 40);
    binop(IN_XOR, regs->x4, regs->t0);

    /* x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2; */
    binop(IN_XOR, regs->x1, regs->x0);
    binop(IN_XOR, regs->x3, regs->x2);
    binop(IN_XOR, regs->x0, regs->x4);
#if 0
    /* Inverting x2 is integrated into the round constant for the next round */
    unop(IN_NOT, regs->x2);
#endif
}

/* Generate the code for a single sliced ASCON round */
static void gen_round_sliced(reg_names *regs, int round)
{
    /* Round constants for all rounds */
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };
    reg_t *t2;

    /* Set up to operate on the even words which are currently in registers */
    regs->x0 = regs->x0_e;
    regs->x1 = regs->x1_e;
    regs->x2 = regs->x2_e;
    regs->x3 = regs->x3_e;
    regs->x4 = regs->x4_e;

    /* Apply the inverted version of the round constant to x2_e */
    xor_rc(regs->x2, ~((int)RC[round * 2]));

    /* Apply the S-box to the even half of the state */
    gen_sbox(regs);

    /* Store the even half to the stack and load the odd half into registers */
    spill_to_stack(regs->x1_e); /* Re-ordered to improve scheduling */
    spill_to_stack(regs->x2_e);
    spill_to_stack(regs->x0_e);
    spill_to_stack(regs->x3_e);
    spill_to_stack(regs->x4_e);
    live_from_stack(regs->x0_o);
    live_from_stack(regs->x1_o);
    live_from_stack(regs->x2_o);
    live_from_stack(regs->x3_o);
    live_from_stack(regs->x4_o);

    /* Set up to operate on the odd words which are now in registers */
    regs->x0 = regs->x0_o;
    regs->x1 = regs->x1_o;
    regs->x2 = regs->x2_o;
    regs->x3 = regs->x3_o;
    regs->x4 = regs->x4_o;

    /* Apply the inverted version of the round constant to x2_o */
    xor_rc(regs->x2, ~((int)RC[round * 2 + 1]));

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
    move(regs->t0, regs->x0);
    move(regs->t1, t2);
    ror(regs->t0, 4);
    ror(regs->t1, 5);
    binop(IN_XOR, regs->t0, t2);
    binop(IN_XOR, regs->t1, regs->x0);
    ror(regs->t0, 10);
    ror(regs->t1, 9);
    binop(IN_XOR, regs->t0, regs->x0);
    binop(IN_XOR, t2, regs->t1);
    store(regs->t0, REG_ESP, X0_O);
    move(regs->x0, t2);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
    load(t2, REG_ESP, X1_E);
    move(regs->t1, regs->x1);
    move(regs->t0, t2);
    ror(regs->t1, 11);
    ror(regs->t0, 11);
    binop(IN_XOR, regs->t1, regs->x1);
    binop(IN_XOR, regs->t0, t2);
    ror(regs->t1, 19);
    ror(regs->t0, 20);
    binop(IN_XOR, t2, regs->t1);
    binop(IN_XOR, regs->t0, regs->x1);
    move(regs->x1, t2);
    store(regs->t0, REG_ESP, X1_O);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
    load(t2, REG_ESP, X2_E);
    move(regs->t0, regs->x2);
    move(regs->t1, t2);
    ror(regs->t0, 2);
    ror(regs->t1, 3);
    binop(IN_XOR, regs->t0, t2);
    binop(IN_XOR, regs->t1, regs->x2);
    ror(regs->t0, 1);
    binop(IN_XOR, t2, regs->t1);
    binop(IN_XOR, regs->t0, regs->x2);
    move(regs->x2, t2);
    store(regs->t0, REG_ESP, X2_O);

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
    load(t2, REG_ESP, X3_E);
    move(regs->t0, regs->x3);
    move(regs->t1, t2);
    ror(regs->t0, 3);
    ror(regs->t1, 4);
    binop(IN_XOR, regs->t0, t2);
    binop(IN_XOR, regs->t1, regs->x3);
    ror(regs->t0, 5);
    ror(regs->t1, 5);
    binop(IN_XOR, t2, regs->t0);
    binop(IN_XOR, regs->t1, regs->x3);
    move(regs->x3, t2);
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
    move(regs->t1, regs->x4);
    move(regs->t0, t2);
    ror(regs->t1, 17);
    ror(regs->t0, 17);
    binop(IN_XOR, regs->t1, regs->x4);
    binop(IN_XOR, regs->t0, t2);
    ror(regs->t1, 3);
    ror(regs->t0, 4);
    binop(IN_XOR, t2, regs->t1);
    binop(IN_XOR, regs->t0, regs->x4);
    move(regs->x4, t2);
    store(regs->t0, REG_ESP, X4_O);

    /* Reclaim x0 */
    load(regs->x0, REG_ESP, 40);

    /* Transfer the register allocations back to the even words */
    transfer(regs->x0_e, regs->x0_o);
    transfer(regs->x1_e, regs->x1_o);
    transfer(regs->x2_e, regs->x2_o);
    transfer(regs->x3_e, regs->x3_o);
    transfer(regs->x4_e, regs->x4_o);
    dirty(regs->x0_e);
    dirty(regs->x1_e);
    dirty(regs->x2_e);
    dirty(regs->x3_e);
    dirty(regs->x4_e);
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
    char *reg_list[] = {
        REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_EAX, REG_EBP, NULL
    };

    /* Set up the stack frame, and load the arguments into eax and ebp */
#if X86_64_PLATFORM
    push(REG_RBP);
    push(REG_RBX);
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNQ(sub) "%s, 48\n", REG_ESP);
#else
    printf(INSNQ(sub) "$48, %s\n", REG_ESP);
#endif
    move_direct(REG_RAX, REG_RDI);
    move_direct(REG_RBP, REG_RSI);
    move_direct(REG_R8, REG_RDI); /* Save in r8 for the later store */
    state = REG_RAX;
    first_round = REG_EBP;
    flush_pipeline();
#else
    push(REG_EBP);
    push(REG_EBX);
    push(REG_ESI);
    push(REG_EDI);
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNL(sub) "%s, 48\n", REG_ESP);
#else
    printf(INSNL(sub) "$48, %s\n", REG_ESP);
#endif
    load_machine(REG_EAX, REG_ESP, 48 + 16 + 4);
    load_machine(REG_EBP, REG_ESP, 48 + 16 + 8);
    state = REG_EAX;
    first_round = REG_EBP;
    flush_pipeline();
#endif

    /* Start the register allocator */
    start_allocator(reg_list, state, REG_ESP);

    /* Shift the state to the stack so that we can offset via SP.
     * We keep the even words in registers between rounds and store
     * the odd words in the stack.  The even slots on the stack
     * will be filled later when we need to swap even and odd. */
    regs.x0_o = alloc_state("x0_o", X0_O);
    regs.x1_o = alloc_state("x1_o", X1_O);
    regs.x2_o = alloc_state("x2_o", X2_O);
    regs.x3_o = alloc_state("x3_o", X3_O);
    regs.x4_o = alloc_state("x4_o", X4_O);
    live(regs.x0_o);
    live(regs.x1_o);
    live(regs.x2_o);
    live(regs.x3_o);
    live(regs.x4_o);
    unop(IN_NOT, regs.x2_o); /* Invert x2_o before the first round */
    spill_to_stack(regs.x0_o);
    spill_to_stack(regs.x1_o);
    spill_to_stack(regs.x2_o);
    spill_to_stack(regs.x3_o);
    spill_to_stack(regs.x4_o);
    regs.x0_e = alloc_state("x0_e", X0_E);
    regs.x1_e = alloc_state("x1_e", X1_E);
    regs.x2_e = alloc_state("x2_e", X2_E);
    regs.x3_e = alloc_state("x3_e", X3_E);
    regs.x4_e = alloc_state("x4_e", X4_E);
    live(regs.x0_e);
    live(regs.x1_e);
    live(regs.x2_e);
    live(regs.x3_e);
    live(regs.x4_e);
    unop(IN_NOT, regs.x2_e); /* Invert x2_e before the first round */

    /* Allocate temporaries */
    regs.t0 = alloc_temp("t0");
    regs.t1 = alloc_temp("t1");
    acquire(regs.t0);
    acquire(regs.t1);

    /* Determine which round is first and jump ahead.  Most of the time,
     * we will be seeing "first round" set to 6, 0, or 4 so we handle
     * those cases first.  But we can do any number of rounds.   If the
     * "first round" value is 12 or higher, then we will do nothing. */
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNL(cmp) "%s, 6\n", first_round);
    printf("\tje\t.L6\n");
    printf(INSNL(cmp) "%s, 0\n", first_round);
    printf("\tje\t.L0\n");
    printf(INSNL(cmp) "%s, 4\n", first_round);
    printf("\tje\t.L4\n");
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        printf(INSNL(cmp) "%s, %d\n", first_round, round);
        printf("\tje\t.L%d\n", round);
    }
    printf("\tjmp\t.L12\n");
#else
    printf(INSNL(cmp) "$6, %s\n", first_round);
    printf("\tje\t.L6\n");
    printf(INSNL(cmp) "$0, %s\n", first_round);
    printf("\tje\t.L0\n");
    printf(INSNL(cmp) "$4, %s\n", first_round);
    printf("\tje\t.L4\n");
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        printf(INSNL(cmp) "$%d, %s\n", round, first_round);
        printf("\tje\t.L%d\n", round);
    }
    printf("\tjmp\t.L12\n");
#endif

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round_sliced(&regs, round);
        flush_pipeline();
    }

    /* Store the words back to the state */
    printf(".L12:\n");
#if X86_64_PLATFORM
    move_direct(REG_RAX, REG_R8);
#else
    load_machine(REG_EAX, REG_ESP, 48 + 16 + 4);
#endif
    unop(IN_NOT, regs.x2_e); /* Invert x2_e after the last round */
    spill(regs.x0_e);
    spill(regs.x1_e);
    spill(regs.x2_e);
    spill(regs.x3_e);
    spill(regs.x4_e);
    live_from_stack(regs.x0_o);
    live_from_stack(regs.x1_o);
    live_from_stack(regs.x2_o);
    live_from_stack(regs.x3_o);
    live_from_stack(regs.x4_o);
    unop(IN_NOT, regs.x2_o); /* Invert x2_o after the last round */
    spill(regs.x0_o);
    spill(regs.x1_o);
    spill(regs.x2_o);
    spill(regs.x3_o);
    spill(regs.x4_o);

    /* Clear sensitive material from scratch registers and the stack.
     * We would like to delay this to ascon_backend_free() but we cannot
     * control if the same stack locations will be used when that
     * function is called.  So we clean things up here instead. */
    clear_reg(REG_EAX);
    clear_reg(REG_ECX);
    clear_reg(REG_EDX);
    for (round = 0; round < 48; round += 4) {
        if ((round % 12) == 0)
            store_machine(REG_EAX, REG_ESP, round);
        else if ((round % 12) == 4)
            store_machine(REG_ECX, REG_ESP, round);
        else
            store_machine(REG_EDX, REG_ESP, round);
    }

    /* Pop the stack frame */
#if X86_64_PLATFORM
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNQ(add) "%s, 48\n", REG_ESP);
#else
    printf(INSNQ(add) "$48, %s\n", REG_ESP);
#endif
    pop(REG_RBX);
    pop(REG_RBP);
    flush_pipeline();
#else
    flush_pipeline();
#if INTEL_SYNTAX
    printf(INSNL(add) "%s, 48\n", REG_ESP);
#else
    printf(INSNL(add) "$48, %s\n", REG_ESP);
#endif
    pop(REG_EDI);
    pop(REG_ESI);
    pop(REG_EBX);
    pop(REG_EBP);
    flush_pipeline();
#endif
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Targetting a 32-bit platform */
    target_word_size = 32;

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

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
