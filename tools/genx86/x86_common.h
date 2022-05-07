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

#ifndef X86_COMMON_H
#define X86_COMMON_H

#include "reg_alloc.h"

/* Should we output Intel syntax (1) or AT&T syntax (0)? */
#ifndef INTEL_SYNTAX
#define INTEL_SYNTAX 1
#endif

/* Special hack for testing the i386 backend on x86-64 platforms if 1.
 * Pointer registers are 64-bit and word registers are 32-bit. */
#ifndef X86_64_PLATFORM
#define X86_64_PLATFORM 0
#endif

/* Determine the register names to use on 64-bit platforms */
#if INTEL_SYNTAX
#define REG_RAX "rax"
#define REG_RBX "rbx"
#define REG_RCX "rcx"
#define REG_RDX "rdx"
#define REG_RDI "rdi"
#define REG_RSI "rsi"
#define REG_RBP "rbp"
#define REG_RSP "rsp"
#define REG_R8  "r8"
#define REG_R9  "r9"
#define REG_R10 "r10"
#define REG_R11 "r11"
#define REG_R12 "r12"
#define REG_R13 "r13"
#define REG_R14 "r14"
#define REG_R15 "r15"
#else
#define REG_RAX "%rax"
#define REG_RBX "%rbx"
#define REG_RCX "%rcx"
#define REG_RDX "%rdx"
#define REG_RDI "%rdi"
#define REG_RSI "%rsi"
#define REG_RBP "%rbp"
#define REG_RSP "%rsp"
#define REG_R8  "%r8"
#define REG_R9  "%r9"
#define REG_R10 "%r10"
#define REG_R11 "%r11"
#define REG_R12 "%r12"
#define REG_R13 "%r13"
#define REG_R14 "%r14"
#define REG_R15 "%r15"
#endif
#define REG_STATE64 REG_RDI

/* Determine the register names to use on 32-bit platforms */
#if INTEL_SYNTAX
#define REG_EAX "eax"
#define REG_EBX "ebx"
#define REG_ECX "ecx"
#define REG_EDX "edx"
#define REG_EDI "edi"
#define REG_ESI "esi"
#define REG_EBP "ebp"
#define REG_AX "ax"
#define REG_BX "bx"
#define REG_CX "cx"
#define REG_DX "dx"
#define REG_AL "al"
#define REG_BL "bl"
#define REG_CL "cl"
#define REG_DL "dl"
#if X86_64_PLATFORM
#define REG_ESP REG_RSP
#define REG_STATE32 REG_RDI
#else
#define REG_ESP "esp"
#define REG_STATE32 REG_EAX
#endif
#else
#define REG_EAX "%eax"
#define REG_EBX "%ebx"
#define REG_ECX "%ecx"
#define REG_EDX "%edx"
#define REG_EDI "%edi"
#define REG_ESI "%esi"
#define REG_EBP "%ebp"
#define REG_AX "%ax"
#define REG_BX "%bx"
#define REG_CX "%cx"
#define REG_DX "%dx"
#define REG_AL "%al"
#define REG_BL "%bl"
#define REG_CL "%cl"
#define REG_DL "%dl"
#if X86_64_PLATFORM
#define REG_ESP REG_RSP
#define REG_STATE32 REG_RDI
#else
#define REG_ESP "%esp"
#define REG_STATE32 REG_EAX
#endif
#endif

/* Instructions that operates on long word and quad word registers */
#if INTEL_SYNTAX
#define INSNL(name) "\t" #name "\t"
#define INSNQ(name) "\t" #name "\t"
#else
#define INSNL(name) "\t" #name "l\t"
#define INSNQ(name) "\t" #name "q\t"
#endif

/* Instructions names */
#define IN_XOR      "xor"
#define IN_AND      "and"
#define IN_OR       "or"
#define IN_NOT      "not"
#define IN_REVBYTES "bswap"

/* Condition codes for branch instructions */
#define BR_ALWAYS   "jmp"
#define BR_GT       "jg"
#define BR_GT_U     "ja"
#define BR_LT       "jl"
#define BR_LT_U     "jb"
#define BR_GE       "jge"
#define BR_GE_U     "jae"
#define BR_LE       "jle"
#define BR_LE_U     "jbe"
#define BR_EQ       "je"
#define BR_NE       "jne"

/* Target word size, either 32 or 64.  Defaults to 64. */
extern int target_word_size;

/* Output a function header */
void function_header(const char *name);

/* Output a function footer, including the "ret" instruction */
void function_footer(const char *name);

/* Generates a binary operator */
void binop(const char *name, reg_t *reg1, reg_t *reg2);

/* Generates a unary operator */
void unop(const char *name, reg_t *reg);

/* Generates a rotate-right of a register */
void ror(reg_t *dest, int shift);

/* Generates a rotate-right of a register with the shift amount in a register */
void ror_reg(reg_t *dest, reg_t *shift);

/* Generates a shift-left of a register */
void shl(reg_t *dest, int shift);

/* Generates a shift-left of a register with the shift amount in a register */
void shl_reg(reg_t *dest, reg_t *shift);

/* Generates a shift-right of a register */
void shr(reg_t *dest, int shift);

/* Generates a shift-right of a register with the shift amount in a register */
void shr_reg(reg_t *dest, reg_t *shift);

/* XOR's a round constant with a register */
void xor_rc(reg_t *reg, int rc);

/* XOR's a directly named register with a logical register */
void xor_direct(reg_t *reg1, const char *reg2);

/* Moves a value from a source register to a destination register */
void move(reg_t *dest, reg_t *src);

/* Moves an immediate value into a destination register */
void move_imm(reg_t *dest, long long value);

/* Adds an immediate value to a register */
void add_imm(reg_t *reg, int value);

/* Compares a register with an immediate value and branch */
int compare_imm(const char *condition, int label, reg_t *reg, int value);

/* Branch to a label */
int branch(const char *condition, int label);

/* Set the location of a label */
int set_label(int label);

/* Loads a register from a memory location */
void load(reg_t *reg, const char *ptr, int offset);

/* Loads a value from a memory location and XOR's it with a register */
void load_and_xor(reg_t *reg, const char *ptr, int offset);

/* Loads a register from a memory location that is less than word-sized */
void load_smaller(reg_t *reg, const char *ptr, int offset, int size);

/* Loads a register from a memory location that is less than word-sized */
void load_smaller_plus_reg
    (reg_t *reg, const char *ptr, const char *ptrplus, int size);

/* Stores a register to a memory location */
void store(reg_t *reg, const char *ptr, int offset);

/* Stores a register to a smaller memory location */
void store_smaller(reg_t *reg, const char *ptr, int offset, int size);

/* XOR's a register with a memory location */
void xor_and_store(reg_t *reg, const char *ptr, int offset);

/* Clears the contents of a register to zero */
void clear_reg(const char *reg);

/* Pushes a register on the stack */
void push(const char *reg);

/* Pops a register from the stack */
void pop(const char *reg);

/* Moves a register directly */
void move_direct(const char *dest, const char *src);

/* Reschedules the previous instruction by an offset */
void reschedule(int offset);

/* Flush the instruction pipeline */
void flush_pipeline(void);

/* Maximum number of regular arguments */
#define MAX_ARGS 8

/* Maximum number of logical registers that may contain random words */
#define MAX_RANDOM 8

/* Maximum number of registers that may be in the register list */
#define MAX_REG_LIST 16

/* Information about the stack frame for a masked word utility function */
typedef struct
{
    /* Logical registers that the arguments end up in */
    reg_t *arg[MAX_ARGS];

    /* Logical registers that contain the TRNG-allocated words */
    reg_t *random[MAX_RANDOM];

    /* Register list for the register allocator */
    char *reg_list[MAX_REG_LIST];

    /* Registers that were saved on the stack */
    char *save_regs[MAX_REG_LIST];

    /* Number of registers that were saved on the stack */
    int num_save_regs;

    /* Size of the stack frame, rounded up for alignment */
    int frame_size;

    /* Register for the masked word / state */
    const char *state_reg;

} util_frame_t;

/* Set up the stack frame for a masked word utility function and
 * allocate a certain number of bytes from the TRNG.
 *
 *      num_args    Number of arguments to the function, excluding the TRNG.
 *      word_arg    Index of the argument for the masked word pointer.
 *      trng_bytes  Number of bytes to allocate from the TRNG (0..32).
 *
 * This will also initialize the register allocator.
 */
void util_function_setup
    (util_frame_t *frame, int num_args, int word_arg, int trng_bytes);

/* Tear down the stack frame for a masked word utility function */
void util_function_teardown(util_frame_t *frame);

#endif /* X86_COMMON_H */
