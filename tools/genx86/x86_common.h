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

/* Target word size, either 32 or 64.  Defaults to 64. */
extern int target_word_size;

/* Output a function header */
void function_header(const char *name);

/* Output a function footer, including the "ret" instruction */
void function_footer(const char *name);

/* Generates a binary operator */
void binop(const char *name, reg_t reg1, reg_t reg2);

/* Generates a unary operator */
void unop(const char *name, reg_t reg);

/* Generates a rotate-right of a register */
void ror(reg_t dest, int shift);

/* XOR's a round constant with a register */
void xor_rc(reg_t reg, int rc);

/* Clears the contents of a register to zero */
void clear_reg(const char *reg);

/* Pushes a register on the stack */
void push(const char *reg);

/* Pops a register from the stack */
void pop(const char *reg);

/* Moves a register directly */
void move_direct(const char *dest, const char *src);

#endif /* X86_COMMON_H */
