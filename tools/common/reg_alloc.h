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

#ifndef REG_ALLOC_H
#define REG_ALLOC_H

/* Logical register which may refer to an actual register, a slot on
 * the stack, or a slot in the permutation state buffer. */
typedef struct
{
    /* Friendly name for the logical register, not the real register. */
    const char *name;

    /* Name of the real register that the value is live within,
     * or NULL if the value is not currently live in a register. */
    const char *real_reg;

    /* Offset of where the word is stored in the permutation state
     * when it is not live in a register, or -1. */
    int state_offset;

    /* Offset of where the word is stored in the stack frame when
     * it is not live in a register, or -1. */
    int stack_offset;

    /* Non-zero if this is a temporary register */
    int is_temp;

} reg_t;

/* Starts the register allocator, passing it a list of registers
 * that can be used for later allocations.  All other registers
 * are considered locked to a special purpose by the generator. */
void start_allocator(char **regs, const char *state_reg, const char *stack_reg);

/* Allocates a register to represent a word in the permutation state.
 * The word is not loaded from the state until live() is called. */
void alloc_state(const char *name, reg_t *reg, int offset);

/* Allocates a fixed real register to a word in the permutation state.
 * The word is made live immediately by loading it from the state. */
void alloc_state_fixed
    (const char *name, reg_t *reg, int offset, const char *real_reg);

/* Allocates a register to represent a word in the stack.
 * The word is not loaded from the stack until live() or
 * live_noload() is called. */
void alloc_stack(const char *name, reg_t *reg, int offset);

/* Makes the value of a state or stack word live in a real register.
 * Does nothing if the value is already live. */
void live(reg_t *reg);

/* Makes the value of a register live but does not load it from the stack.
 * Used when allocating a temporary stack location that hasn't been
 * written to yet. */
void live_noload(reg_t *reg);

/* Makes the value of a state word live, loaded from a stack location */
void live_from_stack(reg_t *reg);

/* Spills the contents of a register out to the state or stack,
 * and releases the real register for re-use.  Will fail if there
 * is no location to spill the value to (e.g. for a temporary). */
void spill(reg_t *reg);

/* Spills a state word to the same-numbered stack position */
void spill_to_stack(reg_t *reg);

/* Gets a temporary register from the unallocated real registers. */
void get_temp(const char *name, reg_t *reg);

/* Releases a temporary register, forgetting its value and releasing
 * the real register back to the allocation pool.  Will fail if an
 * attempt is made to release a non-temporary register. */
void release(reg_t *reg);

/* Gets the name of the real register underneath a logical register */
const char *get_real(const reg_t *reg);

/* Loads a register from a memory location (machine-specific) */
void load(const char *reg, const char *ptr, int offset);

/* Stores a register to a memory location (machine-specific) */
void store(const char *reg, const char *ptr, int offset);

#endif /* REG_ALLOC_H */
