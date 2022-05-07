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
    unsigned char is_temp;

    /* Non-zero if the register is dirty and its value needs to be
     * spilled back to the state or stack unless explicitly discarded
     * because its value is temporary. */
    unsigned char is_dirty;

    /* Non-zero if this logical register is pinned to its real register
     * and cannot be spilled by a live() call to reuse an old register. */
    unsigned char pinned;

    /* Age of the register for determining which register to spill
     * using a least-recently used algorithm */
    unsigned long age;

} reg_t;

/* Starts the register allocator, passing it a list of registers
 * that can be used for later allocations.  All other registers
 * are considered locked to a special purpose by the generator. */
void start_allocator(char **regs, const char *state_reg, const char *stack_reg);

/* Allocates a register to represent a word in the permutation state.
 * The word is not loaded from the state until live() is called. */
reg_t *alloc_state(const char *name, int offset);

/* Allocates a register to represent a word in the stack.
 * The word is not loaded from the stack until live() or
 * live_noload() is called. */
reg_t *alloc_stack(const char *name, int offset);

/* Allocates a temporary register but does not allocate a real register yet. */
reg_t *alloc_temp(const char *name);

/* Allocate a specific named register */
reg_t *alloc_named_register(const char *name);

/* Marks a register as dirty.  The value it contains must be spilled
 * or explicitly discarded if it is in a temporary. */
void dirty(reg_t *reg);

/* Marks a register as clean.  The value it contains can be discarded. */
void clean(reg_t *reg);

/* Touch a register to make it more recently used. */
void touch(reg_t *reg);

/* Pins a logical register to its real register and prevents spilling. */
void pin(reg_t *reg);

/* Unpins a logical register so that it can be spilled. */
void unpin(reg_t *reg);

/* Makes the value of a state or stack word live in a real register.
 * Does nothing if the value is already live. */
void live(reg_t *reg);

/* Makes the value of a register live but does not load it from the state.
 * Used when allocating a temporary stack location that hasn't been
 * written to yet. */
int live_noload(reg_t *reg);

/* Makes the value of a state word live, loaded from a stack location */
void live_from_stack(reg_t *reg);

/* Spills the contents of a register out to the state or stack,
 * and releases the real register for re-use.  Will fail if there
 * is no location to spill the value to (e.g. for a temporary). */
void spill(reg_t *reg);

/* Spills a state word to the same-numbered stack position */
void spill_to_stack(reg_t *reg);

/* Transfers the register allocation from one logical register to another */
void transfer(reg_t *dest, reg_t *src);

/* Acquires a temporary register by allocating a real register for it. */
void acquire(reg_t *reg);

/* Releases a temporary register, forgetting its value and releasing
 * the real register back to the allocation pool.  Will fail if an
 * attempt is made to release a non-temporary register. */
void release(reg_t *reg);

/* Gets the name of the real register underneath a logical register */
const char *get_real(const reg_t *reg);

/* Loads a register from a memory location (machine-specific) */
void load_machine(const char *reg, const char *ptr, int offset);

/* Stores a register to a memory location (machine-specific) */
void store_machine(const char *reg, const char *ptr, int offset);

#endif /* REG_ALLOC_H */
