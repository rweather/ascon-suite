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

#include "reg_alloc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_MACHINE_REGS 64
#define MAX_ALLOC_REGS 256

static char **reg_list = 0;
static int allocated[MAX_MACHINE_REGS];
static const char *state_reg = 0;
static const char *stack_reg = 0;
static reg_t regs[MAX_ALLOC_REGS];
static int num_regs = 0;
static unsigned long age = 0;

static const char *try_allocate_reg(const char *name)
{
    int index = 0;
    while (reg_list[index]) {
        if (!allocated[index]) {
            allocated[index] = 1;
            return reg_list[index];
        }
        ++index;
    }
    return 0;
}

static const char *allocate_reg(const char *name)
{
    const char *reg = try_allocate_reg(name);
    if (!reg) {
        fprintf(stderr, "allocate_reg: cannot allocate a register for %s\n", name);
        exit(1);
    }
    return reg;
}

static void release_reg(const char *name, const char *real_reg)
{
    int index = 0;
    while (reg_list[index]) {
        if (!strcmp(reg_list[index], real_reg)) {
            if (!allocated[index]) {
                fprintf(stderr, "release_reg: %s is already released\n",
                        name);
                exit(1);
            }
            allocated[index] = 0;
            return;
        }
        ++index;
    }
    fprintf(stderr, "release_reg: %s is not a valid register name\n", real_reg);
    exit(1);
}

/* Reclaim the oldest register that we can spill */
static void reclaim(void)
{
    int index;
    int oldest_index = -1;
    unsigned long oldest_age = ~((unsigned long)0);
    for (index = 0; index < num_regs; ++index) {
        reg_t *reg = &(regs[index]);
        if (!reg->real_reg)
            continue; /* Nothing allocated to this register */
        if (reg->pinned)
            continue; /* Pinned registers can never be spilled */
        if (reg->is_temp)
            continue; /* Temporaries must be explicitly released */
        if (reg->age < oldest_age) {
            oldest_age = reg->age;
            oldest_index = index;
        }
    }
    if (oldest_index >= 0) {
        /* We have found something that we can spill */
        spill(&(regs[oldest_index]));
    }
}

void start_allocator(char **regs, const char *st_reg, const char *stk_reg)
{
    state_reg = st_reg;
    stack_reg = stk_reg;
    reg_list = regs;
    memset(allocated, 0, sizeof(allocated));
    num_regs = 0;
}

reg_t *alloc_state(const char *name, int offset)
{
    reg_t *reg;
    if (num_regs >= MAX_ALLOC_REGS) {
        fprintf(stderr, "alloc_state: too many logical registers\n");
        exit(1);
    }
    reg = &(regs[num_regs++]);
    reg->name = name;
    reg->real_reg = 0;
    reg->state_offset = offset;
    reg->stack_offset = -1;
    reg->is_temp = 0;
    reg->is_dirty = 0;
    reg->pinned = 0;
    reg->age = age++;
    return reg;
}

reg_t *alloc_stack(const char *name, int offset)
{
    reg_t *reg;
    if (num_regs >= MAX_ALLOC_REGS) {
        fprintf(stderr, "alloc_stack: too many logical registers\n");
        exit(1);
    }
    reg = &(regs[num_regs++]);
    reg->name = name;
    reg->real_reg = 0;
    reg->state_offset = -1;
    reg->stack_offset = offset;
    reg->is_temp = 0;
    reg->is_dirty = 0;
    reg->pinned = 0;
    reg->age = age++;
    return reg;
}

reg_t *alloc_temp(const char *name)
{
    reg_t *reg;
    if (num_regs >= MAX_ALLOC_REGS) {
        fprintf(stderr, "alloc_temp: too many logical registers\n");
        exit(1);
    }
    reg = &(regs[num_regs++]);
    reg->name = name;
    reg->real_reg = 0;
    reg->state_offset = -1;
    reg->stack_offset = -1;
    reg->is_temp = 1;
    reg->is_dirty = 0;
    reg->pinned = 0;
    reg->age = age++;
    return reg;
}

reg_t *alloc_named_register(const char *name)
{
    reg_t *reg;
    int index = 0;
    while (reg_list[index]) {
        if (!strcmp(reg_list[index], name)) {
            if (allocated[index])
                break;
            name = reg_list[index];
            if (num_regs >= MAX_ALLOC_REGS) {
                fprintf(stderr, "alloc_named_register: too many logical registers\n");
                exit(1);
            }
            allocated[index] = 1;
            reg = &(regs[num_regs++]);
            reg->name = name;
            reg->real_reg = name;
            reg->state_offset = -1;
            reg->stack_offset = -1;
            reg->is_temp = 1;
            reg->is_dirty = 0;
            reg->pinned = 1;
            reg->age = age++;
            return reg;
        }
        ++index;
    }
    fprintf(stderr, "alloc_named_register: %s is already allocated\n", name);
    return 0;
}

void dirty(reg_t *reg)
{
    reg->is_dirty = 1;
    reg->age = age++;
}

void clean(reg_t *reg)
{
    reg->is_dirty = 0;
    reg->age = age++;
}

void touch(reg_t *reg)
{
    reg->age = age++;
}

void pin(reg_t *reg)
{
    reg->pinned = 1;
}

void unpin(reg_t *reg)
{
    reg->pinned = 0;
}

void live(reg_t *reg)
{
    if (live_noload(reg)) {
        if (reg->state_offset >= 0)
            load_machine(reg->real_reg, state_reg, reg->state_offset);
        else
            load_machine(reg->real_reg, stack_reg, reg->stack_offset);
        reg->is_dirty = 0;
    }
    reg->age = age++;
}

int live_noload(reg_t *reg)
{
    if (reg->real_reg) {
        /* The value is already live in a register */
        reg->age = age++;
        return 0;
    }
    if (reg->state_offset < 0 && reg->stack_offset < 0) {
        fprintf(stderr, "live: nowhere to load the value for %s from\n",
                reg->name);
        exit(1);
    }
    reg->real_reg = try_allocate_reg(reg->name);
    if (!reg->real_reg) {
        /* We have run out of registers, so reclaim something and try again */
        reclaim();
        reg->real_reg = allocate_reg(reg->name);
    }
    reg->age = age++;
    return 1;
}

void live_from_stack(reg_t *reg)
{
    if (reg->state_offset < 0) {
        fprintf(stderr, "live_from_stack: nowhere to load the value for %s from\n",
                reg->name);
        exit(1);
    }
    if (live_noload(reg))
        load_machine(reg->real_reg, stack_reg, reg->state_offset);
    reg->is_dirty = 1;
    reg->age = age++;
}

void spill(reg_t *reg)
{
    if (reg->state_offset < 0 && reg->stack_offset < 0) {
        fprintf(stderr, "spill: nowhere to spill the value for %s to\n",
                reg->name);
        exit(1);
    }
    if (reg->pinned) {
        /* Cannot spill this register */
        reg->age = age++;
        return;
    }
    if (reg->real_reg) {
        if (reg->is_dirty) {
            /* Spill the value back to the state or stack if dirty */
            if (reg->state_offset >= 0)
                store_machine(reg->real_reg, state_reg, reg->state_offset);
            else
                store_machine(reg->real_reg, stack_reg, reg->stack_offset);
        }
        release_reg(reg->name, reg->real_reg);
        reg->real_reg = 0;
    }
    reg->is_dirty = 0;
}

void spill_to_stack(reg_t *reg)
{
    if (reg->state_offset < 0) {
        fprintf(stderr, "spill_to_stack: nowhere to spill the value for %s to\n",
                reg->name);
        exit(1);
    }
    if (reg->pinned) {
        /* Cannot spill this register */
        reg->age = age++;
        return;
    }
    if (reg->real_reg) {
        store_machine(reg->real_reg, stack_reg, reg->state_offset);
        release_reg(reg->name, reg->real_reg);
        reg->real_reg = 0;
    }
    reg->is_dirty = 0;
}

void transfer(reg_t *dest, reg_t *src)
{
    if (!src->real_reg) {
        fprintf(stderr, "transfer: %s is not allocated\n", src->name);
        exit(1);
    }
    if (dest->real_reg) {
        fprintf(stderr, "transfer: %s is already allocated\n", dest->name);
        exit(1);
    }
    dest->real_reg = src->real_reg;
    src->real_reg = 0;
    dest->age = age++;
}

void acquire(reg_t *reg)
{
    if (!reg->is_temp) {
        fprintf(stderr, "acquire: %s is not a temporary\n", reg->name);
        exit(1);
    }
    if (!reg->real_reg) {
        reg->real_reg = try_allocate_reg(reg->name);
        if (!reg->real_reg) {
            /* We have run out of registers; reclaim something and try again */
            reclaim();
            reg->real_reg = allocate_reg(reg->name);
        }
    }
    reg->is_dirty = 1; /* Assume we are about to write to the temporary */
    reg->age = age++;
}

void release(reg_t *reg)
{
    if (!reg->is_temp) {
        fprintf(stderr, "release: %s is not a temporary\n", reg->name);
        exit(1);
    }
    if (reg->real_reg) {
        release_reg(reg->name, reg->real_reg);
        reg->real_reg = 0;
    }

    /* Move the age of the temporary back a bit to make it more likely
     * to be allocated for the next temporary value that we need rather
     * than spilling part of the state. */
    reg->age = age - 8;
}

const char *get_real(const reg_t *reg)
{
    if (!reg->real_reg) {
        fprintf(stderr, "get_real: %s is not allocated to a register\n",
                reg->name);
        exit(1);
    }
    return reg->real_reg;
}
