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

#define MAX_REGS 64

static char **reg_list = 0;
static int allocated[MAX_REGS];
static const char *state_reg = 0;
static const char *stack_reg = 0;

static const char *allocate_reg(const char *name)
{
    int index = 0;
    while (reg_list[index]) {
        if (!allocated[index]) {
            allocated[index] = 1;
            return reg_list[index];
        }
        ++index;
    }
    fprintf(stderr, "allocate_reg: cannot allocate a register for %s\n", name);
    exit(1);
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

static void allocate_fixed(const char *real_reg)
{
    int index = 0;
    while (reg_list[index]) {
        if (!strcmp(reg_list[index], real_reg)) {
            if (allocated[index]) {
                fprintf(stderr, "allocate_fixed: %s is already allocated\n",
                        real_reg);
                exit(1);
            }
            allocated[index] = 1;
            return;
        }
        ++index;
    }
    fprintf(stderr, "allocate_fixed: %s is not a valid register name\n",
            real_reg);
    exit(1);
}

void start_allocator(char **regs, const char *st_reg, const char *stk_reg)
{
    state_reg = st_reg;
    stack_reg = stk_reg;
    reg_list = regs;
    memset(allocated, 0, sizeof(allocated));
}

void alloc_state(const char *name, reg_t *reg, int offset)
{
    reg->name = name;
    reg->real_reg = 0;
    reg->state_offset = offset;
    reg->stack_offset = -1;
    reg->is_temp = 0;
}

void alloc_state_fixed(const char *name, reg_t *reg, int offset, const char *real_reg)
{
    allocate_fixed(real_reg);
    reg->name = name;
    reg->real_reg = real_reg;
    reg->state_offset = offset;
    reg->stack_offset = -1;
    reg->is_temp = 0;
    load(real_reg, state_reg, offset);
}

void alloc_stack(const char *name, reg_t *reg, int offset)
{
    reg->name = name;
    reg->real_reg = 0;
    reg->state_offset = -1;
    reg->stack_offset = offset;
    reg->is_temp = 0;
}

void live(reg_t *reg)
{
    live_noload(reg);
    if (reg->state_offset >= 0)
        load(reg->real_reg, state_reg, reg->state_offset);
    else
        load(reg->real_reg, stack_reg, reg->stack_offset);
}

void live_noload(reg_t *reg)
{
    if (reg->real_reg) {
        /* The value is already live in a register */
        return;
    }
    if (reg->state_offset < 0 && reg->stack_offset < 0) {
        fprintf(stderr, "live: nowhere to load the value for %s from\n",
                reg->name);
        exit(1);
    }
    reg->real_reg = allocate_reg(reg->name);
}

void live_from_stack(reg_t *reg)
{
    if (reg->state_offset < 0) {
        fprintf(stderr, "live_from_stack: nowhere to load the value for %s from\n",
                reg->name);
        exit(1);
    }
    live_noload(reg);
    load(reg->real_reg, stack_reg, reg->state_offset);
}

void spill(reg_t *reg)
{
    if (reg->state_offset < 0 && reg->stack_offset < 0) {
        fprintf(stderr, "spill: nowhere to spill the value for %s to\n",
                reg->name);
        exit(1);
    }
    if (reg->real_reg) {
        if (reg->state_offset >= 0)
            store(reg->real_reg, state_reg, reg->state_offset);
        else
            store(reg->real_reg, stack_reg, reg->stack_offset);
        release_reg(reg->name, reg->real_reg);
        reg->real_reg = 0;
    }
}

void spill_to_stack(reg_t *reg)
{
    if (reg->state_offset < 0) {
        fprintf(stderr, "spill_to_stack: nowhere to spill the value for %s to\n",
                reg->name);
        exit(1);
    }
    if (reg->real_reg) {
        store(reg->real_reg, stack_reg, reg->state_offset);
        release_reg(reg->name, reg->real_reg);
        reg->real_reg = 0;
    }
}

void get_temp(const char *name, reg_t *reg)
{
    reg->name = name;
    reg->real_reg = allocate_reg(name);
    reg->state_offset = -1;
    reg->stack_offset = -1;
    reg->is_temp = 1;
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
