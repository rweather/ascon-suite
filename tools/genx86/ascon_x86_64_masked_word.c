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
 * masked word operations for x86-64 microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"
#include "x86_common.h"

/* Maximum number of shares that we support */
#define MAX_SHARES 4

/* Each share is rotated with respect to the next by this much */
#define ROT_SHARE 11
#define ROT(n) (ROT_SHARE * (n))
#define UNROT(n) (64 - ROT_SHARE * (n))

static char function_name[128];

/* Type of masked word load to perform */
#define LOAD_ZERO 0
#define LOAD_WORD64 1
#define LOAD_WORD32 2
#define LOAD_PARTIAL 3

/* Algorithm family name */
static const char family[] = "ascon";

/* Load a masked word */
static void masked_word_load(int num_shares, int type)
{
    util_frame_t frame;
    int posn;
    int label, label2;
    reg_t *temp;

    /* Function header */
    if (type == LOAD_ZERO) {
        snprintf(function_name, sizeof(function_name),
                 "%s_masked_word_x%d_zero", family, num_shares);
        function_header(function_name);
        util_function_setup(&frame, 1, 0, (num_shares - 1) * 8);
    } else if (type == LOAD_WORD64) {
        snprintf(function_name, sizeof(function_name),
                 "%s_masked_word_x%d_load", family, num_shares);
        function_header(function_name);
        util_function_setup(&frame, 2, 0, (num_shares - 1) * 8);
    } else if (type == LOAD_WORD32) {
        snprintf(function_name, sizeof(function_name),
                 "%s_masked_word_x%d_load_32", family, num_shares);
        function_header(function_name);
        util_function_setup(&frame, 3, 0, (num_shares - 1) * 8);
    } else {
        snprintf(function_name, sizeof(function_name),
                 "%s_masked_word_x%d_load_partial", family, num_shares);
        function_header(function_name);
        util_function_setup(&frame, 3, 0, (num_shares - 1) * 8);
    }

    /* Generate the first word as the XOR of all random values */
    if (num_shares == 2 && type == LOAD_ZERO) {
        store(frame.random[0], frame.state_reg, 0);
    } else {
        reg_t *first_word = alloc_state("a", 0);
        live_noload(first_word);
        if (type == LOAD_ZERO) {
            move(first_word, frame.random[0]);
        } else if (type == LOAD_WORD64) {
            /* Load and mask the first word.  Byteswap after the word
             * is randomized to minimize the time that the plaintext
             * word is exposed in a register. */
            move(first_word, frame.random[0]);
            load_and_xor(first_word, frame.arg[1]->real_reg, 0);
            unop(IN_REVBYTES, first_word);
            unop(IN_REVBYTES, frame.random[0]);
        } else if (type == LOAD_WORD32) {
            /* Load the plaintext word in two 32-bit halves */
            reg_t *temp = alloc_temp("low");
            acquire(temp);
            load_smaller(first_word, frame.arg[1]->real_reg, 0, 4);
            binop(IN_XOR, first_word, frame.random[0]);
            load_smaller(temp, frame.arg[2]->real_reg, 0, 4);
            ror(temp, 32);
            binop(IN_XOR, first_word, temp);
            clear_reg(temp->real_reg);
            unop(IN_REVBYTES, first_word);
            unop(IN_REVBYTES, frame.random[0]);
            release(temp);
        } else {
            /* Load a partial word one byte at a time */
            reg_t *temp = alloc_temp("fragment");
            acquire(temp);
            move(first_word, frame.random[0]);
            label = branch(BR_ALWAYS, -1);
            label2 = set_label(-1);
            add_imm(frame.arg[2], -1);
            load_smaller_plus_reg
                (temp, frame.arg[1]->real_reg, frame.arg[2]->real_reg, 1);
            binop(IN_XOR, first_word, temp);
            ror(first_word, 8);
            ror(frame.random[0], 8);
            set_label(label);
            compare_imm(BR_GT, label2, frame.arg[2], 0);
            clear_reg(temp->real_reg);
            release(temp);
        }
        for (posn = 1; posn < (num_shares - 1); ++posn) {
            binop(IN_XOR, first_word, frame.random[posn]);
        }
        spill(first_word);
        reschedule(num_shares - 1);
    }

    /* Rotate and store the rest of the shares */
    for (posn = 0; posn < (num_shares - 1); ++posn) {
        ror(frame.random[posn], ROT(posn + 1));
    }
    for (posn = 0; posn < (num_shares - 1); ++posn) {
        store(frame.random[posn], frame.state_reg, (posn + 1) * 8);
    }

    /* Fill the unused shares with zeroes */
    temp = alloc_temp("zero");
    acquire(temp);
    flush_pipeline();
    if (num_shares == 2) {
        printf("#if ASCON_MASKED_MAX_SHARES >= 3\n");
        clear_reg(temp->real_reg);
        store(temp, frame.state_reg, 16);
        flush_pipeline();
        printf("#endif\n");
        printf("#if ASCON_MASKED_MAX_SHARES >= 4\n");
        store(temp, frame.state_reg, 24);
        flush_pipeline();
        printf("#endif\n");
    } else if (num_shares == 3) {
        printf("#if ASCON_MASKED_MAX_SHARES >= 4\n");
        clear_reg(temp->real_reg);
        store(temp, frame.state_reg, 24);
        flush_pipeline();
        printf("#endif\n");
    }

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* Unmask and store a masked word */
static void masked_word_store(int num_shares)
{
    util_frame_t frame;
    reg_t *word[MAX_SHARES];
    int posn;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_x%d_store", family, num_shares);
    function_header(function_name);
    util_function_setup(&frame, 2, 1, 0);

    /* Load all of the shares and rotate into the same bit order */
    for (posn = 0; posn < num_shares; ++posn) {
        word[posn] = alloc_temp("share");
        acquire(word[posn]);
        load(word[posn], frame.arg[1]->real_reg, posn * 8);
    }
    for (posn = 1; posn < num_shares; ++posn) {
        ror(word[posn], UNROT(posn));
    }
    for (posn = 0; posn < num_shares; ++posn) {
        unop(IN_REVBYTES, word[posn]);
    }
    for (posn = 1; posn < num_shares; ++posn) {
        binop(IN_XOR, word[0], word[posn]);
    }
    store(word[0], frame.arg[0]->real_reg, 0);

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* Unmask and store a partial masked word */
static void masked_word_store_partial(int num_shares)
{
    util_frame_t frame;
    reg_t *word[MAX_SHARES];
    int posn;
    int label, label2;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_x%d_store_partial", family, num_shares);
    function_header(function_name);
    util_function_setup(&frame, 3, 2, 0);

    /* Load all of the shares and rotate into the same bit order */
    for (posn = 0; posn < num_shares; ++posn) {
        word[posn] = alloc_temp("share");
        acquire(word[posn]);
        load(word[posn], frame.arg[2]->real_reg, posn * 8);
    }
    for (posn = 1; posn < num_shares; ++posn) {
        ror(word[posn], UNROT(posn));
    }

    /* Unmask the first share */
    for (posn = 1; posn < num_shares; ++posn) {
        binop(IN_XOR, word[0], word[posn]);
    }

    /* Extract one byte at a time and store */
    label = branch(BR_ALWAYS, -1);
    label2 = set_label(-1);
    ror(word[0], 64 - 8);
    store_smaller(word[0], frame.arg[0]->real_reg, 0, 1);
    add_imm(frame.arg[1], -1);
    add_imm(frame.arg[0], 1);
    set_label(label);
    compare_imm(BR_GT, label2, frame.arg[1], 0);

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* Randomize a masked word */
static void masked_word_randomize(int num_shares)
{
    util_frame_t frame;
    reg_t *word;
    int posn;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_x%d_randomize", family, num_shares);
    function_header(function_name);
    util_function_setup(&frame, 2, 1, (num_shares - 1) * 8);

    /* Randomize the first word */
    word = alloc_temp("t");
    acquire(word);
    load(word, frame.arg[1]->real_reg, 0);
    for (posn = 1; posn < num_shares; ++posn) {
        binop(IN_XOR, word, frame.random[posn - 1]);
    }
    store(word, frame.arg[0]->real_reg, 0);

    /* Randomize the remaining words */
    for (posn = 1; posn < num_shares; ++posn) {
        load(word, frame.arg[1]->real_reg, posn * 8);
        ror(frame.random[posn - 1], ROT(posn));
        binop(IN_XOR, frame.random[posn - 1], word);
        store(frame.random[posn - 1], frame.arg[0]->real_reg, posn * 8);
    }

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* XOR two masked words */
static void masked_word_xor(int num_shares)
{
    util_frame_t frame;
    reg_t *word[MAX_SHARES];
    int posn;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_x%d_xor", family, num_shares);
    function_header(function_name);
    util_function_setup(&frame, 2, 1, 0);

    /* XOR the source with the destination */
    for (posn = 0; posn < num_shares; ++posn) {
        word[posn] = alloc_temp("src");
        acquire(word[posn]);
        load(word[posn], frame.arg[1]->real_reg, posn * 8);
    }
    for (posn = 0; posn < num_shares; ++posn) {
        xor_and_store(word[posn], frame.arg[0]->real_reg, posn * 8);
    }

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* Replace part of a masked word */
static void masked_word_replace(int num_shares)
{
    util_frame_t frame;
    reg_t *shift;
    reg_t *mask1;
    reg_t *mask2;
    reg_t *temp1;
    reg_t *temp2;
    int posn;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_x%d_replace", family, num_shares);
    function_header(function_name);
    util_function_setup(&frame, 3, 0, 0);

    /* Create the two masks */
    shift = alloc_named_register(REG_RCX); /* Shift count must be in CL */
    mask1 = alloc_temp("mask1");
    mask2 = alloc_temp("mask2");
    acquire(mask1);
    acquire(mask2);
    move(shift, frame.arg[2]);
    move_imm(mask1, -1);
    shl(shift, 3);
    shr_reg(mask1, shift);
    move(mask2, mask1);
    unop(IN_NOT, mask2);

    /* Perform the replacement on the shares */
    temp1 = shift;
    temp2 = alloc_temp("temp2");
    acquire(temp2);
    for (posn = 0; posn < num_shares; ++posn) {
        load(temp1, frame.arg[0]->real_reg, posn * 8);
        load(temp2, frame.arg[1]->real_reg, posn * 8);
        binop(IN_AND, temp1, mask1);
        binop(IN_AND, temp2, mask2);
        binop(IN_OR, temp1, temp2);
        store(temp1, frame.arg[0]->real_reg, posn * 8);
        if (posn < (num_shares - 1)) {
            /* Rotate the masks for the next share */
            ror(mask1, ROT(1));
            ror(mask2, ROT(1));
        }
    }

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* Conversion rule tables */
#define SRC_0       1
#define SRC_1       2
#define SRC_2       3
#define SRC_3       4
#define RANDOM_0    5
#define RANDOM_1    6
#define RANDOM_2    7
#define ROT_1       8
#define ROT_2       9
#define ROT_3       10
#define UNROT_1     11
#define UNROT_2     12
#define UNROT_3     13
static int const convert_x2_from_x3[] = {
    SRC_0, RANDOM_0, 0,
    SRC_1, ROT_1, RANDOM_0, UNROT_1, SRC_2, 0,
    0
};
static int const convert_x2_from_x4[] = {
    SRC_0, RANDOM_0, UNROT_2, SRC_2, 0,
    SRC_1, ROT_1, RANDOM_0, UNROT_2, SRC_3, 0,
    0
};
static int const convert_x3_from_x2[] = {
    SRC_0, RANDOM_0, RANDOM_1, 0,
    SRC_1, ROT_1, RANDOM_0, 0,
    ROT_2, RANDOM_1, 0,
    0
};
static int const convert_x3_from_x4[] = {
    SRC_0, RANDOM_0, RANDOM_1, UNROT_3, SRC_3, 0,
    SRC_1, ROT_1, RANDOM_0, 0,
    SRC_2, ROT_2, RANDOM_1, 0,
    0
};
static int const convert_x4_from_x2[] = {
    SRC_0, RANDOM_0, RANDOM_1, RANDOM_2, 0,
    SRC_1, ROT_1, RANDOM_0, 0,
    ROT_2, RANDOM_1, 0,
    ROT_3, RANDOM_2, 0,
    0
};
static int const convert_x4_from_x3[] = {
    SRC_0, RANDOM_0, RANDOM_1, RANDOM_2, 0,
    SRC_1, ROT_1, RANDOM_0, 0,
    SRC_2, ROT_2, RANDOM_1, 0,
    ROT_3, RANDOM_2, 0,
    0
};

/* Convert from one number of shares to another */
static void masked_word_convert
    (int to_shares, int from_shares, const int *rules)
{
    util_frame_t frame;
    reg_t *temp1;
    reg_t *temp2;
    int share;
    int rotation;
    int rule;
    int loaded;
    int offset;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_x%d_from_x%d", family, to_shares, from_shares);
    function_header(function_name);
    util_function_setup(&frame, 2, 0, (to_shares - 1) * 8);

    /* Run the rules for the randomized output shares */
    temp1 = alloc_temp("t1");
    temp2 = alloc_temp("t2");
    acquire(temp1);
    acquire(temp2);
    share = 0;
    while (*rules) {
        rotation = 0;
        loaded = 0;
        while ((rule = *rules++) != 0) {
            switch (rule) {
            case SRC_0:
            case SRC_1:
            case SRC_2:
            case SRC_3:
                offset = (rule - SRC_0) * 8;
                if (loaded) {
                    if (rotation == 0) {
                        load_and_xor(temp1, frame.arg[1]->real_reg, offset);
                    } else {
                        load(temp2, frame.arg[1]->real_reg, offset);
                        if (rotation != 0)
                            ror(temp2, rotation);
                        binop(IN_XOR, temp1, temp2);
                    }
                } else {
                    load(temp1, frame.arg[1]->real_reg, offset);
                    if (rotation != 0)
                        ror(temp1, rotation);
                    loaded = 1;
                }
                rotation = 0;
                break;

            case RANDOM_0:
            case RANDOM_1:
            case RANDOM_2:
                if (loaded) {
                    if (rotation == 0) {
                        binop(IN_XOR, temp1, frame.random[rule - RANDOM_0]);
                    } else {
                        move(temp2, frame.random[rule - RANDOM_0]);
                        if (rotation != 0)
                            ror(temp2, rotation);
                        binop(IN_XOR, temp1, temp2);
                    }
                } else {
                    move(temp1, frame.random[rule - RANDOM_0]);
                    if (rotation != 0)
                        ror(temp1, rotation);
                    loaded = 1;
                }
                break;

            case ROT_1:     rotation = ROT(1); break;
            case ROT_2:     rotation = ROT(2); break;
            case ROT_3:     rotation = ROT(3); break;
            case UNROT_1:   rotation = UNROT(1); break;
            case UNROT_2:   rotation = UNROT(2); break;
            case UNROT_3:   rotation = UNROT(3); break;
            }
        }
        store(temp1, frame.arg[0]->real_reg, share * 8);
        ++share;
    }

    /* Set the unused shares to zero */
    clear_reg(temp1->real_reg);
    flush_pipeline();
    if (to_shares == 2) {
        printf("#if ASCON_MASKED_MAX_SHARES >= 3\n");
        store(temp1, frame.state_reg, 16);
        flush_pipeline();
        printf("#endif\n");
        printf("#if ASCON_MASKED_MAX_SHARES >= 4\n");
        store(temp1, frame.state_reg, 24);
        flush_pipeline();
        printf("#endif\n");
    } else if (to_shares == 3) {
        printf("#if ASCON_MASKED_MAX_SHARES >= 4\n");
        store(temp1, frame.state_reg, 24);
        flush_pipeline();
        printf("#endif\n");
    }

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* Pad a masked word */
static void masked_word_pad(void)
{
    util_frame_t frame;
    reg_t *temp;
    reg_t *shift;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_pad", family);
    function_header(function_name);
    util_function_setup(&frame, 2, 0, 0);

    /* Create the padding value and XOR it in */
    shift = alloc_named_register(REG_RCX); /* Shift count must be in CL */
    temp = alloc_temp("padding");
    acquire(temp);
    move(shift, frame.arg[1]);
    shl(shift, 3);
    move_imm(temp, 0x8000000000000000LL);
    shr_reg(temp, shift);
    xor_and_store(temp, frame.arg[0]->real_reg, 0);

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

/* Put a separator value into a masked word */
static void masked_word_separator(void)
{
    util_frame_t frame;
    reg_t *temp;

    /* Function header */
    snprintf(function_name, sizeof(function_name),
             "%s_masked_word_separator", family);
    function_header(function_name);
    util_function_setup(&frame, 1, 0, 0);

    /* XOR the separator into the word */
    temp = alloc_temp("sep");
    acquire(temp);
    move_imm(temp, 1);
    xor_and_store(temp, frame.arg[0]->real_reg, 0);

    /* Function footer */
    util_function_teardown(&frame);
    function_footer(function_name);
}

static void if_shares(int num_shares)
{
    printf("#if ASCON_MASKED_MAX_SHARES >= %d\n", num_shares);
}

static void endif_shares(void)
{
    printf("#endif\n");
}

int main(int argc, char *argv[])
{
    /* Output the file header */
    printf("#include \"ascon-masked-backend.h\"\n");
    printf("#if defined(ASCON_MASKED_WORD_BACKEND_X86_64)\n");
    fputs(copyright_message, stdout);
#if INTEL_SYNTAX
    printf("\t.intel_syntax noprefix\n");
#endif
    printf("#if defined(__APPLE__)\n");
    printf("\t.section __TEXT,__text,regular,pure_instructions\n");
    printf("#define trng_generate_64 _%s_trng_generate_64\n", family);
    printf("#else\n");
    printf("\t.text\n");
    printf("#if defined(__PIC__)\n");
    printf("#define trng_generate_64 %s_trng_generate_64@PLT\n", family);
    printf("#else\n");
    printf("#define trng_generate_64 %s_trng_generate_64\n", family);
    printf("#endif\n");
    printf("#endif\n");

    /* Output word operations for 2-share words */
    masked_word_load(2, LOAD_ZERO);
    masked_word_load(2, LOAD_WORD64);
    masked_word_load(2, LOAD_PARTIAL);
    masked_word_load(2, LOAD_WORD32);
    masked_word_store(2);
    masked_word_store_partial(2);
    masked_word_randomize(2);
    masked_word_xor(2);
    masked_word_replace(2);
    if_shares(3);
    masked_word_convert(2, 3, convert_x2_from_x3);
    endif_shares();
    if_shares(4);
    masked_word_convert(2, 4, convert_x2_from_x4);
    endif_shares();

    /* Output word operations for 3-share words */
    if_shares(3);
    masked_word_load(3, LOAD_ZERO);
    masked_word_load(3, LOAD_WORD64);
    masked_word_load(3, LOAD_PARTIAL);
    masked_word_load(3, LOAD_WORD32);
    masked_word_store(3);
    masked_word_store_partial(3);
    masked_word_randomize(3);
    masked_word_xor(3);
    masked_word_replace(3);
    masked_word_convert(3, 2, convert_x3_from_x2);
    if_shares(4);
    masked_word_convert(3, 4, convert_x3_from_x4);
    endif_shares();
    endif_shares();

    /* Output word operations for 4-share words */
    if_shares(4);
    masked_word_load(4, LOAD_ZERO);
    masked_word_load(4, LOAD_WORD64);
    masked_word_load(4, LOAD_PARTIAL);
    masked_word_load(4, LOAD_WORD32);
    masked_word_store(4);
    masked_word_store_partial(4);
    masked_word_randomize(4);
    masked_word_xor(4);
    masked_word_replace(4);
    masked_word_convert(4, 2, convert_x4_from_x2);
    masked_word_convert(4, 3, convert_x4_from_x3);
    endif_shares();

    /* Some common utility functions */
    masked_word_pad();
    masked_word_separator();

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
