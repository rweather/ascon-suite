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

#include "gen.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

// Adjustment to the Z pointer to access the high shares.
#define ASCON_OFFSET_ADJUST 64

// Locations of words in the state.  Offsets less than 64 are accessed
// relative to the Z pointer.  Offsets 64 or greater are accessed
// relative to the local stack space (Y pointer).
typedef struct
{
    // Operational location for x0, x1, x2, x3, x4.
    int loc[5];

    // Original location in the state structure for x0, x1, x2, x3, x4.
    int st[5];

} ascon_locations_t;

// Load a single byte from the state.
static void load_byte
    (Code &code, const Reg &reg, int offset, int share, int byte)
{
    offset += share * 8;
    if (offset < 64)
        code.ldz(reg, offset + 7 - byte);       // Big endian order.
    else
        code.ldlocal(reg, offset + byte - 64);  // Little endian order.
}

// Store a single byte to the state.
static void store_byte
    (Code &code, const Reg &reg, int offset, int share, int byte)
{
    offset += share * 8;
    if (offset < 64)
        code.stz(reg, offset + 7 - byte);       // Big endian order.
    else
        code.stlocal(reg, offset + byte - 64);  // Little endian order.
}

// Load a 64-bit word from the state.
static void load_word
    (Code &code, const Reg &reg, int offset, int share)
{
    offset += share * 8;
    if (offset < 64)
        code.ldz(reg.reversed(), offset);       // Big endian order.
    else
        code.ldlocal(reg, offset - 64);         // Little endian order.
}

// Store a 64-bit word to the state.
static void store_word
    (Code &code, const Reg &reg, int offset, int share)
{
    offset += share * 8;
    if (offset < 64)
        code.stz(reg.reversed(), offset);       // Big endian order.
    else
        code.stlocal(reg, offset - 64);         // Little endian order.
}

// Compute "x ^= (~y) & z" using a 2-share masked representation.
static void bic_xor
    (Code &code, Reg &x_a, Reg &x_b, Reg &x_c,
     Reg &y_a, Reg &y_b, Reg &y_c, Reg &z_a, Reg &z_b, Reg &z_c)
{
    // We need a temporary register.
    Reg t1 = code.allocateReg(1);

    // x_a ^= (~y_a) & z_a;
    // x_a ^= y_a & z_b;
    // x_a ^= y_a & z_c;
    code.lognot(t1, y_a);
    code.logand(t1, z_a);
    code.logxor(x_a, t1);
    code.move(t1, y_a);
    code.logand(t1, z_b);
    code.logxor(x_a, t1);
    code.move(t1, y_a);
    code.logand(t1, z_c);
    code.logxor(x_a, t1);

    // x_b ^= y_b & z_a;
    // x_b ^= (~y_b) & z_b;
    // x_b ^= y_b & z_c;
    code.move(t1, y_b);
    code.logand(t1, z_a);
    code.logxor(x_b, t1);
    code.lognot(t1, y_b);
    code.logand(t1, z_b);
    code.logxor(x_b, t1);
    code.move(t1, y_b);
    code.logand(t1, z_c);
    code.logxor(x_b, t1);

    // x_c ^= y_c & (~z_a);
    // x_c ^= y_c & z_b;
    // x_c ^= y_c | z_c;
    code.lognot(t1, z_a);
    code.logand(t1, y_c);
    code.logxor(x_c, t1);
    code.move(t1, y_c);
    code.logand(t1, z_b);
    code.logxor(x_c, t1);
    code.move(t1, y_c);
    code.logor(t1, z_c);
    code.logxor(x_c, t1);

    // Free the temporary register.
    code.releaseReg(t1);
}

static void ascon_substitute
    (Code &code, const ascon_locations_t &locations, int offset, Reg &x2_a)
{
    // Allocate and load the registers for all byte shares.
    // The x2.a value has already been loaded by the calling function.
    Reg x0_a = code.allocateReg(1);
    Reg x1_a = code.allocateReg(1);
    Reg x3_a = code.allocateReg(1);
    Reg x4_a = code.allocateReg(1);
    Reg x0_b = code.allocateReg(1);
    Reg x1_b = code.allocateReg(1);
    Reg x2_b = code.allocateReg(1);
    Reg x3_b = code.allocateReg(1);
    Reg x4_b = code.allocateReg(1);
    Reg x0_c = code.allocateReg(1);
    Reg x1_c = code.allocateReg(1);
    Reg x2_c = code.allocateReg(1);
    Reg x3_c = code.allocateReg(1);
    Reg x4_c = code.allocateReg(1);
    load_byte(code, x0_a, locations.loc[0], 0, offset);
    load_byte(code, x0_b, locations.loc[0], 1, offset);
    load_byte(code, x0_c, locations.loc[0], 2, offset);
    load_byte(code, x1_a, locations.loc[1], 0, offset);
    load_byte(code, x1_b, locations.loc[1], 1, offset);
    load_byte(code, x1_c, locations.loc[1], 2, offset);
    load_byte(code, x2_b, locations.loc[2], 1, offset);
    load_byte(code, x2_c, locations.loc[2], 2, offset);
    load_byte(code, x3_a, locations.loc[3], 0, offset);
    load_byte(code, x3_b, locations.loc[3], 1, offset);
    load_byte(code, x3_c, locations.loc[3], 2, offset);
    load_byte(code, x4_a, locations.loc[4], 0, offset);
    load_byte(code, x4_b, locations.loc[4], 1, offset);
    load_byte(code, x4_c, locations.loc[4], 2, offset);

    // We need some temporary registers as well to hold the t0 shares.
    Reg t0_a = code.allocateReg(1);
    Reg t0_b = code.allocateReg(1);
    Reg t0_c = code.allocateReg(1);
    Reg t1_a = code.allocateReg(1);
    Reg t1_b = code.allocateReg(1);
    Reg t1_c = code.allocateReg(1);

    // Start of the substitution layer, first share.
    code.logxor(x0_a, x4_a);        // x0_a ^= x4_a;
    code.logxor(x4_a, x3_a);        // x4_a ^= x3_a;
    code.logxor(x2_a, x1_a);        // x2_a ^= x1_a;
    code.move(t1_a, x0_a);          // t1_a  = x0_a;

    // Start of the substitution layer, second share.
    code.logxor(x0_b, x4_b);        // x0_b ^= x4_b;
    code.logxor(x4_b, x3_b);        // x4_b ^= x3_b;
    code.logxor(x2_b, x1_b);        // x2_b ^= x1_b;
    code.move(t1_b, x0_b);          // t1_b  = x0_b;

    // Start of the substitution layer, third share.
    code.logxor(x0_c, x4_c);        // x0_c ^= x4_c;
    code.logxor(x4_c, x3_c);        // x4_c ^= x3_c;
    code.logxor(x2_c, x1_c);        // x2_c ^= x1_c;
    code.move(t1_c, x0_c);          // t1_c  = x0_c;

    // Create zero as a pair of random shares, t0_b = t0_a.
    code.ldx(t0_a, POST_INC);
    code.ldx(t0_b, 0);
    code.move(t0_c, t0_a);
    code.logxor(t0_c, t0_b);

    // Middle part of the substitution layer, Chi5.
    // t0 ^= (~x0) & x1;
    bic_xor(code, t0_a, t0_b, t0_c, x0_a, x0_b, x0_c, x1_a, x1_b, x1_c);
    // x0 ^= (~x1) & x2;
    bic_xor(code, x0_a, x0_b, x0_c, x1_a, x1_b, x1_c, x2_a, x2_b, x2_c);
    // x1 ^= (~x2) & x3;
    bic_xor(code, x1_a, x1_b, x1_c, x2_a, x2_b, x2_c, x3_a, x3_b, x3_c);
    // x2 ^= (~x3) & x4;
    bic_xor(code, x2_a, x2_b, x2_c, x3_a, x3_b, x3_c, x4_a, x4_b, x4_c);
    // x3 ^= (~x4) & t1;
    bic_xor(code, x3_a, x3_b, x3_c, x4_a, x4_b, x4_c, t1_a, t1_b, t1_c);
    code.logxor(x4_a, t0_a);        // x4_a ^= t0_a;
    code.logxor(x4_b, t0_b);        // x4_b ^= t0_b;
    code.logxor(x4_c, t0_c);        // x4_c ^= t0_c;

    // End of the substitution layer.
    code.logxor(x1_a, x0_a);        // x1_a ^= x0_a;
    code.logxor(x0_a, x4_a);        // x0_a ^= x4_a;
    code.logxor(x3_a, x2_a);        // x3_a ^= x2_a;
    code.lognot(x2_a);              // x2_a = ~x2_a;
    code.logxor(x1_b, x0_b);        // x1_b ^= x0_b;
    code.logxor(x0_b, x4_b);        // x0_b ^= x4_b;
    code.logxor(x3_b, x2_b);        // x3_b ^= x2_b;
    code.logxor(x1_c, x0_c);        // x1_c ^= x0_c;
    code.logxor(x0_c, x4_c);        // x0_c ^= x4_c;
    code.logxor(x3_c, x2_c);        // x3_c ^= x2_c;

    // Write all values back to the state except for x2_a which is
    // handled by the caller.
    store_byte(code, x0_a, locations.loc[0], 0, offset);
    store_byte(code, x0_b, locations.loc[0], 1, offset);
    store_byte(code, x0_c, locations.loc[0], 2, offset);
    store_byte(code, x1_a, locations.loc[1], 0, offset);
    store_byte(code, x1_b, locations.loc[1], 1, offset);
    store_byte(code, x1_c, locations.loc[1], 2, offset);
    store_byte(code, x2_b, locations.loc[2], 1, offset);
    store_byte(code, x2_c, locations.loc[2], 2, offset);
    store_byte(code, x3_a, locations.loc[3], 0, offset);
    store_byte(code, x3_b, locations.loc[3], 1, offset);
    store_byte(code, x3_c, locations.loc[3], 2, offset);
    store_byte(code, x4_a, locations.loc[4], 0, offset);
    store_byte(code, x4_b, locations.loc[4], 1, offset);
    store_byte(code, x4_c, locations.loc[4], 2, offset);
    code.sub_ptr_x(1);
    code.stx(t0_a, POST_INC);
    code.stx(t0_b, POST_INC);

    // Release all registers except x2_a.
    code.releaseReg(x0_a);
    code.releaseReg(x1_a);
    code.releaseReg(x3_a);
    code.releaseReg(x4_a);
    code.releaseReg(x0_b);
    code.releaseReg(x1_b);
    code.releaseReg(x2_b);
    code.releaseReg(x3_b);
    code.releaseReg(x4_b);
    code.releaseReg(x0_c);
    code.releaseReg(x1_c);
    code.releaseReg(x2_c);
    code.releaseReg(x3_c);
    code.releaseReg(x4_c);
    code.releaseReg(t0_a);
    code.releaseReg(t0_b);
    code.releaseReg(t0_c);
    code.releaseReg(t1_a);
    code.releaseReg(t1_b);
    code.releaseReg(t1_c);
}

static void ascon_diffuse
    (Code &code, const ascon_locations_t &locations, const Reg &x,
     int word, int shift1, int shift2, int share = 0)
{
    // Compute "x ^= (x >>> shift1) ^ (x >>> shift2)".
    Reg t = code.allocateReg(8);
    load_word(code, x, locations.loc[word], share);
    code.move(t, x);
    code.ror(t, shift1);
    code.logxor(t, x);
    code.ror(x, shift2);
    code.logxor(x, t);
    store_word(code, x, locations.loc[word], share);
    code.releaseReg(t);
}

void gen_ascon_x3_permutation(Code &code)
{
    int index;

    // Set up the function prologue with 56 bytes of local variable storage.
    //
    // Z points to the permutation state on input and output.
    // X points to the preserved randomness on input.
    //
    // Local stack frame:
    //      8 bytes for a copy of the x2.c share.
    //      24 bytes for a copy of the x3 shares.
    //      24 bytes for a copy of the x4 shares.
    //
    // The 16 bytes of the preserved randomness t0 is kept in the memory
    // that is pointed at by the X register.  We cheat a little by using
    // the even bytes for t0.a and the odd bytes for t0.b rather than
    // separate the words.  The input is random so there shouldn't be
    // any issue with interleaving the preserved randomness like this.
    Reg round = code.prologue_masked_permutation("ascon_x3_permute", 56);

    // Compute "round = ((0x0F - round) << 4) | round" to convert the
    // first round number into a round constant.
    Reg temp = code.allocateHighReg(1);
    code.move(temp, 0x0F);
    code.sub(temp, round);
    code.onereg(Insn::SWAP, temp.reg(0));
    code.logor(round, temp);
    code.releaseReg(temp);

    // Set up the locations of all words.  There are 120 bytes in the
    // state plus 16 bytes of preserved randomness.  We can efficiently
    // access only 64 bytes with the Z pointer without constant pointer
    // readjustment.  To alleviate this, we transfer some of the words
    // to the stack so that we can access them with respect to the Y
    // pointer instead.
    ascon_locations_t locations;
    locations.st[0] = 0;
    locations.st[1] = 24;
    locations.st[2] = 48;
    locations.st[3] = 72;
    locations.st[4] = 96;
    locations.loc[0] = 0;
    locations.loc[1] = 24;
    locations.loc[2] = 48;
    locations.loc[3] = 72;
    locations.loc[4] = 96;

    // Transfer x2.c, x3, and x4 to the stack to make them easier to access.
    Reg t0 = code.allocateReg(8);
    code.add_ptr_z(ASCON_OFFSET_ADJUST);
    load_word(code, t0, locations.st[2] - ASCON_OFFSET_ADJUST, 2);
    store_word(code, t0, locations.loc[2], 2);
    load_word(code, t0, locations.st[3] - ASCON_OFFSET_ADJUST, 0);
    store_word(code, t0, locations.loc[3], 0);
    load_word(code, t0, locations.st[3] - ASCON_OFFSET_ADJUST, 1);
    store_word(code, t0, locations.loc[3], 1);
    load_word(code, t0, locations.st[3] - ASCON_OFFSET_ADJUST, 2);
    store_word(code, t0, locations.loc[3], 2);
    load_word(code, t0, locations.st[4] - ASCON_OFFSET_ADJUST, 0);
    store_word(code, t0, locations.loc[4], 0);
    load_word(code, t0, locations.st[4] - ASCON_OFFSET_ADJUST, 1);
    store_word(code, t0, locations.loc[4], 1);
    load_word(code, t0, locations.st[4] - ASCON_OFFSET_ADJUST, 2);
    store_word(code, t0, locations.loc[4], 2);
    code.sub_ptr_z(ASCON_OFFSET_ADJUST);
    code.releaseReg(t0);

    // Top of the round loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // Perform the substitution layer byte by byte.
    for (index = 0; index < 8; ++index) {
        Reg x2_a = code.allocateReg(1);
        load_byte(code, x2_a, locations.loc[2], 0, index);
        if (index == 0) {
            // XOR the round constant with the low byte of "x2.a".
            code.logxor(x2_a, round);
        }
        ascon_substitute(code, locations, index, x2_a);
        store_byte(code, x2_a, locations.loc[2], 0, index);
        code.releaseReg(x2_a);
    }
    code.sub_ptr_x(16);

    // The code is very large at this point.  The "rjmp" at the bottom
    // of the loop won't be able to reach back to the top.  So we create
    // an intermediate leapfrog here to get back up to the top.
    unsigned char label1 = 0;
    unsigned char label2 = 0;
    code.jmp(label2);
    code.label(label1);
    code.jmp(top_label);
    code.label(label2);

    // Perform the linear diffusion layer on each of the state words.
    t0 = code.allocateReg(8);
    ascon_diffuse(code, locations, t0, 0, 19, 28, 2);   // Third share.
    ascon_diffuse(code, locations, t0, 1, 61, 39, 2);
    ascon_diffuse(code, locations, t0, 2,  1,  6, 2);
    ascon_diffuse(code, locations, t0, 3, 10, 17, 2);
    ascon_diffuse(code, locations, t0, 4,  7, 41, 2);

    ascon_diffuse(code, locations, t0, 0, 19, 28, 1);   // Second share.
    ascon_diffuse(code, locations, t0, 1, 61, 39, 1);
    ascon_diffuse(code, locations, t0, 2,  1,  6, 1);
    ascon_diffuse(code, locations, t0, 3, 10, 17, 1);
    ascon_diffuse(code, locations, t0, 4,  7, 41, 1);

    ascon_diffuse(code, locations, t0, 0, 19, 28, 0);   // First share.
    ascon_diffuse(code, locations, t0, 1, 61, 39, 0);
    ascon_diffuse(code, locations, t0, 2,  1,  6, 0);
    ascon_diffuse(code, locations, t0, 3, 10, 17, 0);
    ascon_diffuse(code, locations, t0, 4,  7, 41, 0);

    // Rotate t0_a right by 13 bits and t0_b right by 29 bits to produce
    // the preseved random value for the next round.
    //
    // Rotate right by 13 is the same as rotate left by 3 and right by 16.
    // Rotate right by 29 is the same as rotate left by 3 and right by 32.
    //
    // The t0_a and t0_b values are interleaved in memory at the X pointer.
    Reg t1 = code.allocateReg(8);
    for (index = 0; index < 8; ++index) {
        code.ldx(Reg(t0, index, 1), POST_INC);
        code.ldx(Reg(t1, index, 1), POST_INC);
    }
    code.rol(t0, 3);
    code.rol(t1, 3);
    for (index = 7; index >= 0; --index) {
        code.stx(Reg(t0, (index + 2) % 8, 1), PRE_DEC);
        code.stx(Reg(t1, (index + 4) % 8, 1), PRE_DEC);
    }
    code.releaseReg(t1);
    code.releaseReg(t0);

    // Bottom of the round loop.  Adjust the round constant and
    // check to see if we have reached the final round.
    code.sub(round, 0x0F);
    code.compare_and_loop(round, 0x3C, label1);

    // Transfer x2.c, x3, and x4 from local variables back to the state.
    t0 = code.allocateReg(8);
    code.add_ptr_z(ASCON_OFFSET_ADJUST);
    load_word(code, t0, locations.loc[2], 2);
    store_word(code, t0, locations.st[2] - ASCON_OFFSET_ADJUST, 2);
    load_word(code, t0, locations.loc[3], 0);
    store_word(code, t0, locations.st[3] - ASCON_OFFSET_ADJUST, 0);
    load_word(code, t0, locations.loc[3], 1);
    store_word(code, t0, locations.st[3] - ASCON_OFFSET_ADJUST, 1);
    load_word(code, t0, locations.loc[3], 2);
    store_word(code, t0, locations.st[3] - ASCON_OFFSET_ADJUST, 2);
    load_word(code, t0, locations.loc[4], 0);
    store_word(code, t0, locations.st[4] - ASCON_OFFSET_ADJUST, 0);
    load_word(code, t0, locations.loc[4], 1);
    store_word(code, t0, locations.st[4] - ASCON_OFFSET_ADJUST, 1);
    load_word(code, t0, locations.loc[4], 2);
    store_word(code, t0, locations.st[4] - ASCON_OFFSET_ADJUST, 2);
}

/* Load a big-endian 64-bit word from a byte buffer */
#define be_load_word64(ptr) \
    ((((uint64_t)((ptr)[0])) << 56) | \
     (((uint64_t)((ptr)[1])) << 48) | \
     (((uint64_t)((ptr)[2])) << 40) | \
     (((uint64_t)((ptr)[3])) << 32) | \
     (((uint64_t)((ptr)[4])) << 24) | \
     (((uint64_t)((ptr)[5])) << 16) | \
     (((uint64_t)((ptr)[6])) << 8) | \
      ((uint64_t)((ptr)[7])))

/* Store a big-endian 64-bit word into a byte buffer */
#define be_store_word64(ptr, x) \
    do { \
        uint64_t _x = (x); \
        (ptr)[0] = (uint8_t)(_x >> 56); \
        (ptr)[1] = (uint8_t)(_x >> 48); \
        (ptr)[2] = (uint8_t)(_x >> 40); \
        (ptr)[3] = (uint8_t)(_x >> 32); \
        (ptr)[4] = (uint8_t)(_x >> 24); \
        (ptr)[5] = (uint8_t)(_x >> 16); \
        (ptr)[6] = (uint8_t)(_x >> 8); \
        (ptr)[7] = (uint8_t)_x; \
    } while (0)

// Get a random 64-bit word.
static uint64_t get_random(void)
{
    static bool initialized = false;
    if (!initialized) {
        srand(time(NULL));
        initialized = true;
    }
    // rand() produces a 31-bit number; we need a 64-bit number.
    return ((uint64_t)rand()) |
           (((uint64_t)rand()) << 31) |
           (((uint64_t)rand()) << 62);
}

// Mask the input state.
static void mask(unsigned char out[120], const unsigned char in[40])
{
    uint64_t word;
    uint64_t random1;
    uint64_t random2;
    int index;
    memset(out, 0, 120);
    for (index = 0; index < 5; ++index) {
        random1 = get_random();
        random2 = get_random();
        word = be_load_word64(in + index * 8);
        word ^= random1 ^ random2;
        be_store_word64(out + index * 24, word);
        be_store_word64(out + index * 24 + 8, random1);
        be_store_word64(out + index * 24 + 16, random2);
    }
}

// Unmask the output state.
static void unmask(unsigned char out[40], const unsigned char in[120])
{
    uint64_t word;
    uint64_t random1;
    uint64_t random2;
    int index;
    for (index = 0; index < 5; ++index) {
        word = be_load_word64(in + index * 24);
        random1 = be_load_word64(in + index * 24 + 8);
        random2 = be_load_word64(in + index * 24 + 16);
        word ^= random1 ^ random2;
        be_store_word64(out + index * 8, word);
    }
}

bool test_ascon_x3_permutation(Code &code)
{
    static unsigned char const input[40] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };
    static unsigned char const output_12[40] = {
        0x06, 0x05, 0x87, 0xe2, 0xd4, 0x89, 0xdd, 0x43,
        0x1c, 0xc2, 0xb1, 0x7b, 0x0e, 0x3c, 0x17, 0x64,
        0x95, 0x73, 0x42, 0x53, 0x18, 0x44, 0xa6, 0x74,
        0x96, 0xb1, 0x71, 0x75, 0xb4, 0xcb, 0x68, 0x63,
        0x29, 0xb5, 0x12, 0xd6, 0x27, 0xd9, 0x06, 0xe5
    };
    static unsigned char const output_8[40] = {
        0x83, 0x0d, 0x26, 0x0d, 0x33, 0x5f, 0x3b, 0xed,
        0xda, 0x0b, 0xba, 0x91, 0x7b, 0xcf, 0xca, 0xd7,
        0xdd, 0x0d, 0x88, 0xe7, 0xdc, 0xb5, 0xec, 0xd0,
        0x89, 0x2a, 0x02, 0x15, 0x1f, 0x95, 0x94, 0x6e,
        0x3a, 0x69, 0xcb, 0x3c, 0xf9, 0x82, 0xf6, 0xf7
    };
    unsigned char state[120];
    unsigned char result[40];
    unsigned char preserve[16];
    int ok;
    mask(state, input);
    be_store_word64(preserve, get_random());
    be_store_word64(preserve + 8, get_random());
    code.exec_masked_permutation(state, 120, 0, preserve, 16);
    unmask(result, state);
    ok = !memcmp(output_12, result, 40);
    mask(state, input);
    be_store_word64(preserve, get_random());
    be_store_word64(preserve + 8, get_random());
    code.exec_masked_permutation(state, 120, 4, preserve, 16);
    unmask(result, state);
    return ok && !memcmp(output_8, result, 40);
}
