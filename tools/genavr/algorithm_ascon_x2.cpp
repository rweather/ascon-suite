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

// Offset of a word in the ASCON state.  Points to the high byte.
#define ASCON_WORD(word, share) (((word) * 2 + (share)) * 8)

// Offset of a byte in the ASCON state in big-endian byte order.
#define ASCON_BYTE(word, share, byte) (ASCON_WORD((word), (share)) + 7 - (byte))

// Adjustment to the Z pointer to access the x4.a and x4.b shares.
#define ASCON_OFFSET_ADJUST 64

// Offset of a byte in word 4 of the state on the stack.
#define ASCON_BYTE4(share, byte) ((share) * 8 + (byte))

// Compute "x ^= (~y) & z" using a 2-share masked representation.
static void bic_xor
    (Code &code, Reg &x_a, Reg &x_b, Reg &y_a, Reg &y_b, Reg &z_a, Reg &z_b)
{
    // x_a ^= (~y_a) & z_b;
    // x_a ^= (~y_a) & z_a;
    // x_b ^= y_b & z_b;
    // x_b ^= y_b & z_a;
    Reg t1 = code.allocateReg(1);
    Reg t2 = code.allocateReg(1);
    code.lognot(t1, y_a);
    code.move(t2, t1);
    code.logand(t1, z_a);
    code.logand(t2, z_b);
    code.logxor(x_a, t1);
    code.logxor(x_a, t2);
    code.move(t1, y_b);
    code.move(t2, y_b);
    code.logand(t1, z_a);
    code.logand(t2, z_b);
    code.logxor(x_b, t1);
    code.logxor(x_b, t2);
    code.releaseReg(t1);
    code.releaseReg(t2);
}

static void ascon_substitute(Code &code, int offset, Reg &x2_a)
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
    code.ldz(x0_a, ASCON_BYTE(0, 0, offset));
    code.ldz(x0_b, ASCON_BYTE(0, 1, offset));
    code.ldz(x1_a, ASCON_BYTE(1, 0, offset));
    code.ldz(x1_b, ASCON_BYTE(1, 1, offset));
    code.ldz(x2_b, ASCON_BYTE(2, 1, offset));
    code.ldz(x3_a, ASCON_BYTE(3, 0, offset));
    code.ldz(x3_b, ASCON_BYTE(3, 1, offset));
    code.ldlocal(x4_a, ASCON_BYTE4(0, offset));
    code.ldlocal(x4_b, ASCON_BYTE4(1, offset));

    // We need some temporary registers as well to hold the t0 shares.
    Reg t0_a = code.allocateReg(1);
    Reg t0_b = code.allocateReg(1);
    Reg t1_a = code.allocateReg(1);
    Reg t1_b = code.allocateReg(1);

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

    // Create zero as a pair of random shares, t0_b = t0_a.
    code.ldlocal(t0_a, 16 + offset);
    code.move(t0_b, t0_a);

    // Middle part of the substitution layer, Chi5.
    bic_xor(code, t0_a, t0_b, x0_a, x0_b, x1_a, x1_b);  // t0 ^= (~x0) & x1;
    bic_xor(code, x0_a, x0_b, x1_a, x1_b, x2_a, x2_b);  // x0 ^= (~x1) & x2;
    bic_xor(code, x1_a, x1_b, x2_a, x2_b, x3_a, x3_b);  // x1 ^= (~x2) & x3;
    bic_xor(code, x2_a, x2_b, x3_a, x3_b, x4_a, x4_b);  // x2 ^= (~x3) & x4;
    bic_xor(code, x3_a, x3_b, x4_a, x4_b, t1_a, t1_b);  // x3 ^= (~x4) & t1;
    code.logxor(x4_a, t0_a);        // x4_a ^= t0_a;
    code.logxor(x4_b, t0_b);        // x4_b ^= t0_b;

    // End of the substitution layer.
    code.logxor(x1_a, x0_a);        // x1_a ^= x0_a;
    code.logxor(x0_a, x4_a);        // x0_a ^= x4_a;
    code.logxor(x3_a, x2_a);        // x3_a ^= x2_a;
    code.lognot(x2_a);              // x2_a = ~x2_a;
    code.logxor(x1_b, x0_b);        // x1_b ^= x0_b;
    code.logxor(x0_b, x4_b);        // x0_b ^= x4_b;
    code.logxor(x3_b, x2_b);        // x3_b ^= x2_b;

    // Write all values back to the state except for x2_a which we
    // keep in registers between rounds.
    code.stz(x0_a, ASCON_BYTE(0, 0, offset));
    code.stz(x0_b, ASCON_BYTE(0, 1, offset));
    code.stz(x1_a, ASCON_BYTE(1, 0, offset));
    code.stz(x1_b, ASCON_BYTE(1, 1, offset));
    code.stz(x2_b, ASCON_BYTE(2, 1, offset));
    code.stz(x3_a, ASCON_BYTE(3, 0, offset));
    code.stz(x3_b, ASCON_BYTE(3, 1, offset));
    code.stlocal(x4_a, ASCON_BYTE4(0, offset));
    code.stlocal(x4_b, ASCON_BYTE4(1, offset));
    code.stlocal(t0_a, 16 + offset);

    // Release all registers except x2 and x4.
    code.releaseReg(x0_a);
    code.releaseReg(x1_a);
    code.releaseReg(x3_a);
    code.releaseReg(x4_a);
    code.releaseReg(x0_b);
    code.releaseReg(x1_b);
    code.releaseReg(x2_b);
    code.releaseReg(x3_b);
    code.releaseReg(x4_b);
    code.releaseReg(t0_a);
    code.releaseReg(t0_b);
    code.releaseReg(t1_a);
    code.releaseReg(t1_b);
}

static void ascon_diffuse
    (Code &code, const Reg &x, int word, int shift1, int shift2, int share = 0)
{
    // Compute "x ^= (x >>> shift1) ^ (x >>> shift2)".
    Reg t = code.allocateReg(8);
    if (word == 4)
        code.ldlocal(x, ASCON_BYTE4(share, 0)); // x4 is in local variables.
    else if (word != 2 || share != 0)
        code.ldz(x.reversed(), ASCON_WORD(word, share));
    code.move(t, x);
    code.ror(t, shift1);
    code.logxor(t, x);
    code.ror(x, shift2);
    code.logxor(x, t);
    if (word == 4)
        code.stlocal(x, ASCON_BYTE4(share, 0));
    else if (word != 2 || share != 0)
        code.stz(x.reversed(), ASCON_WORD(word, share));
    code.releaseReg(t);
}

void gen_ascon_x2_permutation(Code &code)
{
    // Set up the function prologue with 24 bytes of local variable storage.
    //
    // Z points to the permutation state on input and output.
    // X points to the preserved randomness on input.
    //
    // Local stack frame:
    //      16 bytes for a copy of the x4.a and x4.b shares.
    //      8 bytes for t0.a to hold the randomness from round to round.
    Reg round = code.prologue_masked_permutation("ascon_x2_permute", 24);

    // We are short on registers, so allow r0 to be used as a temporary.
    code.setFlag(Code::TempR0);

    // Compute "round = ((0x0F - round) << 4) | round" to convert the
    // first round number into a round constant.
    Reg temp = code.allocateHighReg(1);
    code.move(temp, 0x0F);
    code.sub(temp, round);
    code.onereg(Insn::SWAP, temp.reg(0));
    code.logor(round, temp);
    code.releaseReg(temp);

    // Transfer the preserved randomness from the caller to local t0.a.
    Reg x2 = code.allocateReg(8);
    code.ldx(x2.reversed(), POST_INC);
    code.stlocal(x2, 16);

    // Release the X register for use as temporaries during the function.
    // We will reload it when it is time to pass t0.a back to the caller.
    code.setFlag(Code::TempX);

    // We keep x2.a in registers between rounds so preload it.
    code.ldz(x2.reversed(), ASCON_WORD(2, 0));

    // There are 80 bytes in the state but we can efficiently only access
    // 64 of them with the Z pointer without constant pointer readjustment.
    // To alleviate this, we transfer x4.a and x4.b to local variables
    // so that we can access x4 with respect to the Y pointer instead.
    Reg x4 = code.allocateReg(8);
    code.add_ptr_z(ASCON_OFFSET_ADJUST);
    code.ldz(x4.reversed(), ASCON_WORD(4, 0) - ASCON_OFFSET_ADJUST);
    code.stlocal(x4, ASCON_BYTE4(0, 0));
    code.ldz(x4.reversed(), ASCON_WORD(4, 1) - ASCON_OFFSET_ADJUST);
    code.stlocal(x4, ASCON_BYTE4(1, 0));
    code.sub_ptr_z(ASCON_OFFSET_ADJUST);
    code.releaseReg(x4);

    // Top of the round loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // XOR the round constant with the low byte of "x2".
    code.logxor(x2, round);

    // Perform the substitution layer byte by byte.
    for (int index = 0; index < 8; ++index) {
        Reg x2_byte(x2, index, 1);
        ascon_substitute(code, index, x2_byte);
    }

    // Perform the linear diffusion layer on each of the state words.
    // "x2" is still in registers, but nothing else is.
    Reg t0 = code.allocateReg(8);
    ascon_diffuse(code, t0, 0, 19, 28, 0);  // First share.
    ascon_diffuse(code, t0, 1, 61, 39, 0);
    ascon_diffuse(code, x2, 2,  1,  6, 0);
    ascon_diffuse(code, t0, 3, 10, 17, 0);
    ascon_diffuse(code, t0, 4,  7, 41, 0);

    ascon_diffuse(code, t0, 0, 19, 28, 1);  // Second share.
    ascon_diffuse(code, t0, 1, 61, 39, 1);
    ascon_diffuse(code, t0, 2,  1,  6, 1);
    ascon_diffuse(code, t0, 3, 10, 17, 1);
    ascon_diffuse(code, t0, 4,  7, 41, 1);

    // Rotate t0_a right by 13 bits to produce the preseved random value
    // for the next round.  Equivalent to rotate left by 3 and right by 16.
    code.ldlocal(t0, 16);
    code.rol(t0, 3);
    code.stlocal(t0.shuffle(2, 3, 4, 5, 6, 7, 0, 1), 16);
    code.releaseReg(t0);

    // Bottom of the round loop.  Adjust the round constant and
    // check to see if we have reached the final round.
    code.sub(round, 0x0F);
    code.compare_and_loop(round, 0x3C, top_label);

    // Store the final version of x2.a back to the state memory.
    code.stz(x2.reversed(), ASCON_WORD(2, 0));

    // Transfer x4.a and x4.b from local variables back to the state.
    code.add_ptr_z(ASCON_OFFSET_ADJUST);
    code.ldlocal(x2, ASCON_BYTE4(0, 0));
    code.stz(x2.reversed(), ASCON_WORD(4, 0) - ASCON_OFFSET_ADJUST);
    code.ldlocal(x2, ASCON_BYTE4(1, 0));
    code.stz(x2.reversed(), ASCON_WORD(4, 1) - ASCON_OFFSET_ADJUST);

    // Transfer the preserved randomness in t0.a back to the caller.
    code.load_output_ptr();
    code.ldlocal(x2.reversed(), 16);
    code.stx(x2, POST_INC);
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
static void mask(unsigned char out[80], const unsigned char in[40])
{
    uint64_t word;
    uint64_t random;
    int index;
    for (index = 0; index < 5; ++index) {
        random = get_random();
        word = be_load_word64(in + index * 8);
        word ^= random;
        be_store_word64(out + index * 16, word);
        be_store_word64(out + index * 16 + 8, random);
    }
}

// Unmask the output state.
static void unmask(unsigned char out[40], const unsigned char in[80])
{
    uint64_t word;
    uint64_t random;
    int index;
    for (index = 0; index < 5; ++index) {
        word = be_load_word64(in + index * 16);
        random = be_load_word64(in + index * 16 + 8);
        word ^= random;
        be_store_word64(out + index * 8, word);
    }
}

bool test_ascon_x2_permutation(Code &code)
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
    unsigned char state[80];
    unsigned char result[40];
    unsigned char preserve[8];
    int ok;
    mask(state, input);
    be_store_word64(preserve, get_random());
    code.exec_masked_permutation(state, 80, 0, preserve, 8);
    unmask(result, state);
    ok = !memcmp(output_12, result, 40);
    mask(state, input);
    be_store_word64(preserve, get_random());
    code.exec_masked_permutation(state, 80, 4, preserve, 8);
    unmask(result, state);
    return ok && !memcmp(output_8, result, 40);
}
