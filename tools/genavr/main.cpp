/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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
#include "copyright.h"
#include <iostream>
#include <cstring>

enum Mode
{
    Generate,
    Test
};

static void header(std::ostream &ostream)
{
    ostream << "#include \"ascon-select-backend.h\"" << std::endl;
    ostream << "#if defined(ASCON_BACKEND_AVR)" << std::endl;
    ostream << copyright_message;
    ostream << "#include <avr/io.h>" << std::endl;
    ostream << "/* Automatically generated - do not edit */" << std::endl;
}

static void footer(std::ostream &ostream)
{
    ostream << std::endl;
    ostream << "#endif" << std::endl;
}

static bool ascon(enum Mode mode)
{
    Code code;
    gen_ascon_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_ascon_permutation(code)) {
            std::cout << "ASCON tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ASCON tests succeeded" << std::endl;
        }
    }
    return true;
}

typedef bool (*gen_code)(enum Mode mode);

int main(int argc, char *argv[])
{
    bool generate = true;
    int exit_val = 0;
    gen_code gen1 = 0;
    gen_code gen2 = 0;
    gen_code gen3 = 0;

    if (argc > 1 && !strcmp(argv[1], "--test")) {
        generate = false;
    } else {
        if (argc <= 1) {
            fprintf(stderr, "Usage: %s algorithm-name\n", argv[0]);
            return 1;
        }
        if (!strcmp(argv[1], "ASCON")) {
                gen1 = ascon;
        }
    }

    if (generate) {
        header(std::cout);
        if (gen1)
            gen1(Generate);
        if (gen2)
            gen2(Generate);
        if (gen3)
            gen3(Generate);
        footer(std::cout);
    } else {
        if (!ascon(Test))
            exit_val = 1;
    }

    return exit_val;
}
