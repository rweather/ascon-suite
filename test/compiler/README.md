
If you are having problems building the assembly code versions then it
may be due to differences in your assembler to mine.

To help resolve this, compile the test programs in this directory to
assembly code and send me the output.  Also collect up the macros that
the compiler platform uses.  If your compiler is compatible with gcc
command-line syntax, then the Makefile makes this easy:

    $ make clean
    $ make
    cc  -S -c test.c -o test-nopic.s
    cc  -fPIC -S -c test.c -o test-pic.s
    cc  -dM -E - </dev/null >test-predefined.h
    $ ls
    Makefile  README.md  test.c  test-nopic.s  test-pic.s  test-predefined.h

Send me "test-nopic.s", "test-pic.s", and "test-predefined.h".

If you are using a cross-compiler, then specify the CC and CFLAGS variables:

    $ make clean
    $ CC="avr-gcc" CFLAGS="-mmcu=atmega2560" make
    avr-gcc -mmcu=atmega2560 -S -c test.c -o test-nopic.s
    avr-gcc -mmcu=atmega2560 -fPIC -S -c test.c -o test-pic.s
    avr-gcc -mmcu=atmega2560 -dM -E - </dev/null >test-predefined.h
    $ ls
    Makefile  README.md  test.c  test-nopic.s  test-pic.s  test-predefined.h
