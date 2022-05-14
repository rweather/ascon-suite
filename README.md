ASCON Suite
===========

This repository builds a number of useful cryptographic primitives
around the ASCON permutation.

API's are provided for the following areas:

* Authenticated Encryption with Associated Data (AEAD)
* Hashing
* Pseudorandom Function (PRF)
* Message Authentication Code (MAC)
* HMAC-based Key Derivation Function (HKDF)
* Hashed Message Authentication Code (HMAC)
* ISAP AEAD Mode with Side Channel Protections
* Keyed Message Authentication Code (KMAC)
* Password-Based Key Derivation Function (PBKDF2)
* Pseudorandom Number Generation (PRNG)
* Synthetic Initialization Vector (SIV)
* Extensible Output Functions (XOF)
* Direct Access to the ASCON Permutation

See the [HTML documentation](https://rweather.github.io/ascon-suite/index.html)
for more information on the suite.

A version of ASCON Suite is available for Arduino devices in a
[separate repository](https://github.com/rweather/ascon-arduino).

Building
--------

ASCON Suite uses [cmake](https://cmake.org/) to build, so you will need to
have that installed.  Here is the simplest method to compile, test, and
install the library:

    mkdir build
    cd build
    cmake ..
    make
    make test
    sudo make install

To build with a cross-compiler, set the "CC" and "CMAKE\_C\_FLAGS"
variables when invoking cmake:

    mkdir build
    cd build
    CC="avr-gcc" cmake -DMINIMAL=ON -DCMAKE_C_FLAGS="-mmcu=atmega2560" ..
    make

Note carefully the placement of environment variables before the "cmake"
command name, and the cmake variables specified with "-D" after.

The MINIMAL option suppresses the compilation of shared libraries, examples,
and test programs, which may not compile for embedded microcontrollers due to
missing libc functions or other platform constraints.  Only the static library
libascon\_static.a is built in the minimal configuration.

History
-------

The functionality in this library was originally prototyped in the
[LWC Finalists](https://github.com/rweather/lwc-finalists) repository.
This repository extracts and expands the ASCON-specific parts of the
original repository.

Contact
-------

For more information on this code, to report bugs, or to suggest
improvements, please contact the author Rhys Weatherley via
[email](mailto:rhys.weatherley@gmail.com).
