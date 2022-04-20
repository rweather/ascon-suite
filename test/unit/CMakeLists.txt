
enable_testing()

add_executable(ascon-tests
    sha256.c
    sha256.h
    sha3.c
    sha3.h
    test-cipher.c
    test-cipher.h
    test-hkdf.c
    test-hmac.c
    test-kmac.c
    test-main.c
    test-pbkdf2.c
    test-permutation.c
)
target_link_libraries(ascon-tests PUBLIC ascon_static)

add_test(NAME unit-tests COMMAND ascon-tests)
