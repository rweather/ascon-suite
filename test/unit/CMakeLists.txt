
enable_testing()

list(APPEND COMMON_TEST_SOURCES
    sha256.c
    sha256.h
    sha3.c
    sha3.h
    test-cipher.c
    test-cipher.h
)

add_executable(ascon-test-hkdf
    ${COMMON_TEST_SOURCES}
    test-hkdf.c
)
target_link_libraries(ascon-test-hkdf PUBLIC ascon_static)

add_executable(ascon-test-hmac
    ${COMMON_TEST_SOURCES}
    test-hmac.c
)
target_link_libraries(ascon-test-hmac PUBLIC ascon_static)

add_executable(ascon-test-kmac
    ${COMMON_TEST_SOURCES}
    test-kmac.c
)
target_link_libraries(ascon-test-kmac PUBLIC ascon_static)

add_executable(ascon-test-pbkdf2
    ${COMMON_TEST_SOURCES}
    test-pbkdf2.c
)
target_link_libraries(ascon-test-pbkdf2 PUBLIC ascon_static)

add_executable(ascon-test-permutation
    ${COMMON_TEST_SOURCES}
    test-permutation.c
)
target_link_libraries(ascon-test-permutation PUBLIC ascon_static)

add_test(NAME ASCON-Permutation COMMAND ascon-test-permutation)
add_test(NAME ASCON-HKDF COMMAND ascon-test-hkdf)
add_test(NAME ASCON-HMAC COMMAND ascon-test-hmac)
add_test(NAME ASCON-KMAC COMMAND ascon-test-kmac)
add_test(NAME ASCON-PBKDF2 COMMAND ascon-test-pbkdf2)
