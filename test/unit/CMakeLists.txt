
enable_testing()

list(APPEND COMMON_TEST_SOURCES
    sha256.c
    sha256.h
    test-cipher.c
    test-cipher.h
)

add_executable(ascon-test-cxof
    ${COMMON_TEST_SOURCES}
    test-cxof.c
)
target_link_libraries(ascon-test-cxof PUBLIC ascon_static)

add_executable(ascon-test-cxof-shared
    ${COMMON_TEST_SOURCES}
    test-cxof.c
)
target_link_libraries(ascon-test-cxof-shared PUBLIC ascon)

add_executable(ascon-test-hkdf
    ${COMMON_TEST_SOURCES}
    test-hkdf.c
)
target_link_libraries(ascon-test-hkdf PUBLIC ascon_static)

add_executable(ascon-test-hkdf-shared
    ${COMMON_TEST_SOURCES}
    test-hkdf.c
)
target_link_libraries(ascon-test-hkdf-shared PUBLIC ascon)

add_executable(ascon-test-hmac
    ${COMMON_TEST_SOURCES}
    test-hmac.c
)
target_link_libraries(ascon-test-hmac PUBLIC ascon_static)

add_executable(ascon-test-hmac-shared
    ${COMMON_TEST_SOURCES}
    test-hmac.c
)
target_link_libraries(ascon-test-hmac-shared PUBLIC ascon)

add_executable(ascon-test-kmac
    ${COMMON_TEST_SOURCES}
    test-kmac.c
)
target_link_libraries(ascon-test-kmac PUBLIC ascon_static)

add_executable(ascon-test-kmac-shared
    ${COMMON_TEST_SOURCES}
    test-kmac.c
)
target_link_libraries(ascon-test-kmac-shared PUBLIC ascon)

add_executable(ascon-test-masked-keys
    ${COMMON_TEST_SOURCES}
    test-masked-keys.c
)
target_link_libraries(ascon-test-masked-keys PUBLIC ascon_static)

add_executable(ascon-test-masked-keys-shared
    ${COMMON_TEST_SOURCES}
    test-masked-keys.c
)
target_link_libraries(ascon-test-masked-keys-shared PUBLIC ascon)

add_executable(ascon-test-pbkdf2
    ${COMMON_TEST_SOURCES}
    test-pbkdf2.c
)
target_link_libraries(ascon-test-pbkdf2 PUBLIC ascon_static)

add_executable(ascon-test-pbkdf2-shared
    ${COMMON_TEST_SOURCES}
    test-pbkdf2.c
)
target_link_libraries(ascon-test-pbkdf2-shared PUBLIC ascon)

add_executable(ascon-test-permutation
    ${COMMON_TEST_SOURCES}
    test-permutation.c
)
target_link_libraries(ascon-test-permutation PUBLIC ascon_static)

add_executable(ascon-test-permutation-shared
    ${COMMON_TEST_SOURCES}
    test-permutation.c
)
target_link_libraries(ascon-test-permutation-shared PUBLIC ascon)

add_executable(ascon-test-permutation-x2
    ${COMMON_TEST_SOURCES}
    test-permutation-x2.c
)
target_link_libraries(ascon-test-permutation-x2 PUBLIC ascon_static)

add_executable(ascon-test-permutation-x2-shared
    ${COMMON_TEST_SOURCES}
    test-permutation-x2.c
)
target_link_libraries(ascon-test-permutation-x2-shared PUBLIC ascon)

add_executable(ascon-test-permutation-x3
    ${COMMON_TEST_SOURCES}
    test-permutation-x3.c
)
target_link_libraries(ascon-test-permutation-x3 PUBLIC ascon_static)

add_executable(ascon-test-permutation-x3-shared
    ${COMMON_TEST_SOURCES}
    test-permutation-x3.c
)
target_link_libraries(ascon-test-permutation-x3-shared PUBLIC ascon)

add_executable(ascon-test-permutation-x4
    ${COMMON_TEST_SOURCES}
    test-permutation-x4.c
)
target_link_libraries(ascon-test-permutation-x4 PUBLIC ascon_static)

add_executable(ascon-test-permutation-x4-shared
    ${COMMON_TEST_SOURCES}
    test-permutation-x4.c
)
target_link_libraries(ascon-test-permutation-x4-shared PUBLIC ascon)

# Tests that are linked against the static library.
add_test(NAME ASCON-Permutation COMMAND ascon-test-permutation)
add_test(NAME ASCON-Permutation-x2 COMMAND ascon-test-permutation-x2)
add_test(NAME ASCON-Permutation-x3 COMMAND ascon-test-permutation-x3)
add_test(NAME ASCON-Permutation-x4 COMMAND ascon-test-permutation-x4)
add_test(NAME ASCON-cXOF COMMAND ascon-test-cxof)
add_test(NAME ASCON-HKDF COMMAND ascon-test-hkdf)
add_test(NAME ASCON-HMAC COMMAND ascon-test-hmac)
add_test(NAME ASCON-KMAC COMMAND ascon-test-kmac)
add_test(NAME ASCON-Masked-Keys COMMAND ascon-test-masked-keys)
add_test(NAME ASCON-PBKDF2 COMMAND ascon-test-pbkdf2)

# Tests that are linked against the shared library.
add_test(NAME ASCON-Permutation-Shared COMMAND ascon-test-permutation-shared)
add_test(NAME ASCON-Permutation-x2-Shared COMMAND ascon-test-permutation-x2-shared)
add_test(NAME ASCON-Permutation-x3-Shared COMMAND ascon-test-permutation-x3-shared)
add_test(NAME ASCON-Permutation-x4-Shared COMMAND ascon-test-permutation-x4-shared)
add_test(NAME ASCON-cXOF-Shared COMMAND ascon-test-cxof-shared)
add_test(NAME ASCON-HKDF-Shared COMMAND ascon-test-hkdf-shared)
add_test(NAME ASCON-HMAC-Shared COMMAND ascon-test-hmac-shared)
add_test(NAME ASCON-KMAC-Shared COMMAND ascon-test-kmac-shared)
add_test(NAME ASCON-Masked-Keys-Shared COMMAND ascon-test-masked-keys-shared)
add_test(NAME ASCON-PBKDF2-Shared COMMAND ascon-test-pbkdf2-shared)
