
list(APPEND ASCON_SOURCES
    aead/ascon-aead-128.c
    aead/ascon-aead-128a.c
    aead/ascon-aead-80pq.c
    aead/ascon-aead-common.c
    aead/ascon-aead-common.h
    core/ascon-asm-armv6m.S
    core/ascon-asm-armv6.S
    core/ascon-asm-armv7m.S
    core/ascon-asm-armv8a-64.S
    core/ascon-asm-avr5.S
    core/ascon-asm-i386.S
    core/ascon-asm-m68k.S
    core/ascon-asm-riscv32e.S
    core/ascon-asm-riscv32i.S
    core/ascon-asm-riscv64i.S
    core/ascon-asm-x86-64.S
    core/ascon-asm-xtensa.S
    core/ascon-c32.c
    core/ascon-c64.c
    core/ascon-clean.c
    core/ascon-direct-xor.c
    core/ascon-select-backend.h
    core/ascon-sliced32.c
    core/ascon-sliced32.h
    core/ascon-sliced64.c
    core/ascon-util.h
    core/ascon-util-snp.h
    core/ascon-version.c
    hash/ascon-hasha.c
    hash/ascon-hash.c
    hash/ascon-xofa.c
    hash/ascon-xof.c
    isap/ascon-isap-128.c
    isap/ascon-isap-128a.c
    isap/ascon-isap-common.h
    kdf/ascon-pbkdf2.c
    mac/ascon-hmac.c
    mac/ascon-hmaca.c
    mac/ascon-hmac-common.h
    mac/ascon-kmac.c
    mac/ascon-kmaca.c
    mac/ascon-kmac-common.h
    siv/ascon-siv-128.c
    siv/ascon-siv-128a.c
    siv/ascon-siv-80pq.c
)

if(NOT DEFINED ENV{MINIMAL})
add_library(ascon SHARED ${ASCON_SOURCES})

target_include_directories(ascon
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/../include
        ${CMAKE_CURRENT_LIST_DIR}/core
        ${CMAKE_CURRENT_LIST_DIR}
        ${PROJECT_BINARY_DIR}
)
set_target_properties(ascon PROPERTIES
    VERSION ${AsconSuite_VERSION_MAJOR}.${AsconSuite_VERSION_MINOR}.${AsconSuite_VERSION_PATCH}
    SOVERSION ${AsconSuite_VERSION_MAJOR}
)
endif()

add_library(ascon_static STATIC ${ASCON_SOURCES})
target_include_directories(ascon_static
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/../include
        ${CMAKE_CURRENT_LIST_DIR}/core
        ${CMAKE_CURRENT_LIST_DIR}
        ${PROJECT_BINARY_DIR}
)

# Install the libraries.
install(TARGETS ascon DESTINATION lib)
install(TARGETS ascon_static DESTINATION lib)
