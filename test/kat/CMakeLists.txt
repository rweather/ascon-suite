
enable_testing()

# Program for running KAT tests.
add_executable(kat
    aead-metadata.h
    algorithms.c
    algorithms.h
    internal-blake2s.c
    internal-blake2s.h
    internal-chachapoly.c
    internal-chachapoly.h
    kat.c
    timing.c
    timing.h
)
target_link_libraries(kat PUBLIC ascon_static)
target_include_directories(kat
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/../../src/aead
)
if(HAVE_LIBRT)
    target_link_libraries(kat PRIVATE -lrt)
endif()
if(MINGW)
    target_link_options(kat PUBLIC --static)
endif()

# Program for generating KAT tests.
add_executable(kat-gen
    aead-metadata.h
    algorithms.c
    algorithms.h
    kat-gen.c
)
target_link_libraries(kat-gen PUBLIC ascon_static)
if(HAVE_LIBRT)
    target_link_libraries(kat-gen PRIVATE -lrt)
endif()
if(MINGW)
    target_link_options(kat-gen PUBLIC --static)
endif()

# Function to perform KAT tests on a specific algorithm.
function(kat_test algorithm kat_file gen_opts)
    # Add a unit test to run the KAT test.
    add_test(NAME kat-run-${algorithm} COMMAND bash -c "${CMAKE_CURRENT_BINARY_DIR}/kat ${algorithm} - <${CMAKE_CURRENT_LIST_DIR}/${kat_file}")

    # Add a unit test to generate the KAT output and cross-check.
    add_test(NAME kat-gen-${algorithm} COMMAND bash -c "${CMAKE_CURRENT_BINARY_DIR}/kat-gen ${gen_opts} ${algorithm} - | diff --strip-trailing-cr -q - ${CMAKE_CURRENT_LIST_DIR}/${kat_file}")

    # Add a custom command to run performance tests on the algorithm.
    add_custom_command(
        OUTPUT kat-perf-${algorithm}
        COMMAND bash -c "${CMAKE_CURRENT_BINARY_DIR}/kat --performance ${algorithm} - <${CMAKE_CURRENT_LIST_DIR}/${kat_file}"
    )
    list(APPEND PERF_RULES kat-perf-${algorithm})
    set(PERF_RULES ${PERF_RULES} PARENT_SCOPE)
endfunction()

# Perform all of the Known Answer Tests (KAT's).
kat_test(ASCON-128 ASCON-128.txt "")
kat_test(ASCON-128a ASCON-128a.txt "")
kat_test(ASCON-80pq ASCON-80pq.txt "")
kat_test(ASCON-128-incremental ASCON-128.txt "")
kat_test(ASCON-128a-incremental ASCON-128a.txt "")
kat_test(ASCON-80pq-incremental ASCON-80pq.txt "")
kat_test(ASCON-HASH ASCON-HASH.txt "")
kat_test(ASCON-HASHA ASCON-HASHA.txt "")
kat_test(ASCON-XOF ASCON-XOF.txt "")
kat_test(ASCON-XOFA ASCON-XOFA.txt "")
kat_test(ASCON-XOF-fixed-length ASCON-HASH.txt "")
kat_test(ASCON-XOFA-fixed-length ASCON-HASHA.txt "")
kat_test(ASCON-128-SIV ASCON-128-SIV.txt "")
kat_test(ASCON-128a-SIV ASCON-128a-SIV.txt "")
kat_test(ASCON-80pq-SIV ASCON-80pq-SIV.txt "")
kat_test(ISAP-A-128 ISAP-A-128.txt "")
kat_test(ISAP-A-128A ISAP-A-128A.txt "")
kat_test(ASCON-128-masked ASCON-128.txt "")
kat_test(ASCON-128a-masked ASCON-128a.txt "")
kat_test(ASCON-80pq-masked ASCON-80pq.txt "")
kat_test(ASCON-Prf ASCON-Prf.txt "")
kat_test(ASCON-PrfShort ASCON-PrfShort.txt "--max-msg=16")
kat_test(ASCON-Mac ASCON-Mac.txt "")
kat_test(ASCON-HMAC ASCON-HMAC.txt "")
kat_test(ASCON-HMACA ASCON-HMACA.txt "")

# Add a custom 'perf' target to run all performance tests.
add_custom_target(perf DEPENDS ${PERF_RULES})
