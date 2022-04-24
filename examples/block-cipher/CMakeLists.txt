enable_testing()
add_executable(ascon-block-cipher
    main.c
    ascon-ecb.c
    ascon-ecb.h
)
target_link_libraries(ascon-block-cipher PUBLIC ascon_static)
add_test(NAME ASCON-ECB COMMAND ascon-block-cipher)
