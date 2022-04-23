add_executable(asconcrypt asconcrypt.c fileops.c readpass.c)
target_link_libraries(asconcrypt PUBLIC ascon_static)
install(TARGETS asconcrypt DESTINATION bin)
