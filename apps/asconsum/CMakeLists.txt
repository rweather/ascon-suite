add_executable(asconsum asconsum.c)
target_link_libraries(asconsum PUBLIC ascon_static)
install(TARGETS asconsum DESTINATION bin)
