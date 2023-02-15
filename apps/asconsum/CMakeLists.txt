add_executable(asconsum asconsum.c)
target_link_libraries(asconsum PUBLIC ascon_static)
install(TARGETS asconsum DESTINATION bin)
install(FILES asconsum.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)
