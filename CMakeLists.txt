cmake_minimum_required(VERSION 3.5)
include(CheckIncludeFiles)
include(CheckFunctionExists)

# Set the project name and version number.
project(AsconSuite VERSION 0.1.0 LANGUAGES C ASM)

# Add the version details to the version.h include file.
configure_file(include/ascon/version.h.in version.h)

# Set up the type of build and the compiler flags to use.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS "-Wall -Wextra -DHAVE_CONFIG_H ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

# Require the c99 standard to compile the code.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Set up the assembler options.
set(ASM_OPTIONS "-x assembler-with-cpp")
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS} ${ASM_OPTIONS}")

# Check for some system features.
check_include_files(strings.h HAVE_STRINGS_H)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(memset_s HAVE_MEMSET_S)
configure_file(config.h.in config.h)

# Set up the main include directory.
include_directories(include)

# Add the subdirectories.
add_subdirectory(include)
add_subdirectory(src)
if(NOT DEFINED ENV{MINIMAL})
    add_subdirectory(test)
    add_subdirectory(examples EXCLUDE_FROM_ALL)
endif()

# Enable testing support.
enable_testing()

# Custom 'test' rule to run the unit tests in a more verbose way.
add_custom_target(test-verbose COMMAND ${CMAKE_CTEST_COMMAND}
    --force-new-ctest-process
    --verbose
    --output-on-failure
)

# Install the version.h include file.
install(FILES ${PROJECT_BINARY_DIR}/version.h DESTINATION include/ascon)
