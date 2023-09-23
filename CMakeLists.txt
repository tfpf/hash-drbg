cmake_minimum_required(VERSION 3.22)
cmake_policy(SET CMP0048 NEW)
project(hdrbg VERSION 1.0.0 DESCRIPTION "C implementation of Hash DRBG")
include(GNUInstallDirs)

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

file(GLOB sources lib/*.c)
list(FILTER sources EXCLUDE REGEX ".*py.*")
add_library(hdrbg SHARED ${sources})
target_include_directories(hdrbg PRIVATE include)
configure_file(hdrbg.pc.in hdrbg.pc @ONLY)

set_target_properties(hdrbg PROPERTIES
    PUBLIC_HEADER include/hdrbg.h
    SOVERSION 1
    VERSION ${PROJECT_VERSION}
)
target_compile_options(hdrbg PRIVATE -O2 -Wall -Wextra -fstrict-aliasing)

install(TARGETS hdrbg
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(FILES ${CMAKE_BINARY_DIR}/hdrbg.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)
