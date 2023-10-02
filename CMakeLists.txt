cmake_minimum_required(VERSION 3.18)
cmake_policy(SET CMP0048 NEW)
project(hdrbg LANGUAGES C VERSION 1.0.0 DESCRIPTION "C implementation of Hash DRBG")
include(GNUInstallDirs)

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

file(GLOB sources lib/*.c)
list(FILTER sources EXCLUDE REGEX ".*py.*")
add_library(hdrbg SHARED ${sources})
target_include_directories(hdrbg PRIVATE include)
configure_file(hdrbg.pc.in hdrbg.pc @ONLY)

find_package(OpenSSL 3.0.0)
if(OPENSSL_FOUND)
    target_compile_definitions(hdrbg PRIVATE TFPF_HASH_DRBG_OPENSSL_FOUND=1)
    target_include_directories(hdrbg PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(hdrbg PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})
endif()

if(MINGW OR MSYS)
    target_link_libraries(hdrbg PRIVATE -lbcrypt)
endif()

set_target_properties(hdrbg PROPERTIES
    PUBLIC_HEADER include/hdrbg.h
    SOVERSION 1
    VERSION ${PROJECT_VERSION}
)
target_compile_options(hdrbg PRIVATE -O2 -Wall -Wextra -fstrict-aliasing)

install(TARGETS hdrbg
    CONFIGURATIONS Release
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(FILES ${CMAKE_BINARY_DIR}/hdrbg.pc
    CONFIGURATIONS Release
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)
