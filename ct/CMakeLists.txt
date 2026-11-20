# Builds ct/probe.c against zlibstat.lib and an Mbed TLS release. ct/ci.py
# configures it once for each toolset and C runtime Cyber Triage links
# zlibstat.lib with, choosing the C runtime with CMAKE_MSVC_RUNTIME_LIBRARY.
#
#   ZLIB_INCLUDE     directories with zlib.h and the generated zconf.h
#   ZLIB_LIB         zlibstat.lib
#   MBEDTLS_INCLUDE  the Mbed TLS include directory
#   MBEDTLS_LIB      the Mbed TLS mbedTLS.lib for the same toolset and C runtime
cmake_minimum_required(VERSION 3.15)
project(ct_probe C)

add_executable(probe probe.c)
target_include_directories(probe PRIVATE ${ZLIB_INCLUDE} "${MBEDTLS_INCLUDE}")
target_link_libraries(probe PRIVATE "${ZLIB_LIB}" "${MBEDTLS_LIB}")
# A link warning, such as LNK4098 for a mixed C runtime or LNK4099 for a
# missing PDB, fails the build.
set_target_properties(probe PROPERTIES LINK_FLAGS "/WX")
