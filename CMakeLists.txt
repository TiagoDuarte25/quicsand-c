CMAKE_MINIMUM_REQUIRED(VERSION 3.22.1)
PROJECT(quicsand)

if(EXISTS "/etc/lsb-release")
    file(STRINGS "/etc/lsb-release" LSB_RELEASE_CONTENT)
    string(REGEX MATCH "DISTRIB_ID=([a-zA-Z]+)" DISTRO_NAME ${LSB_RELEASE_CONTENT})
    message(STATUS "Distro Name from lsb-release: ${DISTRO_NAME}")
elseif(EXISTS "/etc/os-release")
    file(STRINGS "/etc/os-release" OS_RELEASE_CONTENT)
    string(REGEX MATCH "PRETTY_NAME=\"([^\"]+)\"" DISTRO_NAME ${OS_RELEASE_CONTENT})
    message(STATUS "Distro Name from os-release: ${DISTRO_NAME}")
else()
    message(FATAL_ERROR "No recognizable OS version file found.")
endif()

# Default to Release build if not set
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Set compiler flags for Debug and Release builds
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DOPENSSL_DEBUG -DDEBUG -fsanitize=address,undefined,leak -Wall -Wextra -Wshadow -Wformat=2 -Werror -fstack-protector-all -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "-g -O0")

# Optionally, set C++ flags if you are using C++
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

message(STATUS "Compiler flags (Debug): ${CMAKE_C_FLAGS_DEBUG}")
message(STATUS "Compiler flags (Release): ${CMAKE_C_FLAGS_RELEASE}")

option(BUILD_IN_DOCKER "Build in Docker container" OFF)

add_definitions(-D_GNU_SOURCE)

FILE(GLOB SRC "quicsand/src/*.c")
include_directories(quicsand/include)

if(NOT DEFINED IMPL)
    message(FATAL_ERROR "IMPL variable is not set. Please set it to either 'msquic' or 'quiche'.")
endif()
message(STATUS "IMPL: ${IMPL}")

if("${IMPL}" STREQUAL "msquic")

    add_definitions(-DMSQUIC)

    if(BUILD_IN_DOCKER)
        set(MSQUIC_DIR /msquic)
        set(MSQUIC_LIB_DIR msquic)
    else()
        set(MSQUIC_DIR ${CMAKE_BINARY_DIR}/msquic)
        set(MSQUIC_LIB_DIR ${MSQUIC_DIR}/build/bin/Release/libmsquic.so)
    endif()
    
    # Add msquic include directories
    include_directories(${MSQUIC_DIR}/src/inc)

    # Set libraries
    SET(LIBS ${MSQUIC_LIB_DIR} bpf m)

    set(DEF MSQUIC)

ELSEIF("${IMPL}" STREQUAL "quiche")

    add_definitions(-DQUICHE)

    if(BUILD_IN_DOCKER)
        set(QUICHE_DIR /quiche)
        set(QUICHE_LIB_DIR quiche)
    else()
        # build quiche
        set(QUICHE_DIR ${CMAKE_BINARY_DIR}/quiche)
        set(QUICHE_LIB_DIR ${QUICHE_DIR}/target/debug/libquiche.a)
    endif()

    include_directories(${QUICHE_DIR}/quiche/include)

    # Set libraries
    SET(LIBS ${QUICHE_LIB_DIR} ev m)

    set(DEF QUICHE)

ELSE()
    message(FATAL_ERROR "IMPL must be either msquic or quiche")
ENDIF()

find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(deps REQUIRED IMPORTED_TARGET glib-2.0)

# Include both client and server source files
file(GLOB CLIENT_SOURCES quicsand/src/client/*.c)
file(GLOB SERVER_SOURCES quicsand/src/server/*.c)
set(APP_SOURCES ${CLIENT_SOURCES} ${SERVER_SOURCES})
foreach(testsourcefile ${APP_SOURCES})
    # Cut off the file extension and directory path
    get_filename_component(testname ${testsourcefile} NAME_WE)
    add_executable( ${testname} ${SRC} ${testsourcefile} )
    # Make sure YourLib is linked to each app
    target_include_directories(${testname} PRIVATE quicsand/include)
    target_include_directories(${testname} PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${testname} ${LIBS})
    target_link_libraries(${testname} PkgConfig::deps)
    target_link_libraries(${testname} OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(${testname} PRIVATE ${DEF})
    set_target_properties(${testname} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endforeach(testsourcefile ${APP_SOURCES})