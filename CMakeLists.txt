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

IF(CMAKE_BUILD_TYPE STREQUAL "")
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
IF (CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -DOPENSSL_DEBUG -DDEBUG")
ELSEIF (CMAKE_BUILD_TYPE STREQUAL Release)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
ENDIF()
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

option(BUILD_IN_DOCKER "Build in Docker container" OFF)

add_definitions(-D_GNU_SOURCE)


FILE(GLOB CLIENT_SRC "quicsand/src/client/*.c")
FILE(GLOB SERVER_SRC "quicsand/src/server/*.c")
FILE(GLOB SRC "quicsand/src/*.c")
INCLUDE_DIRECTORIES(quicsand/include)

# Create executables targets
ADD_EXECUTABLE(client ${SRC} ${CLIENT_SRC})
ADD_EXECUTABLE(server ${SRC} ${SERVER_SRC})

set(THREAD_POOL_DIR ${CMAKE_BINARY_DIR}/C-Thread-Pool)
set(LIBEV_DIR ${CMAKE_BINARY_DIR}/libev)

# Clone and build C-Thread-Pool
if(NOT EXISTS ${THREAD_POOL_DIR})
execute_process(
    COMMAND git clone https://github.com/Pithikos/C-Thread-Pool.git ${THREAD_POOL_DIR}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
# Compile the source files into a shared library
execute_process(
    COMMAND gcc -fPIC -shared thpool.c -o libthpool.so -pthread
    WORKING_DIRECTORY ${THREAD_POOL_DIR}
)
endif()

# Clone and build libev
if(NOT EXISTS ${LIBEV_DIR})
execute_process(
    COMMAND git clone https://github.com/enki/libev.git ${LIBEV_DIR}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
execute_process(
    COMMAND ./autoreconf -vfi
    WORKING_DIRECTORY ${LIBEV_DIR}
)
execute_process(
    COMMAND ./configure --prefix=/usr --enable-shared
    WORKING_DIRECTORY ${LIBEV_DIR}
)
execute_process(
    COMMAND make
    WORKING_DIRECTORY ${LIBEV_DIR}
)
endif()

include_directories(${LIBEV_DIR})
include_directories(${THREAD_POOL_DIR})

# Find the libev library
find_library(EVENT_LIBRARY NAMES libev.so PATHS ${LIBEV_DIR}/.libs NO_DEFAULT_PATH)
find_library(THREAD_POOL_LIBRARY NAMES thpool PATHS ${THREAD_POOL_DIR} NO_DEFAULT_PATH)

if("${IMPL}" STREQUAL "msquic")

    if(BUILD_IN_DOCKER)
        set(MSQUIC_DIR /msquic)
    else()
        set(MSQUIC_DIR ${CMAKE_BINARY_DIR}/msquic)
    endif()
    
    # Add msquic include directories
    include_directories(${MSQUIC_DIR}/src/inc)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
    target_link_libraries(server PkgConfig::GLIB)
    target_link_libraries(client PkgConfig::GLIB)
    

    # Set libraries
    SET(LIBS ${MSQUIC_DIR}/build/bin/Release/libmsquic.so bpf ${EVENT_LIBRARY} ${THREAD_POOL_LIBRARY} m)

    target_compile_definitions(client PRIVATE MSQUIC)
    target_compile_definitions(server PRIVATE MSQUIC)


ELSEIF("${IMPL}" STREQUAL "quiche")

    if(BUILD_IN_DOCKER)
        set(QUICHE_DIR /quiche)
        set(QUICHE_LIB_DIR ${QUICHE_DIR}/target/release/libquiche.a)
    else()
        # build quiche
        set(QUICHE_DIR ${CMAKE_BINARY_DIR}/quiche)
        set(QUICHE_LIB_DIR ${QUICHE_DIR}/target/debug/libquiche.a)
    endif()

    include_directories(${QUICHE_DIR}/quiche/include)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(deps REQUIRED IMPORTED_TARGET glib-2.0)
    target_link_libraries(server PkgConfig::deps)
    target_link_libraries(client PkgConfig::deps)

    # Set libraries
    SET(LIBS ${QUICHE_LIB_DIR} ${EVENT_LIBRARY} ${THREAD_POOL_LIBRARY} m)

    target_compile_definitions(client PRIVATE QUICHE)
    target_compile_definitions(server PRIVATE QUICHE)

ELSE()
    message(FATAL_ERROR "IMPL must be either msquic or quiche")
ENDIF()
    
TARGET_INCLUDE_DIRECTORIES(server PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(server ${LIBS})
SET_TARGET_PROPERTIES(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

TARGET_INCLUDE_DIRECTORIES(client PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(client ${LIBS})
SET_TARGET_PROPERTIES(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)