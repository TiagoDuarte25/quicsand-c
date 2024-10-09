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

if("${IMPL}" STREQUAL "lsquic")

    add_definitions(-DLSQUIC)   

    message(STATUS "Building LSQUIC with BoringSSL")

    # Define directories
    set(BORINGSSL_DIR ${CMAKE_BINARY_DIR}/boringssl)
    set(LSQUIC_DIR ${CMAKE_BINARY_DIR}/lsquic)

    # Clone and build BoringSSL
    if(NOT EXISTS ${BORINGSSL_DIR}/ssl/libssl.so OR NOT EXISTS ${BORINGSSL_DIR}/crypto/libcrypto.so)
        if(EXISTS ${BORINGSSL_DIR})
            file(REMOVE_RECURSE ${BORINGSSL_DIR})
        endif()
        execute_process(
            COMMAND git clone https://boringssl.googlesource.com/boringssl ${BORINGSSL_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
        # Enable dynamic libraries
        execute_process(
            COMMAND cmake -DBUILD_SHARED_LIBS=1 -DCMAKE_C_FLAGS="-Wno-error" -DCMAKE_CXX_FLAGS="-Wno-error" .
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
        execute_process(
            COMMAND make ssl crypto
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
    endif()

    # Clone and build LSQUIC
    if(NOT EXISTS ${LSQUIC_DIR}/src/liblsquic/liblsquic.so)
        if(EXISTS ${LSQUIC_DIR})
            file(REMOVE_RECURSE ${LSQUIC_DIR})
        endif()
        execute_process(
            COMMAND git clone https://github.com/litespeedtech/lsquic.git ${LSQUIC_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND git submodule update --init
            WORKING_DIRECTORY ${LSQUIC_DIR}
        )
        execute_process(
            COMMAND cmake -DBORINGSSL_DIR=${BORINGSSL_DIR} -DLSQUIC_SHARED_LIB=1 .
            WORKING_DIRECTORY ${LSQUIC_DIR}
        )
        execute_process(
            COMMAND make
            WORKING_DIRECTORY ${LSQUIC_DIR}
        )
    endif()

    # Add LSQUIC library directories and BoringSSL include directories
    include_directories(${BORINGSSL_DIR}/include)
    include_directories(${BORINGSSL_DIR}/include/openssl)
    include_directories(${BORINGSSL_DIR}/include/crypto)
    include_directories(${LSQUIC_DIR}/include)
    include_directories(${LSQUIC_DIR}/src/liblsquic)

    # Manually set the libraries
    set(LIBS ${EVENT_LIBRARY} ${THREAD_POOL_LIBRARY} ${BORINGSSL_DIR}/ssl/libssl.so ${BORINGSSL_DIR}/crypto/libcrypto.so ${LSQUIC_DIR}/src/liblsquic/liblsquic.so m yaml z)

    IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # If using older glibc, need to link with -lrt. See clock_getres(2).
        EXECUTE_PROCESS(
            COMMAND ${PROJECT_SOURCE_DIR}/print-glibc-version.sh ${CMAKE_C_COMPILER}
            OUTPUT_VARIABLE GLIBC_VERSION)
        IF(NOT GLIBC_VERSION EQUAL "" AND GLIBC_VERSION VERSION_LESS 2.17)
            SET(LIBS ${LIBS} rt)
        ENDIF()
    ENDIF()
ELSEIF("${IMPL}" STREQUAL "msquic")

    add_definitions(-DMSQUIC)

    # Clone and build msquic
    if(NOT EXISTS ${CMAKE_BINARY_DIR}/msquic)
        execute_process(
            COMMAND git clone https://github.com/microsoft/msquic.git ${CMAKE_BINARY_DIR}/msquic
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND git submodule update --init
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/msquic
        )
        execute_process(
            COMMAND pwsh ./scripts/prepare-machine.ps1 -UseXdp -ForceXdpInstall
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/msquic
        )
        execute_process(
            COMMAND pwsh ./scripts/build.ps1 -UseXdp
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/msquic
        )
    endif()
    
    # Add msquic
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/inc)
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/core)
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/platform/linux)
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/platform/linux/interop)
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/platform/linux/interop/openssl)
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/platform/linux/interop/openssl/include)
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/platform/linux/interop/openssl/crypto/include)
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/platform/linux/interop/openssl/ssl/include)

    # Set libraries
    SET(LIBS msquic yaml bpf ${EVENT_LIBRARY} ${THREAD_POOL_LIBRARY})

ELSEIF("${IMPL}" STREQUAL "quiche")

    add_definitions(-DQUICHE)

    # Add a custom command to build libquiche.so
    ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_SOURCE_DIR}/implementations/quiche/target/release/libquiche.so
                        COMMAND cargo build --release --features ffi
                        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/implementations/quiche
                        COMMENT "Building libquiche.so")

    # Add a custom target that depends on the custom command
    ADD_CUSTOM_TARGET(BuildQuiche DEPENDS implementations/quiche/target/release/libquiche.so)

    # Add the custom target as a dependency for the client and server executables
    ADD_DEPENDENCIES(client BuildQuiche)
    ADD_DEPENDENCIES(server BuildQuiche)

    # Add quiche
    INCLUDE_DIRECTORIES(implementations/quiche/quiche/include)
    INCLUDE_DIRECTORIES(implementations/libev)

    # Find the quiche library
    FIND_LIBRARY(QUICHE_LIBRARY NAMES quiche PATHS implementations/quiche/target/release NO_DEFAULT_PATH)
    FIND_LIBRARY(EVENT_LIBRARY NAMES ev PATHS implementations/libev/.libs NO_DEFAULT_PATH)

    MESSAGE(STATUS "QUICHE_LIBRARY: ${QUICHE_LIBRARY}")
    MESSAGE(STATUS "EVENT_LIBRARY: ${EVENT_LIBRARY}")

    # Set libraries
    SET(LIBS ${QUICHE_LIBRARY} ${EVENT_LIBRARY} yaml)

# ELSE()
#     MESSAGE(FATAL_ERROR "Invalid implementation: ${IMPL}")
ENDIF()
    
TARGET_INCLUDE_DIRECTORIES(server PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(server ${LIBS})
SET_TARGET_PROPERTIES(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

TARGET_INCLUDE_DIRECTORIES(client PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(client ${LIBS})
SET_TARGET_PROPERTIES(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)