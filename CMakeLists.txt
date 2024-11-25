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
remove_definitions(-DLSQUIC)
remove_definitions(-DMSQUIC)
remove_definitions(-DQUICHE)
remove_definitions(-DNGTCP2)


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

    if(NOT EXISTS ${BORINGSSL_DIR})
        execute_process(
            COMMAND git clone https://boringssl.googlesource.com/boringssl ${BORINGSSL_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
    endif()

    # Build BoringSSL
    if(NOT EXISTS ${BORINGSSL_DIR}/ssl/libssl.so OR NOT EXISTS ${BORINGSSL_DIR}/crypto/libcrypto.so)
        # Enable dynamic libraries
        execute_process(
            COMMAND cmake -DBUILD_SHARED_LIBS=1 -DCMAKE_C_FLAGS="-Wno-error" -DCMAKE_CXX_FLAGS="-Wno-error" .
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
        execute_process(
            COMMAND make -j ssl crypto
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
    endif()

    # Clone LSQUIC
    if(NOT EXISTS ${LSQUIC_DIR})
        execute_process(
            COMMAND git clone https://github.com/litespeedtech/lsquic.git ${LSQUIC_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND git submodule update --init
            WORKING_DIRECTORY ${LSQUIC_DIR}
        )
    endif()
        

    # Build LSQUIC
    if(NOT EXISTS ${LSQUIC_DIR}/src/liblsquic/liblsquic.so)
        execute_process(
            COMMAND cmake -DBORINGSSL_DIR=${BORINGSSL_DIR} -DLSQUIC_SHARED_LIB=1 .
            WORKING_DIRECTORY ${LSQUIC_DIR}
        )
        execute_process(
            COMMAND make -j lsquic
            WORKING_DIRECTORY ${LSQUIC_DIR}
        )
    endif()

    # Add LSQUIC library directories and BoringSSL include directories
    include_directories(${BORINGSSL_DIR}/include)
    include_directories(${LSQUIC_DIR}/include)
    include_directories(${LSQUIC_DIR}/src/liblsquic)


    # Add LSQUIC examples
    set(LSQUIC_EXAMPLES_DIR ${LSQUIC_DIR}/bin)
    include_directories(${LSQUIC_EXAMPLES_DIR})
    CONFIGURE_FILE(${LSQUIC_EXAMPLES_DIR}/test_config.h.in ${LSQUIC_EXAMPLES_DIR}/test_config.h)
    add_executable(tut quicsand/tut.c)
    add_executable(echo_server ${LSQUIC_EXAMPLES_DIR}/echo_server.c ${LSQUIC_EXAMPLES_DIR}/prog.c ${LSQUIC_EXAMPLES_DIR}/test_common.c ${LSQUIC_EXAMPLES_DIR}/test_cert.c)
    add_executable(echo_client ${LSQUIC_EXAMPLES_DIR}/echo_client.c ${LSQUIC_EXAMPLES_DIR}/prog.c ${LSQUIC_EXAMPLES_DIR}/test_common.c ${LSQUIC_EXAMPLES_DIR}/test_cert.c)

    # Manually set the libraries
    set(LIBS ${EVENT_LIBRARY} ${THREAD_POOL_LIBRARY} ${BORINGSSL_DIR}/ssl/libssl.so ${BORINGSSL_DIR}/crypto/libcrypto.so ${LSQUIC_DIR}/src/liblsquic/liblsquic.so m yaml z)

    target_compile_definitions(client PRIVATE LSQUIC)
    target_compile_definitions(server PRIVATE LSQUIC)

    IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # If using older glibc, need to link with -lrt. See clock_getres(2).
        EXECUTE_PROCESS(
            COMMAND ${PROJECT_SOURCE_DIR}/print-glibc-version.sh ${CMAKE_C_COMPILER}
            OUTPUT_VARIABLE GLIBC_VERSION)
        IF(NOT GLIBC_VERSION EQUAL "" AND GLIBC_VERSION VERSION_LESS 2.17)
            SET(LIBS ${LIBS} rt)
        ENDIF()
    ENDIF()
    target_link_libraries(tut ${LIBS})
    target_link_libraries(echo_server ${LIBS} event)
    target_link_libraries(echo_client ${LIBS} event)

ELSEIF("${IMPL}" STREQUAL "msquic")

    add_definitions(-DMSQUIC)

    set(MSQUIC_DIR ${CMAKE_BINARY_DIR}/msquic)

    if(NOT EXISTS ${MSQUIC_DIR})
        execute_process(
            COMMAND git clone https://github.com/microsoft/msquic.git ${MSQUIC_DIR}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND git submodule update --init
            WORKING_DIRECTORY ${MSQUIC_DIR}
        )
    endif()

    # If powershell is not installed, install it
    if (NOT EXISTS /usr/bin/pwsh)
        execute_process(
            COMMAND wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
            COMMAND dpkg -i packages-microsoft-prod.deb
            COMMAND apt-get update
            COMMAND add-apt-repository universe
            COMMAND apt-get install -y powershell
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND apt-get remove libicu57
            COMMAND wget http://security.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7ubuntu0.5_amd64.deb
            COMMAND dpkg -i libicu55_55.1-7ubuntu0.5_amd64.deb
            COMMAND wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.0.0_1.0.2g-1ubuntu4.20_amd64.deb
            COMMAND dpkg -i libssl1.0.0_1.0.2g-1ubuntu4.20_amd64.deb
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )

        execute_process(
            COMMAND apt-add-repository "deb http://mirrors.kernel.org/ubuntu noble main" -y
            COMMAND apt-get install -y libxdp1 libbpf1 libnl-3-200 libnl-route-3-200 libnl-genl-3-200
            COMMAND apt-get --no-install-recommends -y install libxdp-dev libbpf-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev 
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    endif()

    # Clone and build msquic
    if(NOT EXISTS ${MSQUIC_DIR}/build/bin/Release/libmsquic.so)
        if(NOT EXISTS ${MSQUIC_DIR}/build)
            execute_process(
                COMMAND mkdir build
                WORKING_DIRECTORY ${MSQUIC_DIR}
            )
        endif()
        
        execute_process(
            COMMAND cmake -G "Unix Makefiles" ..
            WORKING_DIRECTORY ${MSQUIC_DIR}/build
        )
        execute_process(
            COMMAND cmake --build .
            WORKING_DIRECTORY ${MSQUIC_DIR}/build
        )
    endif()
    
    # Add msquic
    INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/msquic/src/inc)

    # Set libraries
    SET(LIBS ${MSQUIC_DIR}/build/bin/Release/libmsquic.so yaml bpf ${EVENT_LIBRARY} ${THREAD_POOL_LIBRARY})

    target_compile_definitions(client PRIVATE MSQUIC)
    target_compile_definitions(server PRIVATE MSQUIC)

ELSEIF("${IMPL}" STREQUAL "quiche")

    add_definitions(-DQUICHE)

    set (QUICHE_DIR ${CMAKE_BINARY_DIR}/quiche)

    if(NOT EXISTS ${QUICHE_DIR})
        execute_process(
            COMMAND git clone --recursive https://github.com/cloudflare/quiche
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
    endif()
    if (NOT EXISTS ${QUICHE_DIR}/target/debug/libquiche.a)
        execute_process(
            COMMAND cargo build --features ffi
            WORKING_DIRECTORY ${QUICHE_DIR}
        )
    endif()

    include_directories(${QUICHE_DIR}/quiche/include)

    # Set libraries
    SET(LIBS ${QUICHE_DIR}/target/debug/libquiche.a ${EVENT_LIBRARY} ${THREAD_POOL_LIBRARY} yaml m)

    target_compile_definitions(client PRIVATE QUICHE)
    target_compile_definitions(server PRIVATE QUICHE)

ELSEIF("${IMPL}" STREQUAL "ngtcp2")

    # Link libraries
    set(LIBS m yaml z)

    # Build BoringSSL
    set(BORINGSSL_DIR ${CMAKE_BINARY_DIR}/boringssl)
    if (NOT EXISTS ${BORINGSSL_DIR})
        execute_process(
            COMMAND git clone https://boringssl.googlesource.com/boringssl
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND git checkout 76968bb3d53982560bcf08bcd0ba3e1865fe15cd
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
        execute_process(
            COMMAND cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON
            WORKING_DIRECTORY ${BORINGSSL_DIR}
        )
        execute_process(
            COMMAND make -j$(nproc)
            WORKING_DIRECTORY ${BORINGSSL_DIR}\build
        )
    endif()
    include_directories(${BORINGSSL_DIR}/include)
    list(APPEND LIBS ${BORINGSSL_DIR}/build/ssl/libssl.a ${BORINGSSL_DIR}/build/crypto/libcrypto.a)

    # Build nghttp3
    set(NGHTTP3_DIR ${CMAKE_BINARY_DIR}/nghttp3)
    if (NOT EXISTS ${NGHTTP3_DIR})
        execute_process(
            COMMAND git clone --recursive https://github.com/ngtcp2/nghttp3
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND autoreconf -i
            WORKING_DIRECTORY ${NGHTTP3_DIR}
        )
        execute_process(
            COMMAND ./configure --prefix=${NGHTTP3_DIR}/build --enable-lib-only
            WORKING_DIRECTORY ${NGHTTP3_DIR}
        )
        execute_process(
            COMMAND make -j$(nproc) check
            WORKING_DIRECTORY ${NGHTTP3_DIR}
        )
        execute_process(
            COMMAND make install
            WORKING_DIRECTORY ${NGHTTP3_DIR}
        )
    endif()

    include_directories(${NGHTTP3_DIR}/build/include)
    list(APPEND LIBS ${NGHTTP3_DIR}/build/lib/libnghttp3.a)

    # Build ngtcp2
    set(NGTCP2_DIR ${CMAKE_BINARY_DIR}/ngtcp2)
    if (NOT EXISTS ${NGTCP2_DIR})
        execute_process(
            COMMAND git clone --recursive https://github.com/ngtcp2/ngtcp2
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        execute_process(
            COMMAND autoreconf -i
            WORKING_DIRECTORY ${NGTCP2_DIR}
        )
        execute_process(
            COMMAND ./configure PKG_CONFIG_PATH=${NGHTTP3_DIR}/build/lib/pkgconfig
                    BORINGSSL_LIBS="-L${BORINGSSL_DIR}/build/ssl -lssl -L${BORINGSSL_DIR}/build/crypto -lcrypto"
                    BORINGSSL_CFLAGS="-I${BORINGSSL_DIR}/include"
                    --with-boringssl
            WORKING_DIRECTORY ${NGTCP2_DIR}
        )
        execute_process(
            COMMAND make -j$(nproc) check
            WORKING_DIRECTORY ${NGTCP2_DIR}
        )
    endif()
    include_directories(${NGTCP2_DIR}/build/include)
    list(APPEND LIBS ${NGTCP2_DIR}/build/lib/libngtcp2.a)
ENDIF()
    
TARGET_INCLUDE_DIRECTORIES(server PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(server ${LIBS})
SET_TARGET_PROPERTIES(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

TARGET_INCLUDE_DIRECTORIES(client PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(client ${LIBS})
SET_TARGET_PROPERTIES(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)