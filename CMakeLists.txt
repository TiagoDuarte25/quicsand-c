cmake_minimum_required(VERSION 3.22.1)
project(quicsand)

IF(CMAKE_BUILD_TYPE STREQUAL "")
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF()
MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
IF (CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
ELSEIF (CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
ENDIF()
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

# Set the BoringSSL directory
set(BORINGSSL_DIR ${CMAKE_SOURCE_DIR}/implementations/boringssl)
add_subdirectory(${BORINGSSL_DIR})
INCLUDE_DIRECTORIES(implementations/boringssl/include)
INCLUDE_DIRECTORIES(implementations/lsquic/include)
INCLUDE_DIRECTORIES(implementations/lsquic/src/liblsquic)
add_subdirectory(implementations/lsquic/src/liblsquic)
# add_subdirectory(implementations/msquic)

file(GLOB CLIENT_SRC "quicsand/src/client/*.c")
file(GLOB SERVER_SRC "quicsand/src/server/*.c")
file(GLOB SRC "quicsand/src/*.c")
file(GLOB IMPL_CLIENT_SRC "quicsand/src/client_${IMPL}/*.c")
file(GLOB IMPL_SERVER_SRC "quicsand/src/server_${IMPL}/*.c")

# Add these lines before the add_executable(client ...) command
link_directories(${CMAKE_BINARY_DIR}/implementations/lsquic/src/liblsquic)
link_directories(${CMAKE_BINARY_DIR}/implementations/boringssl)

# Add these lines before the add_executable(server ...) command
link_directories(${CMAKE_BINARY_DIR}/implementations/lsquic/src/liblsquic)
link_directories(${CMAKE_BINARY_DIR}/implementations/boringssl)

# Create client executable
add_executable(client ${CLIENT_SRC} ${SRC} ${IMPL_CLIENT_SRC})
target_include_directories(client PUBLIC implementations/boringssl/include)
target_include_directories(client PUBLIC implementations/lsquic/include)
target_include_directories(client PUBLIC quicsand/include)
SET(LIBS lsquic crypto ssl event m yaml z)
TARGET_LINK_LIBRARIES(client ${LIBS})
set_target_properties(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Create server executable
add_executable(server ${SERVER_SRC} ${SRC} ${IMPL_SERVER_SRC})
target_include_directories(server PUBLIC implementations/boringssl/include)
target_include_directories(server PUBLIC implementations/lsquic/include)
target_include_directories(server PUBLIC quicsand/include)
TARGET_LINK_LIBRARIES(server ${LIBS})
set_target_properties(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
