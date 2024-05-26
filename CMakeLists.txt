CMAKE_MINIMUM_REQUIRED(VERSION 3.22.1)
PROJECT(quicsand)

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

FILE(GLOB CLIENT_SRC "quicsand/src/client/*.c")
FILE(GLOB SERVER_SRC "quicsand/src/server/*.c")
FILE(GLOB SRC "quicsand/src/*.c")
FILE(GLOB IMPL_CLIENT_SRC "quicsand/src/client_${IMPL}/*.c")
FILE(GLOB IMPL_SERVER_SRC "quicsand/src/server_${IMPL}/*.c")

# Create executables targets
ADD_EXECUTABLE(client ${CLIENT_SRC} ${SRC} ${IMPL_CLIENT_SRC})
ADD_EXECUTABLE(server ${SERVER_SRC} ${SRC} ${IMPL_SERVER_SRC})

IF(${IMPL} STREQUAL "lsquic")

    # Add boringssl and lsquic
    SET(BORINGSSL_DIR ${CMAKE_SOURCE_DIR}/implementations/boringssl)
    ADD_SUBDIRECTORY(${BORINGSSL_DIR})
    INCLUDE_DIRECTORIES(implementations/boringssl/include)
    INCLUDE_DIRECTORIES(implementations/lsquic/include)
    INCLUDE_DIRECTORIES(implementations/lsquic/src/liblsquic)
    ADD_SUBDIRECTORY(implementations/lsquic/src/liblsquic)
    
    # Set libraries
    SET(LIBS lsquic crypto ssl event m yaml z)

ELSEIF(${IMPL} STREQUAL "msquic")

    # Add msquic
    ADD_SUBDIRECTORY(implementations/msquic)
    INCLUDE_DIRECTORIES(implementations/msquic/include)

    # Set libraries
    SET(LIBS msquic yaml)

ELSE()
    MESSAGE(FATAL_ERROR "Invalid implementation: ${IMPL}")
ENDIF()
    
TARGET_INCLUDE_DIRECTORIES(server PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(server ${LIBS})
SET_TARGET_PROPERTIES(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    
TARGET_INCLUDE_DIRECTORIES(client PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(client ${LIBS})
SET_TARGET_PROPERTIES(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)