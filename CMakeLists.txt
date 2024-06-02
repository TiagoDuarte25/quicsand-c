CMAKE_MINIMUM_REQUIRED(VERSION 3.22.1)
PROJECT(quicsand)

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

    IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # If using older glibc, need to link with -lrt.  See clock_getres(2).
        EXECUTE_PROCESS(
            COMMAND ${PROJECT_SOURCE_DIR}/print-glibc-version.sh ${CMAKE_C_COMPILER}
            OUTPUT_VARIABLE GLIBC_VERSION)
        IF(NOT GLIBC_VERSION EQUAL "" AND GLIBC_VERSION VERSION_LESS 2.17)
            SET(LIBS ${LIBS} rt)
        ENDIF()
    ENDIF()

ELSEIF(${IMPL} STREQUAL "msquic")

    # Add msquic
    ADD_SUBDIRECTORY(implementations/msquic)
    INCLUDE_DIRECTORIES(implementations/msquic/include)

    # Set libraries
    SET(LIBS msquic yaml)

ELSEIF(${IMPL} STREQUAL "quiche")

    # Add a custom command to build libquiche.so
    ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_SOURCE_DIR}/implementations/quiche/target/debug/libquiche.so
                        COMMAND cargo build
                        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/implementations/quiche
                        COMMENT "Building libquiche.so")

    # Add a custom target that depends on the custom command
    ADD_CUSTOM_TARGET(BuildQuiche DEPENDS ${CMAKE_SOURCE_DIR}/implementations/quiche/target/debug/libquiche.so)

    # Add the custom target as a dependency for the client and server executables
    ADD_DEPENDENCIES(client BuildQuiche)
    ADD_DEPENDENCIES(server BuildQuiche)

    # Add quiche
    INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/implementations/quiche/quiche/include)

    # Find the quiche library
    find_library(QUICHE_LIBRARY NAMES libquiche.so PATHS ${CMAKE_SOURCE_DIR}/implementations/quiche/target/debug NO_DEFAULT_PATH)

    # Set libraries
    SET(LIBS ${QUICHE_LIBRARY} yaml)

ELSE()
    MESSAGE(FATAL_ERROR "Invalid implementation: ${IMPL}")
ENDIF()
    
TARGET_INCLUDE_DIRECTORIES(server PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(server ${LIBS})
SET_TARGET_PROPERTIES(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

TARGET_INCLUDE_DIRECTORIES(client PRIVATE quicsand/include)
TARGET_LINK_LIBRARIES(client ${LIBS})
SET_TARGET_PROPERTIES(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)