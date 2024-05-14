cmake_minimum_required(VERSION 3.22.1)
project(quicsand)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")

# Set the BoringSSL directory
set(BORINGSSL_DIR ${CMAKE_SOURCE_DIR}/implementations/boringssl)

file(GLOB CLIENT_SRC "quicsand/src/client/*.c")
file(GLOB SERVER_SRC "quicsand/src/server/*.c")
file(GLOB SRC "quicsand/src/*.c")
file(GLOB IMPL_CLIENT_SRC "quicsand/src/client_${IMPL}/*.c")
file(GLOB IMPL_SERVER_SRC "quicsand/src/server_${IMPL}/*.c")

add_subdirectory(${BORINGSSL_DIR})
add_subdirectory(${CMAKE_SOURCE_DIR}/implementations/lsquic)

# Create client executable
#add_executable(client ${CLIENT_SRC} ${SRC} ${IMPL_CLIENT_SRC})
#target_include_directories(client PUBLIC implementations/boringssl/include)
#target_include_directories(client PUBLIC implementations/lsquic/include)
#target_link_libraries(client PRIVATE ${PROJECT_NAME})
#set_target_properties(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Create server executable
#add_executable(server ${SERVER_SRC} ${SRC} ${IMPL_SERVER_SRC})
#target_include_directories(server PUBLIC implementations/boringssl/include)
#target_include_directories(server PUBLIC implementations/lsquic/include)
#target_link_libraries(server PRIVATE ${PROJECT_NAME})
#set_target_properties(server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
