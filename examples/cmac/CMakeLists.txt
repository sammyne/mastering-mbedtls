cmake_minimum_required(VERSION 3.13)

project(cmac)

set(LDFLAGS "-L/usr/local/lib \
    -lmbedtls -lmbedx509 -lmbedcrypto \
    -Wl,-rpath=/usr/local/lib")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_executable(crypt2 crypt2.cpp)
target_link_libraries(crypt2 ${LDFLAGS})

add_executable(cipher cipher.cpp)
target_link_libraries(cipher ${LDFLAGS})