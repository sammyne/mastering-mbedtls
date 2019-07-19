cmake_minimum_required(VERSION 3.14)

project(ecdsa)

# cmake would search /usr/local by default??
#include_directories(/usr/local/include)
set(LDFLAGS "-L/usr/local/lib \
    -lmbedtls -lmbedx509 -lmbedcrypto \
    -Wl,-rpath=/usr/local/lib")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

foreach(src ${srcs})
    get_filename_component(bin ${src} NAME_WE)

    add_executable(${bin} ${src})
    target_link_libraries(${bin} ${LDFLAGS})
endforeach()