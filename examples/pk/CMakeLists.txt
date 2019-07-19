cmake_minimum_required(VERSION 3.14)

project(mpi)

# cmake would search /usr/local by default??
#include_directories(/usr/local/include)
set(LDFLAGS "-L/usr/local/lib \
    -lmbedtls -lmbedx509 -lmbedcrypto \
    -Wl,-rpath=/usr/local/lib")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} srcs)

foreach(src ${srcs})
    get_filename_component(bin ${src} NAME_WE)

    add_executable(${bin} ${src})
    target_link_libraries(${bin} ${LDFLAGS})
endforeach()