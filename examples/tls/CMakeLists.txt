cmake_minimum_required(VERSION 3.14)

project(tls-tour)

add_compile_definitions(
    MBEDTLS_SSL_TLS_C 
    MBEDTLS_SSL_CLI_C 
    MBEDTLS_X509_CRT_PARSE_C 
    MBEDTLS_NET_C
    MBEDTLS_CERTS_C
)

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