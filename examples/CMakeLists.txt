cmake_minimum_required(VERSION 3.13)

project(mastering-mbedtls)

set(CMAKE_CXX_STANDARD 20)

include(cmake/mbedtls.cmake)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ministd/include)

add_subdirectory(ministd)

add_subdirectory(aes)
add_subdirectory(cmac)
#add_subdirectory(ecdsa)
#add_subdirectory(hash)
#add_subdirectory(mpi)
#add_subdirectory(pk)
#add_subdirectory(tls)
#add_subdirectory(x509)