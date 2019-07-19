cmake_minimum_required(VERSION 3.14)

project(mastering-mbedtls)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/vendor/cppcodec)

#add_subdirectory(aes)
#add_subdirectory(ecdsa)
#add_subdirectory(hash)
add_subdirectory(mpi)