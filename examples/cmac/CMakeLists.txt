cmake_minimum_required(VERSION 3.13)

project(cmac)

add_executable(cmac main.cc)
target_link_libraries(cmac mbedtls-crypto ministd)
