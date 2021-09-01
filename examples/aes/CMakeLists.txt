project(aes)

add_executable(crypt2 crypt2.cc)
target_link_libraries(crypt2 mbedtls-crypto ministd)

add_executable(cipher cipher.cc)
target_link_libraries(cipher mbedtls-crypto ministd)