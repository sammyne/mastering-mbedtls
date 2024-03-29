include(ExternalProject)

# CONFIGURE_COMMAND and CMAKE_ARGS is conflicting, cannot be specifed both
ExternalProject_Add(mbedtls 
  PREFIX mbedtls
  GIT_REPOSITORY https://gitee.com/sammyne/mbedtls.git 
  GIT_TAG v2.27.0 
  INSTALL_DIR ${PROJECT_SOURCE_DIR}/third-party/_mbedtls 
  CONFIGURE_COMMAND bash ${PROJECT_SOURCE_DIR}/scripts/patch_mbedtls.sh <SOURCE_DIR> &&
    cmake . -DCMAKE_INSTALL_PREFIX=${PROJECT_SOURCE_DIR}/third-party/_mbedtls -DENABLE_TESTING=Off
  BUILD_COMMAND make -j
  BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(mbedtls INSTALL_DIR)

# set global env to referenced by others
set(MBEDTLS_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set(MBEDTLS_LINK_DIRECTORIES ${INSTALL_DIR}/lib)

# create the ${INSTALL_DIR}/include directory
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(mbedtls-crypto STATIC IMPORTED GLOBAL)
add_dependencies(mbedtls-crypto mbedtls)
set_property(TARGET mbedtls-crypto PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libmbedcrypto.a)
set_property(TARGET mbedtls-crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

#add_library(mbedtls-tls STATIC IMPORTED GLOBAL)
#set_property(TARGET mbedtls-tls PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libmbedtls.a)
#set_property(TARGET mbedtls-tls PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

#add_library(mbedtls-x509 STATIC IMPORTED GLOBAL)
#set_property(TARGET mbedtls-x509 PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libmbedx509.a)
#set_property(TARGET mbedtls-x509 PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

