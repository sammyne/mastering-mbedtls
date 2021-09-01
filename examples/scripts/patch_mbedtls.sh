#!/bin/bash

if [ "$#" != 1 ]; then
  echo "missing mbedtls's source dir"
  exit 1
fi

mbedtlsDir=$1
#echo "mbedtlsDir: $mbedtlsDir"

sed -i 's|^//#define MBEDTLS_CMAC_C|#define MBEDTLS_CMAC_C|g' include/mbedtls/config.h
