#!/bin/bash

#docker run -it --rm --name mbedtls -p 4433:4433 \
#    -v ${PWD}/examples:/workspace ubuntu:mbedtls-2.18.1 bash
docker run -it --rm --name mbedtls -v ${PWD}:/workspace ubuntu:mbedtls-2.18.1 bash