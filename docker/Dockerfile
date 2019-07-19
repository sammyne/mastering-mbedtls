FROM ubuntu:18.04  

WORKDIR /workspace
ADD sources.list /etc/apt/sources.list

RUN apt update &&\
    apt install lsb-release -y &&\
    apt install build-essential git -y &&\
    git clone -b v3.14.4 --depth=1 https://github.com/Kitware/CMake.git &&\
    cd CMake && ./bootstrap && make -j4 && make install &&\
    ln -sf /usr/local/bin/cmake /usr/bin/cmake &&\
    cd .. && rm -rf CMake
RUN git clone -b mbedtls-2.18.1 --recursive https://github.com/ARMmbed/mbedtls.git &&\
    cd mbedtls && mkdir build && cd build &&\
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .. &&\
    make install &&\
    cd ../.. && rm -rf mbedtls

# lib: /usr/local/lib/
# include: /usr/local/include/mbedtls/
# bin: /usr/local/bin