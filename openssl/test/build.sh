#!/bin/bash

set -ex

MAX_REDIRECTS=5

if [ -n "${BUILD_LIBRESSL_VERSION}" ]; then
    NAME=libressl
    URL1="http://ftp3.usa.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${BUILD_LIBRESSL_VERSION}.tar.gz"
    URL2="http://ftp.eu.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${BUILD_LIBRESSL_VERSION}.tar.gz"
    OUT="/tmp/libressl-${BUILD_OPENSSL_VERSION}.tar.gz"
elif [ -n "${BUILD_OPENSSL_VERSION}" ]; then
    NAME=openssl
    URL1="https://openssl.org/source/openssl-${BUILD_OPENSSL_VERSION}.tar.gz"
    URL2="http://mirrors.ibiblio.org/openssl/source/openssl-${BUILD_OPENSSL_VERSION}.tar.gz"
    OUT="/tmp/openssl-${BUILD_OPENSSL_VERSION}.tar.gz"
else
    exit 0
fi

me=$0
myname=`basename ${me}`

cmp --silent ${me} ${HOME}/${NAME}/${myname} && exit 0 || echo "cache is busted"

rm -rf "${HOME}/${NAME}"

if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
    exit 0
fi

if [ "$TARGET" == "i686-unknown-linux-gnu" ]; then
    OS_COMPILER=linux-elf
    OS_FLAGS=-m32
elif [ "$TARGET" == "arm-unknown-linux-gnueabihf" ]; then
    OS_COMPILER=linux-armv4
    export AR=arm-linux-gnueabihf-ar
    export CC=arm-linux-gnueabihf-gcc
else
    OS_COMPILER=linux-x86_64
fi

mkdir -p /tmp/build
cp ${me} /tmp/build/${myname}
cd /tmp/build

curl -o ${OUT} -L --max-redirs ${MAX_REDIRECTS} ${URL1} \
  || curl -o ${OUT} -L --max-redirs ${MAX_REDIRECTS} ${URL2}

tar --strip-components=1 -xzf ${OUT}

if [ -n "${BUILD_LIBRESSL_VERSION}" ]; then
    ./configure --prefix=${HOME}/libressl
else
    ./Configure --prefix=${HOME}/openssl ${OS_COMPILER} -fPIC ${OS_FLAGS}
fi

make -j$(nproc)
make install
cp ${myname} ${HOME}/${NAME}/${myname}
