#!/bin/bash

set -ex

if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
    exit 0
fi

MAX_REDIRECTS=5

if [ -n "${BUILD_LIBRESSL_VERSION}" ]; then
    URL1="http://ftp3.usa.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${BUILD_LIBRESSL_VERSION}.tar.gz"
    URL2="http://ftp.eu.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${BUILD_LIBRESSL_VERSION}.tar.gz"
    OUT="/tmp/libressl-${BUILD_LIBRESSL_VERSION}.tar.gz"
elif [ -n "${BUILD_OPENSSL_VERSION}" ]; then
    URL1="https://openssl.org/source/openssl-${BUILD_OPENSSL_VERSION}.tar.gz"
    URL2="http://mirrors.ibiblio.org/openssl/source/openssl-${BUILD_OPENSSL_VERSION}.tar.gz"
    OUT="/tmp/openssl-${BUILD_OPENSSL_VERSION}.tar.gz"
else
    exit 0
fi

curl -o ${OUT} -L --max-redirs ${MAX_REDIRECTS} ${URL1} \
  || curl -o ${OUT} -L --max-redirs ${MAX_REDIRECTS} ${URL2}

test -n "${BUILD_LIBRESSL_VERSION}" || exit 0

me=$0
myname=`basename $me`

cmp --silent ${me} ${HOME}/${NAME}/${myname} && exit 0 || echo "cache is busted"

mkdir -p /tmp/build
cp ${me} /tmp/build/${myname}
cd /tmp/build

tar --strip-components=1 -xzf ${OUT}

./configure --prefix=${HOME}/libressl
make -j$(nproc)
make install
cp ${myname} ${HOME}/${NAME}/${myname}
