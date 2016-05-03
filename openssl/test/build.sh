#!/bin/bash
set -e

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    exit 0
fi

if [ "$TARGET" == "arm-unknown-linux-gnueabihf" ]; then
    export C_INCLUDE_PATH=/usr/arm-linux-gnueabihf/include
    CROSS=arm-linux-gnueabihf-
    OS_COMPILER=linux-armv4
else
    OS_COMPILER=linux-x86_64
fi

mkdir /tmp/openssl
cd /tmp/openssl
curl https://openssl.org/source/openssl-1.0.2h.tar.gz | tar --strip-components=1 -xzf -
./Configure --prefix=$HOME/openssl shared --cross-compile-prefix=$CROSS $OS_COMPILER
make
make install
