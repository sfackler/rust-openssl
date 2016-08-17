#!/bin/bash
set -e

MAX_REDIRECTS=5
OPENSSL=openssl-1.0.2h.tar.gz
OUT=/tmp/$OPENSSL
SHA1="577585f5f5d299c44dd3c993d3c0ac7a219e4949"

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

mkdir -p /tmp/openssl
cd /tmp/openssl

curl -o $OUT -L --max-redirs $MAX_REDIRECTS https://openssl.org/source/$OPENSSL \
  || curl -o $OUT -L --max-redirs ${MAX_REDIRECTS} http://mirrors.ibiblio.org/openssl/source/$OPENSSL

echo "$SHA1 $OUT" | sha1sum -c - || exit 1

tar --strip-components=1 -xzf $OUT
./Configure --prefix=$HOME/openssl shared --cross-compile-prefix=$CROSS $OS_COMPILER
make
make install
