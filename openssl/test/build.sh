#!/bin/bash

set -ex

MAX_REDIRECTS=5
OPENSSL=openssl-$BUILD_OPENSSL_VERSION.tar.gz
OUT=/tmp/$OPENSSL

me=$0
myname=`basename $me`

cmp --silent $me $HOME/openssl/$myname && exit 0 || echo "cache is busted"

rm -rf $HOME/openssl

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    exit 0
fi

if [ "$BUILD_OPENSSL_VERSION" == "" ]; then
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

mkdir -p /tmp/openssl
cp $me /tmp/openssl/$myname
cd /tmp/openssl

curl -o $OUT -L --max-redirs $MAX_REDIRECTS https://openssl.org/source/$OPENSSL \
  || curl -o $OUT -L --max-redirs ${MAX_REDIRECTS} http://mirrors.ibiblio.org/openssl/source/$OPENSSL

tar --strip-components=1 -xzf $OUT

./Configure --prefix=$HOME/openssl $OS_COMPILER -fPIC $OS_FLAGS

make -j$(nproc)
make install
cp $myname $HOME/openssl/$myname
