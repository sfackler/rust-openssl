#!/bin/bash
set -e

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    exit 0
fi

if [ -n "$TARGET" ]; then
    FLAGS="os/compiler=$TARGET-"
fi

mkdir /tmp/openssl
cd /tmp/openssl
curl https://openssl.org/source/openssl-1.0.2e.tar.gz | tar --strip-components=1 -xzf -
./Configure --prefix=$HOME/openssl shared $FLAGS
make
make install
