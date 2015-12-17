#!/bin/bash
set -e

if [ $TRAVIS_OS_NAME -eq "osx" ]; then
    exit 0
fi

mkdir /tmp/openssl
cd /tmp/openssl
curl https://openssl.org/source/openssl-1.0.2e.tar.gz | tar --strip-components=1 -xzf -
./config --prefix=$HOME/openssl shared
make
make install
