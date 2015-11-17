#!/bin/bash
set -e

mkdir /tmp/openssl
cd /tmp/openssl
curl https://openssl.org/source/openssl-1.0.2d.tar.gz | tar --strip-components=1 -xzf -
./config --prefix=$HOME/openssl shared
make
make install
