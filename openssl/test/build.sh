#!/bin/bash
set -e

mkdir /tmp/openssl
cd /tmp/openssl
sudo apt-get install gcc make
curl https://openssl.org/source/openssl-1.0.2d.tar.gz | tar --strip-components=1 -xzf -
./config --prefix=/usr/ shared
make
sudo make install
