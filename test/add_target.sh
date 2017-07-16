#!/bin/bash
set -e

case "${TARGET}" in
"x86_64-unknown-linux-gnu")
    exit 0
    ;;
"i686-unknown-linux-gnu")
    apt-get install -y --no-install-recommends gcc-multilib
    ;;
"arm-unknown-linux-gnueabihf")
    echo "deb http://emdebian.org/tools/debian/ jessie main" \
        > /etc/apt/sources.list.d/crosstools.list
    curl http://emdebian.org/tools/debian/emdebian-toolchain-archive.key | apt-key add -
    dpkg --add-architecture armhf
    apt-get update
    apt-get install -y --no-install-recommends \
        gcc-arm-linux-gnueabihf \
        libc6-dev:armhf
    ;;
esac

OUT=/tmp/std.tar.gz
curl -o ${OUT} https://static.rust-lang.org/dist/rust-std-${RUST_VERSION}-${TARGET}.tar.gz

WORKDIR=/tmp/std
mkdir -p ${WORKDIR}
cd ${WORKDIR}

tar --strip-components=1 -xzf ${OUT}

./install.sh
