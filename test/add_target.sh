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
    dpkg --add-architecture armhf
    apt-get update
    apt-get install -y --no-install-recommends \
        gcc-arm-linux-gnueabihf \
        libc6-dev:armhf \
        qemu-user-static
    ;;
esac

rustup target add ${TARGET}
