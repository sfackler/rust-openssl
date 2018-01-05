#!/bin/bash
set -eux

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
    # the amd64 and armhf versions upgrade out of sync which sometimes breaks things
    apt-get remove -y linux-libc-dev:amd64
    apt-get install -y --no-install-recommends \
        gcc-arm-linux-gnueabihf \
        libc6-dev:armhf \
        qemu-user-static
    ;;
esac

rustup target add ${TARGET}
