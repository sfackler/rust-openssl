#!/bin/bash
set -e

if [ "$BUILD_OPENSSL_VERSION" != "" ]; then
    FEATURES="aes_xts aes_ctr npn alpn rfc5114 ecdh_auto"
fi

if [ -d "$HOME/openssl/lib" ]; then
    export OPENSSL_DIR=$HOME/openssl
    export PATH=$HOME/openssl/bin:$PATH
fi

cargo run --manifest-path systest/Cargo.toml --target $TARGET
exec cargo test --manifest-path openssl/Cargo.toml --target $TARGET \
    --features "$FEATURES"
