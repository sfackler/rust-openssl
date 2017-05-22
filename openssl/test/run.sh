#!/bin/bash
set -e

case "$BUILD_OPENSSL_VERSION" in
    1.0.2*)
        FEATURES="v102"
        ;;
    1.1.0*)
        FEATURES="v110"
        ;;
esac

echo Using features: $FEATURES

if [ -n "${BUILD_LIBRESSL_VERSION}" -a -d "$HOME/libressl/lib" ]; then
    echo "Testing build libressl-${BUILD_LIBRESSL_VERSION}"
    export OPENSSL_DIR=${HOME}/libressl
    export LD_LIBRARY_PATH="${HOME}/libressl/lib:${LD_LIBRARY_PATH}"
    export PATH="${HOME}/libressl/bin:${PATH}"

elif [ -n "${BUILD_OPENSSL_VERSION}" -a -d "$HOME/openssl/lib" ]; then
    echo "Testing build openssl-${BUILD_LIBRESSL_VERSION}"
    export OPENSSL_DIR="${HOME}/openssl"
    export LD_LIBRARY_PATH="${HOME}/openssl/lib:${LD_LIBRARY_PATH}"
    export PATH="${HOME}/openssl/bin:${PATH}"
fi

if [ "$TARGET" == "arm-unknown-linux-gnueabihf" ]; then
    FLAGS="--no-run"
fi

cargo run --manifest-path systest/Cargo.toml --target $TARGET -v
exec cargo test --manifest-path openssl/Cargo.toml --target $TARGET \
    --features "$FEATURES" -v $FLAGS
