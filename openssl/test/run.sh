#!/bin/bash
set -e

if [ $TEST_FEATURES == "true" ]; then
    FEATURES="tlsv1_2 tlsv1_1 dtlsv1 dtlsv1_2 sslv2 sslv3 aes_xts aes_ctr npn alpn rfc5114 ecdh_auto pkcs5_pbkdf2_hmac"
fi

if [ $TRAVIS_OS_NAME != "osx" ]; then
    export OPENSSL_LIB_DIR=$HOME/openssl/lib
    export OPENSSL_INCLUDE_DIR=$HOME/openssl/include
    export LD_LIBRARY_PATH=$HOME/openssl/lib:$LD_LIBRARY_PATH
fi

cargo test --manifest-path=openssl/Cargo.toml --features "$FEATURES"
