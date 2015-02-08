#!/bin/bash

set -e

mkdir doc

for crate in $(echo openssl-sys openssl); do
    mkdir -p $crate/target
    ln -s -t $crate/target ../../doc
    (cd $crate && cargo doc --no-deps --features "$FEATURES")
done
