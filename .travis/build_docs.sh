#!/bin/bash

set -e

mkdir doc

for crate in $(echo openssl-sys openssl); do
    mkdir -p $crate/target
    (cd $crate/target && ln -s ../../doc)
    (cd $crate && cargo doc --no-deps --features "$FEATURES")
done
