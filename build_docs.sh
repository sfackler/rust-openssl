#!/bin/bash
set -e

export CARGO_TARGET_DIR=target

for toml in $(find . -maxdepth 2 -name "Cargo.toml"); do
    cargo update --manifest-path $toml || true
    features=$(cargo read-manifest --manifest-path $toml | jq -r '.features|keys|join(" ")')
    cargo doc --no-deps --manifest-path $toml --features "$features"
done
