# Babassl Rust bindings

openssl-sys/tongsuo 锁定在 <https://github.com/Tongsuo-Project/Tongsuo/commit/d36d0669a206e1c07e1793496124ab38435f9bac>

兼容openssl 1.1.1

Pre installation

```
git submodule update --init --remote --recursive
apt install clang pkg-config -y
```

Building

```
cargo build
```

使用
```
openssl = { version = "0.10.42", path = "../deps/rust-openssl/openssl/", features = ["tokio", "tongsuo"]}
```

features
- tokio: 支持async
- tongsuo：开启rust-openssl bindgen feature。支持gm

# rust-openssl

[![crates.io](https://img.shields.io/crates/v/openssl.svg)](https://crates.io/crates/openssl)

OpenSSL bindings for the Rust programming language.

[Documentation](https://docs.rs/openssl).

## Release Support

The current supported release of `openssl` is 0.10 and `openssl-sys` is 0.9.

New major versions will be published at most once per year. After a new
release, the previous major version will be partially supported with bug
fixes for 3 months, after which support will be dropped entirely.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.
