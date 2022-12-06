Thanks to Steven Fackler rust-openssl project

# tongsuo Rust bindings

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

注意
在tongsuo逻辑中，如果SSL_CTX开启ntls，请求到来后会从socket里MSG_PEEK，判断是NTLS则走到ntls的逻辑分支。

这要求stream必须具有as_raw_fd的能力。rust-openssl使用非socket形式的bio，本身不支持MSG_PEEK。如果请求混合存在标准tls，ntls请求，就会导致请求hangup。
本库提供了额外两个接口

SSL#set_ssl_method

```rs
ssl.set_ssl_method(SslMethod::ntls());
```

SSL#disable_ntls

```
ssl.disable_ntls()
```

所以上面问题的解决办法是
初始化SSL_CTX时开启ntls

请求到来后，手写TLS Sniffer，从client hello获取SNI，判断是否开启ntls

开启则`ssl.ssl.set_ssl_method(SslMethod::ntls());`，否则 `ssl.disable_ntls`。

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
