# Change Log

## [Unreleased]

## [v0.9.58] - 2020-06-05

### Added

* Added `SSL_set_mtu`.
* Added support for LibreSSL 3.2.0.
* Added `PEM_read_bio_EC_PUBKEY`, `PEM_write_bio_EC_PUBKEY`, `d2i_EC_PUBKEY`, and `i2d_EC_PUBKEY`.
* Added `EVP_PKEY_encrypt_init`, `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt_init`, `EVP_PKEY_decrypt`,
    `EVP_PKEY_get_raw_public_key`, `EVP_PKEY_new_raw_public_key`, `EVP_PKEY_get_raw_private_key`,
    and `EVP_PKEY_new_raw_private_key`.
* Added `OBJ_sn2nid`.

## [v0.9.57] - 2020-05-24

### Added

* Added support for LibreSSL 3.1.x.

## [v0.9.56] - 2020-05-07

### Fixed

* Fixed vendored builds on windows-gnu targets.

### Added

* Added support for LibreSSL 3.0.0.

## [v0.9.55] - 2020-04-07

### Fixed

* Fixed windows-msvc library names when using OpenSSL from vcpkg.

### Added

* If the `OPENSSL_NO_VENDOR` environment variable is set, vendoring will not be used even if enabled.
* Added `SSL_CTX_get_verify_mode` and `SSL_get_verify_mode`.
* Added `SSL_is_init_finished`.
* Added `SSL_CTX_set_cert_store`.
* Added `TLS_server_method` and `TLS_client_method`.
* Added `X509_STORE_get0_objects`.
* Added `X509_OBJECT_free`, `X509_OBJECT_get_type`, and `X509_OBJECT_get0_X509`.

## [v0.9.54] - 2020-01-29

### Added

* Added `BIO_CTRL_DGRAM_QUERY_MTU`.
* Added `EVP_EncryptInit_ex`, `EVP_EncryptFinal_ex`, `EVP_DecryptInit_ex`, and `EVP_DecryptFinal_ex`.
* Added `EVP_md_null`.
* Added `EVP_PKCS82PKEY`.
* Added `PKCS8_PRIV_KEY_INFO`, `d2i_PKCS8_PRIV_KEY_INFO`, and `PKCS8_PRIV_KEY_INFO_free`.
* Added `SSL_OP_NO_RENEGOTIATION`.

## [v0.9.53] - 2019-11-22

### Added

* Added `ASN1_TIME_diff`.
* Added `EC_GROUP_order_bits`.
* Added `EVP_EncodeBlock` and `EVP_DecodeBlock`.
* Added `SSL_CTRL_SET_GROUPS_LIST`, `SSL_CTRL_SET_SIGALGS_LIST`, `SSL_CTX_set1_groups_list`, and
    `SSL_CTX_set1_sigalgs_list`.
* Added `Clone` implementations to `SHA_CTX`, `SHA256_CTX`, and `SHA512_CTX`.

## [v0.9.52] - 2019-10-19

### Added

* Added support for LibreSSL 3.0.x.

## [v0.9.51] - 2019-10-02

### Added

* Added support for LibreSSL 3.0.1.

## [v0.9.50] - 2019-10-02

### Added

* Added `CRYPTO_LOCK_EVP_PKEY`.
* Added `EVP_PKEY_ED25519` and `EVP_PKEY_ED448`.
* Added `EVP_DigestSign` and `EVP_DigestVerify`.
* Added `EVP_PKEY_up_ref`.
* Added `NID_ED25519` and `NID_ED448`.

## [v0.9.49] - 2019-08-15

### Added

* Added support for LibreSSL 3.0.0.

## [v0.9.48] - 2019-07-19

### Added

* Added `AES_wrap_key` and `AES_unwrap_key`.
* Added `EC_GROUP_get_cofactor`, `EC_GROUP_get0_generator`, and `EC_POINT_dup`.
* Added `EVP_aes_128_ofb`, `EVP_aes_192_ecb`, `EVP_aes_192_cbc`, `EVP_aes_192_cfb1`, `EVP_aes_192_cfb8`,
    `EVP_aes_192_cfb_128`, `EVP_aes_192_ctr`, `EVP_aes_192_ccm`, `EVP_aes_192_gcm`, `EVP_aes_192_ofb`, and
    `EVP_aes_256_ofb`.
* Added `PEM_read_bio_CMS` and `PEM_write_bio_CMS`.

## [v0.9.47] - 2019-05-18

### Added

* Added `SSL_CTX_add_client_CA`.

## [v0.9.46] - 2019-05-08

### Added

* Added support for the LibreSSL 2.9.x series.

## [v0.9.45] - 2019-05-03

### Fixed

* Reverted a change to windows-gnu library names that caused regressions.

## [v0.9.44] - 2019-04-30

### Added

* The `DEP_OPENSSL_VENDORED` environment variable tells downstream build scripts if the vendored feature was enabled.
* Added `EVP_SealInit`, `EVP_SealFinal`, `EVP_EncryptUpdate`, `EVP_OpenInit`, `EVP_OpenFinal`, and `EVP_DecryptUpdate`.
* Added `EVP_PKEY_size`.

### Fixed

* Fixed library names when targeting windows-gnu and pkg-config fails.

## [v0.9.43] - 2019-03-20

### Added

* Added `d2i_CMS_ContentInfo` and `CMS_encrypt`.
* Added `X509_verify` and `X509_REQ_verify`.
* Added `EVP_MD_type` and `EVP_GROUP_get_curve_name`.

[Unreleased]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.57...master
[v0.9.57]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.56...openssl-sys-v0.9.57
[v0.9.56]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.55...openssl-sys-v0.9.56
[v0.9.55]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.54...openssl-sys-v0.9.55
[v0.9.54]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.53...openssl-sys-v0.9.54
[v0.9.53]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.52...openssl-sys-v0.9.53
[v0.9.52]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.51...openssl-sys-v0.9.52
[v0.9.51]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.50...openssl-sys-v0.9.51
[v0.9.50]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.49...openssl-sys-v0.9.50
[v0.9.49]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.48...openssl-sys-v0.9.49
[v0.9.48]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.47...openssl-sys-v0.9.48
[v0.9.47]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.46...openssl-sys-v0.9.47
[v0.9.46]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.45...openssl-sys-v0.9.46
[v0.9.45]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.44...openssl-sys-v0.9.45
[v0.9.44]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.43...openssl-sys-v0.9.44
[v0.9.43]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.42...openssl-sys-v0.9.43
