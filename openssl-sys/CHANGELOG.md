# Change Log

## [Unreleased]

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

[Unreleased]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.53...master
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
