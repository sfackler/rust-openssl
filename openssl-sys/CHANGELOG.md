# Change Log

## [Unreleased]

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

[Unreleased]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.46...master
[v0.9.46]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.45...openssl-sys-v0.9.46
[v0.9.45]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.44...openssl-sys-v0.9.45
[v0.9.44]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.43...openssl-sys-v0.9.44
[v0.9.43]: https://github.com/sfackler/rust-openssl/compare/openssl-sys-v0.9.42...openssl-sys-v0.9.43
