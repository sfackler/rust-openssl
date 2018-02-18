# Change Log

## [Unreleased]

### Added

* Added OpenSSL 1.1.1 support.
* Added `Rsa::public_key_from_pem_pkcs1`.
* Added `SslOptions::NO_TLSV1_3`. (OpenSSL 1.1.1 only)
* Added `SslVersion` and `SslRef::version2`.
* Added `SslSessionCacheMode` and `SslContextBuilder::set_session_cache_mode`.
* Added `SslContextBuilder::set_new_session_callback`,
    `SslContextBuilder::set_remove_session_callback`, and
    `SslContextBuilder::set_get_session_callback`.
* Added `SslContextBuilder::set_keylog_callback`. (OpenSSL 1.1.1 only)
* Added `SslRef::client_random` and `SslRef::server_random`. (OpenSSL 1.1.0+ only)

### Fixed

* The `SslAcceptorBuilder::mozilla_modern` constructor now disables TLSv1.0 and TLSv1.1 in
    accordance with Mozilla's recommendations.

### Deprecated

* `SslRef::version` has been deprecated. Use `SslRef::version_str` instead.

## [v0.10.3] - 2018-02-12

### Added

* OpenSSL is now automatically detected on FreeBSD systems.
* Added `GeneralName` accessors for `rfc822Name` and `uri` variants.
* Added DES-EDE3 support.

### Fixed

* Fixed a memory leak in `X509StoreBuilder::add_cert`.

## [v0.10.2] - 2018-01-11

### Added

* Added `ConnectConfiguration::set_use_server_name_indication` and
    `ConnectConfiguration::set_verify_hostname` for use in contexts where you don't have ownership
    of the `ConnectConfiguration`.

## [v0.10.1] - 2018-01-10

### Added

* Added a `From<ErrorStack> for ssl::Error` implementation.

## [v0.10.0] - 2018-01-10

### Compatibility

* openssl 0.10 still uses openssl-sys 0.9, so openssl 0.9 and 0.10 can coexist without issue.

### Added

* The `ssl::select_next_proto` function can be used to easily implement the ALPN selection callback
    in a "standard" way.
* FIPS mode support is available in the `fips` module.
* Accessors for the Issuer and Issuer Alternative Name fields of X509 certificates have been added.
* The `X509VerifyResult` can now be set in the certificate verification callback via
    `X509StoreContextRef::set_error`.

### Changed

* All constants have been moved to associated constants of their type. For example, `bn::MSB_ONE`
    is now `bn::MsbOption::ONE`.
* Asymmetric key types are now parameterized over what they contain. In OpenSSL, the same type is
    used for key parameters, public keys, and private keys. Unfortunately, some APIs simply assume
    that certain components are present and will segfault trying to use things that aren't there.

    The `pkey` module contains new tag types named `Params`, `Public`, and `Private`, and the
    `Dh`, `Dsa`, `EcKey`, `Rsa`, and `PKey` have a type parameter set to one of those values. This
    allows the `Signer` constructor to indicate that it requires a private key at compile time for
    example. Previously, `Signer` would simply segfault if provided a key without private
    components.
* ALPN support has been changed to more directly model OpenSSL's own APIs. Instead of a single
    method used for both the server and client sides which performed everything automatically, the
    `SslContextBuilder::set_alpn_protos` and `SslContextBuilder::set_alpn_select_callback` handle
    the client and server sides respectively.
* `SslConnector::danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication`
    has been removed in favor of new methods which provide more control. The
    `ConnectConfiguration::use_server_name_indication` method controls the use of Server Name
    Indication (SNI), and the `ConnectConfiguration::verify_hostname` method controls the use of
    hostname verification. These can be controlled independently, and if both are disabled, the
    domain argument to `ConnectConfiguration::connect` is ignored.
* Shared secret derivation is now handled by the new `derive::Deriver` type rather than
    `pkey::PKeyContext`, which has been removed.
* `ssl::Error` is now no longer an enum, and provides more direct access to the relevant state.
* `SslConnectorBuilder::new` has been moved and renamed to `SslConnector::builder`.
* `SslAcceptorBuilder::mozilla_intermediate` and `SslAcceptorBuilder::mozilla_modern` have been
    moved to `SslAcceptor` and no longer take the private key and certificate chain. Install those
    manually after creating the builder.
* `X509VerifyError` is now `X509VerifyResult` and can now have the "ok" value in addition to error
    values.
* `x509::X509FileType` is now `ssl::SslFiletype`.
* Asymmetric key serialization and deserialization methods now document the formats that they
    correspond to, and some have been renamed to better indicate that.

### Removed

* All deprecated APIs have been removed.
* NPN support has been removed. It has been supersceded by ALPN, and is hopefully no longer being
    used in practice. If you still depend on it, please file an issue!
* `SslRef::compression` has been removed.
* Some `ssl::SslOptions` flags have been removed as they no longer do anything.

## Older

Look at the [release tags] for information about older releases.

[Unreleased]: https://github.com/sfackler/rust-openssl/compare/openssl-v0.10.3...master
[v0.10.3]: https://github.com/sfackler/rust-openssl/compare/openssl-v0.10.2...openssl-v0.10.3
[v0.10.2]: https://github.com/sfackler/rust-openssl/compare/openssl-v0.10.1...openssl-v0.10.2
[v0.10.1]: https://github.com/sfackler/rust-openssl/compare/openssl-v0.10.0...openssl-v0.10.1
[v0.10.0]: https://github.com/sfackler/rust-openssl/compare/v0.9.23...openssl-v0.10.0
[release tags]: https://github.com/sfackler/rust-openssl/releases
