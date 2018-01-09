# Change Log

## [Unreleased]

### Compatibility

* openssl 0.10 still uses openssl-sys 0.9, so openssl 0.9 and 0.10 can coexist without issue.

### Added

* The `ssl::select_next_proto` function can be used to easily implement the ALPN selection callback
    in a "standard" way.
* FIPS mode support is available in the `fips` module.
* Accessors for the Issuer and Issuer Alternative Name fields of X509 certificates have been added.

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
* `X509VerifyError` is now `X509VerifyResult` and can now have the "ok" value.
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

[Unreleased]: https://github.com/sfackler/rust-openssl/compare/v0.9.23...master
[release tags]: https://github.com/sfackler/rust-openssl/releases