This package provides Rust bindings for the functionality exposed by OpenSSL's
libcrypto. Currently provided:

* Hashes (hash.rs)
  * MD5
  * SHA-1
  * SHA-2 (224, 256, 384, 512)
* Symmetric crypto (symm.rs)
  * AES-128 or AES-256 in ECB or CBC mode
  * RC4-128
* Keypair generation (pkey.rs)
  * RSA, all key lengths
* Asymmetric encryption (pkey.rs)
  * RSA with PKCS #1 OAEP padding or PKCS #1 v1.5 padding
* Digital signatures (pkey.rs)
  * RSA with PKCS #1 v1.5 padding and any supported hash

Each module provides two interfaces: a low-level API which wraps the OpenSSL
interfaces as directly as possible and a high-level API which presents the
OpenSSL API as a Rust object and tries to make sensible default choices about
parameters most users won't care about. You probably want to use the high-level
API. For documentation on these, see the individual source files.
