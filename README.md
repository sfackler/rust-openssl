This package provides Rust bindings for the functionality exposed by OpenSSL's
libcrypto. OpenSSL 1.0.1 or higher is required. Currently provided:

* Hash functions (hash.rs)
  * SHA-512, SHA-384, SHA-256, SHA-224
  * SHA-1
  * MD5
* Symmetric crypto (symm.rs)
  * AES-128 and AES-256 (ECB, CBC, CTR or GCM mode)
  * RC4-128
* RSA (pkey.rs)
  * Encryption with PKCS #1 OAEP padding or PKCS #1 v1.5 padding
  * Signatures with PKCS #1 v1.5 padding and any supported hash
