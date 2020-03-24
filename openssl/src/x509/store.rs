//! Describe a context in which to verify an `X509` certificate.
//!
//! The `X509` certificate store holds trusted CA certificates used to verify
//! peer certificates.
//!
//! # Example
//!
//! ```rust
//!
//! extern crate openssl;
//!
//! use openssl::x509::store::{X509StoreBuilder, X509Store};
//! use openssl::x509::{X509, X509Name};
//! use openssl::pkey::PKey;
//! use openssl::hash::MessageDigest;
//! use openssl::rsa::Rsa;
//! use openssl::nid::Nid;
//!
//! fn main() {
//!     let rsa = Rsa::generate(2048).unwrap();
//!     let pkey = PKey::from_rsa(rsa).unwrap();
//!
//!     let mut name = X509Name::builder().unwrap();
//!     name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com").unwrap();
//!     let name = name.build();
//!
//!     let mut builder = X509::builder().unwrap();
//!     builder.set_version(2).unwrap();
//!     builder.set_subject_name(&name).unwrap();
//!     builder.set_issuer_name(&name).unwrap();
//!     builder.set_pubkey(&pkey).unwrap();
//!     builder.sign(&pkey, MessageDigest::sha256()).unwrap();
//!
//!     let certificate: X509 = builder.build();
//!
//!     let mut builder = X509StoreBuilder::new().unwrap();
//!     let _ = builder.add_cert(certificate);
//!
//!     let store: X509Store = builder.build();
//! }
//! ```

use ffi;
use foreign_types::ForeignTypeRef;
use std::mem;

use error::ErrorStack;
use stack::StackRef;
use x509::{X509Object, X509};
use {cvt, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A builder type used to construct an `X509Store`.
    pub struct X509StoreBuilder;
    /// Reference to an `X509StoreBuilder`.
    pub struct X509StoreBuilderRef;
}

impl X509StoreBuilder {
    /// Returns a builder for a certificate store.
    ///
    /// The store is initially empty.
    pub fn new() -> Result<X509StoreBuilder, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::X509_STORE_new()).map(X509StoreBuilder)
        }
    }

    /// Constructs the `X509Store`.
    pub fn build(self) -> X509Store {
        let store = X509Store(self.0);
        mem::forget(self);
        store
    }
}

impl X509StoreBuilderRef {
    /// Adds a certificate to the certificate store.
    // FIXME should take an &X509Ref
    pub fn add_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_add_cert(self.as_ptr(), cert.as_ptr())).map(|_| ()) }
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_paths(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_set_default_paths(self.as_ptr())).map(|_| ()) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A certificate store to hold trusted `X509` certificates.
    pub struct X509Store;
    /// Reference to an `X509Store`.
    pub struct X509StoreRef;
}

impl X509StoreRef {
    /// Get a reference to the cache of certificates in this store.
    pub fn objects(&self) -> &StackRef<X509Object> {
        unsafe { StackRef::from_ptr(X509_STORE_get0_objects(self.as_ptr())) }
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl270))] {
        use ffi::X509_STORE_get0_objects;
    } else {
        #[allow(bad_style)]
        unsafe fn X509_STORE_get0_objects(x: *mut ffi::X509_STORE) -> *mut ffi::stack_st_X509_OBJECT {
            (*x).objs
        }
    }
}
