use ffi;
use foreign_types::ForeignTypeRef;
use std::mem;

use {cvt, cvt_p};
use error::ErrorStack;
use x509::X509;

foreign_type! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    pub struct X509StoreBuilder;
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
    pub fn add_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        unsafe {
            let ptr = cert.as_ptr();
            mem::forget(cert); // the cert will be freed inside of X509_STORE_add_cert on error
            cvt(ffi::X509_STORE_add_cert(self.as_ptr(), ptr)).map(|_| ())
        }
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_paths(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_STORE_set_default_paths(self.as_ptr())).map(|_| ())
        }
    }
}

foreign_type! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    pub struct X509Store;
    pub struct X509StoreRef;
}
