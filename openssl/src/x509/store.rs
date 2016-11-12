use ffi;
use std::mem;

use cvt;
use error::ErrorStack;
use types::OpenSslTypeRef;
use x509::X509;

type_!(X509StoreBuilder, X509StoreBuilderRef, ffi::X509_STORE, ffi::X509_STORE_free);

impl X509StoreBuilderRef {
    /// Adds a certificate to the certificate store.
    pub fn add_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        unsafe {
            let ptr = cert.as_ptr();
            mem::forget(cert); // the cert will be freed inside of X509_STORE_add_cert on error
            cvt(ffi::X509_STORE_add_cert(self.as_ptr(), ptr)).map(|_| ())
        }
    }
}
