use ffi;

#[allow(dead_code)]
extern "C" {
    pub fn rust_SSL_CTX_clone(cxt: *mut ffi::SSL_CTX);
    pub fn rust_X509_clone(x509: *mut ffi::X509);
}
