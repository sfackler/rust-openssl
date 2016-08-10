use ffi;

#[allow(dead_code)]
extern "C" {
    pub fn rust_SSL_CTX_clone(cxt: *mut ffi::SSL_CTX);
    pub fn rust_X509_clone(x509: *mut ffi::X509);
    pub fn rust_X509_get_extensions(x: *mut ffi::X509) -> *mut ffi::stack_st_X509_EXTENSION;
}
