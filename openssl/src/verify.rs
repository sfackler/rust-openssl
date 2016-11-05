use libc::c_uint;
use ffi;

use cvt;
use error::ErrorStack;
use types::OpenSslTypeRef;

bitflags! {
    pub flags X509CheckFlags: c_uint {
        const X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT = ffi::X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT,
        const X509_CHECK_FLAG_NO_WILDCARDS = ffi::X509_CHECK_FLAG_NO_WILDCARDS,
        const X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = ffi::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
        const X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = ffi::X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS,
        const X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS
            = ffi::X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
        /// Requires the `v110` feature and OpenSSL 1.1.0.
        #[cfg(all(feature = "v110", ossl110))]
        const X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = ffi::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
    }
}

type_!(X509VerifyParam, X509VerifyParamRef, ffi::X509_VERIFY_PARAM, ffi::X509_VERIFY_PARAM_free);

impl X509VerifyParamRef {
    pub fn set_hostflags(&mut self, hostflags: X509CheckFlags) {
        unsafe {
            ffi::X509_VERIFY_PARAM_set_hostflags(self.as_ptr(), hostflags.bits);
        }
    }

    pub fn set_host(&mut self, host: &str) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set1_host(self.as_ptr(),
                                                 host.as_ptr() as *const _,
                                                 host.len()))
                .map(|_| ())
        }
    }
}
