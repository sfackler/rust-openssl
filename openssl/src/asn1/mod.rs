use libc::c_long;
use std::ptr;

use ffi;
use error::ErrorStack;

pub struct Asn1Time(*mut ffi::ASN1_TIME);

impl Asn1Time {
    /// Wraps existing ASN1_TIME and takes ownership
    pub unsafe fn from_ptr(handle: *mut ffi::ASN1_TIME) -> Asn1Time {
        Asn1Time(handle)
    }

    fn from_period(period: c_long) -> Result<Asn1Time, ErrorStack> {
        ffi::init();

        unsafe {
            let handle = try_ssl_null!(ffi::X509_gmtime_adj(ptr::null_mut(), period));
            Ok(Asn1Time::from_ptr(handle))
        }
    }

    /// Creates a new time on specified interval in days from now
    pub fn days_from_now(days: u32) -> Result<Asn1Time, ErrorStack> {
        Asn1Time::from_period(days as c_long * 60 * 60 * 24)
    }

    /// Returns the raw handle
    pub fn as_ptr(&self) -> *mut ffi::ASN1_TIME {
        self.0
    }
}

impl Drop for Asn1Time {
    fn drop(&mut self) {
        unsafe { ffi::ASN1_TIME_free(self.0) };
    }
}
