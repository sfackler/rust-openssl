use libc::{c_long};
use std::ptr;

use ffi;
use ssl::error::{SslError};


pub struct Asn1Time {
    handle: *mut ffi::ASN1_TIME,
    owned: bool
}

impl Asn1Time {
    /// Wraps existing ASN1_TIME and takes ownership
    pub fn new(handle: *mut ffi::ASN1_TIME) -> Asn1Time {
        Asn1Time {
            handle: handle,
            owned: true
        }
    }

    fn new_with_period(period: u64) -> Result<Asn1Time, SslError> {
        ffi::init();

        let handle = unsafe {
            try_ssl_null!(ffi::X509_gmtime_adj(ptr::null_mut(),
                                               period as c_long))
        };
        Ok(Asn1Time::new(handle))
    }

    /// Creates a new time on specified interval in days from now
    pub fn days_from_now(days: u32) -> Result<Asn1Time, SslError> {
        Asn1Time::new_with_period(days as u64 * 60 * 60 * 24)
    }

    /// Returns raw handle
    pub unsafe fn get_handle(&self) -> *mut ffi::ASN1_TIME {
        return self.handle
    }
}

impl Drop for Asn1Time {
    fn drop(&mut self) {
        if self.owned {
            unsafe { ffi::ASN1_TIME_free(self.handle) };
        }
    }
}
