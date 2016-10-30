use libc::c_long;
use std::{ptr, fmt};
use std::ops::Deref;

use ffi;
use opaque::Opaque;

use {cvt, cvt_p};
use bio::MemBio;
use error::ErrorStack;

/// A borrowed Asn1Time
pub struct Asn1TimeRef(Opaque);

impl Asn1TimeRef {
    /// Creates a new `Asn1TimeRef` wrapping the provided handle.
    pub unsafe fn from_ptr<'a>(handle: *mut ffi::ASN1_TIME) -> &'a Asn1TimeRef {
        &*(handle as *mut _)
    }

    /// Returns the raw handle
    pub fn as_ptr(&self) -> *mut ffi::ASN1_TIME {
        self as *const _ as *mut _
    }
}

impl fmt::Display for Asn1TimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mem_bio = try!(MemBio::new());
        let as_str = unsafe {
            try!(cvt(ffi::ASN1_TIME_print(mem_bio.as_ptr(), self.as_ptr())));
            String::from_utf8_unchecked(mem_bio.get_buf().to_owned())
        };
        write!(f, "{}", as_str)
    }
}


/// Corresponds to the ASN.1 structure Time defined in RFC5280
pub struct Asn1Time(*mut ffi::ASN1_TIME);

impl Asn1Time {
    /// Wraps existing ASN1_TIME and takes ownership
    pub unsafe fn from_ptr(handle: *mut ffi::ASN1_TIME) -> Asn1Time {
        Asn1Time(handle)
    }

    fn from_period(period: c_long) -> Result<Asn1Time, ErrorStack> {
        ffi::init();

        unsafe {
            let handle = try!(cvt_p(ffi::X509_gmtime_adj(ptr::null_mut(), period)));
            Ok(Asn1Time::from_ptr(handle))
        }
    }

    /// Creates a new time on specified interval in days from now
    pub fn days_from_now(days: u32) -> Result<Asn1Time, ErrorStack> {
        Asn1Time::from_period(days as c_long * 60 * 60 * 24)
    }
}

impl Deref for Asn1Time {
    type Target = Asn1TimeRef;

    fn deref(&self) -> &Asn1TimeRef {
        unsafe { Asn1TimeRef::from_ptr(self.0) }
    }
}

impl Drop for Asn1Time {
    fn drop(&mut self) {
        unsafe { ffi::ASN1_TIME_free(self.as_ptr()) };
    }
}
