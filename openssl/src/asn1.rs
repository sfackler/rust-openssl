use libc::c_long;
use std::{ptr, fmt};
use ffi;

use {cvt, cvt_p};
use bio::MemBio;
use error::ErrorStack;
use types::{OpenSslType, Ref};

type_!(Asn1Time, ffi::ASN1_TIME, ffi::ASN1_TIME_free);

impl fmt::Display for Ref<Asn1Time> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mem_bio = try!(MemBio::new());
        let as_str = unsafe {
            try!(cvt(ffi::ASN1_TIME_print(mem_bio.as_ptr(), self.as_ptr())));
            String::from_utf8_unchecked(mem_bio.get_buf().to_owned())
        };
        write!(f, "{}", as_str)
    }
}

impl Asn1Time {
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
