use ffi;
use libc::{c_long, c_char};
use std::fmt;
use std::ptr;
use std::slice;
use std::str;

use {cvt, cvt_p};
use bio::MemBio;
use error::ErrorStack;
use types::{OpenSslType, OpenSslTypeRef};
use string::OpensslString;

type_!(Asn1GeneralizedTime, Asn1GeneralizedTimeRef, ffi::ASN1_GENERALIZEDTIME, ffi::ASN1_GENERALIZEDTIME_free);

impl fmt::Display for Asn1GeneralizedTimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = try!(MemBio::new());
            try!(cvt(ffi::ASN1_GENERALIZEDTIME_print(mem_bio.as_ptr(), self.as_ptr())));
            write!(f, "{}", str::from_utf8_unchecked(mem_bio.get_buf()))
        }
    }
}

type_!(Asn1Time, Asn1TimeRef, ffi::ASN1_TIME, ffi::ASN1_TIME_free);

impl fmt::Display for Asn1TimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = try!(MemBio::new());
            try!(cvt(ffi::ASN1_TIME_print(mem_bio.as_ptr(), self.as_ptr())));
            write!(f, "{}", str::from_utf8_unchecked(mem_bio.get_buf()))
        }
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

type_!(Asn1String, Asn1StringRef, ffi::ASN1_STRING, ffi::ASN1_STRING_free);

impl Asn1StringRef {
    pub fn as_utf8(&self) -> Result<OpensslString, ErrorStack> {
        unsafe {
            let mut ptr = ptr::null_mut();
            let len = ffi::ASN1_STRING_to_UTF8(&mut ptr, self.as_ptr());
            if len < 0 {
                return Err(ErrorStack::get());
            }

            Ok(OpensslString::from_ptr(ptr as *mut c_char))
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(ASN1_STRING_data(self.as_ptr()), self.len()) }
    }

    pub fn len(&self) -> usize {
        unsafe { ffi::ASN1_STRING_length(self.as_ptr()) as usize }
    }
}

type_!(Asn1Integer, Asn1IntegerRef, ffi::ASN1_INTEGER, ffi::ASN1_INTEGER_free);

impl Asn1IntegerRef {
    pub fn get(&self) -> i64 {
        unsafe {
            return ::ffi::ASN1_INTEGER_get(self.as_ptr());
        }
    }

    pub fn set(&self, value: i64) -> Result<(), ErrorStack>
    {
        unsafe {
            let res = ::ffi::ASN1_INTEGER_set(self.as_ptr(), value);
            if res < 0 {
                return Err(ErrorStack::get());
            }

            Ok(())
        }
    }
}

#[cfg(any(ossl101, ossl102))]
use ffi::ASN1_STRING_data;

#[cfg(ossl110)]
#[allow(bad_style)]
unsafe fn ASN1_STRING_data(s: *mut ffi::ASN1_STRING) -> *mut ::libc::c_uchar {
    ffi::ASN1_STRING_get0_data(s) as *mut _
}
