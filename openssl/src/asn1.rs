//! Defines the format of certificiates
//!
//! Abstract Syntax Notation One is an interface description language.
//! The specification comes from [X.208] by OSI, and rewritten in X.680.
//! ASN.1 describes properties of an object with a type set.  Those types
//! can be atomic, structured, choice, and other (CHOICE and ANY).  These
//! types are expressed as a number and the assignment operator ::=  gives
//! the type a name.
//!
//! The implementation here provides a subset of the ASN.1 types that OpenSSL
//! uses, especially in the properties of a certificate used in HTTPS.
//!
//! [X.208]: https://www.itu.int/rec/T-REC-X.208-198811-W/en

use ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_long, c_char, c_int};
use std::fmt;
use std::ptr;
use std::slice;
use std::str;

use {cvt, cvt_p};
use bio::MemBio;
use error::ErrorStack;
use nid::Nid;
use string::OpensslString;

foreign_type! {
    type CType = ffi::ASN1_GENERALIZEDTIME;
    fn drop = ffi::ASN1_GENERALIZEDTIME_free;

    /// Non-UTC representation of time
    ///
    /// If a time can be represented by UTCTime, UTCTime is used
    /// otherwise, ASN1_GENERALIZEDTIME is used.  This would be, for
    /// example outside the year range of 1950-2049.
    ///
    /// [ASN1_GENERALIZEDTIME_set] documentation from OpenSSL provides
    /// further details of implmentation.
    ///
    /// [ASN1_GENERALIZEDTIME_set]: https://www.openssl.org/docs/manmaster/man3/ASN1_GENERALIZEDTIME_set.html
    pub struct Asn1GeneralizedTime;
    /// Reference to a [`Asn1GeneralizedTime`]
    ///
    /// [`Asn1GeneralizedTime`]: struct.Asn1GeneralizedTime.html
    pub struct Asn1GeneralizedTimeRef;
}

impl fmt::Display for Asn1GeneralizedTimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = try!(MemBio::new());
            try!(cvt(ffi::ASN1_GENERALIZEDTIME_print(
                mem_bio.as_ptr(),
                self.as_ptr(),
            )));
            write!(f, "{}", str::from_utf8_unchecked(mem_bio.get_buf()))
        }
    }
}

foreign_type! {
    type CType = ffi::ASN1_TIME;
    fn drop = ffi::ASN1_TIME_free;
    /// Time storage and comparison
    ///
    /// Asn1Time should be used to store and share time information
    /// using certificates.  If Asn1Time is set using a string, it must
    /// be in either YYMMDDHHMMSSZ, YYYYMMDDHHMMSSZ, or another ASN.1 format.
    ///
    /// [ASN_TIME_set] documentation at OpenSSL explains the ASN.1 implementaiton
    /// used by OpenSSL.
    ///
    /// [ASN_TIME_set]: https://www.openssl.org/docs/manmaster/man3/ASN1_TIME_set.html
    pub struct Asn1Time;
    /// Reference to an [`Asn1Time`]
    ///
    /// [`Asn1Time`]: struct.Asn1Time.html
    pub struct Asn1TimeRef;
}

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

foreign_type! {
    type CType = ffi::ASN1_STRING;
    fn drop = ffi::ASN1_STRING_free;
    /// Primary ASN.1 type used by OpenSSL
    ///
    /// Almost all ASN.1 types in OpenSSL are represented by ASN1_STRING
    /// structures.  This implementation uses [ASN1_STRING-to_UTF8] to preserve
    /// compatibility with Rust's String.
    ///
    /// [ASN1_STRING-to_UTF8]: https://www.openssl.org/docs/manmaster/man3/ASN1_STRING_to_UTF8.html
    pub struct Asn1String;
    /// Reference to [`Asn1String`]
    ///
    /// [`Asn1String`]: struct.Asn1String.html
    pub struct Asn1StringRef;
}

impl Asn1StringRef {
    /// Converts the ASN.1 underlying format to UTF8
    ///
    /// ASN.1 strings may utilize UTF-16, ASCII, BMP, or UTF8.  This is important to
    /// consume the string in a meaningful way without knowing the underlying
    /// format.
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

    /// Return the string as an array of bytes
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(ASN1_STRING_data(self.as_ptr()), self.len()) }
    }

    /// Return the length of the Asn1String (number of bytes)
    pub fn len(&self) -> usize {
        unsafe { ffi::ASN1_STRING_length(self.as_ptr()) as usize }
    }
}

foreign_type! {
    type CType = ffi::ASN1_INTEGER;
    fn drop = ffi::ASN1_INTEGER_free;

    pub struct Asn1Integer;
    pub struct Asn1IntegerRef;
}

impl Asn1IntegerRef {
    pub fn get(&self) -> i64 {
        unsafe { ::ffi::ASN1_INTEGER_get(self.as_ptr()) as i64 }
    }

    pub fn set(&mut self, value: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(::ffi::ASN1_INTEGER_set(self.as_ptr(), value as c_long)).map(|_| ()) }
    }
}

foreign_type! {
    type CType = ffi::ASN1_BIT_STRING;
    fn drop = ffi::ASN1_BIT_STRING_free;

    pub struct Asn1BitString;
    pub struct Asn1BitStringRef;
}

impl Asn1BitStringRef {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(ASN1_STRING_data(self.as_ptr() as *mut _), self.len()) }
    }

    pub fn len(&self) -> usize {
        unsafe { ffi::ASN1_STRING_length(self.as_ptr() as *mut _) as usize }
    }
}

foreign_type! {
    type CType = ffi::ASN1_OBJECT;
    fn drop = ffi::ASN1_OBJECT_free;

    pub struct Asn1Object;
    pub struct Asn1ObjectRef;
}

impl Asn1ObjectRef {
    /// Returns the NID associated with this OID.
    pub fn nid(&self) -> Nid {
        unsafe { Nid::from_raw(ffi::OBJ_obj2nid(self.as_ptr())) }
    }
}

impl fmt::Display for Asn1ObjectRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mut buf = [0; 80];
            let len = ffi::OBJ_obj2txt(
                buf.as_mut_ptr() as *mut _,
                buf.len() as c_int,
                self.as_ptr(),
                0,
            );
            let s = try!(str::from_utf8(&buf[..len as usize]).map_err(|_| fmt::Error));
            fmt.write_str(s)
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
