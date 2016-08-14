//! PKCS #12 archives.

use ffi;
use libc::{c_long, c_uchar};
use std::cmp;
use std::ptr;

use error::ErrorStack;

/// A PKCS #12 archive.
pub struct Pkcs12(*mut ffi::PKCS12);

impl Drop for Pkcs12 {
    fn drop(&mut self) {
        unsafe { ffi::PKCS12_free(self.0); }
    }
}

impl Pkcs12 {
    pub fn from_der(der: &[u8]) -> Result<Pkcs12, ErrorStack> {
        unsafe {
            let mut ptr = der.as_ptr() as *const c_uchar;
            let length = cmp::min(der.len(), c_long::max_value() as usize) as c_long;
            let p12 = try_ssl_null!(ffi::d2i_PKCS12(ptr::null_mut(), &mut ptr, length));
            Ok(Pkcs12(p12))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_der() {
        let der = include_bytes!("../../test/identity.p12");
        Pkcs12::from_der(der).unwrap();
    }
}
