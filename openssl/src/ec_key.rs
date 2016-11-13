use ffi;
use std::cmp;
use libc::c_long;
use std::ptr;

use {cvt, cvt_p, init};
use error::ErrorStack;
use nid::Nid;
use types::OpenSslTypeRef;

type_!(EcKey, EcKeyRef, ffi::EC_KEY, ffi::EC_KEY_free);

impl EcKeyRef {
    /// Serializes the private key components to DER.
    pub fn private_key_to_der(&self) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let len = try!(cvt(ffi::i2d_ECPrivateKey(self.as_ptr(), ptr::null_mut())));
            let mut buf = vec![0; len as usize];
            try!(cvt(ffi::i2d_ECPrivateKey(self.as_ptr(), &mut buf.as_mut_ptr())));
            Ok(buf)
        }
    }
}

impl EcKey {
    pub fn new_by_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(EcKey)
        }
    }
    /// Deserializes a DER-encoded private key.
    pub fn private_key_from_der(der: &[u8]) -> Result<EcKey, ErrorStack> {
        unsafe {
            init();
            let len = cmp::min(der.len(), c_long::max_value() as usize) as c_long;
            cvt_p(ffi::d2i_ECPrivateKey(ptr::null_mut(), &mut der.as_ptr(), len)).map(EcKey)
        }
    }

    private_key_from_pem!(EcKey, ffi::PEM_read_bio_ECPrivateKey);
}

#[cfg(test)]
mod test {
    use nid;
    use super::*;

    #[test]
    fn new_by_curve_name() {
        EcKey::new_by_curve_name(nid::X9_62_PRIME256V1).unwrap();
    }
}
