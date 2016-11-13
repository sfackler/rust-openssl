use ffi;
use std::ptr;

use {cvt, cvt_p, init};
use error::ErrorStack;
use nid::Nid;
use types::OpenSslTypeRef;

type_!(EcKey, EcKeyRef, ffi::EC_KEY, ffi::EC_KEY_free);

impl EcKeyRef {
    private_key_to_pem!(ffi::PEM_write_bio_ECPrivateKey);
    private_key_to_der!(ffi::i2d_ECPrivateKey);
}

impl EcKey {
    pub fn new_by_curve_name(nid: Nid) -> Result<EcKey, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(EcKey)
        }
    }

    private_key_from_pem!(EcKey, ffi::PEM_read_bio_ECPrivateKey);
    private_key_from_der!(EcKey, ffi::d2i_ECPrivateKey);
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
